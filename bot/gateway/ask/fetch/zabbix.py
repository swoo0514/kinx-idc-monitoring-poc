"""지표·열린 문제 조회(Zabbix)."""

import logging
from ... import masking

from ..policy import allowed_sources
log = logging.getLogger("gateway.ask")


def metric_item(it: dict, raw: list, shown: list, kind: str, mask) -> dict:
    """지표 아이템 하나의 전송 형태."""
    return {"name": mask(str(it.get("name") or "")),
            "key": mask(str(it.get("key_") or "")),
            "units": it.get("units"), "last": it.get("lastvalue"),
            # 몇 점을 읽어 몇 점으로 줄였는지, 무엇을 읽었는지 함께 준다
            "sampled_from": len(raw), "series": shown,
            "source_kind": kind,
            "point_meaning": ("1시간 최대값(추세). avg·min 동봉"
                              if kind == "trend" else "원본 측정값")}


def metrics_result(items: list, series: dict, masker: masking.Masker = None) -> dict:
    """지표 결과 한 벌. 조회 없이 조립만 한다 — 검사가 실경로와 같은 조립을 쓰게."""
    from .. import tools as asktools
    mask = masker.mask if masker is not None else (lambda x: x)
    out = []
    for it in items or []:
        raw = list((series or {}).get(str(it.get("itemid"))) or [])
        out.append(metric_item(it, raw, asktools.downsample(raw), "history", mask))
    return {"metrics": out}


def problems_result(rows: list, masker: masking.Masker = None, total: int = 0) -> dict:
    """열린 문제 결과 한 벌."""
    from ...alerts import collector
    mask = masker.mask if masker is not None else (lambda x: x)
    def _one(p):
        # 어느 대상의 문제인지 없으면 전체 조회가 쓸모없다 — 사슬이 여러 호스트에 걸친
        # 사건에서 이 목록이 유일한 연결 고리다(랩 실증 단계 3).
        hs = p.get("hosts") or []
        host = mask(str((hs[0] or {}).get("host") or "")) if hs else ""
        row = {"name": mask(str(p.get("name") or "")), "sev": p.get("severity"),
               "t": int(p.get("clock") or 0)}
        if host:
            row["host"] = host
        return row

    out = {"problems": [_one(p) for p in rows or []],
           "status": collector.SOURCE_OK}
    if total:
        out["total"] = int(total)
        if int(total) > len(out["problems"]):
            out["note"] = ("지금 열린 문제는 모두 %d건인데 최근 %d건만 실었다. 건수는 "
                           "total 을 쓰고, 나머지는 host 를 지정해 좁혀서 보라"
                           % (int(total), len(out["problems"])))
    return out


async def fetch_metrics(entry: dict, match: str, start: int, end: int,
                        masker: masking.Masker = None) -> dict:
    """호스트의 지표 추이. 아이템 이름·키에 든 문자열로 고른다."""
    import httpx

    from ...alerts import collector
    from .. import tools as asktools
    mask = masker.mask if masker is not None else (lambda x: x)
    try:
        zbx = collector.ZabbixClient(source=entry.get("source", ""))
        async with httpx.AsyncClient() as c:
            hosts = await zbx.call(c, "host.get", {
                "filter": {"host": entry.get("host", "")}, "output": ["hostid"]})
            if not hosts:
                return {"metrics": [], "status": collector.SOURCE_UNMATCHED,
                        "note": "감시 서버가 이 호스트를 모른다"}
            params = {"hostids": hosts[0]["hostid"],
                      "output": ["itemid", "name", "key_", "value_type", "units",
                                 "lastvalue"],
                      "sortfield": "name"}
            if match:
                params["search"] = {"name": match, "key_": match}
                params["searchByAny"] = True
            items = await zbx.call(c, "item.get", params)
            if not items:
                return {"metrics": [], "status": collector.SOURCE_OK,
                        "note": "그 조건에 맞는 아이템이 없다. match 를 넓혀 보라"}
            # 가나다순 앞에서 자르지 않는다 — cpu 17개 중 앞 5개가 guest·idle 로 채워졌다
            items = asktools.rank_items(items, match)
            total = len(items)
            dropped = [mask(str(x.get("name") or "")) for x in items[asktools.ITEM_LIMIT:]]
            picked = items[:asktools.ITEM_LIMIT]
            # 아이템마다 따로 묻지 않는다 — itemids 배열로 묶으면 이력 최대 두 번, 추세 한 번이다
            trend = asktools.use_trend(start, end)
            series = {}
            if trend:
                rows = await zbx.call(c, "trend.get", {
                    "itemids": [it["itemid"] for it in picked
                                if int(it.get("value_type", 3)) in (0, 3)],
                    "time_from": start, "time_till": end, "output": "extend",
                    "limit": asktools.HISTORY_FETCH_MAX * len(picked)})
                for r in rows:
                    # 값은 시간별 최대를 쓴다 — 평균으로 줄이면 튄 자리가 묻혀 "정상입니다"가 나온다
                    series.setdefault(str(r.get("itemid")), []).append(
                        {"t": int(r["clock"]), "v": r.get("value_max"),
                         "avg": r.get("value_avg"), "min": r.get("value_min")})
            else:
                # 값 유형이 섞이면 나눠 부른다. history 는 호출마다 하나여야 한다.
                by_type = {}
                for it in picked:
                    vt = int(it.get("value_type", 3))
                    if vt in (0, 3):
                        by_type.setdefault(vt, []).append(it["itemid"])
                for vt, ids in by_type.items():
                    # 구간 전체를 받아 놓고 줄인다 — 최신순 상한이면 먼저 난 스파이크를 못 본다
                    hist = await zbx.call(c, "history.get", {
                        "itemids": ids, "history": vt,
                        "time_from": start, "time_till": end, "output": "extend",
                        "sortfield": "clock", "sortorder": "ASC",
                        "limit": asktools.HISTORY_FETCH_MAX * len(ids)})
                    for h in hist:
                        series.setdefault(str(h.get("itemid")), []).append(
                            {"t": int(h["clock"]), "v": h["value"]})
            out = []
            for it in picked:
                raw = sorted(series.get(str(it["itemid"])) or [], key=lambda x: x["t"])
                kind = ("trend" if trend else "history") if raw else ""
                out.append(metric_item(it, raw, asktools.downsample(raw), kind, mask))
    except Exception as e:
        log.warning("지표 조회 실패: %s", e)
        return {"metrics": [], "status": collector.SOURCE_UNAVAILABLE,
                "note": "조회하지 못했다. 이 결과를 '없음'으로 읽지 마라"}
    return asktools.note_if_cut(
        {"metrics": out, "matched": total, "window": [start, end],
         "status": collector.SOURCE_OK},
        total=total, shown=len(out), dropped=dropped)


async def _attach_hosts(zbx, client, rows: list) -> None:
    """문제마다 어느 대상의 것인지 붙인다.

    **`problem.get` 은 `selectHosts` 를 받지 않는다** — 공식 문서상 select 파라미터는
    acknowledges·tags·suppressionData 뿐이다. 호스트는 `objectid`(트리거)로 한 번 더
    조회해서 붙인다. 어느 대상의 문제인지 없으면 전체 조회가 쓸모없다.
    """
    ids = sorted({str(r.get("objectid") or "") for r in rows or []} - {""})
    if not ids:
        return
    try:
        trg = await zbx.call(client, "trigger.get",
                             {"triggerids": ids, "output": ["triggerid"],
                              "selectHosts": ["host"]})
    except Exception as e:
        log.warning("문제의 호스트 조회 실패: %s", e)
        return
    by_id = {str(t.get("triggerid")): (t.get("hosts") or []) for t in trg or []}
    for r in rows or []:
        hs = by_id.get(str(r.get("objectid") or ""))
        if hs:
            r["hosts"] = hs


async def fetch_problems(entry, masker: masking.Masker = None) -> dict:
    """지금 열려 있는 문제. 호스트를 안 주면 허용된 감시 서버 전체."""
    import httpx

    from ...alerts import collector
    try:
        sources = [entry["source"]] if entry else allowed_sources()
        out, total = [], 0
        for src in sources:
            zbx = collector.ZabbixClient(source=src)
            async with httpx.AsyncClient() as c:
                params = {"output": ["eventid", "name", "severity", "clock",
                                     "objectid"],
                          "sortfield": "eventid", "sortorder": "DESC", "limit": 50}
                if entry:
                    hosts = await zbx.call(c, "host.get", {
                        "filter": {"host": entry.get("host", "")}, "output": ["hostid"]})
                    if not hosts:
                        continue
                    params["hostids"] = hosts[0]["hostid"]
                got = await zbx.call(c, "problem.get", params)
                # 총계는 countOutput 으로 따로 센다 — 빼는 것이지 비우는 것이 아니다(output: None 은 거부)
                cnt_params = {k: v for k, v in params.items()
                              if k not in ("output", "limit", "sortfield", "sortorder")}
                cnt_params["countOutput"] = True
                cnt = await zbx.call(c, "problem.get", cnt_params)
                try:
                    total += int(cnt if isinstance(cnt, (int, str)) else 0)
                except (TypeError, ValueError):
                    total += len(got)
                await _attach_hosts(zbx, c, got)
                out.extend(problems_result(got, masker)["problems"])
    except Exception as e:
        log.warning("열린 문제 조회 실패: %s", e)
        return {"problems": [], "status": collector.SOURCE_UNAVAILABLE,
                "note": "조회하지 못했다. 이 결과를 '없음'으로 읽지 마라"}
    # 조립은 한 곳에서 한다. 총계까지 넘겨야 잘림 안내가 붙는다.
    res = problems_result([], masker, total=total)
    res["problems"] = out
    if total and int(total) <= len(out):
        res.pop("note", None)
    elif total:
        res["note"] = ("지금 열린 문제는 모두 %d건인데 최근 %d건만 실었다. 건수는 "
                       "total 을 쓰고, 나머지는 host 를 지정해 좁혀서 보라"
                       % (int(total), len(out)))
    return res
