"""지표·열린 문제 조회(Zabbix).

원본은 한 파일(`ask.py`, 1,289줄)이었다. 2026-08-19 에 옮기기만 했고
기능은 바꾸지 않았다.
"""

import logging
from ... import masking

from ..policy import allowed_sources
log = logging.getLogger("gateway.ask")


def metric_item(it: dict, raw: list, shown: list, kind: str, mask) -> dict:
    """지표 아이템 하나의 전송 형태.

    **이름과 키를 이름 표에 거친다.** 인증서 감시 아이템 키가
    `web.certificate.get[<도메인>,443]` 형태라, 가리지 않으면 "인증서 며칠 남았어" 한 마디에
    고객 도메인이 통째로 나간다(2026-08-19 감사).
    """
    return {"name": mask(str(it.get("name") or "")),
            "key": mask(str(it.get("key_") or "")),
            "units": it.get("units"), "last": it.get("lastvalue"),
            # 몇 점을 읽어 몇 점으로 줄였는지, 그리고 **무엇을 읽었는지** 준다.
            # 안 알리면 모델이 실린 점이 전부라고 여기고 간격도 지어낸다.
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
    """열린 문제 결과 한 벌.

    Zabbix 문제명은 매크로가 풀린 문장이라 `Zabbix agent is not available on <호스트명>`
    처럼 호스트명이 박혀 있다. 같은 값을 알림 경로는 이미 가린다(masking.py).

    **총 건수를 함께 받는다.** 소스당 50건에서 자르는데 그 말이 없으면 모델은 실린 것이
    전부인 줄 안다. 실환경 사내 Zabbix 는 Warning 노이즈로 50건을 쉽게 넘는다.
    """
    from ...alerts import collector
    mask = masker.mask if masker is not None else (lambda x: x)
    out = {"problems": [{"name": mask(str(p.get("name") or "")),
                         "sev": p.get("severity"),
                         "t": int(p.get("clock") or 0)} for p in rows or []],
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
    """호스트의 지표 추이. 아이템 이름·키에 든 문자열로 고른다.

    특정 시각을 물으면 `range` 로 절대 구간이 온다. 사람은 "어제 2시에 튀었다" 로 묻지
    "지금부터 몇 분" 으로 묻지 않는다.
    """
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
            # **가나다순 앞에서 자르지 않는다.** 랩 실측으로 `cpu` 는 17개가 걸리고
            # 앞 5개가 guest·idle 시간으로 채워져 CPU utilization 이 한 번도 안 들어왔다.
            items = asktools.rank_items(items, match)
            total = len(items)
            dropped = [mask(str(x.get("name") or "")) for x in items[asktools.ITEM_LIMIT:]]
            picked = items[:asktools.ITEM_LIMIT]
            # **아이템마다 따로 묻지 않는다.** 상한이 8개라 왕복이 10번까지 갔고 콜당
            # 5초라 최악 50초였다(2026-08-19 감사). Zabbix 는 itemids 에 배열을 받으므로
            # 값 유형으로 묶으면 이력은 최대 두 번, 추세는 한 번이다.
            trend = asktools.use_trend(start, end)
            series = {}
            if trend:
                rows = await zbx.call(c, "trend.get", {
                    "itemids": [it["itemid"] for it in picked
                                if int(it.get("value_type", 3)) in (0, 3)],
                    "time_from": start, "time_till": end, "output": "extend",
                    "limit": asktools.HISTORY_FETCH_MAX * len(picked)})
                for r in rows:
                    # 값은 시간별 **최대**를 쓴다. 평균으로 줄이면 한 시간 안에 튄 자리가
                    # 묻혀 "정상입니다" 가 나온다.
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
                    # **구간 전체를 받아 놓고 줄인다.** 상한만큼만 최신순으로 받으면
                    # 앞부분이 잘려 먼저 난 스파이크를 못 본다(2026-08-18 실측).
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
                params = {"output": ["eventid", "name", "severity", "clock"],
                          "sortfield": "eventid", "sortorder": "DESC", "limit": 50}
                if entry:
                    hosts = await zbx.call(c, "host.get", {
                        "filter": {"host": entry.get("host", "")}, "output": ["hostid"]})
                    if not hosts:
                        continue
                    params["hostids"] = hosts[0]["hostid"]
                got = await zbx.call(c, "problem.get", params)
                # 총계는 따로 센다. Zabbix 는 countOutput 으로 개수만 돌려준다.
                # **빼는 것이지 비우는 것이 아니다.** `output: None` 을 보내면 Zabbix 가
                # 거부해 조회 전체가 실패한다(2026-08-19 랩 실측).
                cnt_params = {k: v for k, v in params.items()
                              if k not in ("output", "limit", "sortfield", "sortorder")}
                cnt_params["countOutput"] = True
                cnt = await zbx.call(c, "problem.get", cnt_params)
                try:
                    total += int(cnt if isinstance(cnt, (int, str)) else 0)
                except (TypeError, ValueError):
                    total += len(got)
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
