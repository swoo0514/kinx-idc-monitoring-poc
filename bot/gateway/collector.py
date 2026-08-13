"""컨텍스트 수집기 — Zabbix(읽기전용 `.get`) + Loki 로그 + Wazuh 경보. 상세는 GATEWAY_GUIDE §9.

환경변수: ZABBIX_URL·ZABBIX_TOKEN(필수) / LOKI_URL·WAZUH_INDEXER_URL·WAZUH_INDEXER_USER·
WAZUH_INDEXER_PASSWORD(선택 — 없으면 해당 소스 생략, 열화 진행).
"""

import asyncio
import fnmatch
import logging
import os
import re
import time

import httpx

from . import prejudge, registry

log = logging.getLogger("gateway.collector")

HISTORY_WINDOW_S = 3600
HISTORY_LIMIT = 20
TIMEOUT_S = 5   # 콜당 — 수집이 30초 예산을 안 갉게

# 인시던트 시간창 — 로그·보안은 이 창에서만 (병합 대상 신호 정렬용)
CORR_WINDOW_S = 900   # 15분
# 조회 상한과 전송 상한을 나눈다. 랩 실측(2026-08-13): 평상시에도 15분에 120줄인
# 호스트가 있어 40줄 상한이 매번 3분의 2를 버렸다. 더 읽고 골라 보낸다.
# 300 은 랩 최대(120줄)의 2.5배다. 실환경은 호스트당 로그량이 미지라 도입 전 재측정한다.
LOKI_FETCH_LIMIT = 300
# 전송 예산. **줄 수가 아니라 글자 수가 진짜 예산이다** — 모델이 먹는 단위가 글자
# 수이고, 줄 수는 줄 길이에 따라 같은 값이 열 배 차이가 난다.
#
# 40줄이라는 옛 값은 응답 시간 때문이라고 적혀 있었으나 근거가 없었다. 실측
# (2026-08-13, claude-opus-4-8, 3회 중앙값): 입력을 3,746토큰에서 278,286토큰으로
# 75배 늘려도 응답 시간은 9.70초에서 11.86초로 2.2초 늘었다. 40줄 제한이 지킨 것은
# 2초였고, 그 대가는 원인 줄을 버릴 위험이었다.
#
# 그래서 상한을 조회 상한과 같은 300줄로 올리고, 실제 제동은 글자 수로 건다.
# 64KB 는 300줄이 평균 213자 이하일 때 통째로 나가는 크기다. 랩 실측 줄 길이는
# 중앙값 108자·최대 233자이므로 평상시에는 걸리지 않고, 스택 트레이스처럼 줄이
# 유난히 긴 구간에서만 선별이 개입한다.
LOKI_SEND_LIMIT = 300
LOKI_SEND_BYTES = 64 * 1024
# 줄 수만으로는 부족하다. 300자 절단은 응답을 받은 뒤 우리가 하므로 와이어에는 전장이
# 온다. 4KB 줄이면 300줄이 1.2MB 이고 그 파싱이 이벤트 루프를 막는다.
LOKI_FETCH_BYTES = 2 * 1024 * 1024
LOKI_LINE_MAX = 300   # 라인당 최대 문자 (토큰 억제). 랩 실측 최대 233자로 현재는 안 걸린다
WAZUH_LIMIT = 20
# 과거 이벤트 목록 상한. 개수는 따로 세므로 이 값이 판정에 영향을 주지 않는다.
PAST_EVENT_LIMIT = 200

# 한 호스트에서 열린 문제를 몇 건까지 받아 볼지. 오래된 것부터 받는다.
OPEN_PROBLEM_LIMIT = 100

# 호스트 이름이 그 소스에 등록돼 있는지 확인할 때 되짚는 기간
KNOWN_HOST_LOOKBACK_S = 7 * 86400
LOKI_HOST_LABEL = os.environ.get("LOKI_HOST_LABEL", "host")

# 교차 소스 조회 상태 — "신호 없음"과 "조회 실패"를 구분한다. 근거는 GATEWAY_GUIDE §12.
SOURCE_OK = "ok"                    # 조회 성공 (결과가 비어 있어도 "없음"이 사실)
SOURCE_UNAVAILABLE = "unavailable"  # 조회 시도했으나 실패 — 비어 있음을 근거로 쓰면 안 됨
SOURCE_DISABLED = "disabled"        # 미배선(URL 미설정) — 애초에 판단 근거가 없음
SOURCE_UNMATCHED = "unmatched"      # 조회는 됐으나 그 호스트 이름을 그 소스가 모름


class ZabbixClient:
    """감시 서버 하나에 붙는 조회 전용 클라이언트.

    감시 서버가 둘 이상이면 **알림이 온 곳에 되물어야 한다.** 사내 알림의 이력을 MSP
    서버에 물으면 없는 호스트라 빈 결과가 오거나, 더 나쁘게는 이름이 같은 남의 호스트
    자료가 온다. 어느 서버에 물을지는 명부의 감시 서버 절에서 고른다.
    """

    def __init__(self, url: str = None, token: str = None, source: str = ""):
        conf = registry.source_conf(source) if source else {}
        # 명부를 못 읽었으면 소스를 지정한 조회를 막는다. 조용히 기본 서버로 떨어지면
        # MSP 알림의 이벤트 ID 를 사내 서버에 묻게 되는데, ID 는 서버마다 따로 늘어나므로
        # 없으면 "90일 내 이력 없음 = 신규"로 확정되고 겹치면 남의 호스트 자료가 그
        # 고객 사건에 실린다. 둘 다 예외가 안 나서 상태는 ok 로 남는다.
        #
        # 명부가 아예 설정 안 된 환경(감시 서버 하나)은 여기 안 걸린다 — 그때는
        # registry.status()["error"] 가 비어 있다.
        if url is None and source and not conf.get("url"):
            st = registry.status()
            if st.get("error"):
                raise RuntimeError(
                    "호스트 명부를 못 읽어(%s) 감시 서버 %r 의 주소를 모른다. 기본 서버로 "
                    "대신 묻지 않는다 — 남의 서버 자료가 이 사건에 실린다. "
                    "명부(%s)를 고치고 재기동한다." % (st["error"], source, st["path"]))
        if url is None and conf.get("url"):
            url = conf["url"]
            # 토큰은 파일이 아니라 환경변수에서 읽는다(명부는 깃에 올라간다).
            token = token or os.environ.get(conf.get("token_env") or "", "")
            if not token:
                log.error("감시 서버 %s 의 토큰이 비었다(%s 미설정) — 조회가 실패한다",
                          source, conf.get("token_env"))
        base = (url or os.environ.get("ZABBIX_URL", "")).rstrip("/")
        self.api = base + "/api_jsonrpc.php"
        self.token = token or os.environ.get("ZABBIX_TOKEN", "")
        self.source = source
        self._id = 0

    async def call(self, client: httpx.AsyncClient, method: str, params: dict):
        if not method.endswith(".get"):   # 읽기 전용 강제 (작업 원칙 4)
            raise ValueError(f"read-only violation: {method}")
        # 설정 실수는 스택 트레이스가 아니라 한 줄로 말한다.
        if not self.api.startswith(("http://", "https://")):
            raise RuntimeError(
                "ZABBIX_URL 이 비었거나 형식이 틀렸다(현재: %r). "
                "base 까지만 적는다 — 코드가 /api_jsonrpc.php 를 붙인다. "
                ".env 는 `set -a; source bot/.env; set +a` 로 읽는다"
                "(source 만 하면 셸 변수라 파이썬이 못 본다)." % self.api)
        if not self.token:
            raise RuntimeError("ZABBIX_TOKEN 이 비었다. 읽기 전용 토큰을 설정한다.")
        self._id += 1
        r = await client.post(
            self.api,
            json={"jsonrpc": "2.0", "method": method, "params": params, "id": self._id},
            headers={"Authorization": f"Bearer {self.token}",
                     "Content-Type": "application/json-rpc"},
            timeout=TIMEOUT_S,
        )
        r.raise_for_status()
        body = r.json()
        if "error" in body:
            raise RuntimeError(f"zabbix api error on {method}: {body['error']}")
        return body["result"]


async def _zabbix_alert_context(zbx: ZabbixClient, client: httpx.AsyncClient,
                                event_id: str, trigger_id: str, now: int) -> dict:
    """트리거 1건의 Zabbix 컨텍스트(이벤트·트리거·호스트·메트릭·선판정). 로그·보안 제외."""
    # 과거 이력은 **개수와 최근 목록을 따로** 받는다. 한 번에 받으면 상한에 걸려
    # 만성끼리 순위가 안 나온다(실환경 90일: 상한 초과 12계열이 이벤트의 95%이고,
    # 21,585회와 547회가 똑같이 상한값으로 보였다). 근거는 GATEWAY_GUIDE §7-3.
    past_window = {"objectids": trigger_id, "source": 0, "object": 0, "value": 1,
                   "time_from": now - prejudge.WINDOW_S, "time_till": now}
    cur_event, trigger, metrics, past, past_count = await asyncio.gather(
        zbx.call(client, "event.get", {
            "eventids": event_id, "selectTags": "extend", "output": "extend"}),
        zbx.call(client, "trigger.get", {
            "triggerids": trigger_id, "output": "extend",
            "expandExpression": True, "selectHosts": ["hostid", "host", "name"]}),
        _metrics_trend(zbx, client, trigger_id, now),
        # 목록은 마지막 발생 시각을 알기 위한 것이라 최근 것만 있으면 된다.
        zbx.call(client, "event.get", dict(past_window, **{
            "output": ["eventid", "clock"], "sortfield": "clock", "sortorder": "DESC",
            "limit": PAST_EVENT_LIMIT})),
        # 개수는 내용을 안 받으므로 몇만 건이어도 응답이 한 줄이다(공식: countOutput).
        zbx.call(client, "event.get", dict(past_window, countOutput=True)),
    )
    host = {}
    hosts = (trigger[0].get("hosts") if trigger else None) or []
    if hosts:
        got = await zbx.call(client, "host.get", {
            "hostids": hosts[0]["hostid"], "output": ["hostid", "host", "name", "status"],
            "selectHostGroups": ["name"], "selectInterfaces": ["ip", "dns"]})
        host = got[0] if got else {}
    if not host.get("host") and hosts:
        host = {**host, "host": hosts[0].get("host", "")}
    # 상한에 걸렸는지는 **거른 뒤 개수가 아니라 받은 개수**로 판정해야 한다. 현재
    # 이벤트를 빼면 199 가 되어, 받는 쪽이 200 과 비교하면 영원히 안 걸린다.
    past_truncated = len(past) >= PAST_EVENT_LIMIT
    past_clocks = [int(e["clock"]) for e in past if e.get("eventid") != str(event_id)]
    # countOutput 은 숫자를 문자열로 돌려준다. 현재 이벤트가 창 안에 있으므로 1 을 뺀다.
    total = _as_count(past_count)
    if total is not None:
        total = max(0, total - 1)
    return {
        "event": cur_event[0] if cur_event else {},
        "trigger": trigger[0] if trigger else {},
        "host": host,
        "metrics": metrics,
        "prejudge": prejudge.judge(past_clocks, now=now, total_count=total,
                                   listed_truncated=past_truncated),
    }


def _as_count(res) -> int:
    """countOutput 응답을 정수로. 형태가 다르면 None — 개수를 지어내지 않는다."""
    try:
        return int(res)
    except (TypeError, ValueError):
        log.warning("countOutput 응답을 숫자로 못 읽었다(%r) — 목록 길이로 대체", res)
        return None


async def collect_context(zbx: ZabbixClient, event_id: str, trigger_id: str) -> dict:
    """단건 알림 컨텍스트 — Zabbix + Loki 로그 + Wazuh 경보 (같은 시간창)."""
    now = int(time.time())
    async with httpx.AsyncClient() as client:
        base = await _zabbix_alert_context(zbx, client, event_id, trigger_id, now)

    zbx_host = base["host"].get("host") or ""
    source = ""   # 단건 경로는 소스를 안 받는다 — 명부는 소스 없는 항목으로 매칭된다
    # 축마다 이름이 다를 수 있다(Loki 라벨과 Wazuh 에이전트명이 갈리는 환경이 있다).
    loki_label = _resolve_label(zbx_host, base["host"], source, "logs")
    wz_label = _resolve_label(zbx_host, base["host"], source, "security")
    (logs, logs_status, logs_capped, logs_clip), (security, sec_status) = await asyncio.gather(
        _loki_logs(loki_label, now, zbx_host, source),
        _wazuh_alerts(wz_label, now, zbx_host, source),
    )
    picked_logs = select_logs(logs)
    return {
        **base,
        "loki_label": loki_label,
        "wazuh_label": wz_label,
        "logs": picked_logs,   # Loki (Alloy) — 조회분 중 보낼 것만
        "security": security,    # Wazuh Indexer — 침해·변경 경보
        # 빈 목록의 의미를 확정하는 상태. ok 일 때만 "없음 = 사실"이다.
        "sources": {"logs": logs_status, "security": sec_status},
        # 조회 상태와 별개다. 창에서 몇 줄을 읽었고 그중 몇 줄을 보냈는지,
        # 조회 자체가 상한에 닿았는지를 각각 낸다.
        "logs_fetched": len(logs),
        # 생략 표시는 줄이 아니다. 세면 41줄 조회에서 fetched 와 selected 가 같아져
        # "일부만 실렸다"는 경고가 붙지 않는다(2026-08-13 감사).
        "logs_selected": sum(1 for r in picked_logs if "line" in r),
        "logs_fetch_capped": logs_capped,
        # 이 경로는 알림이 실시간으로 도착한 것이라 지금이 곧 사건 시각이다.
        "logs_window_guessed": False,
        "logs_clipped": logs_clip,
        # 사람이 원문으로 되짚을 재료. 화이트리스트에 없어 모델에는 안 간다.
        "logs_query": '{%s="%s"}' % (LOKI_HOST_LABEL, loki_label) if loki_label else "",
        "logs_from": now - CORR_WINDOW_S,
        "logs_to": now,
    }


def reference_time(incident, now: int, extra_clocks=()) -> int:
    """로그·보안 조회 창의 기준 시각.

    사건이 난 시각을 알면 그 시각을 쓴다. 재기동 후 대기 알림을 다시 넣으면 받은
    시각은 새로 찍히지만 사건이 난 시각은 그대로이므로, 이 값이 있어야 실제 로그
    구간을 본다.

    모르면(0) 지금을 쓴다 — 없는 값을 지어내지 않는다. 미래 시각도 안 믿는다.
    발행 측 시계가 앞서 있으면 창이 통째로 빗나가는데, 그게 조용히 일어난다.
    """
    # 감시 서버가 돌려준 이벤트 시각이 가장 정확하다. 발송 설정이 시각을 안 실어
    # 보내도 이 값은 온다. 발송 측 매크로에 의존하지 않으려고 이 순서로 둔다.
    known = _known_clocks(incident, now, extra_clocks)
    if not known:
        return now
    return int(min(known))


def _known_clocks(incident, now: int, extra_clocks=()) -> list:
    known = [c for c in extra_clocks if c]
    known += [a.clock for a in getattr(incident, "alerts", []) if getattr(a, "clock", 0)]
    return [c for c in known if c <= now + 60]


def reference_guessed(incident, now: int, extra_clocks=()) -> bool:
    """조회 창의 기준을 사건 시각이 아니라 '지금'으로 떨어뜨렸는가.

    떨어뜨리는 것 자체는 설계다(없는 값을 지어내지 않는다). 문제는 그 사실이 조용하다는
    점이다. 2026-08-13 랩에서 사건 두 시간 뒤에 재분석을 돌렸더니 시각을 아무도 주지
    못해 창이 조용히 지금이 됐고, 그 한산한 창에서 잡힌 6줄을 보고 모델이 "로그 축에는
    이번 사건을 설명할 신호가 없다"고 썼다. 신호가 없던 것이 아니라 사건이 없던 시간대를
    본 것이다.
    """
    return not _known_clocks(incident, now, extra_clocks)


async def zabbix_probe(source: str = "", client=None) -> dict:
    """조회 토큰이 지금 유효한지 본다.

    토큰 만료는 사건이 나기 전에는 아무 데도 안 나타난다. JSON-RPC 는 오류도 HTTP 200
    으로 돌려주므로 웹 접근 로그에도 성공만 찍힌다. 실제로 2026-08-13 랩에서 만료된
    토큰으로 며칠을 돌았고, 그 사이 사건은 전부 "지표 미상"으로 기록됐다. 그래서
    기동 때 한 번 물어본다.
    """
    try:
        zbx = client if client is not None else ZabbixClient(source=source)
    except RuntimeError as e:
        return {"ok": False, "error": str(e)}
    try:
        async with httpx.AsyncClient() as c:
            await zbx.call(c, "host.get", {"limit": 1, "output": ["hostid"]})
        return {"ok": True, "error": ""}
    except Exception as e:                      # 어떤 실패든 기동을 막지는 않는다
        return {"ok": False, "error": str(e)}


async def collect_incident_context(zbx: ZabbixClient, incident) -> dict:
    """병합 인시던트 컨텍스트 — 알림별 Zabbix 조각 + 호스트 단위 로그·보안 1회.

    incident.alerts 는 같은 호스트(키에 host 포함). Zabbix 알림은 트리거별로 병렬 수집하고,
    Loki 로그·Wazuh 경보는 호스트 1회만 조회해 중복 호출을 막는다. trigger_id 없는 알림
    (Wazuh 등)은 이름·심각도만 실어 보낸다.
    """
    now = int(time.time())
    zbx_alerts = [a for a in incident.alerts if a.trigger_id]
    per = []
    if zbx_alerts:
        async with httpx.AsyncClient() as client:
            per = await asyncio.gather(*[
                _zabbix_alert_context(zbx, client, a.event_id, a.trigger_id, now)
                for a in zbx_alerts
            ], return_exceptions=True)

    host_obj = {}
    for r in per:
        if isinstance(r, dict) and (r.get("host") or {}).get("host"):
            host_obj = r["host"]
            break
    zbx_host = host_obj.get("host") or incident.host
    source = incident.alerts[0].source if incident.alerts else ""
    loki_label = _resolve_label(zbx_host, host_obj, source, "logs") if host_obj else zbx_host
    wz_label = _resolve_label(zbx_host, host_obj, source, "security") if host_obj else zbx_host

    # 열린 문제 조회는 창 마감 시점에 1회만. 알림 도착 시점에 부르면 디바운스 창이
    # 외부 API 응답 시간만큼 흔들린다.
    async def _open_probe():
        hid = host_obj.get("hostid")
        if not hid:
            # 호스트 객체를 못 받았으면 조회 자체가 불가 — 성공이 아니다.
            return [], SOURCE_UNAVAILABLE
        exclude = {a.event_id for a in incident.alerts if a.event_id}
        async with httpx.AsyncClient() as c2:
            return await _open_problems(zbx, c2, hid, incident.classes(), exclude, now)

    # 로그·보안은 **사건이 난 시각** 기준으로 본다. 지금 기준으로 잡으면 재기동 후
    # 다시 넣은 알림에서 실제 장애 구간이 창 밖으로 밀린다.
    event_clocks = []
    for r in per:
        if isinstance(r, dict):
            try:
                event_clocks.append(int((r.get("event") or {}).get("clock") or 0))
            except (TypeError, ValueError):
                pass
    ref = reference_time(incident, now, event_clocks)
    win_guessed = reference_guessed(incident, now, event_clocks)
    if win_guessed:
        log.warning("사건 시각을 아무도 주지 않아 로그·보안 창을 지금 기준으로 "
                    "잡는다 host=%s — 이 창의 '신호 없음'은 근거가 못 된다", zbx_host)
    if ref != now:
        log.info("조회 기준을 사건 시각으로 맞춘다 host=%s (%d초 전)", zbx_host, now - ref)
    ((logs, logs_status, logs_capped, logs_clip), (security, sec_status),
     (opens, opens_status)) = await asyncio.gather(
        _loki_logs(loki_label, ref, zbx_host, source),
        _wazuh_alerts(wz_label, ref, zbx_host, source),
        _open_probe(),
    )

    # 하나라도 성공했으면 ok. 전부 실패했으면 미상이다. 알림이 애초에 Zabbix 축을
    # 안 가지면(Wazuh 단독) 판단할 대상이 없으므로 미배선으로 둔다.
    if not zbx_alerts:
        metrics_status = SOURCE_DISABLED
    elif any(isinstance(r, dict) for r in per):
        metrics_status = SOURCE_OK
    else:
        # **사유를 반드시 남긴다.** JSON-RPC 는 오류도 HTTP 200 으로 돌려주므로 접근
        # 로그에는 성공만 찍힌다. 실제로 2026-08-13 랩에서 `API token expired.` 로
        # 전건 실패했는데 원인이 어디에도 안 남아 있었다. 예외는 gather 가 담아 둔
        # 채 버려진다.
        reasons = []
        for r in per:
            if isinstance(r, BaseException):
                t = "%s: %s" % (type(r).__name__, r)
                if t not in reasons:
                    reasons.append(t)
        log.warning("Zabbix 수집 전건 실패 host=%s alerts=%d — 미상으로 표시한다. 사유: %s",
                    zbx_host, len(zbx_alerts), " / ".join(reasons) or "사유 미상")
        metrics_status = SOURCE_UNAVAILABLE

    alerts_ctx = []
    for a, r in zip(zbx_alerts, per):
        if not isinstance(r, dict):
            alerts_ctx.append({"name": a.alert_name, "source": a.source, "sev": a.sev,
                               "class": a.incident_class, "error": "collect_failed"})
            continue
        ev = r.get("event") or {}
        alerts_ctx.append({
            "name": ev.get("name") or a.alert_name,
            "source": a.source, "sev": a.sev, "class": a.incident_class,
            "trigger": r.get("trigger", {}),
            "metrics": r.get("metrics", []),
            "prejudge": r.get("prejudge", {}),
        })
    for a in incident.alerts:
        if not a.trigger_id:   # Wazuh 등 트리거 없는 알림
            alerts_ctx.append({"name": a.alert_name, "source": a.source, "sev": a.sev,
                               "class": a.incident_class, "prejudge": {}})

    picked_logs = select_logs(logs)
    return {
        "incident": {
            "host": zbx_host,
            "classes": sorted(incident.classes()),
            "alert_count": len(incident.alerts),
            "merge_reason": incident.merge_reason(),
            "fingerprint": incident.fingerprint(),
            "dominant_sev": incident.dominant_sev(),
            "scope": incident.scope(),
            "automate": incident.automate(),
        },
        "host": host_obj,
        # 축마다 부르는 이름이 다를 수 있고, 로그 라인 본문에는 그 이름이 들어 있다.
        # 마스킹이 등록하려면 컨텍스트에 실려야 한다(전송 화이트리스트에는 안 넣는다 —
        # 등록용이지 보낼 값이 아니다).
        "loki_label": loki_label,
        "wazuh_label": wz_label,
        "alerts": alerts_ctx,
        "logs": picked_logs,
        "security": security,
        # 이번 알림보다 먼저 열려 있던, 연계 관계에 있는 문제. 병합 대상이 아니라 참고 정보다.
        "open_problems": opens,
        # Zabbix 축도 상태를 낸다. 수집은 예외를 위로 안 던지므로(gather 가 예외를
        # 값으로 돌려준다) 전건 실패해도 여기까지 조용히 온다. 로그·보안만 상태를
        # 내면 게이트와 카드가 "조회는 정상"으로 읽어, Zabbix 가 죽어 있던 시간대의
        # 사건이 전부 "봐줬는데 볼 게 없었다"로 남는다.
        "sources": {"logs": logs_status, "security": sec_status,
                    "open_problems": opens_status, "metrics": metrics_status},
        # 조회 상태와 별개다. 창에서 몇 줄을 읽었고 그중 몇 줄을 보냈는지,
        # 조회 자체가 상한에 닿았는지를 각각 낸다.
        "logs_fetched": len(logs),
        # 생략 표시는 줄이 아니다. 세면 41줄 조회에서 fetched 와 selected 가 같아져
        # "일부만 실렸다"는 경고가 붙지 않는다(2026-08-13 감사).
        "logs_selected": sum(1 for r in picked_logs if "line" in r),
        "logs_fetch_capped": logs_capped,
        "logs_window_guessed": win_guessed,
        "logs_clipped": logs_clip,
        # 사람이 원문으로 되짚을 재료. 화이트리스트에 없어 모델에는 안 간다.
        "logs_query": '{%s="%s"}' % (LOKI_HOST_LABEL, loki_label) if loki_label else "",
        "logs_from": ref - CORR_WINDOW_S,
        "logs_to": ref,
    }


def _resolve_label(zbx_host: str, host_obj: dict, source: str = "", axis: str = "logs") -> str:
    """Zabbix 호스트명 → Loki/Wazuh 라벨. 세 시스템이 이름을 달리 쓰고 공유 키가 없어 필요.

    우선순위: HOST_LABEL_MAP(명시) → 인터페이스 dns(FQDN 일 때만) → Zabbix 호스트명.
    이 맵은 손 설치 호스트용 스톱갭이고, 정답은 배포 시 FQDN 정규화다 —
    docs/01-build/hosts.md.

    dns 에 점이 없으면 쓰지 않는다. 랩 실측에서 그 칸에 컨테이너 이름이 들어 있었고
    (`zabbix-agent2`·`snmpsim`), 그 이름은 여러 호스트가 공유할 수 있어 남의 로그를
    이 호스트 것으로 읽을 위험이 있다.
    """
    # 명부가 먼저다. 호스트에 관한 사실은 한 곳에 모으고, 환경변수는 명부가 없을 때만 쓴다.
    named = registry.label(source, zbx_host, axis)
    if named:
        return named
    mapping = {}
    for pair in os.environ.get("HOST_LABEL_MAP", "").split(","):
        if "=" in pair:
            k, v = pair.split("=", 1)
            mapping[k.strip()] = v.strip()
    if zbx_host in mapping:
        return mapping[zbx_host]
    for iface in (host_obj.get("interfaces") or []):
        dns = (iface.get("dns") or "").strip()
        if "." in dns:
            return dns
        if dns:
            log.debug("dns '%s' 는 FQDN 이 아니라 호스트명 '%s' 를 쓴다", dns, zbx_host)
    return zbx_host


def axis_exempt(zbx_host: str, axis: str, source: str = "") -> bool:
    """그 축이 없는 것이 정상인 호스트인가. axis 는 "logs" 또는 "security".

    두 축은 커버리지가 다르다. 로그는 라벨로 컨테이너 여럿을 논리 호스트 하나에 붙일 수
    있지만, Wazuh 는 에이전트가 OS 인스턴스마다 붙어서 컨테이너를 그 호스트로 귀속시킬
    수단이 없다. 실환경도 Wazuh 에이전트가 일부 서버에만 있다. 그래서 축마다 따로 적는다.

    안 적으면 그 호스트의 알림마다 이름 불일치로 분석이 돌고, 진짜 불일치에 쓸 상한을
    먼저 소진한다. 패턴은 Zabbix 호스트명에 맞추며 `*` 만 쓴다. 근거는 GATEWAY_GUIDE §12.
    """
    on = registry.axis_on(source, zbx_host, axis)
    if on is not None:
        return not on          # 명부가 "이 축 없음"이라고 하면 조회하지 않는다
    var = {"logs": "LOGS_EXEMPT_HOSTS", "security": "SECURITY_EXEMPT_HOSTS"}[axis]
    # 축 구분 전에 쓰던 이름. 안 지운 설정이 조용히 무시되면 왜 안 먹는지 알 수 없다.
    raw = os.environ.get(var)
    if raw is None:
        raw = os.environ.get("LOG_AXIS_EXEMPT_HOSTS", "")
    pats = [p.strip() for p in raw.split(",") if p.strip()]
    return any(fnmatch.fnmatch(zbx_host, p) for p in pats)


async def _open_problems(zbx, client, hostid: str, current_classes, exclude_ids,
                         now: int) -> tuple:
    """이 호스트에 지금 열려 있는 문제 중 현재 인시던트와 연계 관계인 것.

    병합하지 않고 컨텍스트로만 붙인다. 상태를 자체 유지하지 않고 매번 조회한다.
    설계 판단은 private/docs/open_problem_linkage_design.md.

    반환 (목록, 상태). 조회 실패를 "선행 문제 없음"으로 읽으면 없는 사실을 단언하게 된다.
    """
    # incident 가 이 모듈의 SOURCE_UNAVAILABLE 을 import 하므로 모듈 최상단에서 맞import
    # 하면 순환이 된다. 호출 시점 import 로 끊는다.
    from . import incident

    if not hostid:
        return [], SOURCE_UNAVAILABLE
    try:
        rows = await zbx.call(client, "problem.get", {
            "output": ["eventid", "name", "clock", "severity"],
            "hostids": [str(hostid)],
            "selectTags": "extend",
            "recent": False,          # 미해소만. 기본값이지만 의도를 코드에 남긴다
            "sortfield": "eventid",
            # 선행 문제는 **오래된** 쪽이다. 최근 순으로 받으면 폭주 중에 받은 100건이
            # 전부 5분 미만이라 경과 필터에서 전멸하고, 세 시간째 열려 있는 진짜 선행
            # 문제는 상한 밖으로 밀린다.
            "sortorder": "ASC",
            "limit": OPEN_PROBLEM_LIMIT,
        }) or []
    except Exception as e:
        log.warning("problem.get failed hostid=%s: %s", hostid, e)
        return [], SOURCE_UNAVAILABLE

    out = []
    for p in rows:
        eid = str(p.get("eventid") or "")
        if eid in (exclude_ids or set()):     # 이번 인시던트의 알림 자신
            continue
        age = now - int(p.get("clock", 0) or 0)
        if age < incident.OPEN_LINK_MIN_AGE_S:
            continue                          # 방금 난 것은 시간창 병합이 맡는다
        cls = incident.classify(p.get("name") or "", tags=p.get("tags"))
        # 같은 유형이 이미 인시던트에 있으면 선행이 아니라 같은 문제의 다른 임계
        # 트리거다. 같은 호스트만 조회하므로 유형이 같으면 같은 조건으로 본다.
        if cls in (current_classes or ()):
            continue
        link = incident.open_link(cls, current_classes)
        if not link:
            continue
        out.append({"name": p.get("name") or "", "class": cls, "open_for_s": age,
                    # 오래 열린 것은 선행 원인이 아니라 방치 항목이다. 지우지 않고 표시한다 —
                    # 지우면 "그런 문제가 없다"로 읽히고, 그대로 두면 인과로 읽힌다.
                    "stale": age >= incident.OPEN_LINK_STALE_AGE_S,
                    "link": link})
    # 최근 것을 먼저 — 상한에 걸려 잘릴 때 오래된 방치 항목이 아니라 선행 후보가 남게.
    out.sort(key=lambda x: x["open_for_s"])
    if not out and len(rows) >= OPEN_PROBLEM_LIMIT:
        # 상한만큼 받았는데 하나도 안 걸렸다. 상한 밖에 더 있을 수 있으므로 "없음"
        # 이라고 말하면 안 된다. 없는 사실을 단언하는 것과 같다.
        log.warning("열린 문제가 상한(%d)을 채웠는데 연계 후보가 없다 hostid=%s — "
                    "없음이 아니라 미상으로 보고한다", OPEN_PROBLEM_LIMIT, hostid)
        return [], SOURCE_UNAVAILABLE
    return out[:incident.OPEN_LINK_MAX], SOURCE_OK


# 등급은 앵커를 요구한다. 부분 문자열로 잡으면 `0 errors`·`error_rate=0`·
# `ErrorDocument 404` 가 전부 오류가 된다. 줄머리·대괄호·JSON 키·구분자 뒤만 본다.
_LEVELS = "EMERG|ALERT|CRIT|CRITICAL|FATAL|ERR|ERROR|WARN|WARNING"
# 등급 필드에 담겨 온 경우. 이때는 대소문자를 가리지 않는다.
# 열쇠 이름은 실제 형식에서 확인한 것만 넣는다 — JSON 은 level·lvl·levelname·
# severity·log.level 을 쓰고 logfmt 은 level 을 쓴다. Apache 2.4 는 [모듈:등급] 이라
# 앞자리에 콜론이 온다.
_LEVEL_FIELD_RE = re.compile(
    r'(?:^|[\s\[\(\|<{,:\'"])'
    r'(?:"?(?:level|lvl|levelname|severity|priority|log\.level)"?\s*[:=]\s*"?)'
    r'(%s)(?=$|[\s\]\)\|>:,\'"])' % _LEVELS, re.IGNORECASE)
# 괄호·대괄호 안에 등급만 들어 있는 경우. nginx `[error]`, Apache `[core:error]`.
_LEVEL_BRACKET_RE = re.compile(r'[\[\(](?:[a-z_]+:)?(%s)[\]\)]' % _LEVELS, re.IGNORECASE)
# 문장 안에 낱말로 서 있는 경우. **대문자일 때만** 인정한다. `Error Rate: 0%`,
# `warning: none`, `cpu critical threshold` 같은 평범한 문장이 오류로 잡히기 때문이다.
# alert·crit·emerg 는 이 경로에서 뺀다 — 게이트웨이·Keep·Zabbix 가 평상시에 쓰는
# 낱말이라 자기 로그가 오류 자리를 먹는다(2026-08-13 감사).
_LEVEL_BARE_RE = re.compile(
    r'(?:^|(?<=[\s\[\(\|<{,]))(FATAL|ERROR|ERR|WARNING|WARN)'
    r'(?=$|[\s\]\)\|>:,"])')
_LEVEL_MAP = {"emerg": "error", "alert": "error", "crit": "error",
              "critical": "error", "fatal": "error", "err": "error",
              "error": "error", "warn": "warn", "warning": "warn"}

# 등급 낱말이 없어도 중요한 줄이 있다. 커널과 systemd 가 그렇다.
# 문구는 공식 소스로 대조했다 — `Out of memory: Kill` 은 linux v5.14 mm/oom_kill.c,
# `Failed to start`·`Failed with result`·`Dependency failed for` 는 systemd v252
# src/core/job.c·unit.c 다. `entered failed state` 는 v219 까지만 notice 였고 지금은
# debug 라 Rocky 8·9 저널에 안 남는다 — 빼고 현행 문구로 바꾼다.
_CRITICAL_RE = re.compile(
    r"Out of memory: Kill|oom-kill|segfault|"
    r"Failed to start |Failed with result '|Dependency failed for |"
    r"Timed out starting |I/O error|EXT4-fs error")

# 정규화 — 같은 형태를 세기 위한 비교 키다. 절대 전송하지 않는다.
# 순서가 중요하다. IP → UUID → 긴 hex → 숫자 순으로 걸러야 안쪽이 먼저 먹지 않는다.
_NORM = (
    # 시각 형식이 ISO 만이 아니다. 슬래시 날짜 하나를 빠뜨렸더니 랩의 한 서버에서
    # 469줄이 408가지 모양으로 세어져 반복 접기가 통째로 죽었다(2026-08-13 실측).
    (re.compile(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?"), "<TS>"),
    (re.compile(r"\d{4}/\d{2}/\d{2}[T ]?\d{2}:\d{2}:\d{2}(?:[.,]\d+)?"), "<TS>"),
    # Apache 접근 로그: 13/Aug/2026:10:00:00
    (re.compile(r"\d{1,2}/[A-Z][a-z]{2}/\d{4}:\d{2}:\d{2}:\d{2}"), "<TS>"),
    # RFC3164 syslog: Aug 13 10:00:00 / Apache 오류 로그: Wed Aug 13 10:00:00 2026
    (re.compile(r"(?:[A-Z][a-z]{2} )?[A-Z][a-z]{2} [ \d]?\d \d{2}:\d{2}:\d{2}"
                r"(?: \d{4})?"), "<TS>"),
    # 위에서 안 걸린 맨 시각. MariaDB 오류 로그는 시가 한 자리다(`2026-08-13  2:13:33`).
    (re.compile(r"\b\d{1,2}:\d{2}:\d{2}(?:[.,]\d+)?\b"), "<TS>"),
    # 시각이 떨어져 있는 날짜
    (re.compile(r"\b\d{4}-\d{2}-\d{2}\b"), "<TS>"),
    (re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b"), "<IP>"),
    (re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b",
                re.IGNORECASE), "<UUID>"),
    (re.compile(r"\b[0-9a-f]{8,}\b", re.IGNORECASE), "<HEX>"),
    (re.compile(r"\b\d+(?:\.\d+)?(?:ms|s|us|ns|B|KB|MB|GB)\b", re.IGNORECASE), "<QTY>"),
    (re.compile(r"\b\d{4,}\b"), "<N>"),
    # 경로의 숫자 구간은 변수다(`/v1/pay/151`). 디렉토리 이름은 남긴다 — `/etc/shadow`
    # 와 `/tmp/junk` 가 합쳐지면 보안 축과의 교차 판단이 무너진다.
    (re.compile(r"(?<=/)\d+\b"), "<N>"),
)
# `key=값` 의 숫자는 변수다(`retry=0`·`pid=5`). 다만 아래로 끝나는 열쇠는 남긴다 —
# 상태 코드·오류 번호·사용자 번호·신호 번호가 접히면 서로 다른 사건이 한 형태로
# 합쳐진다. MySQL 오류 번호가 4자리라 자리수 규칙에 먼저 먹히고 있었다.
_KEEP_NUM_SUFFIX = ("status", "code", "rc", "exit", "errno", "level", "signal",
                    "sig", "uid", "gid", "res", "retcode")
_KV_NUM_RE = re.compile(r"\b([A-Za-z_][\w.]*)=(\d+)\b")
_KEPT_RE = re.compile(r"\x00(\d+)\x00")
# `key=값` 이 아니라 낱말 뒤에 맨 숫자로 오는 오류 번호도 남긴다. MySQL 은
# `Error 1045 (28000)` 형식이라 네 자리 규칙에 먹힌다.
_BARE_CODE_RE = re.compile(
    r"\b(error|errno|code|status|sqlstate)\s+(\d+)", re.IGNORECASE)
SAME_SHAPE_MAX = 3          # 같은 형태를 몇 줄까지 실을지
# 선별을 끄는 스위치. 끄면 예전 동작(최신 N줄)으로 돌아간다.
SELECT_ENABLED = os.environ.get("LOG_SELECT_ENABLED", "1") != "0"
# 몫. **접어도 예산을 넘을 때만 쓰는 비상 배분이다.** 랩 실측(2026-08-13)에서는 접기만으로
# 15분 120줄이 12줄이 되어 이 배분이 한 번도 개입하지 않았다. 값 자체는 임의값이므로,
# 이 경로가 실제로 도는 환경을 만나면 그때 실측으로 정한다.
SELECT_QUOTA = (("error", 14), ("novel", 8), ("pre", 12), ("recent", 6))


def log_level(line: str) -> str:
    """줄이 말하는 등급. 못 뽑으면 빈 문자열 — 미상을 오류로 올리지 않는다.

    등급 필드 → 괄호 → 대문자 낱말 순으로 본다. 앞의 둘은 형식이 분명해 대소문자를
    안 가리고, 마지막은 평범한 문장과 구분이 안 되므로 대문자만 인정한다.
    """
    line = line or ""
    if _CRITICAL_RE.search(line):
        return "error"
    for rx in (_LEVEL_FIELD_RE, _LEVEL_BRACKET_RE, _LEVEL_BARE_RE):
        m = rx.search(line)
        if m:
            return _LEVEL_MAP.get(m.group(1).lower(), "")
    return ""


def log_shape(line: str) -> str:
    """같은 모양인지 비교하는 키. HTTP 상태 코드·errno 는 남긴다 — 그것이 갈리면
    오류 줄과 정상 줄이 같은 형태가 되어 선별이 통째로 죽는다."""
    out = line or ""

    # 남길 값을 **먼저** 감춘다. 자리수 규칙이 먼저 돌면 errno=1062 처럼 네 자리인
    # 오류 번호가 접혀서 서로 다른 오류가 한 형태가 된다.
    def _hide(m):
        key = m.group(1).lower()
        if key.endswith(_KEEP_NUM_SUFFIX):
            return "%s=\x00%s\x00" % (m.group(1), m.group(2))
        return "%s=<N>" % m.group(1)

    out = _KV_NUM_RE.sub(_hide, out)
    out = _BARE_CODE_RE.sub(lambda m: "%s \x00%s\x00" % (m.group(1), m.group(2)), out)
    for rx, tok in _NORM:
        out = rx.sub(tok, out)
    out = _KEPT_RE.sub(lambda m: m.group(1), out)
    # 날짜와 시각이 따로 잡히면 토큰이 둘이 된다(`2026-08-13  2:13:33`). 같은 형식인데
    # 자리 수만 다른 줄이 갈리므로 이어진 시각 토큰과 공백을 하나로 모은다.
    out = re.sub(r"\s+", " ", out)
    return re.sub(r"(?:<TS> ?){2,}", "<TS> ", out).strip()


def _with_gaps(recs: list, chosen: set, why_of: dict, line_of) -> list:
    """안 실린 구간을 표시한다.

    고른 줄만 이어 붙이면 모델은 그것이 연속된 기록인 줄 알고 인접성에서 인과를
    만든다. 몇 줄이 어느 구간에서 빠졌는지 함께 낸다 — 줄 수만으로는 그 사이에
    몇 초가 비었는지 안 보인다.
    """
    out, gap, gap_from, gap_to = [], 0, None, None
    for i, r in enumerate(recs):
        if i in chosen:
            if gap:
                out.append({"t": int(gap_from), "gap": gap, "to": int(gap_to)})
                gap, gap_from, gap_to = 0, None, None
            out.append(line_of(i, why_of[i]))
        else:
            gap += 1
            if gap_from is None:
                gap_from = r["t"]
            gap_to = r["t"]      # 다음에 실린 줄이 아니라 **마지막으로 빠진 줄**이다
    if gap:
        out.append({"t": int(gap_from), "gap": gap, "to": int(gap_to)})
    return out


def select_logs(records: list, limit: int = None, budget: int = None) -> list:
    """조회한 것 중 보낼 것을 고른다. 접기가 먼저고 선별은 그다음이다.

    순서가 중요하다. 접기(같은 모양 최대 3줄 + 개수 표기)만으로 랩 15분 120줄이
    12줄로 줄었고, 그 뒤에 몫 선별은 할 일이 없었다(2026-08-13 실측). 드물게 한 번
    나타난 줄은 그 자체가 하나의 모양이라 접기 단계에서 반드시 살아남는다. 우리가
    고치려던 고장(정상 260줄에 섞인 오류 3줄이 잘림)은 접기만으로 해결된다.

    그래서 몫 선별은 평상시에 개입하지 않는다. **접은 결과가 예산을 넘을 때만**
    무엇을 버릴지 정한다. 예산은 줄 수가 아니라 글자 수로 잡는다. 모델이 실제로
    먹는 단위가 글자 수이고, 줄 수는 줄 길이에 따라 같은 값이 열 배 차이가 난다.

    고른 뒤에는 반드시 시각순으로 돌려준다. 모델이 인접성에서 인과를 만들기 때문이다.
    """
    limit = LOKI_SEND_LIMIT if limit is None else limit
    budget = LOKI_SEND_BYTES if budget is None else budget
    recs = sorted(records, key=lambda r: r["t"])
    if not SELECT_ENABLED:
        # 되돌리기용. 선별을 끄면 예전 동작(최신 N줄)으로 돌아간다. 커밋을 되돌리지
        # 않고도 원래 상태를 확인할 수 있어야 한다.
        return [dict(r, why="recent", n=1) for r in recs[-limit:]]
    # **자리 번호로 고른다.** 값(시각+본문)으로 같은지 보면, 같은 줄이 같은 초에 여러 번
    # 기록됐을 때 되찾는 과정에서 같은 항목이 여러 번 붙어 상한이 무너진다. 실제로 같은
    # 줄 300개를 넣었더니 300줄이 그대로 나갔다(2026-08-13 감사). 나노초를 초로 바꾸면서
    # 해상도가 사라져 서로 다른 줄이 같은 시각이 되는 경로도 있다.
    shapes_of = [log_shape(r["line"]) for r in recs]
    levels_of = [log_level(r["line"]) for r in recs]
    counts = {}
    for s in shapes_of:
        counts[s] = counts.get(s, 0) + 1

    def _line(i, why):
        # 접은 줄은 개수로 알린다. 안 알리면 260줄이 3줄로 조용히 줄어든다.
        return dict(recs[i], n=counts[shapes_of[i]], why=why,
                    **({"level": levels_of[i]} if levels_of[i] else {}))

    # 1단계 — 접기. 항상 한다. 여기서 남는 줄이 곧 후보다. 조건을 달면 규칙이 둘로
    #   갈라지고, 같은 줄 200개가 그대로 나가는 경로가 생긴다.
    seen, folded = {}, []
    for i in range(len(recs)):
        s = shapes_of[i]
        if seen.get(s, 0) < SAME_SHAPE_MAX:
            seen[s] = seen.get(s, 0) + 1
            folded.append(i)

    # 2단계 — 예산 안에 들어오면 선별하지 않는다. 랩에서는 항상 이 경로다.
    if len(folded) <= limit and sum(len(recs[i]["line"]) for i in folded) <= budget:
        return _with_gaps(recs, set(folded), {i: "fold" for i in folded}, _line)

    # 3단계 — 접어도 예산을 넘는 구간에서만 무엇을 버릴지 정한다.
    first_err = next((i for i, lv in enumerate(levels_of) if lv == "error"), None)
    pools = {
        "error": [i for i, lv in enumerate(levels_of) if lv == "error"],
        "novel": [i for i, lv in enumerate(levels_of) if lv == "warn"],
        # 오류에 **가까운 쪽부터** 본다. 원인은 대개 바로 앞에 있다. 앞에서부터 훑으면
        # 오류에서 가장 먼 줄만 실린다.
        "pre": list(range(first_err - 1, -1, -1)) if first_err else [],
        "recent": list(range(len(recs) - 1, -1, -1)),
    }
    chosen, used, why_of = set(), {}, {}
    spent = [0]

    def _take(pool, n, why):
        got = 0
        for i in pool:
            if got >= n or len(chosen) >= limit:
                break
            if i in chosen or used.get(shapes_of[i], 0) >= SAME_SHAPE_MAX:
                continue
            # 넘고 나서가 아니라 넘기 전에 멈춘다. 뒤에서 재면 마지막 한 줄만큼
            # 항상 초과한다. 첫 줄은 아무리 길어도 싣는다 — 빈 채로 보내면
            # 모델이 "로그에 흔적이 없다"를 쓴다.
            if chosen and spent[0] + len(recs[i]["line"]) > budget:
                break
            chosen.add(i)
            spent[0] += len(recs[i]["line"])
            used[shapes_of[i]] = used.get(shapes_of[i], 0) + 1
            why_of[i] = why
            got += 1
        return got

    # 몫대로 채우고, 덜 찬 몫은 버리지 않고 뒤로 넘긴다.
    carry = 0
    for name, quota in SELECT_QUOTA:
        want = quota + carry
        carry = want - _take(pools[name], want, name)
    # 몫 합계보다 상한이 크면 남은 자리를 최신 쪽으로 채운다. 형태 상한으로 자리가
    # 남는 경우에는 아무것도 안 늘어나는데, 그건 의도한 동작이다 — 거의 같은 줄로
    # 40칸을 채우는 것보다 대표 몇 줄과 개수를 보내는 편이 낫다.
    if len(chosen) < limit:
        _take(pools["recent"], limit - len(chosen), "recent")

    out = _with_gaps(recs, chosen, why_of, _line)
    return out


def _loki_ts(ts) -> float:
    """Loki 는 나노초 문자열을 준다. 못 읽으면 0 — 지어내지 않는다."""
    try:
        return int(ts) / 1_000_000_000
    except (TypeError, ValueError):
        return 0.0


async def _loki_logs(host_label: str, now: int, zbx_host: str = "", source: str = "") -> tuple:
    """Loki 최근 로그. 반환 (레코드 목록, 조회 상태, 창 절단 여부, 줄 잘린 수).

    레코드는 `{"t": unix초, "line": 줄}` 이다. 시각을 버리면 정렬도 증거 범위도
    "첫 오류 직전"도 만들 수 없다.

    **합친 뒤 시각으로 정렬한다.** `{host="…"}` 는 스트림이 여럿이라 Loki 응답을 이어
    붙인 순서는 시각순이 아니다. 지금은 조회 상한과 전송 상한이 같아 결과 집합은 맞지만,
    둘을 나누는 순간 "최신 순"이 스트림 나열 순서에 좌우된다.

    절단은 조회 상태와 별개다. 40줄에서 자른 것도 조회는 성공이므로 상태는 ok 이지만,
    그것만 보내면 모델이 그 40줄에 없는 것을 없는 것으로 읽는다. 사건이 클수록 잘리는
    비율이 높으니 하필 분석이 가장 필요할 때 가장 크게 틀린다.
    """
    url = os.environ.get("LOKI_URL", "").rstrip("/")
    if not url:
        return [], SOURCE_DISABLED, False, 0
    if zbx_host and axis_exempt(zbx_host, "logs", source):
        return [], SOURCE_DISABLED, False, 0
    if not host_label:   # 호스트 라벨을 못 정하면 조회 자체가 불가 — 성공이 아니다
        log.warning("loki skipped: host label 미해석 (HOST_LABEL_MAP·인터페이스 dns 확인)")
        return [], SOURCE_UNAVAILABLE, False, 0
    query = '{%s="%s"}' % (LOKI_HOST_LABEL, host_label)
    try:
        async with httpx.AsyncClient() as client:
            r = await client.get(f"{url}/loki/api/v1/query_range", params={
                "query": query,
                "start": str((now - CORR_WINDOW_S) * 1_000_000_000),
                "end": str(now * 1_000_000_000),
                "limit": LOKI_FETCH_LIMIT, "direction": "backward"}, timeout=TIMEOUT_S)
            r.raise_for_status()
            out, clipped, size = [], 0, 0
            over_bytes = False
            for stream in r.json().get("data", {}).get("result", []):
                for ts, line in stream.get("values", []):
                    size += len(line)
                    if size > LOKI_FETCH_BYTES:
                        over_bytes = True
                        break
                    if len(line) > LOKI_LINE_MAX:
                        clipped += 1
                    out.append({"t": _loki_ts(ts), "line": line[:LOKI_LINE_MAX]})
                if over_bytes:
                    break
            if out:
                out.sort(key=lambda r: r["t"])
                # 상한을 채웠으면 그 창에 더 있었다고 본다. 정확히 상한만큼이었을 수도
                # 있으나, 없는 것을 없다고 단언하는 쪽보다 더 있었다고 보는 쪽이 안전하다.
                capped = over_bytes or len(out) >= LOKI_FETCH_LIMIT
                return out, SOURCE_OK, capped, clipped
            return [], await _loki_name_status(client, url, host_label, now), False, 0
    except Exception as e:
        log.warning("loki query failed host=%s: %s", host_label, e)
        return [], SOURCE_UNAVAILABLE, False, 0


async def _loki_name_status(client, url: str, host_label: str, now: int) -> str:
    """15분 창에 로그가 없을 때, Loki 가 이 호스트 이름을 아는지 확인한다.

    이름이 안 맞아 0건인 경우와 정말 로그가 없는 경우를 구분하지 않으면 봇이
    "로그에 기록 없음"이라고 단언한다. 세 소스가 같은 호스트를 다른 이름으로
    부르는 것은 이 랩에서 실제로 겪은 문제다. 근거는 GATEWAY_GUIDE §12.
    """
    try:
        r = await client.get(f"{url}/loki/api/v1/label/{LOKI_HOST_LABEL}/values", params={
            "start": str((now - KNOWN_HOST_LOOKBACK_S) * 1_000_000_000),
            "end": str(now * 1_000_000_000)}, timeout=TIMEOUT_S)
        r.raise_for_status()
        known = r.json().get("data") or []
    except Exception as e:
        # 확인 자체를 못 했으므로 "로그 없음"이 사실인지 알 수 없다.
        log.warning("loki label values failed host=%s: %s", host_label, e)
        return SOURCE_UNAVAILABLE
    if host_label in known:
        return SOURCE_OK
    log.warning("loki: 라벨 %s 에 '%s' 없음 (알려진 값 %d개). HOST_LABEL_MAP 확인",
                LOKI_HOST_LABEL, host_label, len(known))
    return SOURCE_UNMATCHED


async def _wazuh_alerts(agent_name: str, now: int, zbx_host: str = "", source: str = "") -> tuple:
    """Wazuh Indexer(OpenSearch) 최근 경보. 반환 (경보 목록, 조회 상태).

    빈 목록을 "침해 배제"로 해석해도 되는 것은 상태가 SOURCE_OK 일 때뿐이다.
    """
    url = os.environ.get("WAZUH_INDEXER_URL", "").rstrip("/")
    user = os.environ.get("WAZUH_INDEXER_USER", "")
    pw = os.environ.get("WAZUH_INDEXER_PASSWORD", "")
    if not url:
        return [], SOURCE_DISABLED
    if zbx_host and axis_exempt(zbx_host, "security", source):
        return [], SOURCE_DISABLED
    if not agent_name:
        log.warning("wazuh skipped: agent name 미해석")
        return [], SOURCE_UNAVAILABLE
    body = {
        "size": WAZUH_LIMIT,
        "sort": [{"@timestamp": {"order": "desc"}}],
        "query": {"bool": {"must": [
            # 이름이 정확히 같은 것만. 양쪽 와일드카드로 두면 db01 조회가
            # customer-b-db01 의 경보까지 가져오는데, 그 항목은 이번 사건 호스트만
            # 등록된 마스커를 거치므로 다른 고객의 파일 경로·규칙 설명이 원문 그대로
            # 나가고 카드에는 이 호스트의 침해 신호처럼 보인다.
            #
            # 이름이 안 맞으면 결과가 비고, 그때는 아래 _wazuh_name_status 가
            # "이름 불일치"인지 "정말 경보가 없음"인지 갈라 준다. 그 계약이 이미
            # 있으므로 여기서 느슨하게 맞출 이유가 없다.
            {"term": {"agent.name": agent_name}},
            {"range": {"@timestamp": {"gte": f"now-{CORR_WINDOW_S // 60}m"}}},
        ]}},
        "_source": ["@timestamp", "rule.level", "rule.description", "agent.name",
                    "rule.id", "rule.groups", "syscheck.path", "syscheck.event"],
    }
    try:
        # 랩 Wazuh Indexer는 자체서명 TLS → verify=False (프로덕션은 사내 CA). basic auth.
        async with httpx.AsyncClient(verify=False) as client:
            r = await client.post(f"{url}/wazuh-alerts-*/_search",
                                  json=body, auth=(user, pw), timeout=TIMEOUT_S)
            r.raise_for_status()
            out = []
            for h in r.json().get("hits", {}).get("hits", []):
                src = h.get("_source", {})
                rule = src.get("rule", {}) or {}
                sc = src.get("syscheck", {}) or {}
                groups = rule.get("groups") or []
                out.append({"level": rule.get("level"),
                            "desc": rule.get("description"),
                            "ts": src.get("@timestamp"),
                            "rule_id": rule.get("id"),
                            "groups": ",".join(groups) if isinstance(groups, list) else groups,
                            "path": sc.get("path"),
                            "change": sc.get("event")})
            if out:
                return out, SOURCE_OK
            return [], await _wazuh_name_status(client, url, user, pw, agent_name)
    except Exception as e:
        log.warning("wazuh query failed agent=%s: %s", agent_name, e)
        return [], SOURCE_UNAVAILABLE


async def _wazuh_name_status(client, url: str, user: str, pw: str, agent_name: str) -> str:
    """Loki 쪽과 같은 확인. 경보가 없을 때 이 에이전트 이름이 인덱스에 있는지 본다.

    비어 있음을 "침해 배제"로 읽어도 되는 것은 이름이 맞을 때뿐이다.
    """
    body = {"size": 0, "query": {"bool": {"must": [
        # 여기도 정확히 일치하는 것만 센다. 느슨하게 세면 이름이 비슷한 다른 호스트가
        # 있다는 이유로 "이 이름은 알려져 있다"가 되어, 실제로는 이름이 안 맞는 상태를
        # "정말 경보가 없음"으로 보고하게 된다.
        {"term": {"agent.name": agent_name}},
        {"range": {"@timestamp": {"gte": "now-%dd" % (KNOWN_HOST_LOOKBACK_S // 86400)}}},
    ]}}}
    try:
        r = await client.post(f"{url}/wazuh-alerts-*/_search",
                              json=body, auth=(user, pw), timeout=TIMEOUT_S)
        r.raise_for_status()
        total = (r.json().get("hits", {}).get("total") or {}).get("value", 0)
    except Exception as e:
        log.warning("wazuh name check failed agent=%s: %s", agent_name, e)
        return SOURCE_UNAVAILABLE
    if total:
        return SOURCE_OK
    log.warning("wazuh: agent.name 에 '%s' 로 잡히는 경보가 최근에 없음. 에이전트 이름 확인",
                agent_name)
    return SOURCE_UNMATCHED


async def _metrics_trend(zbx: ZabbixClient, client: httpx.AsyncClient,
                         trigger_id: str, now: int) -> list:
    items = await zbx.call(client, "item.get", {
        "triggerids": trigger_id,
        "output": ["itemid", "name", "key_", "value_type", "units", "lastvalue"]})
    out = []
    for it in items[:5]:
        vt = int(it.get("value_type", 3))
        history = []
        if vt in (0, 3):  # float / unsigned — 수치형만 추이 조회
            history = await zbx.call(client, "history.get", {
                "itemids": it["itemid"], "history": vt,
                "time_from": now - HISTORY_WINDOW_S,
                "output": "extend", "sortfield": "clock", "sortorder": "DESC",
                "limit": HISTORY_LIMIT})
        out.append({
            "name": it.get("name"), "key": it.get("key_"), "units": it.get("units"),
            "lastvalue": it.get("lastvalue"),
            "recent": [{"clock": h["clock"], "value": h["value"]} for h in reversed(history)],
        })
    return out
