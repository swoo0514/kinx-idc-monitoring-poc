"""컨텍스트 수집기 — Zabbix(읽기전용 `.get`) + Loki 로그 + Wazuh 경보. 상세는 GATEWAY_GUIDE §9.

환경변수: ZABBIX_URL·ZABBIX_TOKEN(필수) / LOKI_URL·WAZUH_INDEXER_URL·WAZUH_INDEXER_USER·
WAZUH_INDEXER_PASSWORD(선택 — 없으면 해당 소스 생략, 열화 진행).
"""

import asyncio
import fnmatch
import logging
import os
import time

import httpx

from . import prejudge, registry

log = logging.getLogger("gateway.collector")

HISTORY_WINDOW_S = 3600
HISTORY_LIMIT = 20
TIMEOUT_S = 5   # 콜당 — 수집이 30초 예산을 안 갉게

# 인시던트 시간창 — 로그·보안은 이 창에서만 (병합 대상 신호 정렬용)
CORR_WINDOW_S = 900   # 15분
LOKI_LIMIT = 40
LOKI_LINE_MAX = 300   # 라인당 최대 문자 (토큰 억제)
WAZUH_LIMIT = 20
# 과거 이벤트 목록 상한. 개수는 따로 세므로 이 값이 판정에 영향을 주지 않는다.
PAST_EVENT_LIMIT = 200

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
    (logs, logs_status), (security, sec_status) = await asyncio.gather(
        _loki_logs(loki_label, now, zbx_host, source),
        _wazuh_alerts(wz_label, now, zbx_host, source),
    )
    return {
        **base,
        "logs": logs,            # Loki (Alloy) — 백업/앱 로그 등
        "security": security,    # Wazuh Indexer — 침해·변경 경보
        # 빈 목록의 의미를 확정하는 상태. ok 일 때만 "없음 = 사실"이다.
        "sources": {"logs": logs_status, "security": sec_status},
    }


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

    (logs, logs_status), (security, sec_status), (opens, opens_status) = await asyncio.gather(
        _loki_logs(loki_label, now, zbx_host, source),
        _wazuh_alerts(wz_label, now, zbx_host, source),
        _open_probe(),
    )

    # 하나라도 성공했으면 ok. 전부 실패했으면 미상이다. 알림이 애초에 Zabbix 축을
    # 안 가지면(Wazuh 단독) 판단할 대상이 없으므로 미배선으로 둔다.
    if not zbx_alerts:
        metrics_status = SOURCE_DISABLED
    elif any(isinstance(r, dict) for r in per):
        metrics_status = SOURCE_OK
    else:
        log.warning("Zabbix 수집 전건 실패 host=%s alerts=%d — 미상으로 표시한다",
                    zbx_host, len(zbx_alerts))
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

    return {
        "incident": {
            "host": zbx_host,
            "classes": sorted(incident.classes()),
            "alert_count": len(incident.alerts),
            "merge_reason": incident.merge_reason(),
            "fingerprint": incident.fingerprint(),
            "dominant_sev": incident.dominant_sev(),
        },
        "host": host_obj,
        "alerts": alerts_ctx,
        "logs": logs,
        "security": security,
        # 이번 알림보다 먼저 열려 있던, 연계 관계에 있는 문제. 병합 대상이 아니라 참고 정보다.
        "open_problems": opens,
        # Zabbix 축도 상태를 낸다. 수집은 예외를 위로 안 던지므로(gather 가 예외를
        # 값으로 돌려준다) 전건 실패해도 여기까지 조용히 온다. 로그·보안만 상태를
        # 내면 게이트와 카드가 "조회는 정상"으로 읽어, Zabbix 가 죽어 있던 시간대의
        # 사건이 전부 "봐줬는데 볼 게 없었다"로 남는다.
        "sources": {"logs": logs_status, "security": sec_status,
                    "open_problems": opens_status, "metrics": metrics_status},
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
            "sortorder": "DESC",
            "limit": 100,
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
    return out[:incident.OPEN_LINK_MAX], SOURCE_OK


async def _loki_logs(host_label: str, now: int, zbx_host: str = "", source: str = "") -> tuple:
    """Loki 최근 로그. 반환 (로그 목록, 조회 상태). 상태는 SOURCE_* 넷 중 하나."""
    url = os.environ.get("LOKI_URL", "").rstrip("/")
    if not url:
        return [], SOURCE_DISABLED
    if zbx_host and axis_exempt(zbx_host, "logs", source):
        return [], SOURCE_DISABLED
    if not host_label:   # 호스트 라벨을 못 정하면 조회 자체가 불가 — 성공이 아니다
        log.warning("loki skipped: host label 미해석 (HOST_LABEL_MAP·인터페이스 dns 확인)")
        return [], SOURCE_UNAVAILABLE
    try:
        async with httpx.AsyncClient() as client:
            r = await client.get(f"{url}/loki/api/v1/query_range", params={
                "query": '{%s="%s"}' % (LOKI_HOST_LABEL, host_label),
                "start": str((now - CORR_WINDOW_S) * 1_000_000_000),
                "end": str(now * 1_000_000_000),
                "limit": LOKI_LIMIT, "direction": "backward"}, timeout=TIMEOUT_S)
            r.raise_for_status()
            out = []
            for stream in r.json().get("data", {}).get("result", []):
                for _ts, line in stream.get("values", []):
                    out.append(line[:LOKI_LINE_MAX])
            if out:
                return out[:LOKI_LIMIT], SOURCE_OK
            return [], await _loki_name_status(client, url, host_label, now)
    except Exception as e:
        log.warning("loki query failed host=%s: %s", host_label, e)
        return [], SOURCE_UNAVAILABLE


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
