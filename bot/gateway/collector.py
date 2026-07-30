"""컨텍스트 수집기 — Zabbix(읽기전용 `.get`) + Loki 로그 + Wazuh 경보. 상세는 GATEWAY_GUIDE §9.

환경변수: ZABBIX_URL·ZABBIX_TOKEN(필수) / LOKI_URL·WAZUH_INDEXER_URL·WAZUH_INDEXER_USER·
WAZUH_INDEXER_PASSWORD(선택 — 없으면 해당 소스 생략, 열화 진행).
"""

import asyncio
import logging
import os
import time

import httpx

from . import prejudge

log = logging.getLogger("gateway.collector")

HISTORY_WINDOW_S = 3600
HISTORY_LIMIT = 20
TIMEOUT_S = 5   # 콜당 — 수집이 30초 예산을 안 갉게

# 인시던트 시간창 — 로그·보안은 이 창에서만 (병합 대상 신호 정렬용)
CORR_WINDOW_S = 900   # 15분
LOKI_LIMIT = 40
LOKI_LINE_MAX = 300   # 라인당 최대 문자 (토큰 억제)
WAZUH_LIMIT = 20

# 교차 소스 조회 상태 — "신호 없음"과 "조회 실패"를 구분한다 (G1).
# 빈 리스트만 돌려주면 Wazuh 인덱서 장애가 "침해 흔적 없음"으로 둔갑하고, 발동조건 게이트도
# 교차 신호 0으로 보아 LLM을 스킵한다. 즉 관측 백엔드가 죽을수록 봇이 조용해지고 자신만만해진다.
SOURCE_OK = "ok"                    # 조회 성공 (결과가 비어 있어도 "없음"이 사실)
SOURCE_UNAVAILABLE = "unavailable"  # 조회 시도했으나 실패 — 비어 있음을 근거로 쓰면 안 됨
SOURCE_DISABLED = "disabled"        # 미배선(URL 미설정) — 애초에 판단 근거가 없음


class ZabbixClient:
    def __init__(self, url: str = None, token: str = None):
        base = (url or os.environ.get("ZABBIX_URL", "")).rstrip("/")
        self.api = base + "/api_jsonrpc.php"
        self.token = token or os.environ.get("ZABBIX_TOKEN", "")
        self._id = 0

    async def call(self, client: httpx.AsyncClient, method: str, params: dict):
        if not method.endswith(".get"):   # 읽기 전용 강제 (작업 원칙 4)
            raise ValueError(f"read-only violation: {method}")
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
    cur_event, trigger, metrics, past = await asyncio.gather(
        zbx.call(client, "event.get", {
            "eventids": event_id, "selectTags": "extend", "output": "extend"}),
        zbx.call(client, "trigger.get", {
            "triggerids": trigger_id, "output": "extend",
            "expandExpression": True, "selectHosts": ["hostid", "host", "name"]}),
        _metrics_trend(zbx, client, trigger_id, now),
        zbx.call(client, "event.get", {
            "objectids": trigger_id, "source": 0, "object": 0, "value": 1,
            "time_from": now - prejudge.WINDOW_S, "time_till": now,
            "output": ["eventid", "clock"], "sortfield": "clock", "sortorder": "DESC",
            "limit": 200}),
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
    past_clocks = [int(e["clock"]) for e in past if e.get("eventid") != str(event_id)]
    return {
        "event": cur_event[0] if cur_event else {},
        "trigger": trigger[0] if trigger else {},
        "host": host,
        "metrics": metrics,
        "prejudge": prejudge.judge(past_clocks, now=now),
    }


async def collect_context(zbx: ZabbixClient, event_id: str, trigger_id: str) -> dict:
    """단건 알림 컨텍스트 — Zabbix + Loki 로그 + Wazuh 경보 (같은 시간창)."""
    now = int(time.time())
    async with httpx.AsyncClient() as client:
        base = await _zabbix_alert_context(zbx, client, event_id, trigger_id, now)

    zbx_host = base["host"].get("host") or ""
    host_label = _resolve_label(zbx_host, base["host"])   # Zabbix명 → Loki/Wazuh FQDN 라벨
    (logs, logs_status), (security, sec_status) = await asyncio.gather(
        _loki_logs(host_label, now),
        _wazuh_alerts(host_label, now),
    )
    return {
        **base,
        "logs": logs,            # Loki (Alloy) — 백업/앱 로그 등
        "security": security,    # Wazuh Indexer — 침해·변경 경보
        # 빈 목록의 의미를 확정하는 상태. ok일 때만 "없음 = 사실"이다 (G1)
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
    host_label = _resolve_label(zbx_host, host_obj) if host_obj else incident.host

    (logs, logs_status), (security, sec_status) = await asyncio.gather(
        _loki_logs(host_label, now),
        _wazuh_alerts(host_label, now),
    )

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
        "sources": {"logs": logs_status, "security": sec_status},
    }


def _resolve_label(zbx_host: str, host_obj: dict) -> str:
    """Zabbix 호스트명 → Loki/Wazuh 라벨. 세 시스템이 이름을 달리 쓰고 공유 키가 없어 필요.
    우선순위: HOST_LABEL_MAP(명시) → 인터페이스 dns(FQDN이면 자동) → Zabbix 호스트명.
    프로덕션은 온보딩에서 FQDN 정규화(STRATEGY §4-7 ⭐) — 이 맵은 스톱갭."""
    mapping = {}
    for pair in os.environ.get("HOST_LABEL_MAP", "").split(","):
        if "=" in pair:
            k, v = pair.split("=", 1)
            mapping[k.strip()] = v.strip()
    if zbx_host in mapping:
        return mapping[zbx_host]
    for iface in (host_obj.get("interfaces") or []):
        if iface.get("dns"):
            return iface["dns"]
    return zbx_host


async def _loki_logs(host_label: str, now: int) -> tuple:
    """Loki 최근 로그. 반환 (로그 목록, 조회 상태). 상태는 SOURCE_* 셋 중 하나 (G1)."""
    url = os.environ.get("LOKI_URL", "").rstrip("/")
    if not url:
        return [], SOURCE_DISABLED
    if not host_label:   # 호스트 라벨을 못 정하면 조회 자체가 불가 — 성공이 아니다
        log.warning("loki skipped: host label 미해석 (HOST_LABEL_MAP·인터페이스 dns 확인)")
        return [], SOURCE_UNAVAILABLE
    try:
        async with httpx.AsyncClient() as client:
            r = await client.get(f"{url}/loki/api/v1/query_range", params={
                "query": '{host="%s"}' % host_label,   # 라벨 정확 일치 (맵이 FQDN 제공)
                "start": str((now - CORR_WINDOW_S) * 1_000_000_000),
                "end": str(now * 1_000_000_000),
                "limit": LOKI_LIMIT, "direction": "backward"}, timeout=TIMEOUT_S)
            r.raise_for_status()
            out = []
            for stream in r.json().get("data", {}).get("result", []):
                for _ts, line in stream.get("values", []):
                    out.append(line[:LOKI_LINE_MAX])
            return out[:LOKI_LIMIT], SOURCE_OK
    except Exception as e:
        log.warning("loki query failed host=%s: %s", host_label, e)
        return [], SOURCE_UNAVAILABLE


async def _wazuh_alerts(agent_name: str, now: int) -> tuple:
    """Wazuh Indexer(OpenSearch) 최근 경보. 반환 (경보 목록, 조회 상태).

    빈 목록을 "침해 배제"로 해석해도 되는 것은 상태가 SOURCE_OK 일 때뿐이다 (G1).
    """
    url = os.environ.get("WAZUH_INDEXER_URL", "").rstrip("/")
    user = os.environ.get("WAZUH_INDEXER_USER", "")
    pw = os.environ.get("WAZUH_INDEXER_PASSWORD", "")
    if not url:
        return [], SOURCE_DISABLED
    if not agent_name:
        log.warning("wazuh skipped: agent name 미해석")
        return [], SOURCE_UNAVAILABLE
    body = {
        "size": WAZUH_LIMIT,
        "sort": [{"@timestamp": {"order": "desc"}}],
        "query": {"bool": {"must": [
            {"wildcard": {"agent.name": f"*{agent_name}*"}},
            {"range": {"@timestamp": {"gte": f"now-{CORR_WINDOW_S // 60}m"}}},
        ]}},
        # rule.id·groups 는 "무슨 종류의 보안 이벤트인가"를 LLM 이 알기 위해, syscheck.* 는
        # 어떤 파일이 어떻게 바뀌었는지를 알기 위해 가져온다. 이게 없으면 FIM 을 켜도 봇은
        # "보안 경보 N건"까지만 알고 노이즈성 변경과 유의미한 변경을 구분할 수 없다.
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
            return out, SOURCE_OK
    except Exception as e:
        log.warning("wazuh query failed agent=%s: %s", agent_name, e)
        return [], SOURCE_UNAVAILABLE


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
