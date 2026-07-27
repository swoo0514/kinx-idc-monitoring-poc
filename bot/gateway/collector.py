"""컨텍스트 수집기 — Zabbix(읽기전용 `.get`) + Loki 로그 + Wazuh 경보. 상세는 GATEWAY_GUIDE §9.

환경변수: ZABBIX_URL·ZABBIX_TOKEN(필수) / LOKI_URL·WAZUH_INDEXER_URL·WAZUH_INDEXER_USER·
WAZUH_INDEXER_PASSWORD(선택 — 없으면 해당 소스 생략, 열화 진행).
"""

import asyncio
import os
import time

import httpx

from . import prejudge

HISTORY_WINDOW_S = 3600
HISTORY_LIMIT = 20
TIMEOUT_S = 5   # 콜당 — 수집이 30초 예산을 안 갉게

# 인시던트 시간창 — 로그·보안은 이 창에서만 (병합 대상 신호 정렬용)
CORR_WINDOW_S = 900   # 15분
LOKI_LIMIT = 40
LOKI_LINE_MAX = 300   # 라인당 최대 문자 (토큰 억제)
WAZUH_LIMIT = 20


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


async def collect_context(zbx: ZabbixClient, event_id: str, trigger_id: str) -> dict:
    # ①현재이벤트 ②트리거정의 ③메트릭추이 ④동일트리거 이력(선판정용) 병렬, ⑤host는 후행
    now = int(time.time())
    async with httpx.AsyncClient() as client:
        cur_event, trigger, metrics, past, = await asyncio.gather(
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

    # 병합용 교차 소스 — 호스트 식별자로 Loki 로그 + Wazuh 경보 (같은 시간창)
    host_label = host.get("host") or (hosts[0].get("host") if hosts else "")
    logs, security = await asyncio.gather(
        _loki_logs(host_label, now),
        _wazuh_alerts(host_label, now),
    )

    past_clocks = [int(e["clock"]) for e in past if e.get("eventid") != str(event_id)]
    return {
        "event": cur_event[0] if cur_event else {},
        "trigger": trigger[0] if trigger else {},
        "host": host,
        "metrics": metrics,
        "logs": logs,            # Loki (Alloy) — 백업/앱 로그 등
        "security": security,    # Wazuh Indexer — 침해·변경 경보 (없으면 [] = 배제 신호)
        "prejudge": prejudge.judge(past_clocks, now=now),
    }


async def _loki_logs(host_label: str, now: int) -> list:
    """Loki 최근 로그. LOKI_URL 없거나 실패 시 [] (열화). 호스트 라벨은 FQDN 정규화 전제."""
    url = os.environ.get("LOKI_URL", "").rstrip("/")
    if not url or not host_label:
        return []
    try:
        async with httpx.AsyncClient() as client:
            r = await client.get(f"{url}/loki/api/v1/query_range", params={
                "query": '{host=~"%s.*"}' % host_label,   # node1 vs node1.fqdn 관용
                "start": str((now - CORR_WINDOW_S) * 1_000_000_000),
                "end": str(now * 1_000_000_000),
                "limit": LOKI_LIMIT, "direction": "backward"}, timeout=TIMEOUT_S)
            r.raise_for_status()
            out = []
            for stream in r.json().get("data", {}).get("result", []):
                for _ts, line in stream.get("values", []):
                    out.append(line[:LOKI_LINE_MAX])
            return out[:LOKI_LIMIT]
    except Exception:
        return []


async def _wazuh_alerts(agent_name: str, now: int) -> list:
    """Wazuh Indexer(OpenSearch) 최근 경보. 미설정·실패 시 [] (열화 = 침해 배제 신호로 해석)."""
    url = os.environ.get("WAZUH_INDEXER_URL", "").rstrip("/")
    user = os.environ.get("WAZUH_INDEXER_USER", "")
    pw = os.environ.get("WAZUH_INDEXER_PASSWORD", "")
    if not url or not agent_name:
        return []
    body = {
        "size": WAZUH_LIMIT,
        "sort": [{"@timestamp": {"order": "desc"}}],
        "query": {"bool": {"must": [
            {"wildcard": {"agent.name": f"*{agent_name}*"}},
            {"range": {"@timestamp": {"gte": f"now-{CORR_WINDOW_S // 60}m"}}},
        ]}},
        "_source": ["@timestamp", "rule.level", "rule.description", "agent.name"],
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
                out.append({"level": rule.get("level"),
                            "desc": rule.get("description"),
                            "ts": src.get("@timestamp")})
            return out
    except Exception:
        return []


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
