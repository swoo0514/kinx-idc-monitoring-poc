"""컨텍스트 수집기 — Zabbix API 5종 병렬(읽기 전용 `.get`만). 상세는 GATEWAY_GUIDE.md §9.

환경변수: ZABBIX_URL, ZABBIX_TOKEN (조회 전용 계정).
"""

import asyncio
import os
import time

import httpx

from . import prejudge

HISTORY_WINDOW_S = 3600
HISTORY_LIMIT = 20
TIMEOUT_S = 5   # 콜당 — 수집이 30초 예산을 안 갉게


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

    past_clocks = [int(e["clock"]) for e in past if e.get("eventid") != str(event_id)]
    return {
        "event": cur_event[0] if cur_event else {},
        "trigger": trigger[0] if trigger else {},
        "host": host,
        "metrics": metrics,
        "prejudge": prejudge.judge(past_clocks, now=now),
    }


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
