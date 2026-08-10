"""랩 진단 — 호스트 식별자 3중 불일치(Zabbix/Loki/Wazuh)를 드러내고 다리 후보를 찾는다.

사용:
  python3 probe.py problems            # 발화 중 이벤트 목록 (event_id trigger_id host name)
  python3 probe.py map <trigger_id>    # 그 트리거 호스트의 Zabbix 이름·표시명·인터페이스 dns/ip
                                       #  + Loki host 라벨값 전체 + 각 후보로 Loki 조회 시 로그 수
환경변수: ZABBIX_URL·ZABBIX_TOKEN(필수), LOKI_URL(선택).
"""

import asyncio
import os
import sys
import time

import httpx

# 한국어 Windows 콘솔은 기본 cp949 라 '—' 에서 죽는다. 조회 전에 터져 원인이 안 보인다 —
# docs/03-pitfalls/build-traps.md. bridge_miner.py 와 같은 처리다.
for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass

from gateway.collector import ZabbixClient, CORR_WINDOW_S  # noqa: E402


async def problems():
    z = ZabbixClient()
    async with httpx.AsyncClient() as c:
        es = await z.call(c, "event.get", {
            "output": ["eventid", "name"], "selectRelatedObject": ["triggerid"],
            "selectHosts": ["host"], "source": 0, "object": 0, "value": 1,
            "sortfield": "eventid", "sortorder": "DESC", "limit": 20})
    for e in es:
        tid = (e.get("relatedObject") or {}).get("triggerid")
        hosts = [h["host"] for h in e.get("hosts", [])]
        print(e["eventid"], tid, hosts, e["name"])


async def _loki_count(host_label):
    url = os.environ.get("LOKI_URL", "").rstrip("/")
    if not url:
        return "(LOKI_URL 미설정)"
    now = int(time.time())
    async with httpx.AsyncClient() as c:
        r = await c.get(f"{url}/loki/api/v1/query_range", params={
            "query": '{host=~"%s"}' % host_label,
            "start": str((now - CORR_WINDOW_S) * 1_000_000_000),
            "end": str(now * 1_000_000_000), "limit": 5, "direction": "backward"}, timeout=5)
        n = sum(len(s.get("values", [])) for s in r.json().get("data", {}).get("result", []))
        return f"{n} lines"


async def loki_host_values():
    url = os.environ.get("LOKI_URL", "").rstrip("/")
    if not url:
        return []
    async with httpx.AsyncClient() as c:
        r = await c.get(f"{url}/loki/api/v1/label/host/values", timeout=5)
        return r.json().get("data", [])


async def host_map(trigger_id):
    z = ZabbixClient()
    async with httpx.AsyncClient() as c:
        got = await z.call(c, "trigger.get", {
            "triggerids": trigger_id, "selectHosts": ["hostid", "host", "name"]})
        hosts = (got[0].get("hosts") if got else None) or []
        if not hosts:
            print("트리거에 호스트 없음")
            return
        h = await z.call(c, "host.get", {
            "hostids": hosts[0]["hostid"], "output": ["host", "name"],
            "selectInterfaces": ["ip", "dns"]})
    host = h[0] if h else {}
    zbx_name = host.get("host", "")
    disp = host.get("name", "")
    ifaces = host.get("interfaces", []) or []
    dns_vals = [i.get("dns") for i in ifaces if i.get("dns")]
    ip_vals = [i.get("ip") for i in ifaces if i.get("ip")]

    print("=== Zabbix ===")
    print("  host(기술명):", zbx_name)
    print("  name(표시명):", disp)
    print("  interface dns:", dns_vals)
    print("  interface ip :", ip_vals)

    print("=== Loki host 라벨값 (실제) ===")
    lv = await loki_host_values()
    print(" ", lv)

    print("=== 후보별 Loki 조회 결과 ===")
    for cand in filter(None, [zbx_name, disp, *dns_vals]):
        print(f"  {cand!r} -> {await _loki_count(cand)}")


def show_env():
    for k in ["ZABBIX_URL", "ZABBIX_TOKEN", "LOKI_URL", "WAZUH_INDEXER_URL",
              "WAZUH_INDEXER_USER", "HOST_LABEL_MAP"]:
        v = os.environ.get(k, "")
        # 값은 안 찍음(비밀 보호) — 설정 여부와 HOST_LABEL_MAP만 표시
        if k == "HOST_LABEL_MAP":
            print(f"  {k} = {v!r}")
        else:
            print(f"  {k} = {'(설정됨)' if v else '(비어있음)'}")


async def loki_probe(label, hours):
    """지정 라벨의 로그를 넓은 창(기본 24h)으로 조회 — 에러 안 삼키고 그대로 노출."""
    url = os.environ.get("LOKI_URL", "").rstrip("/")
    if not url:
        print("LOKI_URL 미설정")
        return
    now = int(time.time())
    span = int(hours) * 3600
    async with httpx.AsyncClient() as c:
        r = await c.get(f"{url}/loki/api/v1/query_range", params={
            "query": '{host="%s"}' % label,
            "start": str((now - span) * 1_000_000_000),
            "end": str(now * 1_000_000_000), "limit": 5, "direction": "backward"}, timeout=5)
        print("HTTP", r.status_code)
        streams = r.json().get("data", {}).get("result", [])
        n = sum(len(s.get("values", [])) for s in streams)
        print(f'query={{host="{label}"}} 최근{hours}h -> {n} lines')
        for s in streams:
            for ts, line in s.get("values", [])[:3]:
                print("  ", line[:160])


async def openlink(host_name: str):
    """열린 문제 연계 경로 점검 — 장애 주입 전에 조회부터 되는지 본다.

    확인하는 것: (1) 호스트명 -> hostid 해석 (2) problem.get 응답
    (3) 연계 규칙 매칭 (4) 최소 경과 필터. 어디서 끊기는지가 바로 드러난다.
    """
    import httpx

    from gateway import collector, incident

    zbx = collector.ZabbixClient()
    now = int(time.time())
    print("규칙 %d건 / 측정: %s" % (len(incident.OPEN_LINK_RULES), incident.OPEN_LINK_MEASURED))
    if not incident.OPEN_LINK_RULES:
        print("  ** 규칙이 없다. OPEN_LINK_RULES_FILE 확인 **")
        return
    for (a, b), v in incident.OPEN_LINK_RULES.items():
        print("   %-16s -> %-16s 비율 %.0f%% / %d일" % (a, b, 100 * v["rate"], v["days"]))

    async with httpx.AsyncClient(verify=False) as c:
        hosts = await zbx.call(c, "host.get", {"filter": {"host": [host_name]},
                                               "output": ["hostid", "host"]})
        if not hosts:
            print()
            print("호스트 %r 를 못 찾았다. Zabbix 표시명이 아니라 host 값이어야 한다." % host_name)
            return
        hid = hosts[0]["hostid"]
        print()
        print("hostid = %s (%s)" % (hid, hosts[0]["host"]))

        raw = await zbx.call(c, "problem.get", {
            "output": ["eventid", "name", "clock", "severity"],
            "hostids": [hid], "selectTags": "extend", "recent": False, "limit": 100})
        print("열린 문제 %d건:" % len(raw or []))
        for p in (raw or []):
            age = now - int(p.get("clock", 0) or 0)
            cls = incident.classify(p.get("name") or "", tags=p.get("tags"))
            too_new = age < incident.OPEN_LINK_MIN_AGE_S
            print("   %-52s %-16s %5d분 %s"
                  % ((p.get("name") or "")[:52], cls, age // 60,
                     "(경과 부족)" if too_new else ""))

        for target in sorted({b for _a, b in incident.OPEN_LINK_RULES}):
            out, st = await collector._open_problems(zbx, c, hid, {target}, set(), now)
            print()
            print("현재 인시던트가 %s 라면 -> 상태 %s, 연계 %d건" % (target, st, len(out)))
            for o in out:
                print("   %s (%d분 열림, 비율 %.0f%%)"
                      % (o["name"][:56], o["open_for_s"] // 60, 100 * o["link"]["rate"]))


def main():
    a = sys.argv
    if len(a) >= 2 and a[1] == "problems":
        asyncio.run(problems())
    elif len(a) >= 3 and a[1] == "map":
        asyncio.run(host_map(a[2]))
    elif len(a) >= 2 and a[1] == "env":
        show_env()
    elif len(a) >= 3 and a[1] == "openlink":
        asyncio.run(openlink(a[2]))
    elif len(a) >= 3 and a[1] == "loki":
        asyncio.run(loki_probe(a[2], a[3] if len(a) >= 4 else 24))
    else:
        print(__doc__)
        print("추가: env | loki <label> [hours] | openlink <zabbix호스트명>")


if __name__ == "__main__":
    main()
