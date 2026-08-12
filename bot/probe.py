"""랩 진단 — 호스트 식별자 3중 불일치(Zabbix/Loki/Wazuh)를 드러내고 다리 후보를 찾는다.

사용:
  python3 probe.py problems            # 발화 중 이벤트 목록 (event_id trigger_id host name)
  python3 probe.py map <trigger_id>    # 그 트리거 호스트의 Zabbix 이름·표시명·인터페이스 dns/ip
                                       #  + Loki host 라벨값 전체 + 각 후보로 Loki 조회 시 로그 수
  python3 probe.py names [limit]       # Zabbix 호스트 전체를 Loki·Wazuh 이름과 대조 (어긋난 호스트 목록)
  python3 probe.py registry [source]   # 호스트 명부 초안 출력 (손으로 쓰지 않기 위한 것)
환경변수: ZABBIX_URL·ZABBIX_TOKEN(필수), LOKI_URL(선택).
"""

import asyncio
import json
import logging
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


async def loki_host_values(lookback_s: int = None):
    """host 라벨의 값 목록.

    Loki 는 start 를 안 주면 최근 6시간만 본다. 수집기는 7일을 보므로 여기서도 같은
    창을 넘긴다. 창이 다르면 잠깐 로그가 끊긴 호스트가 진단에서만 사라져, 있지도 않은
    이름 불일치를 쫓게 된다.
    """
    url = os.environ.get("LOKI_URL", "").rstrip("/")
    if not url:
        return []
    from gateway.collector import LOKI_HOST_LABEL, KNOWN_HOST_LOOKBACK_S
    span = KNOWN_HOST_LOOKBACK_S if lookback_s is None else lookback_s
    now = int(time.time())
    async with httpx.AsyncClient() as c:
        r = await c.get(f"{url}/loki/api/v1/label/{LOKI_HOST_LABEL}/values", params={
            "start": str((now - span) * 1_000_000_000),
            "end": str(now * 1_000_000_000)}, timeout=5)
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

    if host_name.startswith(("http://", "https://")):
        raise RuntimeError(
            "인자는 Zabbix 호스트명이다 — 주소가 아니라 감시 대상 이름을 넣는다. "
            "주소는 ZABBIX_URL 환경변수로 준다. "
            "이름을 모르면 먼저 `python bot/probe.py problems` 로 목록을 본다.")

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


async def context(event_id: str, trigger_id: str):
    """실제 알림 1건으로 인시던트 컨텍스트를 조립해 본다 — LLM·장애 주입 없이.

    probe openlink 는 조회 함수만 본다. 이 명령은 그 위에서 collect_incident_context 가
    열린 문제를 실제로 컨텍스트에 싣는지, 그리고 **마스킹을 거쳐 나가는지**까지 확인한다.
    나가는 형태를 그대로 보여주므로 그 출력은 외부에 붙여도 안전하다.
    """
    import time as _t

    from gateway import collector, incident, masking

    zbx = collector.ZabbixClient()
    ev = await zbx_event(zbx, event_id)
    if not ev:
        raise RuntimeError("이벤트 %s 를 못 찾았다. probe.py problems 로 목록을 본다." % event_id)
    host = (ev.get("hosts") or [{}])[0].get("host", "")
    cls = incident.classify(ev.get("name") or "", tags=ev.get("tags"))
    alert = incident.Alert(source="zabbix-internal", event_id=str(event_id),
                           trigger_id=str(trigger_id), host=host,
                           alert_name=ev.get("name") or "", sev="SEV2",
                           incident_class=cls, recv=_t.monotonic())
    inc = incident.Incident(key=(host, cls), host=host, alerts=[alert])
    print("알림: %s / 분류 %s / 호스트 %s" % (alert.alert_name[:50], cls, host))

    ctx = await collector.collect_incident_context(zbx, inc)
    print()
    print("조회 상태: %s" % ctx.get("sources"))
    print("로그 %d줄 / 보안 %d건 / 열린 문제 %d건"
          % (len(ctx.get("logs") or []), len(ctx.get("security") or []),
             len(ctx.get("open_problems") or [])))
    for o in ctx.get("open_problems") or []:
        print("   %s (%s, %d분, stale=%s)"
              % (o["name"][:44], o["class"], o["open_for_s"] // 60, o.get("stale")))

    masked = masking.build_llm_context(ctx, "SEV2", masking.Masker())
    print()
    print("=== 외부로 나가는 형태(마스킹 후) — 열린 문제 절 ===")
    print(json.dumps(masked.get("open_problems"), ensure_ascii=False, indent=1))
    print("sources:", masked.get("sources"))


async def zbx_event(zbx, event_id):
    async with httpx.AsyncClient(verify=False) as c:
        got = await zbx.call(c, "event.get", {
            "eventids": str(event_id), "output": ["eventid", "name"],
            "selectHosts": ["host"], "selectTags": "extend"})
    return got[0] if got else None


async def names(limit: int = 500):
    """Zabbix 호스트 이름이 Loki·Wazuh 에도 그대로 있는지 전수로 대조한다.

    수집기는 사건이 났을 때 그 호스트 하나만 확인한다. 배포 직후나 이름 규칙을 바꾼
    뒤에는 어긋난 호스트를 미리 알아야 하므로 여기서 한 번에 본다. 판정 기준은
    수집기와 같다 — Loki 는 라벨 값 일치, Wazuh 는 agent.name 부분 일치.
    """
    from gateway import collector

    z = collector.ZabbixClient()
    async with httpx.AsyncClient() as c:
        hosts = await z.call(c, "host.get", {
            "output": ["host", "name"], "selectInterfaces": ["dns"], "limit": limit})
    zbx = sorted({h["host"] for h in hosts})
    print("Zabbix 호스트 %d개" % len(zbx))

    # 두 설정은 .env 를 고쳐도 셸을 다시 읽지 않으면 프로세스에 안 들어온다.
    # 안 먹은 채로 결과를 보면 없는 불일치를 쫓게 되므로 먼저 찍는다.
    print("HOST_LABEL_MAP: %s" % (os.environ.get("HOST_LABEL_MAP") or "(비어 있음)"))
    for v in ("LOGS_EXEMPT_HOSTS", "SECURITY_EXEMPT_HOSTS", "LOG_AXIS_EXEMPT_HOSTS"):
        print("%s: %s" % (v, os.environ.get(v) or "(비어 있음)"))

    loki = set(await loki_host_values())
    print("Loki host 라벨 값 %d개 (최근 %d일)"
          % (len(loki), collector.KNOWN_HOST_LOOKBACK_S // 86400))

    # 수집기와 같은 해석 규칙을 쓴다 — 여기서만 다르게 풀면 진단이 현실과 어긋난다.
    resolved = [(h["host"], collector._resolve_label(h["host"], h)) for h in hosts]

    exempt = [(n, lb) for n, lb in resolved if collector.axis_exempt(n, "logs")]
    rest = [(n, lb) for n, lb in resolved if not collector.axis_exempt(n, "logs")]
    hit = [(n, lb) for n, lb in rest if lb in loki]
    miss = [(n, lb) for n, lb in rest if lb not in loki]
    print("\n[ Loki 대조 ]  일치 %d / 불일치 %d / 면제 %d"
          % (len(hit), len(miss), len(exempt)))
    for n, lb in hit:
        print("  ○ %-30s → '%s'" % (n, lb))
    for n, lb in miss[:40]:
        print("  ✗ %-30s → 조회에 쓰는 이름 '%s'" % (n, lb))
    if len(miss) > 40:
        print("  ... 외 %d개" % (len(miss) - 40))
    if exempt:
        print("  면제(로그 축): %s"
              % ", ".join(n for n, _lb in exempt[:10]))
    if loki - {lb for _n, lb in resolved}:
        print("\n  Loki 에만 있는 이름(감시 대상이 아니거나 이름이 다르다):")
        for v in sorted(loki - {lb for _n, lb in resolved})[:20]:
            print("    · %s" % v)

    if os.environ.get("WAZUH_INDEXER_URL"):
        # 호스트마다 수집기가 경고를 남기면 표가 묻힌다. 결과는 아래 표에 있다.
        logging.getLogger("gateway.collector").setLevel(logging.ERROR)
        # 면제는 축마다 다르다 — 컨테이너는 로그는 있고 보안 축이 없다.
        sec_exempt = [n for n, _lb in resolved if collector.axis_exempt(n, "security")]
        sec_rest = [(n, lb) for n, lb in resolved
                    if not collector.axis_exempt(n, "security")]
        st = []
        async with httpx.AsyncClient(verify=False) as wc:
            for n, lb in sec_rest:
                s = await collector._wazuh_name_status(
                    wc, os.environ["WAZUH_INDEXER_URL"].rstrip("/"),
                    os.environ.get("WAZUH_INDEXER_USER", ""),
                    os.environ.get("WAZUH_INDEXER_PASSWORD", ""), lb)
                st.append((n, lb, s))
        bad = [x for x in st if x[2] != collector.SOURCE_OK]
        print("\n[ Wazuh 대조 ]  일치 %d / 불일치·실패 %d / 면제 %d"
              % (len(st) - len(bad), len(bad), len(sec_exempt)))
        for n, lb, s in st:
            if s == collector.SOURCE_OK:
                print("  ○ %-30s → '%s'" % (n, lb))
        for n, lb, s in bad[:40]:
            print("  ✗ %-30s → '%s' (%s)" % (n, lb, s))
        if sec_exempt:
            print("  면제(보안 축): %s" % ", ".join(sec_exempt[:10]))
    else:
        print("\n[ Wazuh 대조 ] WAZUH_INDEXER_URL 미설정 — 생략")


async def gen_registry(source: str = "zabbix-internal", limit: int = 500):
    """호스트 명부 초안을 만든다. 손으로 쓰지 않기 위한 것이다.

    names 와 같은 재료(Zabbix 호스트 목록·Loki 라벨 값·Wazuh 등록 여부)를 쓰되, 결과를
    사람이 고쳐 쓸 수 있는 형태로 낸다. 그대로 쓰지 말고 **읽고 고친 뒤** 저장한다 —
    이름이 안 맞는 호스트는 여기서도 안 맞은 채로 나온다.
    """
    from gateway import collector

    z = collector.ZabbixClient()
    async with httpx.AsyncClient() as c:
        hosts = await z.call(c, "host.get", {
            "output": ["host", "name"], "selectInterfaces": ["dns"], "limit": limit})
    loki = set(await loki_host_values())

    wz_url = os.environ.get("WAZUH_INDEXER_URL", "").rstrip("/")
    known_wz = set()
    if wz_url:
        logging.getLogger("gateway.collector").setLevel(logging.ERROR)
        async with httpx.AsyncClient(verify=False) as wc:
            for h in hosts:
                lb = collector._resolve_label(h["host"], h)
                st = await collector._wazuh_name_status(
                    wc, wz_url, os.environ.get("WAZUH_INDEXER_USER", ""),
                    os.environ.get("WAZUH_INDEXER_PASSWORD", ""), lb)
                if st == collector.SOURCE_OK:
                    known_wz.add(h["host"])

    print("# 호스트 명부 초안 — probe.py registry 로 생성. 읽고 고친 뒤 저장한다.")
    print("# logs·security 는 '그 축이 있는가'다. false 면 조회하지 않는다.")
    print("# realm 은 감시 영역. 감시 서버가 하나면 전부 같은 값이면 된다.")
    print("hosts:")
    for h in hosts:
        name = h["host"]
        lb = collector._resolve_label(name, h)
        print("  - name: %s" % name)
        print("    source: %s" % source)
        print("    realm: %s" % source)
        if lb in loki:
            print("    loki: %s" % lb)
            print("    logs: true")
        else:
            print("    logs: false        # Loki 에 이 이름이 없다 — 확인 후 고칠 것")
        if name in known_wz:
            print("    wazuh: %s" % lb)
            print("    security: true")
        else:
            print("    security: false    # Wazuh 에 이 이름이 없다 — 확인 후 고칠 것")
        print('    id: ""')


def nametable_report():
    """전역 이름 표를 만들고 위험 항목·정확도 수치를 낸다.

    실환경 진단용이다. **이름은 출력하지 않고 개수만 낸다** — 결과를 문서에 남겨야 하는데
    호스트명은 리포에 남기지 않는 것이 이 프로젝트 원칙이다. 위험 항목만 사람이 판단할 수
    있게 이름을 보이고, 그건 화면에서만 본다.
    """
    from gateway import masking, nametable

    # 진단은 디스크에 표를 남기지 않는다 — 실환경 호스트명이 파일로 남으면 안 된다.
    nametable.CACHE_FILE = ""
    st = nametable.build()
    names = [n for n, _ in nametable.terms()]
    print("== 이름 표 ==")
    print("출처별:", st["by_source"])
    print("총 %d개 / 오류: %s" % (st["terms"], st["error"] or "없음"))
    if not st["terms"]:
        print()
        print("표가 비었다. 아래를 설정하고 다시 돌린다 — 하나도 없으면 조회 자체가 안 된다.")
        print("  ZABBIX_URL·ZABBIX_TOKEN  (필수, 읽기 전용 토큰)")
        print("  LOKI_URL·WAZUH_INDEXER_*  (선택 — 없으면 그 출처만 빠진다)")
        print("현재 설정 상태:")
        show_env()
        return

    rk = nametable.risky()
    print()
    print("== 위험 항목 %d개 (%.1f%%) ==" % (len(rk), 100.0 * len(rk) / max(1, len(names))))
    by_why = {}
    for r in rk:
        for w in r["why"]:
            by_why[w] = by_why.get(w, 0) + 1
    for w, c in sorted(by_why.items(), key=lambda kv: -kv[1]):
        print("  %-16s %d" % (w, c))
    print("  (사유별 합계는 한 이름이 여러 사유에 걸리면 중복 계산된다)")

    # 미탐 — 이름이 든 문장을 마스킹한 뒤에도 남는가
    miss = 0
    for n in names:
        mk = masking.Masker()
        nametable.apply_to(mk)
        if n in mk.mask("backup from %s failed" % n):
            miss += 1
    print()
    print("== 미탐 == 이름 %d개 중 마스킹 후 남은 것: %d" % (len(names), miss))

    # 오탐 — 이름이 없어야 하는 문장이 바뀌는가
    clean = [
        "디스크 사용률이 임계치를 넘었습니다. 로그 정리를 권장합니다.",
        "Zabbix agent is not available (for 3m)",
        "MySQL: Replication lag is too high",
        "backup job finished successfully in 12 minutes",
        "the database node was restarted by the operator",
        "web service returned 500 for the health check",
        "high load average detected on the reporting server",
        "disk space is critically low on the data volume",
    ]
    fp = []
    for line in clean:
        mk = masking.Masker()
        nametable.apply_to(mk)
        out = mk.mask(line)
        if out != line:
            fp.append((line, out))
    print("== 오탐 == 문장 %d개 중 바뀐 것: %d" % (len(clean), len(fp)))
    for a, b in fp:
        print("   %s" % a)
        print("   -> %s" % b)
    if rk:
        print()
        print("== 위험 항목 목록 (화면에서만 확인, 문서에 남기지 말 것) ==")
        for r in rk:
            print("  %-30s %s" % (r["name"], ", ".join(r["why"])))


def main():
    a = sys.argv
    if len(a) >= 2 and a[1] == "registry":
        asyncio.run(gen_registry(a[2] if len(a) >= 3 else "zabbix-internal"))
    elif len(a) >= 2 and a[1] == "names":
        asyncio.run(names(int(a[2]) if len(a) >= 3 else 500))
    elif len(a) >= 2 and a[1] == "problems":
        asyncio.run(problems())
    elif len(a) >= 3 and a[1] == "map":
        asyncio.run(host_map(a[2]))
    elif len(a) >= 2 and a[1] == "nametable":
        nametable_report()
    elif len(a) >= 2 and a[1] == "env":
        show_env()
    elif len(a) >= 4 and a[1] == "context":
        asyncio.run(context(a[2], a[3]))
    elif len(a) >= 3 and a[1] == "openlink":
        asyncio.run(openlink(a[2]))
    elif len(a) >= 3 and a[1] == "loki":
        asyncio.run(loki_probe(a[2], a[3] if len(a) >= 4 else 24))
    else:
        print(__doc__)
        print("추가: env | names [limit] | registry [source] | nametable | loki <label> [hours]"
              " | openlink <zabbix호스트명> | context <event_id> <trigger_id>")


if __name__ == "__main__":
    try:
        main()
    except RuntimeError as e:
        # 설정·인자 실수에 스택을 붙이면 무엇을 고쳐야 하는지가 묻힌다.
        sys.exit(str(e))
