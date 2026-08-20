#!/usr/bin/env python3
"""사람이 요청한 심층 조사 — 게이트가 안 태운 사건을 조사 → 가설 → 검증으로 다시 본다.

`analyze_now.py` 와 같은 꼴이다. 승인 계층을 새로 만들지 않고 Keep 의 Run Workflow 를
그대로 쓴다(데모 B·월간 리포트와 네 번째 같은 형태).
"""

import argparse
import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass

from gateway import store  # noqa: E402
from gateway.alerts import collector, incident, triage  # noqa: E402


def main():
    ap = argparse.ArgumentParser(description="사람이 요청한 심층 조사")
    ap.add_argument("--host", required=True, help="Zabbix 호스트명")
    ap.add_argument("--ref", required=True, help="Keep 카드의 analyze_ref")
    args = ap.parse_args()

    from tools.analyze_now import parse_ref     # 사건을 되살리는 재료는 같은 것을 쓴다

    alerts = parse_ref(args.ref, args.host)
    if not alerts:
        print("되살릴 알림이 없다 — analyze_ref 를 확인하라")
        return 2

    inc = incident.Incident(host=args.host, incident_class=alerts[0].incident_class,
                            source=alerts[0].source)
    for a in alerts:
        inc.add(a)

    async def go():
        from gateway.deep import entry as deep_entry

        client = collector.ZabbixClient(source=inc.alerts[0].source)
        ctx = await collector.collect_incident_context(inc, client)
        return await deep_entry.investigate_incident(ctx)

    store.init()
    res = asyncio.run(go())
    if not res.get("ok"):
        print("심층 조사 실패 — %s (%s)" % (res.get("error"), res.get("stopped")))
        return 1
    print("심층 조사 완료 — 라운드 %s · 기록 %s · 종료 %s"
          % (res.get("rounds"), res.get("records"), res.get("stopped")))
    print()
    print(res.get("text") or "")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
