#!/usr/bin/env python3
"""사람이 요청한 분석 — 봇이 건너뛴 사건을 다시 돌린다.

봇은 교차 신호가 없거나 심각도가 낮으면 분석하지 않는다. 그 판단이 늘 맞지는 않으므로
관제 담당자가 필요하다고 보면 직접 요청할 수 있어야 한다. Keep 카드의 Run Workflow 가
이 명령을 부른다.

발동 조건을 건너뛴다. 봇이 안 하기로 한 것을 사람이 뒤집는 경로라서, 여기서 조건을
다시 걸면 요청이 무시된다.

사용:
  python3 analyze_now.py --host customer-a --ref "zabbix-internal,103125,25384,replication"

--ref 는 Keep 카드의 analyze_ref 값이다. 알림이 여럿이면 `|` 로 이어진다.
운영 기준은 bot/GATEWAY_GUIDE.md §8-5, 워크플로는 keep/KEEP_GUIDE.md.
"""

import argparse
import asyncio
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass

from gateway import incident, triage  # noqa: E402


def parse_ref(ref: str, host: str) -> list:
    out = []
    for part in (ref or "").split("|"):
        part = part.strip()
        if not part:
            continue
        f = [x.strip() for x in part.split(",")]
        if len(f) < 2 or not f[1]:
            raise RuntimeError(
                "--ref 형식이 맞지 않는다: %r. "
                "`소스,이벤트ID,트리거ID,유형` 이고 알림이 여럿이면 `|` 로 잇는다." % part)
        out.append(incident.Alert(
            source=f[0], event_id=f[1],
            trigger_id=f[2] if len(f) > 2 else "",
            host=host, alert_name="", sev="SEV2",
            incident_class=f[3] if len(f) > 3 and f[3] else "other",
            recv=time.monotonic()))
    if not out:
        raise RuntimeError("--ref 가 비었다. Keep 카드의 analyze_ref 값을 그대로 넘긴다.")
    return out


def main():
    ap = argparse.ArgumentParser(description="사람이 요청한 분석")
    ap.add_argument("--host", required=True, help="Zabbix 호스트명")
    ap.add_argument("--ref", required=True, help="Keep 카드의 analyze_ref")
    a = ap.parse_args()

    alerts = parse_ref(a.ref, a.host)
    now = time.monotonic()
    inc = incident.Incident(
        key=incident.incident_key(a.host, alerts[0].incident_class),
        host=a.host, alerts=alerts, opened_at=now, last_at=now)

    print("요청 분석: 호스트 %s / 알림 %d건" % (a.host, len(alerts)), file=sys.stderr)
    res = asyncio.run(triage.run_incident(inc, force=True))
    print("완료: %s" % res, file=sys.stderr)


if __name__ == "__main__":
    try:
        main()
    except RuntimeError as e:
        sys.exit(str(e))
