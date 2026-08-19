#!/usr/bin/env python3
"""사람이 요청한 분석 — 봇이 건너뛴 사건을 다시 돌린다."""

import argparse
import asyncio
import os
import sys
import time

# `bot/` 을 경로에 넣는다. 이 파일이 bot/tools/ 로 내려갔으므로 부모다.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass

from gateway import store  # noqa: E402
from gateway.alerts import incident, triage


def label_previous(fingerprint: str) -> int:
    """사람이 재분석을 부른 것은 게이트 판정이 틀렸다는 라벨이다 (§25-2).

    누구에게도 새 행동을 요구하지 않고 모이는 유일한 라벨이라 자동으로 남긴다.
    """
    if not store.init():
        return 0
    row = store.latest_judgment(fingerprint)
    if not row:
        return 0
    ok = store.record_feedback(row["id"], "gate", False,
                               note="사람이 재분석을 요청함",
                               who="workflow:analyze-now")
    return 1 if ok else 0


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
        key=incident.incident_key(alerts[0].source, a.host, alerts[0].incident_class),
        host=a.host, alerts=alerts, opened_at=now, last_at=now)

    print("요청 분석: 호스트 %s / 알림 %d건" % (a.host, len(alerts)), file=sys.stderr)
    # 새 판정이 생기기 전에 붙인다 — 안 그러면 방금 만든 행에 라벨이 간다.
    label_previous(inc.fingerprint())
    res = asyncio.run(triage.run_incident(inc, force=True))
    print("완료: %s" % res, file=sys.stderr)


if __name__ == "__main__":
    try:
        main()
    except RuntimeError as e:
        sys.exit(str(e))
