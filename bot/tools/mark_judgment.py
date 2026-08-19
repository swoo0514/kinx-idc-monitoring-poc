#!/usr/bin/env python3
"""판정 확인·정정 — 관제 담당자가 봇의 판단에 라벨을 남긴다.

Keep 카드의 Run Workflow 가 이 명령을 부른다. 이 라벨이 정확도 산출의 분자·분모가 되고,
확인된 결론만 다음 회차의 과거 결론으로 쓰인다.

사용:
  python3 mark_judgment.py --id 42 --fingerprint 5eebe413de50 --ok yes
  python3 mark_judgment.py --id 42 --fingerprint 5eebe413de50 --ok no --note "봤어야 했다"

운영 기준은 bot/GATEWAY_GUIDE.md §25, 워크플로는 keep/KEEP_GUIDE.md.
"""

import argparse
import os
import sys

# `bot/` 을 경로에 넣는다. 이 파일이 bot/tools/ 로 내려갔으므로 부모다.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass

from gateway import store  # noqa: E402

AXES = ("overall", "gate", "merge", "cause")


def run(jid, fingerprint: str = "", ok: bool = True, axis: str = "overall",
        note: str = "", who: str = "") -> int:
    """0 이면 성공. 그 밖의 값은 워크플로에 실패로 보인다."""
    if axis not in AXES:
        print("모르는 축이다: %s (%s 중 하나)" % (axis, ", ".join(AXES)), file=sys.stderr)
        return 2
    if not store.init():
        print("판정 이력 저장소를 열지 못했다: %s" % store.status().get("error"),
              file=sys.stderr)
        return 3
    row = store.get_judgment(jid)
    if not row:
        print("그런 판정이 없다: id=%s" % jid, file=sys.stderr)
        return 2
    # Keep 은 지문으로 카드를 접으므로, 카드가 최신 판정으로 덮인 뒤에도 옛 식별자가
    # 화면에 남아 있을 수 있다. 둘이 어긋나면 다른 판정에 라벨이 붙는다.
    if fingerprint and row.get("fingerprint") != fingerprint:
        print("판정과 지문이 어긋난다: id=%s 는 %s 인데 %s 로 왔다"
              % (jid, row.get("fingerprint"), fingerprint), file=sys.stderr)
        return 2
    if not store.record_feedback(jid, axis, ok, note=note, who=who):
        print("라벨을 남기지 못했다", file=sys.stderr)
        return 3
    print("판정 %s · 축 %s · %s (%s)"
          % (jid, axis, "확인" if ok else "정정", row.get("host") or "호스트 미상"))
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="판정 확인·정정")
    ap.add_argument("--id", required=True, type=int, help="판정 식별자(카드의 judgment_id)")
    ap.add_argument("--fingerprint", default="", help="카드의 fingerprint (대조용)")
    ap.add_argument("--ok", required=True, choices=("yes", "no"),
                    help="yes=판정 확인, no=판정 정정")
    ap.add_argument("--axis", default="overall", help="|".join(AXES))
    ap.add_argument("--note", default="")
    ap.add_argument("--who", default="")
    a = ap.parse_args()
    return run(a.id, a.fingerprint, a.ok == "yes", a.axis, a.note, a.who)


if __name__ == "__main__":
    sys.exit(main())
