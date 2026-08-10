#!/usr/bin/env python3
"""연계 규칙 교체 — 재측정 결과를 사람 승인 뒤에 반영한다.

왜 사람이 끼는가. 마이닝을 정기 실행해 규칙 파일을 갈아끼우는 것 자체는 기계적이다.
문제는 **규칙이 조용히 바뀌는 것**이다. 이번 달 96% 이던 관계가 다음 달 60% 로 내려가면
봇의 판단이 달라지는데 아무도 모른다. 더 나쁜 경우는 나쁜 측정이 들어가는 것이다 —
대형 사건 1회가 통계를 지배해 없는 관계를 규칙으로 만든다(실측 2026-08-10: 통과 조합의
81% 가 단일 사건에서 나왔다). 집중도 지표로 그 형태는 막았지만 새 실패 형태가 안 생긴다는
보장은 없다.

그래서 **자동 재측정 + 사람 승인**으로 간다. 승인 계층은 새로 만들지 않는다 — 시스템 변경
승인(데모 B)·고객 발송 승인(월간 리포트)에 쓰던 Keep 을 그대로 쓰는 세 번째 적용이다.

흐름:
  1) 마이닝이 후보 파일을 낸다        bridge_miner --emit-rules <staged>
  2) 변경분을 만들어 승인 대기로 올린다  rules_promote.py propose --staged <f> --active <f>
  3) 사람이 Keep 에서 Run Workflow    → SSH → 4)
  4) 그 파일을 그대로 반영한다          rules_promote.py apply --staged <f> --active <f> --expect <hash>

--expect 가 있는 이유는 월간 리포트에서 겪은 것과 같다. **사람이 읽고 승인한 내용과 다른
것이 반영되면 안 된다.** 승인과 반영 사이에 재측정이 한 번 더 돌아 파일이 바뀌었을 수 있다.

사용법·운영 기준은 bot/GATEWAY_GUIDE.md.
"""

import argparse
import hashlib
import json
import os
import shutil
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass


def load(path: str) -> dict:
    if not path or not os.path.exists(path):
        return {"measured": "", "rules": []}
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def digest(path: str) -> str:
    """파일 내용 해시. 승인한 것과 반영하는 것이 같은지 확인하는 데 쓴다."""
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()[:12]


def _key(r: dict) -> tuple:
    return (r.get("open"), r.get("followed"))


def diff(active: dict, staged: dict) -> dict:
    """전체가 아니라 **변경분만** 낸다.

    전체 파일을 보여주면 사람이 무엇이 달라졌는지 찾느라 결국 안 읽는다.
    """
    a = {_key(r): r for r in active.get("rules", [])}
    s = {_key(r): r for r in staged.get("rules", [])}
    added = [s[k] for k in s if k not in a]
    removed = [a[k] for k in a if k not in s]
    changed = []
    for k in s:
        if k not in a:
            continue
        before, after = a[k], s[k]
        if (round(before.get("rate", 0), 3) != round(after.get("rate", 0), 3)
                or before.get("days") != after.get("days")):
            changed.append({"key": k, "before": before, "after": after})
    return {"added": added, "removed": removed, "changed": changed,
            "active_count": len(a), "staged_count": len(s)}


def risky(d: dict, active: dict, staged: dict) -> list:
    """사람 눈이 특히 필요한 변화. 막지 않고 표시만 한다 — 판단은 사람이 한다."""
    out = []
    if d["active_count"] and not d["staged_count"]:
        out.append("규칙이 전부 사라진다. 측정이 부실했을 가능성이 크다 — 재측정 전에는 반영 금지")
    for c in d["changed"]:
        b, a2 = c["before"].get("rate", 0), c["after"].get("rate", 0)
        if b and abs(a2 - b) / b >= 0.3:
            out.append("%s -> %s 비율이 %.0f%% 에서 %.0f%% 로 크게 움직였다"
                       % (c["key"][0], c["key"][1], 100 * b, 100 * a2))
        if c["after"].get("days", 0) < 5 <= c["before"].get("days", 0):
            out.append("%s -> %s 관측 일수가 %d 에서 %d 로 줄었다 — 단발 사건일 수 있다"
                       % (c["key"][0], c["key"][1],
                          c["before"].get("days", 0), c["after"].get("days", 0)))
    for r in d["removed"]:
        out.append("%s -> %s 가 사라진다(관계가 약해졌거나 측정 범위가 달라졌다)"
                   % (r.get("open"), r.get("followed")))
    return out


def render(d: dict, active: dict, staged: dict, warns: list) -> str:
    L = []
    L.append("규칙 %d건 → %d건" % (d["active_count"], d["staged_count"]))
    L.append("현재 측정: %s" % (active.get("measured") or "(없음)"))
    L.append("신규 측정: %s" % (staged.get("measured") or "(없음)"))
    if not (d["added"] or d["removed"] or d["changed"]):
        L.append("")
        L.append("변경 없음 — 반영할 것이 없다.")
        return "\n".join(L)
    if d["added"]:
        L.append("")
        L.append("[ 추가 ]")
        for r in d["added"]:
            L.append("  + %s -> %s   비율 %.0f%% / %d일 / %d회"
                     % (r["open"], r["followed"], 100 * r["rate"], r["days"],
                        r.get("overlaps", 0)))
    if d["changed"]:
        L.append("")
        L.append("[ 변경 ]")
        for c in d["changed"]:
            b, a2 = c["before"], c["after"]
            L.append("  ~ %s -> %s   비율 %.0f%% → %.0f%%   일수 %d → %d"
                     % (c["key"][0], c["key"][1], 100 * b.get("rate", 0),
                        100 * a2.get("rate", 0), b.get("days", 0), a2.get("days", 0)))
    if d["removed"]:
        L.append("")
        L.append("[ 삭제 ]")
        for r in d["removed"]:
            L.append("  - %s -> %s   (직전 비율 %.0f%% / %d일)"
                     % (r["open"], r["followed"], 100 * r.get("rate", 0), r.get("days", 0)))
    if warns:
        L.append("")
        L.append("[ 확인 필요 ]")
        for w in warns:
            L.append("  · %s" % w)
    return "\n".join(L)


def apply(staged: str, active: str, expect: str = "") -> str:
    """승인된 파일을 그대로 반영한다. 이전 파일은 시각을 붙여 남긴다(되돌리기 위해)."""
    got = digest(staged)
    if expect and got != expect:
        raise RuntimeError(
            "승인한 파일과 지금 파일이 다르다(승인 %s / 현재 %s). "
            "승인과 반영 사이에 재측정이 돌았을 수 있다. 변경분을 다시 확인한다." % (expect, got))
    if os.path.exists(active):
        backup = "%s.%s.bak" % (active, time.strftime("%Y%m%d-%H%M%S"))
        shutil.copy2(active, backup)
    else:
        backup = "(이전 파일 없음)"
    os.makedirs(os.path.dirname(os.path.abspath(active)), exist_ok=True)
    shutil.copy2(staged, active)
    return backup


def main():
    ap = argparse.ArgumentParser(description="연계 규칙 교체 (승인 게이트)")
    ap.add_argument("action", choices=["diff", "propose", "apply"])
    ap.add_argument("--staged", required=True, help="마이닝이 낸 후보 파일")
    ap.add_argument("--active", required=True, help="게이트웨이가 읽는 파일(OPEN_LINK_RULES_FILE)")
    ap.add_argument("--expect", default="", help="apply: 승인 시점 해시. 불일치면 거부")
    a = ap.parse_args()

    if not os.path.exists(a.staged):
        raise RuntimeError("후보 파일이 없다: %s" % a.staged)
    act, stg = load(a.active), load(a.staged)
    d = diff(act, stg)
    warns = risky(d, act, stg)
    body = render(d, act, stg, warns)

    if a.action == "diff":
        print(body)
        return

    if a.action == "apply":
        backup = apply(a.staged, a.active, a.expect)
        print(body)
        print()
        print("반영 완료 — %s (이전본: %s)" % (a.active, backup))
        print("게이트웨이가 규칙을 다시 읽도록 재기동한다.")
        return

    # propose — 변경이 없으면 승인 대기를 만들지 않는다. 매달 빈 승인 요청이 쌓이면
    # 사람이 보지 않게 되고, 그러면 진짜 변경도 같이 지나간다.
    if not (d["added"] or d["removed"] or d["changed"]):
        print(body)
        print()
        print("변경이 없어 승인 요청을 만들지 않는다.")
        return

    from gateway import keep
    h = digest(a.staged)
    r = keep.push_alert(
        name="연계 규칙 교체 승인 (%d건 → %d건)" % (d["active_count"], d["staged_count"]),
        sev="SEV3", host="gateway", analysis=body,
        prejudge="검토 대기", playbook="rules_approve",
        fingerprint="rules-promote-%s" % h,
        extra={"staged_path": os.path.abspath(a.staged),
               "active_path": os.path.abspath(a.active),
               "staged_hash": h,
               "added": len(d["added"]), "removed": len(d["removed"]),
               "changed": len(d["changed"]), "warnings": len(warns)})
    print(body)
    print()
    print("승인 대기 등록 — 해시 %s / Keep 응답 %s" % (h, r))


if __name__ == "__main__":
    try:
        main()
    except RuntimeError as e:
        sys.exit(str(e))
