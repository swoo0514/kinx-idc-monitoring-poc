#!/usr/bin/env python3
"""연계 규칙 정기 재측정 — 수집부터 승인 요청까지 한 번에.

왜 이 스크립트가 있는가. 수집·마이닝·규칙 산출·승인 요청이 각각 다른 명령이라, 사람이
기억해서 같은 조건으로 이어 붙여야 했다. 조건이 한 번이라도 달라지면 이전 규칙과 비교가
성립하지 않는다(`measured` 문자열이 달라지고, 무엇이 바뀐 건지 알 수 없게 된다).
**측정 조건을 한 곳에 두고 매번 같은 값으로 돌리는 것**이 이 스크립트의 존재 이유다.

주기 — 규칙은 90일 창으로 잰다. 매일 돌리면 창이 89일 겹쳐 값이 거의 그대로다.
의미 있게 바뀌려면 창의 상당 부분이 갈려야 하므로 **월 1회가 자연스럽다.**
정기보다 중요한 것은 아래 사건 직후의 수동 실행이다.

  · 임계치·의존성 정비 후   — 노이즈가 걷히면 결과가 통째로 달라진다
  · 분류기 변경 후          — 축이 재배치되므로 기존 규칙이 무효가 된다
  · 관측 소스 추가 후        — 교차 소스가 처음 측정 가능해진다
  · 인프라 대규모 변경 후    — 관계 자체가 바뀐다

실패하면 승인 요청을 만들지 않는다. **부분 측정으로 만든 규칙은 이전 규칙보다 나쁘다** —
빠진 기간이 "그때는 신호가 없었다"로 둔갑하기 때문이다. 그 경우 이전 규칙을 그대로 둔다.

사용:
  python remeasure.py --active ~/rules/active.json --workdir ~/rules
  python remeasure.py --active ~/rules/active.json --workdir ~/rules --dry-run
"""

import argparse
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass

# 측정 조건 — **여기 한 곳에만 둔다.** 바꾸면 이전 규칙과 비교가 성립하지 않으므로
# 바꾼 사실이 `measured` 문자열을 통해 승인 화면에 드러난다.
DAYS = 90
AXIS = "cls"              # 게이트웨이가 사건 유형 단위로 연계를 판정한다
MIN_OPEN_S = 3600         # 1시간 미만 열린 것은 만성이 아니다
MIN_DAYS = 3              # 하루에 몰린 조합 배제
MAX_DAY_SHARE = 0.5       # 최대 하루가 이 비중을 넘으면 단일 사건 지배
MIN_AXIS = 3
MIN_PAIRS = 5
NULL_ROUNDS = 300         # p값 해상도 1/(N+1) — FDR 문턱에 도달하려면 이 정도가 필요하다
FDR = 0.05
EXCLUDE = ["errors on interface"]   # 사이트 노이즈 계열. 환경마다 다르므로 인자로 덮는다


def run(cmd: list, label: str) -> None:
    print("\n[%s] %s" % (label, " ".join(cmd[1:])), file=sys.stderr)
    r = subprocess.run(cmd)
    if r.returncode != 0:
        raise RuntimeError(
            "%s 실패(코드 %d). 승인 요청을 만들지 않는다 — 부분 측정으로 만든 규칙은 "
            "이전 규칙보다 나쁘다(빠진 기간이 '신호 없음'으로 둔갑한다). "
            "이전 규칙을 그대로 둔다." % (label, r.returncode))


def main():
    ap = argparse.ArgumentParser(description="연계 규칙 정기 재측정")
    ap.add_argument("--active", required=True, help="게이트웨이가 읽는 규칙 파일")
    ap.add_argument("--workdir", required=True, help="덤프·후보 파일을 둘 곳(커밋 금지 경로)")
    ap.add_argument("--days", type=int, default=DAYS)
    ap.add_argument("--exclude", action="append", default=None,
                    help="제외할 알림명 정규식. 지정하면 기본값을 대체한다")
    ap.add_argument("--dry-run", action="store_true",
                    help="변경분만 보고 승인 요청은 만들지 않는다")
    a = ap.parse_args()

    os.makedirs(a.workdir, exist_ok=True)
    stamp = time.strftime("%Y%m%d")
    dump = os.path.join(a.workdir, "measure_%s.json" % stamp)
    staged = os.path.join(a.workdir, "staged_%s.json" % stamp)
    py = sys.executable
    miner = os.path.join(HERE, "bridge_miner.py")
    promote = os.path.join(HERE, "rules_promote.py")
    excl = EXCLUDE if a.exclude is None else a.exclude

    # 1) 수집 — 소스 하나가 실패해도 나머지는 저장되지만, 그 사실이 파일에 남고
    #    아래 마이닝 출력의 [ 측정 범위 ] 에 드러난다.
    run([py, miner, "--days", str(a.days), "--dump", dump], "수집")

    # 2) 마이닝 + 규칙 산출 — 조건은 위 상수 그대로.
    cmd = [py, miner, "--load", dump, "--by", AXIS, "--overlap",
           "--min-open", str(MIN_OPEN_S), "--min-days", str(MIN_DAYS),
           "--max-day-share", str(MAX_DAY_SHARE), "--min-axis", str(MIN_AXIS),
           "--min-pairs", str(MIN_PAIRS), "--null", str(NULL_ROUNDS),
           "--fdr", str(FDR), "--emit-rules", staged]
    for pat in excl:
        cmd += ["--exclude", pat]
    run(cmd, "마이닝")

    if not os.path.exists(staged):
        raise RuntimeError("후보 파일이 생성되지 않았다: %s" % staged)

    # 3) 변경분 확인 / 승인 요청
    action = "diff" if a.dry_run else "propose"
    run([py, promote, action, "--staged", staged, "--active", a.active], "승인 " + action)

    print("\n[완료] 후보 %s" % staged, file=sys.stderr)
    if a.dry_run:
        print("  --dry-run 이라 승인 요청은 만들지 않았다.", file=sys.stderr)
    else:
        print("  Keep 에서 변경분을 검토하고 승인한다. 승인 전까지 이전 규칙이 유지된다.",
              file=sys.stderr)


if __name__ == "__main__":
    try:
        main()
    except RuntimeError as e:
        sys.exit(str(e))
