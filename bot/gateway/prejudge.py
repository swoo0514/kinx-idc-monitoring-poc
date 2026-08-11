"""만성/신규 선판정 — 과거 발생 이력만으로 결정적 판정(LLM은 재판정 안 함).

기준값 근거·변수화는 bot/GATEWAY_GUIDE.md §7-3.
"""

import math
import os
import time


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        return default


WINDOW_DAYS = _env_int("PREJUDGE_WINDOW_DAYS", 90)
WINDOW_S = WINDOW_DAYS * 24 * 3600

# 만성의 기준은 횟수가 아니라 **재발 간격**으로 둔다. 횟수로 두면 "왜 5회인가"에 답할 수
# 없고, 관측 창을 90일에서 180일로 늘리면 같은 5회가 두 배로 느슨해지는데 아무도 모른다.
#
# 30일로 잡은 근거는 우리가 만든 월간 리포트다. 한 달에 한 번 이상 반복되면 리포트가
# 나올 때마다 그 항목이 실리고, 매달 실리는데 안 고쳐지고 있으면 그것이 정비 대상이다.
# 즉 "월간 리포트에 매번 등장하는 것"이 만성이다. 리포트 주기가 바뀌면 이 값도 바뀐다.
#
# 참고로 밖에는 정해진 수치가 없다. ITIL 문헌에 "같은 증상이 30일에 3건 이상이면 별도
# 관리 대상"이라는 관행이 언급되나 같은 자료가 표준이 아니라 조직별 조정값이라고 밝힌다.
# 우연히 우리 값과 같은 간격이다.
CHRONIC_INTERVAL_DAYS = _env_int("PREJUDGE_CHRONIC_INTERVAL_DAYS", 30)


def chronic_min_for(window_days: int, interval_days: int) -> int:
    """관측 창 안에서 그 간격으로 반복되려면 몇 번 나야 하는가.

    1회는 반복이 아니므로 하한은 2다.
    """
    if interval_days <= 0:
        return 2
    return max(2, math.ceil(window_days / interval_days))


# 명시하면 그 값을 그대로 쓴다 — 이미 값을 정해 둔 환경을 조용히 바꾸지 않기 위해서다.
CHRONIC_MIN_COUNT = (_env_int("PREJUDGE_CHRONIC_MIN", 0)
                     or chronic_min_for(WINDOW_DAYS, CHRONIC_INTERVAL_DAYS))


def judge(past_clocks: list, now: float = None, window_s: int = None,
          chronic_min: int = None, total_count: int = None,
          listed_truncated: bool = None) -> dict:
    """past_clocks: 현재 이벤트 제외한 동일 트리거 과거 발생 unix time 목록.

    total_count 는 창 안 전체 발생 수다. 목록은 조회 상한이 있어 잘리므로 개수를 따로
    받는다 — 안 그러면 상한을 넘는 것들이 전부 같은 수로 보여 무엇이 더 자주 나는지
    가릴 수 없다. 목록은 마지막 발생 시각에만 쓴다.
    """
    now = now or time.time()
    window_s = window_s or WINDOW_S
    chronic_min = chronic_min or CHRONIC_MIN_COUNT
    window_days = round(window_s / 86400)
    in_window = sorted(c for c in past_clocks if now - c <= window_s)
    listed = len(in_window)
    # 개수를 못 받았으면 목록 길이로 떨어진다. 그 경우 상한에 걸렸을 수 있으므로
    # 아래에서 그 사실을 함께 남긴다 — 잘린 값을 실제 값처럼 쓰면 안 된다.
    count = listed if total_count is None else max(total_count, listed)
    # 절단 여부는 조회한 쪽이 알려 주는 것이 정확하다. 여기서 개수로 추측하면,
    # 조회 측이 현재 이벤트를 목록에서 빼는 순간 한 칸씩 어긋나 영원히 안 걸린다.
    if listed_truncated is None:
        listed_truncated = listed >= _list_limit()
    truncated = total_count is None and bool(listed_truncated)

    if count == 0:
        verdict = "신규"
        statement = (f"최근 {window_days}일 내 동일 트리거 발생 이력 없음 — "
                     f"처음 보는 문제이므로 즉시 확인 권장.")
        last_seen_days = None
    else:
        last_seen_days = round((now - in_window[-1]) / 86400, 1)
        if count >= chronic_min:
            verdict = "만성"
            statement = (f"최근 {window_days}일 내 동일 트리거 {count}회 발생"
                         f"(마지막 {last_seen_days}일 전) — 알려진 반복 문제. "
                         f"근본 원인 정비 대상이며 긴급도는 낮을 수 있음.")
        else:
            verdict = "재발"
            statement = (f"최근 {window_days}일 내 동일 트리거 {count}회 발생"
                         f"(마지막 {last_seen_days}일 전) — 간헐 재발. "
                         f"이전 발생과의 공통점 확인 권장.")

    if truncated:
        statement += f" (조회 상한에 걸려 실제 발생 수는 {count}회보다 많을 수 있음)"

    return {
        "verdict": verdict,
        "count_window": count,
        "window_days": window_days,
        "last_seen_days": last_seen_days,
        "count_truncated": truncated,   # 잘린 값인지 — 순위·집계에서 걸러내는 데 쓴다
        "statement": statement,   # LLM 프롬프트에 그대로 주입
    }


def _list_limit() -> int:
    """수집기의 목록 상한. 순환 import 를 피해 여기서 늦게 읽는다."""
    from . import collector
    return collector.PAST_EVENT_LIMIT
