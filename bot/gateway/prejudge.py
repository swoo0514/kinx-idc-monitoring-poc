"""만성/신규 선판정 — 과거 발생 이력만으로 결정적 판정(LLM은 재판정 안 함).

기준값 근거·변수화는 bot/GATEWAY_GUIDE.md §9.
"""

import os
import time


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        return default


WINDOW_DAYS = _env_int("PREJUDGE_WINDOW_DAYS", 90)
CHRONIC_MIN_COUNT = _env_int("PREJUDGE_CHRONIC_MIN", 5)
WINDOW_S = WINDOW_DAYS * 24 * 3600


def judge(past_clocks: list, now: float = None,
          window_s: int = None, chronic_min: int = None) -> dict:
    """past_clocks: 현재 이벤트 제외한 동일 트리거 과거 발생 unix time 목록."""
    now = now or time.time()
    window_s = window_s or WINDOW_S
    chronic_min = chronic_min or CHRONIC_MIN_COUNT
    window_days = round(window_s / 86400)
    in_window = sorted(c for c in past_clocks if now - c <= window_s)
    count = len(in_window)

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

    return {
        "verdict": verdict,
        "count_window": count,
        "window_days": window_days,
        "last_seen_days": last_seen_days,
        "statement": statement,   # LLM 프롬프트에 그대로 주입
    }
