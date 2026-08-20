"""정상 구간 — "평소는 어땠나"를 함께 가져온다.

AgentRCA 절제 실험에서 **이것을 빼면 Top-1 이 87.6% → 40.6%** 로 무너졌다. 어떤 절제보다
큰 폭이었다. 우리 봇이 "iowait 80%"라고 말할 때 평소가 5%인지 60%인지 모르는 채로 말하고
있었다는 뜻이다.

**전이 근거는 유추다.** 그쪽은 화학 공정 데이터(설정점으로 정상이 정의됨)이고 우리는 IT
인프라다. 방향만 가져오고 효과는 랩 실측으로 확인한다.
"""

import logging

log = logging.getLogger("gateway.deep.baseline")

# 정상 창을 언제로 잡을까. 같은 요일·같은 시간대여야 주중/주말과 야간 배치가 섞이지 않는다.
OFFSET_S = 7 * 86400

BASELINE_OK = "ok"
BASELINE_UNAVAILABLE = "unavailable"


def window(start: int, end: int, offset_s: int = OFFSET_S):
    """사건 창에 대응하는 정상 창 `(시작, 끝)`."""
    return int(start) - int(offset_s), int(end) - int(offset_s)


def force_trend(start: int, end: int) -> bool:
    """이 창을 추세로 받아야 하는가.

    **`use_trend` 는 창의 길이로만 판정한다.** 그래서 7일 전 1시간 창은 이력 조회로 가고,
    보관 기간이 짧은 아이템이면 **빈 목록이 조회 성공으로 온다.** 그걸 "평소엔 없었다"로
    읽으면 사건 값이 전부 이상으로 보인다 — 우리가 자랑하는 조회 상태 계약이 정확히
    놓치는 경로다. 그래서 나이로도 판정한다.
    """
    from ..ask import tools as asktools

    import time
    age = time.time() - int(end)
    return asktools.use_trend(start, end) or age > asktools.TREND_FROM_S


def status_of(points: list, queried_ok: bool) -> str:
    """정상 창이 근거로 쓸 만한가. **축 상태와 따로 싣는다.**

    사건 창 조회가 성공했어도 정상 창이 비었으면 비교를 못 한다. 둘을 한 값으로 뭉치면
    "평소엔 없었다"와 "평소를 못 봤다"가 같아진다.
    """
    if not queried_ok:
        return BASELINE_UNAVAILABLE
    return BASELINE_OK if points else BASELINE_UNAVAILABLE


def direction(now_v, base_v):
    """방향성 한 마디. 절제 실험에서 이것만 빼도 43.8% 로 떨어졌다.

    수치를 지어내지 않는다 — 둘 중 하나라도 없으면 빈 문자열이다.
    """
    try:
        a, b = float(now_v), float(base_v)
    except (TypeError, ValueError):
        return ""
    if b == 0:
        return "평소 0 에서 %g 로" % a if a else ""
    r = a / b
    if r >= 1.5:
        return "평소의 %.1f배" % r
    if r <= 0.67:
        return "평소의 %.0f%%" % (r * 100)
    return "평소와 비슷"
