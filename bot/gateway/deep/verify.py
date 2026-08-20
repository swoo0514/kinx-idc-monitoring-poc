"""종합을 내보내기 전 코드가 보는 것 — 시간 순서·인용 실재·위험 명령.

FORGE 실패 분류 중 코드가 판정할 수 있는 것만 여기서 막는다. 판정할 수 없는 것(파생 수치
대조 등)은 프롬프트 규칙과 경고 로그로 낮춘다 — 하드 게이트로 만들면 정당한 서술까지 막는다.
"""

import logging

log = logging.getLogger("gateway.deep.verify")


def time_ok(cause: dict, effect: dict) -> bool:
    """인과 방향이 시간을 위반하지 않는가 (RF-04).

    **발단 순서로 본다.** 원인의 마지막 관측이 결과보다 앞서야 한다고 쓰면 지속되는 원인을
    거부한다 — 우리 대표 시나리오가 정확히 그것이다(백업 부하는 지연이 커지는 내내 돈다).
    시각을 모르면(0) 막지 않는다. 근거 없이 기각하지 않는다는 이 리포의 규칙 그대로다.
    """
    a = int((cause or {}).get("t_first") or 0)
    b = int((effect or {}).get("t_first") or 0)
    if not a or not b:
        return True
    return a <= b
