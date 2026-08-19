"""질의가 닿을 수 있는 감시 영역. 호출자가 신고한 값은 쓰지 않는다(§27-3).

원본은 한 파일(`ask.py`, 1,289줄)이었다. 2026-08-19 에 옮기기만 했고
기능은 바꾸지 않았다.
"""

import logging
import os
from .. import registry

from .config import DEFAULT_ALLOWED_REALMS
log = logging.getLogger("gateway.ask")


def allowed_realms() -> list:
    """질의가 닿을 수 있는 영역. 환경변수를 매번 읽는다 — 재기동 없이 좁힐 수 있어야 한다."""
    raw = os.environ.get("ASK_ALLOWED_REALMS", DEFAULT_ALLOWED_REALMS)
    return [r.strip() for r in raw.split(",") if r.strip()]


def target_allowed(source: str, host: str = "") -> tuple:
    """이 대상을 질의가 조회해도 되는가. 반환 `(허용 여부, 사유)`.

    **호출자가 신고한 값은 쓰지 않는다.** 영역은 명부와 환경변수로만 정해진다.
    `registry.realm()` 은 아무것도 안 적혔을 때 소스 이름을 그대로 돌려주므로, 영역을
    기재하지 않은 감시 서버는 허용 목록에 없는 값이 되어 **자동으로 막힌다.** 설정을
    빠뜨린 사람이 가장 위험해지면 안 된다.
    """
    from .. import incident     # 순환 참조를 피해 쓰는 자리에서 들여온다

    rlm = registry.realm(source, host, incident.REALM_MAP)
    allowed = allowed_realms()
    if rlm in allowed:
        return True, ""
    return False, ("감시 영역 %r 은 질의 대상이 아니다 (허용: %s)"
                   % (rlm or "미상", ", ".join(allowed) or "없음"))


def allowed_sources() -> list:
    """질의가 물어도 되는 감시 서버 이름들."""
    return [n for n in registry.source_names() if target_allowed(n)[0]]
