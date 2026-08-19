"""사용자별 사용량. 신원은 Grafana 가 붙이는 헤더로 들어온다.

원본은 한 파일(`ask.py`, 1,289줄)이었다. 2026-08-19 에 옮기기만 했고
기능은 바꾸지 않았다.
"""

import logging
import re
from . import config

from .config import ANON, USER_MAX_CHARS
log = logging.getLogger("gateway.ask")


_USER_STRIP = re.compile(r"[\x00-\x1f\x7f]")


def who(header_value) -> str:
    """헤더 값을 계수에 쓸 이름으로 다듬는다.

    신원이 없으면 익명으로 **센다**. 안 세면 신원을 안 주는 쪽이 상한을 피해 간다.
    """
    name = _USER_STRIP.sub("", str(header_value or "")).strip()
    return name[:USER_MAX_CHARS] if name else ANON


def user_budget_ok(user: str, now: float = None) -> tuple:
    """이 사용자가 시간당 상한 안에 있는가. 반환 `(가능 여부, 사유)`."""
    from .. import store
    from . import MAX_PER_USER_HOUR as cap

    if cap <= 0:
        return True, ""
    used = store.calls_since(3600, now=now, kind="ask", user=user)
    if used >= cap:
        return False, ("한 시간에 %d회까지 물을 수 있다. 지금까지 %d회 썼다"
                       % (cap, used))
    return True, ""
