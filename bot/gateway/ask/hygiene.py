"""질문 위생과 이력 자르기 — 가릴 수 없으면 보내지 않는다(§27-1).

원본은 한 파일(`ask.py`, 1,289줄)이었다. 2026-08-19 에 옮기기만 했고
기능은 바꾸지 않았다.
"""

import logging
import re
from .. import masking
from . import config

from .config import HISTORY_MAX_CHARS, HISTORY_MAX_MSGS, QUESTION_MAX_CHARS
log = logging.getLogger("gateway.ask")


# 줄바꿈과 탭만 남기고 지운다. 프롬프트 구조를 흉내 내는 입력을 막는다.
_CTRL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def sanitize_question(text: str, mk: masking.Masker) -> dict:
    """질문 문자열을 보낼 수 있는 형태로 만든다.

    반환 `{"ok": bool, "text": str, "reason": str}`.

    **가린 뒤에도 아는 이름이 남으면 보내지 않고 거절한다.** 과거 결론 본문은 버려도
    나머지 근거가 남지만(`masking._prior_item`), 질문을 버리면 요청 자체가 뜻을 잃는다.
    그리고 이름 표의 통제 범위는 호스트명·그룹명·IP 뿐이라(§23-7) 계정명·경로·티켓번호는
    애초에 안 가려진다. 조용히 내보내는 것보다 사람에게 되묻는 편이 낫다.
    """
    raw = _CTRL_RE.sub("", str(text or "")).strip()
    if not raw:
        return {"ok": False, "text": "", "reason": "질문이 비어 있다"}
    # **가릴 수 없으면 안 보낸다.** 표가 비면 아는 이름이 없어 누수 검사가 통과해 버린다.
    # 프록시 경로는 같은 상황을 이미 막는데 질의 경로에는 그 게이트가 없었다(2026-08-19).
    if masking.cannot_mask(mk):
        return {"ok": False, "text": "",
                "reason": ("이름 표가 비어 이름을 가릴 수 없다. 감시 서버 연결을 확인하라 "
                           "(가림 없이 보내려면 PROXY_ALLOW_UNMASKED=1)")}
    if len(raw) > QUESTION_MAX_CHARS:
        return {"ok": False, "text": "",
                "reason": "질문 길이가 %d자를 넘는다 (%d자)" % (QUESTION_MAX_CHARS, len(raw))}
    masked = mk.mask(raw)
    if masking._leaks(masked):
        log.warning("질문에 가려지지 않은 이름이 남아 보내지 않는다")
        return {"ok": False, "text": "",
                "reason": "질문에 가려지지 않은 이름이나 주소가 남아 있다. "
                          "그 부분을 빼고 다시 물어달라"}
    return {"ok": True, "text": masked, "reason": ""}


def trim_history(history) -> tuple:
    """이력을 창 안으로 자른다. 반환 `(자른 이력, 버렸는가)`.

    최신 것을 먼저 지키고 오래된 것부터 버린다. 개수와 글자 수 두 상한을 함께 보는
    이유는, 짧은 턴이 많은 대화와 긴 답이 몇 개인 대화가 서로 다른 방식으로 커지기
    때문이다.

    **버린 사실을 알린다.** 조용히 버리면 모델이 앞 대화를 다 기억한다고 여기고
    "아까 말한 그 호스트" 같은 말을 근거로 쓴다.
    """
    msgs = [m for m in (history or [])
            if isinstance(m, dict) and m.get("role") in ("user", "assistant")
            and isinstance(m.get("content"), str)]
    kept, chars = [], 0
    for m in reversed(msgs):
        if len(kept) >= HISTORY_MAX_MSGS or chars + len(m["content"]) > HISTORY_MAX_CHARS:
            break
        kept.append(m)
        chars += len(m["content"])
    kept.reverse()
    return kept, len(kept) < len(msgs)
