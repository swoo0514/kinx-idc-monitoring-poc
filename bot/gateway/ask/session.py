"""세션 역치환 표와 멈춤. 사람 구분은 §32-3.

원본은 한 파일(`ask.py`, 1,289줄)이었다. 2026-08-19 에 옮기기만 했고
기능은 바꾸지 않았다.
"""

import logging
import threading
import time
from .. import masking, proxy
from . import config

from .config import ANON, SESSION_TTL_S
log = logging.getLogger("gateway.ask")


_sessions: dict = {}     # sid -> {"rev": {토큰: 원문}, "at": 단조시각}


_cancelled: dict = {}    # 세션 -> 멈춤을 누른 단조시각. 다음 라운드에서 확인한다.


_lock = threading.Lock()


def _now() -> float:
    return time.monotonic()


def session_masker(sid: str) -> masking.Masker:
    """이번 요청의 이름 표 + 이 세션이 이미 발행한 토큰을 합친 마스커.

    이름 표는 1시간마다 다시 만들어진다. 대화 도중 갱신되면 앞 턴에 발행한 토큰이
    표에서 사라져 역치환이 안 되고, 사람은 회신에서 토큰 문자열을 그대로 받는다.
    합집합으로 그 구멍을 메운다.
    """
    mk = proxy.build_masker()
    prune_sessions()
    with _lock:
        sess = _sessions.get(sid)
        old = dict(sess["rev"]) if sess else {}
    for tok, name in old.items():
        # 표에 살아 있는 이름이 우선이다. 세션 값은 빠진 것만 메운다.
        if tok not in mk._rev:
            mk._rev[tok] = name
            mk._fwd.setdefault(name, tok)
    mk._re = None
    return mk


def remember(sid: str, mk: masking.Masker) -> int:
    """이번 턴에 발행한 토큰을 세션에 쌓는다. 반환은 세션이 들고 있는 총 개수."""
    with _lock:
        sess = _sessions.setdefault(sid, {"rev": {}, "at": _now()})
        sess["rev"].update(mk._rev)
        sess["at"] = _now()
        return len(sess["rev"])


def prune_sessions(now: float = None) -> int:
    """오래된 세션을 지운다. 반환은 지운 개수."""
    now = _now() if now is None else now
    with _lock:
        dead = [k for k, v in _sessions.items() if now - v["at"] > SESSION_TTL_S]
        for k in dead:
            del _sessions[k]
    prune_cancels(now)
    return len(dead)


def session_key(sid: str, user: str = "") -> str:
    """이 요청이 속한 세션의 열쇠.

    **화면이 보낸 이름만으로 나누지 않는다.** 화면은 새 대화의 첫 턴에 `'ui'` 를 보내므로
    그 값만 쓰면 모든 사람이 한 세션이 된다. 그러면 한 사람의 멈춤이 남의 질문을 끊고,
    역치환 표도 섞인다(2026-08-19 감사, 네 갈래가 같은 결론).
    """
    return "%s|%s" % (str(user or ANON), str(sid or "-"))


def cancel(sid: str) -> None:
    """사람이 멈춤 단추를 눌렀다. 다음 라운드에서 멈춘다.

    지금 도는 조회를 중간에 끊지는 않는다. 끊어도 이미 나간 호출의 비용은 그대로이고,
    받아 놓은 것을 버리면 사람에게 남는 것이 없다.
    """
    with _lock:
        _cancelled[str(sid or "-")] = _now()


def cancelled(sid: str, started: float) -> bool:
    """이 요청을 멈춰야 하는가. 맞으면 표시를 지우고 True.

    **요청이 시작된 뒤에 눌린 것만 인정한다.** 답이 끝난 뒤 도착한 멈춤을 그대로 두면
    다음 질문이 조회 한 번 못 하고 죽는다(2026-08-19 감사 C-3).
    """
    key = str(sid or "-")
    with _lock:
        at = _cancelled.get(key)
        if at is None:
            return False
        if at < float(started):          # 이미 지난 취소다
            del _cancelled[key]
            return False
        del _cancelled[key]
        return True


def prune_cancels(now: float = None) -> int:
    """오래된 취소 표시를 지운다. 반환은 지운 개수."""
    now = _now() if now is None else now
    with _lock:
        dead = [k for k, at in _cancelled.items() if now - at > SESSION_TTL_S]
        for k in dead:
            del _cancelled[k]
    return len(dead)


def forget_all() -> None:
    with _lock:
        _sessions.clear()
        _cancelled.clear()
