"""프롬프트를 파일에서 읽는다. 근거와 문구 목록은 bot/GATEWAY_GUIDE.md §29."""

import logging
import os

log = logging.getLogger("gateway.prompts")

PROMPT_DIR = os.environ.get(
    "PROMPT_DIR",
    os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "prompts"))

_cache: dict = {}


def forget() -> None:
    """읽어 둔 것을 버린다. 검사에서만 쓴다."""
    _cache.clear()


def load(name: str, fallback: str = "") -> str:
    """`<PROMPT_DIR>/<name>.md` 를 읽는다. 못 읽으면 예비 문구."""
    if name in _cache:
        return _cache[name]
    path = os.path.join(PROMPT_DIR, "%s.md" % name)
    try:
        with open(path, encoding="utf-8") as f:
            text = f.read().strip()
    except OSError as e:
        log.info("프롬프트 파일을 안 썼다(%s) — 코드에 있는 문구로 돈다", e)
        text = fallback
    if not text:
        text = fallback
    _cache[name] = text
    return text
