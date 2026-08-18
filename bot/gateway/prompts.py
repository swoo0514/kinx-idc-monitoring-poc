"""프롬프트를 파일에서 읽는다. 근거와 문구 목록은 bot/GATEWAY_GUIDE.md §28.

코드를 안 건드리고 문구만 고칠 수 있게 한다. 동기분 코드(aiops-rca-orchestrator)는
노드마다 프롬프트를 `.md` 한 장으로 둔다.

두 가지를 지킨다.

**파일이 없다고 기동을 막지 않는다.** 배포에서 파일 하나가 빠졌다고 봇 전체가 죽는 것이
문구가 조금 옛것인 것보다 나쁘다. 못 읽으면 코드에 있는 예비 문구로 돈다.

**실행 중에 다시 읽지 않는다.** 프롬프트는 캐시 접두사의 일부다. 도중에 바뀌면 그때까지
쌓인 캐시가 통째로 무효가 되고, 같은 대화 안에서 앞뒤 문구가 달라진다.
"""

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
