"""답 조립·시스템 문구·손잡이 정리(§27-4).

원본은 한 파일(`ask.py`, 1,289줄)이었다. 2026-08-19 에 옮기기만 했고
기능은 바꾸지 않았다.
"""

import functools
import logging
import os
import re
from . import config

from .config import ASK_SYSTEM, NO_EVIDENCE
log = logging.getLogger("gateway.ask")


@functools.lru_cache(maxsize=1)
def load_facts() -> str:
    """지식 조각을 한 덩어리 글로 읽는다. 못 읽으면 빈 문자열.

    YAML 로 적되 파서를 쓰지 않는다. 값이 전부 여러 줄 글이고, 우리가 하는 일은
    그것을 이어 붙이는 것뿐이라 의존성을 늘릴 이유가 없다.
    """
    try:
        # **패키지에서 읽는다.** 밖에서 갈아 끼운 경로가 여기서도 보여야 한다.
        from . import FACTS_FILE as path
        with open(path, encoding="utf-8") as f:
            raw = f.read()
    except OSError as e:
        log.warning("관측 지식 조각을 못 읽었다(%s) — 없이 진행한다", e)
        return ""
    out = []
    for line in raw.splitlines():
        if line.startswith("#") or not line.strip():
            continue
        out.append(line.rstrip().lstrip("|").rstrip("|") if line.endswith("|") else line)
    return chr(10).join(x for x in out if x.strip()).strip()


# 그림 손잡이. 화면은 그림을 따로 그리므로 본문에 남으면 지저분한 글자일 뿐이다.
_HANDLE_RE = re.compile(r"\[?img-[0-9a-z]+\]?")


_MD_IMAGE_RE = re.compile(r"!\[[^\]]*\]\(\s*\[?img-[0-9a-z]+\]?\s*\)")


def chosen_images(images: list, answer: dict) -> list:
    """화면에 붙일 그림. 답이 고른 것만 붙인다.

    답 도구를 안 쓰고 글로 끝낸 경우에는 만든 것을 전부 붙인다. 예전 동작이다.
    """
    picked = (answer or {}).get("image_ids")
    if not answer or picked is None:
        return images
    keep = set(picked)
    return [im for im in images if im.get("id") in keep]


def render_answer(args: dict, had_evidence: bool = True) -> str:
    """답 도구의 필드를 사람이 읽는 글로. 손잡이와 구간을 산문에서 뺀 대가로 여기서 만든다.

    **근거가 하나도 없으면 그 사실을 붙인다.** 2026-08-19 랩 실측으로 모델이 인자를
    깨뜨려 보내 도구가 전부 거부했는데도 "그 시간대 로그가 없습니다" 로 답을 닫았다.
    사람에게는 조회가 된 것처럼 보인다. 판정은 코드가 한다 — 성공한 조회가 있었는지는
    세면 되는 값이다.
    """
    a = args or {}
    parts = [str(a.get("summary") or "").strip()]
    for f in (a.get("findings") or []):
        line = str(f).strip()
        if line:
            parts.append("- " + line)
    win = str(a.get("window_utc") or "").strip()
    if win:
        parts.append("조회 구간: " + win)
    if not had_evidence:
        parts.append(NO_EVIDENCE)
    return (chr(10)).join(p for p in parts if p)


def with_evidence_note(text: str, trace: list, ok_count: int) -> str:
    """근거가 하나도 없으면 그 사실을 붙인다.

    답 도구를 안 쓰고 산문으로 끝내는 길이 남아 있다. 그 길로 나가도 사실은 같다 —
    조회가 전부 실패했는데 "없습니다" 로 닫히면 사람에게는 조회가 된 것처럼 보인다.
    """
    if not text or not trace or int(ok_count) > 0:
        return text
    if NO_EVIDENCE in text:
        return text
    return text + chr(10) + NO_EVIDENCE


def strip_handles(text: str) -> str:
    """답에서 그림 손잡이를 걷어 낸다. 앞뒤 공백도 정리한다."""
    # 마크다운 그림 표기는 통째로 걷어 낸다. 손잡이만 빼면 `![image]()` 가 남아
    # 화면에 "!(image)" 로 찍힌다(2026-08-18 실측). 그림은 따로 붙는다.
    out = _MD_IMAGE_RE.sub("", str(text or ""))
    out = _HANDLE_RE.sub("", out)
    # 손잡이가 괄호 안에 있었으면 빈 괄호가 남는다 — "패널()의" 가 화면에 그대로
    # 나왔다(2026-08-18 실측).
    out = re.sub(r"\(\s*\)|\[\s*\]", "", out)
    out = re.sub(r"[ \t]{2,}", " ", out)
    out = re.sub(r"[ \t]+([,.!?)\]])", r"\1", out)
    return re.sub(r"\n{3,}", "\n\n", out).strip()


def system_prompt() -> str:
    """모델에 줄 지시문. 기본 규칙 뒤에 우리 환경의 사실을 붙인다.

    규칙 본문은 `bot/prompts/ask.md` 에서 읽는다. 파일이 없으면 아래 상수로 돈다.
    """
    from .. import prompts
    base = prompts.load("ask", ASK_SYSTEM)
    facts = load_facts()
    if not facts:
        return base
    return base + (chr(10) * 2) + "[이 환경의 사실]" + chr(10) + facts


def _blocks_text(content) -> str:
    return "\n".join(b.get("text", "") for b in (content or [])
                     if isinstance(b, dict) and b.get("type") == "text").strip()


def stall_note(stopped: str, trace: list) -> str:
    """상한에 걸렸을 때 사람에게 하는 말.

    조회를 하나도 못 했으면 "조회한 것: 없음" 은 사람에게 아무 도움이 안 된다. 그 경우는
    대개 모델 응답이 늦은 것이다(2026-08-18 실측: 한 호출이 96초). 무엇을 하라는 말까지
    적는다.
    """
    if not trace:
        if stopped == "deadline":
            return "모델 응답이 늦어 조회를 시작하지 못했다. 다시 물어보라."
        return "조회를 시작하지 못한 채 상한(%s)에 닿았다. 다시 물어보라." % stopped
    return ("여기까지 확인했고 상한(%s)에 닿아 멈췄다. 조회한 것: %s"
            % (stopped, ", ".join(t["tool"] for t in trace)))
