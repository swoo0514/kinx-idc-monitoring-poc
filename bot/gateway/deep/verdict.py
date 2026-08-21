"""종합이 가설표와 어긋나지 않는가 — 근거 없는 결론을 표시한다.

랩 실증 단계 3 에서 종합이 아직 안 갈린 가설(H1·H3)을 "공동으로 작용했을 가능성이 높습니다"로
결론에 올렸다. 근거가 없다는 것은 본문에서 스스로 밝혔으나 결론 문장에는 남았다.

문헌이 권하는 방식은 근거 없는 주장을 되돌리거나 표시하는 쪽이다. 우리는 **답을 버리지 않고
코드가 확인한 상태를 덧붙인다** — 조사 결과에는 사람이 다음에 무엇을 볼지 정할 재료가 들어
있고, 통째로 막으면 그 재료까지 사라진다. 무엇을 믿을지는 사람이 고른다.
"""

import re

# 가설 id 의 모양. 기록 id(`metrics#1`)와 달리 `#` 가 없다.
_ID = re.compile(r"(?<![A-Za-z0-9])(H[0-9]+)(?![0-9])")

# 이 낱말과 함께 나오면 "밝혀 두는 것"이지 원인으로 내세우는 것이 아니다.
_CLEARED = ("기각", "배제", "아니", "제외", "부정")


def cited(text: str) -> list:
    """글에 등장한 가설 id."""
    seen, out = set(), []
    for m in _ID.finditer(str(text or "")):
        if m.group(1) not in seen:
            seen.add(m.group(1))
            out.append(m.group(1))
    return out


def ungrounded(text: str, table: list) -> list:
    """원인으로 내세웠는데 아직 안 갈린 가설.

    기각을 밝히는 문장은 세지 않는다 — 기각한 것을 적는 것은 요구 사항이다.
    """
    status = {h.get("id"): (h.get("status") or "미결") for h in (table or [])}
    body = str(text or "")
    bad = []
    for hid in cited(body):
        if status.get(hid) != "미결":
            continue
        near = " ".join(ln for ln in body.splitlines() if hid in ln)
        if any(w in near for w in _CLEARED):
            continue
        bad.append(hid)
    return bad


def annotate(text: str, bad: list) -> str:
    """코드가 확인한 상태를 글 끝에 덧붙인다."""
    if not bad:
        return text
    return (str(text or "").rstrip() + "\n\n"
            + "> 코드 확인: " + ", ".join(bad)
            + " 는 아직 **미결**이다. 지지하는 관측 기록이 없으므로 원인으로 확정하지 말 것.")
