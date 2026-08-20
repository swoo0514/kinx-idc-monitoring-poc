"""심층 조사 상태 — 노드 사이를 오가는 값과 그 불변식.

`ask/graph.py` 의 규율을 그대로 따른다. 상태 검사는 어긋나도 예외를 던지지 않고
`stopped="invalid_state"` 로 내려간다 — 사람이 이유 대신 스택을 보면 안 된다.
"""

# 멈출 수 있는 이유. 모르는 값이 화면에 나가면 사람이 해석할 수 없다.
# 앞 셋은 조사가 제 할 일을 한 것이고, 뒤 넷은 안전망이다.
STOP_REASONS = frozenset((
    "",
    "판가름", "공동원인", "못가름",          # 의미 있는 종료 (hypothesis.done)
    "rounds", "deadline", "budget",          # 세는 상한 — 안전망
    "llm_failed", "cancelled", "invalid_state", "no_evidence",
))


def new_state(incident: dict, records: dict) -> dict:
    """조사가 끝난 직후의 첫 상태."""
    return {"incident": dict(incident or {}), "records": dict(records or {}),
            "table": [], "steps": [], "seen": [], "probes": [],
            "round": 0, "spent": 0, "stopped": "", "error": "", "answer": ""}


def check(state: dict) -> str:
    """앞뒤가 맞는가. 어긋나면 사람이 읽을 사유, 맞으면 빈 문자열."""
    from . import hypothesis as H

    if str(state.get("stopped") or "") not in STOP_REASONS:
        return "모르는 멈춤 사유다: %r" % state.get("stopped")
    if int(state.get("round") or 0) < 0 or int(state.get("spent") or 0) < 0:
        return "라운드나 쓴 바이트가 음수다"

    table = state.get("table") or []
    ids = [h.get("id") for h in table]
    if len(ids) != len(set(ids)):
        return "같은 가설 id 가 두 번 있다"

    records = state.get("records") or {}
    for h in table:
        if H.is_null(h):
            continue
        for rid in (list(h.get("supports") or []) + list(h.get("contradicts") or [])):
            if rid not in records:
                return "가설 %s 가 없는 기록 %s 를 인용한다" % (h.get("id"), rid)
        if H.stale_belief(h):
            return "가설 %s 가 반증을 받고도 지지로 남아 있다" % h.get("id")

    # 지문 표가 던진 질의보다 많으면 어딘가에서 기록이 빠졌다
    if len(state.get("seen") or []) > len(state.get("probes") or []):
        return "질의 기록(%d)보다 지문 표(%d)가 많다" % (
            len(state.get("probes") or []), len(state.get("seen") or []))
    return ""
