"""가설표 — 세우고, 인용을 검사하고, 반증에 따라 고치고, 언제 끝났는지 판정한다.

설계와 문헌 근거는 private/docs/deep_mode_design.md. 여기 있는 규칙은 전부 코드가 판정하는
것이고, 모델은 가설의 내용만 만든다.
"""

import logging

log = logging.getLogger("gateway.deep.hypothesis")

# 조회에 성공한 기록만 근거가 된다. 나머지 셋은 "못 봤다"이지 "없었다"가 아니다.
EVIDENCE_OK = "ok"

# "위 어느 것도 아니다". 코드가 만들고, 인용 요건·머릿수·미결 판정에서 모두 빠진다.
NULL_ID = "H0"

STATUS = ("미결", "지지", "기각")
DONE_DECIDED = "판가름"
DONE_JOINT = "공동원인"
DONE_STUCK = "못가름"


def null_hypothesis() -> dict:
    """다른 가설이 전부 기각됐을 때의 답. 덜 기각된 것을 고르지 않게 하려고 상시 둔다."""
    return {"id": NULL_ID, "claim": "위 어느 것도 아니다 — 제시된 가설로는 설명되지 않는다",
            "if_true": "", "if_false": "", "supports": [], "contradicts": [],
            "status": "미결"}


def is_null(h: dict) -> bool:
    return (h or {}).get("id") == NULL_ID


def validate(h: dict, records: dict):
    """가설이 실재하는 기록만 인용했는가. 반환 `(통과, 사유)`."""
    if is_null(h):
        return True, ""
    missing = [r for r in (list(h.get("supports") or []) + list(h.get("contradicts") or []))
               if r not in (records or {})]
    if missing:
        return False, "없는 기록을 인용했다: %s" % ", ".join(sorted(missing))
    if not str(h.get("claim") or "").strip():
        return False, "주장이 비었다"
    return True, ""


def count_real(table: list) -> int:
    """H0 를 뺀 실질 가설 수. '둘 이상'은 이 수로 센다."""
    return sum(1 for h in (table or []) if not is_null(h))


def open_count(table: list) -> int:
    """미결 가설 수. H0 는 세지 않는다 — 세면 루프가 영영 안 끝난다."""
    return sum(1 for h in (table or [])
               if not is_null(h) and h.get("status") == "미결")


def enough(table: list) -> bool:
    """가설이 둘 이상인가 (RF-13 앵커링)."""
    return count_real(table) >= 2


def transition(cur: str, want: str, record_id: str, records: dict):
    """상태를 바꿔도 되는가. 반환 `(허용, 사유)`.

    **조회 실패로는 아무것도 기각하지 못한다** — `unavailable`·`disabled`·`unmatched` 는
    "못 봤다"이지 "없었다"가 아니다 (RF-08, 알림 경로 G1 계약의 확장).
    """
    if want not in STATUS:
        return False, "모르는 상태: %r" % want
    rec = (records or {}).get(record_id)
    if not rec:
        return False, "없는 기록을 근거로 들었다: %r" % record_id
    st = rec.get("status")
    if st != EVIDENCE_OK:
        return False, "조회 상태가 %s 라 근거로 쓸 수 없다" % st
    return True, ""


def stale_belief(h: dict) -> bool:
    """반증을 받고도 상태가 그대로인가 (RF-09 신념 미갱신)."""
    return bool(h.get("contradicts")) and h.get("status") == "지지"


def done(table: list, probes_left: bool):
    """끝났는가. 반환 `(사유, 설명)`. 사유가 빈 문자열이면 계속한다."""
    real = [h for h in (table or []) if not is_null(h)]
    sup = [h for h in real if h.get("status") == "지지"]
    opened = [h for h in real if h.get("status") == "미결"]

    if len(sup) == 1 and not opened:
        return DONE_DECIDED, "하나가 지지되고 나머지가 기각됐다"
    if not sup and not opened and real:
        # 전부 기각 — H0 가 답이다
        return DONE_DECIDED, "제시된 가설이 전부 기각됐다"
    if len(sup) >= 2 and not opened:
        # 복합 원인. 여기서 안 끝나면 대표 사건(복제 경합)이 영영 안 끝난다.
        return DONE_JOINT, "둘 이상이 지지됐다 — 공동 원인으로 서술한다"
    if not probes_left:
        return DONE_STUCK, "남은 질의가 어느 가설도 가르지 못한다"
    return "", ""


def winner(table: list):
    """답이 될 가설 id. 공동 원인이면 None — 하나로 좁히지 않는다."""
    real = [h for h in (table or []) if not is_null(h)]
    sup = [h for h in real if h.get("status") == "지지"]
    if len(sup) == 1:
        return sup[0].get("id")
    if not sup and real and all(h.get("status") == "기각" for h in real):
        return NULL_ID
    return None
