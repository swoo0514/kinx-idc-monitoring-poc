"""축약 — 축 원문을 고정 형태 기록 하나로 줄인다.

받는 것은 **소목표 한 줄과 그 축의 마스킹된 결과**뿐이다. 사건 서사도 다른 축도 가설도
핸드오프 이력도 주지 않는다 — LangChain 벤치마크에서 그 정리가 개선의 큰 몫이었고, 부수
효과로 한 축약 호출이 사건 전체를 못 본다(마스킹 표면 축소).
"""

import json
import logging

log = logging.getLogger("gateway.deep.condense")

AXES = ("metrics", "logs", "security", "history")

# 축마다 보는 것이 다르다 — FORGE 모달리티 민감도(지표는 위치, 로그는 유형)
SUBGOAL = {
    "metrics": "평소 대비 어느 지표가 얼마나 다른가",
    "logs": "평소 대비 무엇이 다른가",
    "security": "침해로 볼 신호가 있는가",
    "history": "같은 문제를 전에 어떻게 판단했는가",
}

# 조회 상태 넷. 뒤 셋은 "못 봤다"이지 "없었다"가 아니다.
STATUSES = ("ok", "unavailable", "disabled", "unmatched")


def adapters(kind: str = "condense") -> list:
    """축약 전용 체인. **`llm._adapters()` 와 섞지 않는다.**

    섞으면 Claude 가 죽는 순간 트리아지 판단 프롬프트가 값싼 모델로 넘어간다. 여기서
    Luna 가 앞이고 haiku 가 뒤인 것은 열화 경로다 — 키가 없거나 죽어도 축약은 돌아야 한다.
    """
    from .. import llm
    from ..integrations import openai_luna

    return [openai_luna.LunaAdapter(kind=kind), llm.ClaudeAdapter(kind=kind)]


def parse(text: str, axis: str, record_id: str):
    """축약 결과를 고정 형태로. 스키마 밖이면 **폐기한다** — 지어낸 칸을 쓰지 않는다.

    반환 `(기록, 사유)`. 기록이 None 이면 그 축은 이번 라운드에 결과가 없는 것으로 둔다.
    """
    raw = (text or "").strip()
    if raw.startswith("```"):
        raw = raw.strip("`")
        raw = raw.split("\n", 1)[-1] if "\n" in raw else raw
    try:
        got = json.loads(raw)
    except Exception as e:
        return None, "형태를 못 읽었다: %s" % e
    if not isinstance(got, dict):
        return None, "사전이 아니다"

    st = str(got.get("status") or "").strip()
    if st not in STATUSES:
        return None, "모르는 조회 상태: %r" % st

    ev = [str(x) for x in (got.get("evidence") or []) if str(x).strip()][:3]
    rec = {
        "id": record_id,
        "axis": axis,
        "subgoal": SUBGOAL.get(axis, ""),
        "status": st,
        "baseline_status": (str(got.get("baseline_status") or "").strip()
                            if str(got.get("baseline_status") or "").strip() in
                            ("ok", "unavailable") else "unavailable"),
        "origin": ("monitoring" if str(got.get("origin") or "") == "monitoring"
                   else "application"),
        "t_first": int(got.get("t_first") or 0),
        "t_last": int(got.get("t_last") or 0),
        "baseline": str(got.get("baseline") or "").strip(),
        "finding": str(got.get("finding") or "").strip(),
        "evidence": ev,
        "units": str(got.get("units") or "").strip() or "—",
        "not_determined": str(got.get("not_determined") or "").strip(),
    }
    if not rec["finding"]:
        return None, "찾은 것이 비었다"
    return rec, ""
