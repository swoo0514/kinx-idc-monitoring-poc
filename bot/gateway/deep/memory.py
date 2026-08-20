"""구조화 기억 — 매 라운드 **두 메시지로 다시 만든다.** 대화를 쌓지 않는다.

우리가 실측한 낭비가 프롬프트 0.4K → 29.9K 누적이었다(2026-08-20). 원인은 라운드마다 이전
대화와 도구 결과를 그대로 다시 실어 보낸 것이다. 그래서 여기서는 계획자에게 갈 것을 **매번
새로 조립**한다 — 시스템 문구(고정, 캐시)와 사용자 메시지 한 개.

칸은 넷이다(Żywot 구조화 기억): 사건 요약 · 가설표 · 축 기록 · 발자취.
"""

import json
import logging

log = logging.getLogger("gateway.deep.memory")

# 축 기록의 원문 증거는 요약이 못 담는 수치를 남기는 자리다. 너무 길면 프롬프트가 다시
# 부풀므로 줄 수와 길이를 함께 제한한다.
EVIDENCE_MAX_LINES = 3
EVIDENCE_MAX_CHARS = 300


def _record_line(rec: dict) -> str:
    """축 기록 한 줄. **`finding` 은 재서술 없이 그대로 옮긴다**(LangChain 개선 2번)."""
    r = rec or {}
    head = "[%s] %s (%s" % (r.get("id"), r.get("finding"), r.get("status"))
    if r.get("baseline_status") == "unavailable":
        head += ", 평소값 없음"
    if r.get("origin") == "monitoring":
        head += ", 감시 인프라"
    if r.get("units") and r.get("units") != "—":
        head += ", 단위 %s" % r.get("units")
    head += ")"

    out = [head]
    if r.get("baseline"):
        out.append("  평소 대비: %s" % r["baseline"])
    for line in (r.get("evidence") or [])[:EVIDENCE_MAX_LINES]:
        out.append("  근거: %s" % str(line)[:EVIDENCE_MAX_CHARS])
    if r.get("not_determined"):
        out.append("  이 축으로 알 수 없는 것: %s" % r["not_determined"])
    return "\n".join(out)


def _hypothesis_line(h: dict) -> str:
    from . import hypothesis as H

    if H.is_null(h):
        return "- %s: %s [%s]" % (h.get("id"), h.get("claim"), h.get("status"))
    bits = ["- %s [%s] %s" % (h.get("id"), h.get("status"), h.get("claim"))]
    if h.get("if_true"):
        bits.append("    참이면: %s" % h["if_true"])
    if h.get("if_false"):
        bits.append("    거짓이면: %s" % h["if_false"])
    if h.get("supports"):
        bits.append("    지지: %s" % ", ".join(h["supports"]))
    if h.get("contradicts"):
        bits.append("    반증: %s" % ", ".join(h["contradicts"]))
    return "\n".join(bits)


def render(state: dict) -> str:
    """계획자에게 보낼 사용자 메시지. **누적이 아니라 재구성이다.**"""
    inc = state.get("incident") or {}
    parts = []

    # ① 사건 요약 — 코드가 정한 값이라 라운드마다 안 바뀐다
    head = ["[사건]",
            "대상: %s" % inc.get("host", "?"),
            "알림: %s" % ", ".join(inc.get("names") or []) or "-",
            "분류: %s" % ", ".join(inc.get("classes") or []) or "-",
            "심각도: %s" % inc.get("sev", "?")]
    if inc.get("verdict"):
        head.append("선판정: %s — %s" % (inc["verdict"], inc.get("statement", "")))
    if inc.get("scope"):
        head.append("계약 범위: %s" % inc["scope"])
    parts.append("\n".join(head))

    # ② 축 기록 — 조사와 검증이 모은 것
    recs = state.get("records") or {}
    if recs:
        body = "\n".join(_record_line(recs[k]) for k in sorted(recs))
        parts.append("[관측]\n" + body)

    # ③ 가설표
    table = state.get("table") or []
    if table:
        parts.append("[가설]\n" + "\n".join(_hypothesis_line(h) for h in table))

    # ④ 발자취 — 무엇을 왜 봤는지. **이미 본 축을 또 묻지 않게 하는 재료다.**
    steps = state.get("steps") or []
    if steps:
        parts.append("[지금까지]\n" + "\n".join("- %s" % s for s in steps))

    parts.append("[라운드] %d" % int(state.get("round") or 0))
    return "\n\n".join(parts)


def add_step(state: dict, text: str) -> None:
    state.setdefault("steps", []).append(str(text))


def put_record(state: dict, rec: dict) -> None:
    state.setdefault("records", {})[rec["id"]] = rec


def next_record_id(state: dict, axis: str) -> str:
    n = 1 + sum(1 for k in (state.get("records") or {}) if k.startswith(axis + "#"))
    return "%s#%d" % (axis, n)


def condense_input(axis: str, subgoal: str, incident_window: dict,
                   baseline_window: dict) -> str:
    """축약에게 갈 사용자 메시지.

    **소목표와 그 축의 결과 둘(사건 창·정상 창)만 준다.** 사건 서사도 다른 축도 가설도
    안 준다 — LangChain 벤치마크에서 그 정리가 개선의 큰 몫이었고, 부수 효과로 한 축약
    호출이 사건 전체를 못 본다.
    """
    return json.dumps({"axis": axis, "subgoal": subgoal,
                       "incident_window": incident_window or {},
                       "baseline_window": baseline_window or {}},
                      ensure_ascii=False)[:60000]
