"""심층 조사 반복문 — 가설을 세우고, 가르는 질의를 던지고, 상태를 고친다.

`ask/graph.py` 의 규율을 따른다 — 계속/중단 판단은 그래프 밖 순수 함수, 상태 검사는 예외
대신 사유, 모델 호출은 반드시 우리 출구를 지난다.

`DEEP_LOOP=react` 로 두면 가설표를 끄고 자유 계획으로 돈다. 작은 모델에서 가설표가 오히려
해로울 수 있다는 경고(AgentRCA 절제·FORGE 권고 5)를 우리 데이터로 재려면 두 형태가 **같은
기억과 같은 가드**를 써야 하므로 여기서 갈라 둔다.
"""

import json
import logging
import os

from . import condense, hypothesis as H, memory, probe as P, state as S

log = logging.getLogger("gateway.deep.graph")

MAX_ROUNDS = int(os.environ.get("DEEP_MAX_ROUNDS", "4"))
# 마감은 목표가 아니라 천장이다. 실측 어림으로 조사 ~8초(병렬) + 반복문 4라운드 ~50초 +
# 종합 ~5초 = 60초대이고, 여기에 여유를 준 값이다. **Grafana 프록시 시한(180초)보다
# 낮아야 한다** — 넘으면 게이트웨이가 조사하는 중에 사람은 502 를 본다.
DEADLINE_S = float(os.environ.get("DEEP_DEADLINE_S", "150"))
RESULT_BYTES = int(os.environ.get("DEEP_RESULT_BYTES", "80000"))
CONDENSE_MAX = int(os.environ.get("DEEP_CONDENSE_MAX", "12"))


def loop_mode() -> str:
    v = (os.environ.get("DEEP_LOOP") or "hypothesis").strip().lower()
    return v if v in ("hypothesis", "react") else "hypothesis"


# 계획자에게 주는 도구. 가설표와 다음 질의의 뜻을 담고, **실제 조회는 ask 도구가 한다** —
# 그쪽 strict 스키마와 가명 토큰 enum 이 이미 값의 범위를 좁혀 놨으므로 다시 만들지 않는다.
def plan_spec() -> dict:
    return {
        "name": "plan",
        "description": ("가설표를 갱신하고, 다음 질의가 어느 가설을 가르는지 적는다. "
                        "실제 조회는 이 도구가 아니라 조회 도구로 함께 호출한다."),
        "strict": True,
        "input_schema": {
            "type": "object", "additionalProperties": False,
            "required": ["hypotheses", "probe_discriminates", "probe_why", "note"],
            "properties": {
                "hypotheses": {
                    "type": "array",
                    "items": {
                        "type": "object", "additionalProperties": False,
                        "required": ["id", "claim", "if_true", "if_false",
                                     "status", "supports", "contradicts"],
                        "properties": {
                            "id": {"type": "string"},
                            "claim": {"type": "string"},
                            "if_true": {"type": "string"},
                            "if_false": {"type": "string"},
                            "status": {"type": "string",
                                       "enum": list(H.STATUS)},
                            "supports": {"type": "array",
                                         "items": {"type": "string"}},
                            "contradicts": {"type": "array",
                                            "items": {"type": "string"}},
                        },
                    },
                },
                "probe_discriminates": {"type": "array", "items": {"type": "string"}},
                "probe_why": {"type": "string"},
                "note": {"type": "string"},
            },
        },
    }


def apply_plan(state: dict, plan: dict) -> list:
    """계획자가 낸 가설표를 상태에 반영한다. 반환은 거절 사유 목록.

    코드가 검사하는 것만 여기서 거른다 — 인용 실재, 상태 전이의 근거, H0 의 예외 지위.
    """
    rejected = []
    records = state.get("records") or {}
    prev = {h.get("id"): h for h in (state.get("table") or [])}
    out = []

    for h in (plan.get("hypotheses") or []):
        if H.is_null(h):
            continue                      # H0 는 코드가 관리한다. 모델이 못 바꾼다.
        ok, why = H.validate(h, records)
        if not ok:
            rejected.append("%s: %s" % (h.get("id"), why))
            continue
        was = (prev.get(h.get("id")) or {}).get("status", "미결")
        want = h.get("status") or "미결"
        if want != was:
            cites = list(h.get("supports") or []) + list(h.get("contradicts") or [])
            allowed = any(H.transition(was, want, c, records)[0] for c in cites)
            if not allowed:
                rejected.append("%s: %s 로 바꿀 근거가 없다(조회 성공 기록 필요)"
                                % (h.get("id"), want))
                h = dict(h, status=was)
        out.append(h)

    if loop_mode() == "hypothesis":
        out.append(H.null_hypothesis())   # 상시 유지. 덜 기각된 것을 답으로 고르지 않게.
    state["table"] = out
    return rejected


def read_probe(state: dict, plan: dict, calls: list):
    """계획자 회신에서 질의를 꺼낸다. 반환 `(질의, 사유)`.

    질의는 **실제 조회 도구 호출**이고, 무엇을 가르는지는 `plan` 이 적는다. 둘을 짝짓는다.
    """
    query = next((c for c in (calls or []) if c.get("name") != "plan"), None)
    if not query:
        return None, "질의를 안 냈다"

    req = {"tool": query.get("name"), "args": query.get("input") or {},
           "discriminates": list(plan.get("probe_discriminates") or []),
           "why": plan.get("probe_why") or ""}
    if loop_mode() == "react":
        # 가설표를 안 쓰는 형태에서는 가름 선언을 요구하지 않는다. 중복 검출은 그대로.
        if P.fingerprint(req) in set(state.get("seen") or []):
            return None, "중복 질의다 — 같은 조회를 이미 했다"
        return req, ""

    ok, why = P.validate(req, state.get("table") or [], set(state.get("seen") or []))
    if not ok:
        return None, why
    if not P.splits(state.get("table") or [], req["discriminates"]):
        return None, "선언한 가설들이 갈리지 않는다"
    return req, ""


def should_continue(state: dict, stop_now) -> bool:
    """한 바퀴 더 돌까. **그래프 밖 순수 함수로 둔다.**"""
    if state.get("stopped"):
        return False
    if stop_now():
        return False
    if int(state.get("round") or 0) >= MAX_ROUNDS:
        return False
    if int(state.get("spent") or 0) > RESULT_BYTES:
        return False
    if len(state.get("probes") or []) >= CONDENSE_MAX:
        return False
    if loop_mode() == "react":
        return True
    if not H.enough(state.get("table") or []):
        return True                       # 아직 가설이 덜 섰다
    return H.open_count(state.get("table") or []) > 0


def build(model_fn, run_probe, guard, system: str = ""):
    """`(state) -> state` 로 도는 그래프.

    `model_fn(system, user, specs) -> 회신` · `run_probe(req) -> (기록, 사유)` ·
    `guard() -> 멈출 이유` 를 밖에서 받는다. 검사가 이 셋을 갈아 끼워 유료 호출 없이 돈다.
    """
    from langgraph.graph import END, StateGraph

    def _untested(state):
        """가를 수 없다는 말을 아직 할 수 없는 상태인가.

        **가를 수 없다는 것은 질의를 해 보고 아는 것이다.** 랩 첫 실행이 축 기록 넷과 미결
        가설 둘을 쥐고 질의 0개로 1라운드에 끝났다 — 이 설계가 막으려던 조기 종결을 설계
        자신이 했다. 그래서 질의가 하나도 안 나갔으면 사유를 지우고 다시 시킨다. 라운드
        상한이 그대로 천장이라 무한히 되풀이하지 않는다.
        """
        if state.get("probes"):
            return False
        if int(state.get("round") or 0) >= MAX_ROUNDS:
            return False
        memory.add_step(state, "질의를 안 냈다 — 가설을 가를 질의를 하나 반드시 내라")
        return True

    def _stop(state, why):
        """멈출 때 **왜 멈췄는지 발자취와 함께 남긴다.**

        사유만 남기면 '못가름'이 질의를 못 만든 것인지 가설이 안 갈린 것인지 알 수 없다.
        운영에서 이 줄이 없으면 조사가 얕은 이유를 사람이 못 짚는다.
        """
        state["stopped"] = why
        table = state.get("table") or []
        log.info("심층 종료 사유=%s 라운드=%s 가설=%d(미결 %d) 기록=%d 질의=%d · %s",
                 why, state.get("round"), H.count_real(table), H.open_count(table),
                 len(state.get("records") or {}), len(state.get("probes") or []),
                 " / ".join((state.get("steps") or [])[-3:]))
        return state

    async def plan_node(state: dict) -> dict:
        from ..ask import tools as asktools

        specs = [plan_spec()] + [t for t in (asktools.TOOL_SPECS or [])
                                 if t.get("name") != "answer"]
        try:
            reply = await model_fn(system, memory.render(state), specs)
        except Exception as e:
            log.warning("계획자 호출 실패: %s", e)
            state["error"] = str(e)
            return _stop(state, "llm_failed")

        calls = [b for b in (reply.get("content") or [])
                 if isinstance(b, dict) and b.get("type") == "tool_use"]
        plan = next((c.get("input") or {} for c in calls
                     if c.get("name") == "plan"), {})

        if loop_mode() == "hypothesis":
            for why in apply_plan(state, plan):
                memory.add_step(state, "거절: %s" % why)
            if not H.enough(state.get("table") or []):
                memory.add_step(state, "가설이 둘 미만이라 다시 세우게 한다")

        req, why = read_probe(state, plan, calls)
        state["probe"] = req
        if not req:
            memory.add_step(state, "질의 없음: %s" % why)
        return state

    async def probe_node(state: dict) -> dict:
        req = state.get("probe")
        if not req:
            return state
        rec, why = await run_probe(req)
        state.setdefault("probes", []).append(req)
        state.setdefault("seen", []).append(P.fingerprint(req))
        if not rec:
            memory.add_step(state, "%s 조회가 결과를 못 냈다: %s" % (req["tool"], why))
            return state
        memory.put_record(state, rec)
        state["spent"] = int(state.get("spent") or 0) + len(json.dumps(rec, ensure_ascii=False))
        memory.add_step(state, "%s 로 %s 를 봤다 — %s"
                        % (req["tool"], ", ".join(req.get("discriminates") or ["-"]),
                           rec.get("finding", "")))
        return state

    async def reduce_node(state: dict) -> dict:
        state["round"] = int(state.get("round") or 0) + 1
        bad = S.check(state)
        if bad:
            log.warning("상태 불일치: %s", bad)
            state["error"] = bad
            return _stop(state, "invalid_state")

        why = guard()
        if why:
            return _stop(state, why)

        reason = ""
        if loop_mode() == "hypothesis":
            reason, _note = H.done(state.get("table") or [],
                                   probes_left=bool(state.get("probe")))
            if reason == "못가름" and _untested(state):
                reason = ""
        elif not state.get("probe") and not _untested(state):
            reason = "못가름"
        if reason:
            return _stop(state, reason)

        if not should_continue(state, lambda: bool(guard())):
            return _stop(state, "rounds" if int(state.get("round") or 0) >= MAX_ROUNDS
                         else "못가름")
        return state

    g = StateGraph(dict)
    g.add_node("plan", plan_node)
    g.add_node("probe", probe_node)
    g.add_node("reduce", reduce_node)
    g.set_entry_point("plan")
    g.add_edge("plan", "probe")
    g.add_edge("probe", "reduce")
    g.add_conditional_edges("reduce",
                            lambda s: "plan" if not s.get("stopped") else END,
                            {"plan": "plan", END: END})
    return g.compile()
