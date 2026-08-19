"""반복문 엔진 선택과 LangGraph 경로(§28)."""

import logging
import os
import json as _json
from . import config

from .config import DEADLINE_S, MAX_ROUNDS, RESULT_BYTES
from .answer import (chosen_images, render_answer, stall_note, strip_handles, with_evidence_note)
from .session import cancelled, remember
log = logging.getLogger("gateway.ask")


def engine_name() -> str:
    """질의 반복문을 무엇으로 돌릴까. `graph`(LangGraph, 기본) 또는 `loop`(직접 구현)."""
    from . import graph
    want = os.environ.get("ASK_ENGINE", "graph").strip().lower()
    if want == "loop":
        return "loop"
    if graph.available():
        return "graph"
    log.warning("langgraph 가 없어 기존 반복문으로 돈다")
    return "loop"


async def _run_graph(system: str, messages: list, mk, sid: str, user: str,
                     exec_tool, model_fn, started: float, tick,
                     specs=None, final=None, made_images=None,
                     ok_queries=None) -> dict:
    """LangGraph 로 도는 경로. 반환 계약은 기존 반복문과 같다."""
    from langchain_core.messages import AIMessage, HumanMessage, SystemMessage

    from . import tools as asktools
    from .loop import force_answer
    from . import graph as G
    def guard() -> bool:
        """더 돌면 안 되는가. 시간 상한과 사람이 누른 멈춤을 함께 본다."""
        if tick() - started > DEADLINE_S:
            _stop["why"] = "deadline"
            return True
        if cancelled(sid, started):
            _stop["why"] = "cancelled"
            return True
        return False

    _stop = {"why": ""}
    lc = [SystemMessage(content=system)]
    for m in messages:
        # 이력의 assistant 는 글만 남아 있다. 도구 호출 이력은 다시 싣지 않는다.
        lc.append(AIMessage(content=m["content"]) if m["role"] == "assistant"
                  else HumanMessage(content=m["content"]))
    app = G.build(system, specs if specs is not None else asktools.TOOL_SPECS,
                  user, exec_tool, model_fn,
                  guard=guard, result_bytes=RESULT_BYTES, max_calls=MAX_ROUNDS,
                  answered=lambda: bool(final))
    state = {"messages": lc, "trace": [], "images": [], "spent": 0, "called": {},
             "stopped": "", "error": ""}
    try:
        # 프레임워크 상한은 넉넉히 두고 실제 제한은 route 가 건다 — 먼저 닿으면 이유를 못 읽는다
        out = await app.ainvoke(state, {"recursion_limit": MAX_ROUNDS * 2 + 4})
    except Exception as e:
        log.warning("그래프 실행 실패: %s", e)
        return {"text": "", "trace": [], "rounds": 0, "images": [],
                "stopped": "llm_failed", "error": "질의를 끝내지 못했다: %s" % e}
    trace = out.get("trace") or []
    if out.get("stopped") == "llm_failed":
        return {"text": "", "trace": trace, "rounds": len(trace),
                "images": out.get("images") or [], "stopped": "llm_failed",
                "error": "모델을 부르지 못했다: %s" % out.get("error", "")}
    text = ""
    if final:
        # 답 도구로 받았으면 그것이 답이다. 산문에서 그림 표시를 걷어 낼 일이 없다.
        text = render_answer(final, int((ok_queries or {}).get("n", 1)) > 0)
    else:
        for m in reversed(out.get("messages") or []):
            if isinstance(m, AIMessage) and isinstance(m.content, str) and m.content.strip():
                text = m.content
                break
    stopped = _stop["why"] or out.get("stopped") or "end_turn"
    # 답을 받았으면 상한 표시를 붙이지 않는다 — 기록을 보는 사람이 답이 잘린 줄 안다
    if stopped == "end_turn" and not final and len(trace) >= MAX_ROUNDS:
        stopped = "rounds"
    if stopped in ("rounds", "deadline", "budget") and not final and trace:
        if await force_answer(system, G.to_anthropic(out.get("messages") or []),
                              specs, user, model_fn, exec_tool, trace):
            text = render_answer(final, int((ok_queries or {}).get("n", 1)) > 0)
    if stopped in ("rounds", "deadline", "budget", "cancelled", "invalid_state") and not final:
        text = (stall_note(stopped, trace)
                + ((chr(10) * 2 + text) if text else ""))
    text = with_evidence_note(text, trace, int((ok_queries or {}).get("n", 1)))
    remember(sid or "-", mk)
    return {"text": strip_handles(mk.unmask(text)), "trace": trace,
            "rounds": len(trace),
            "images": chosen_images(out.get("images") or [], final),
            "stopped": stopped, "error": ""}
