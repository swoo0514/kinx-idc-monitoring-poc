"""LangGraph 로 도는 질의 반복문. 설계와 이관 근거는 bot/GATEWAY_GUIDE.md §28.

**프레임워크가 대신하는 것은 흐름뿐이다.** 모델을 부르는 자리, 도구를 실행하는 자리,
이름을 가리는 자리는 그대로 우리 것이다. 그래야 전송 예산·읽기 전용 강제·마스킹이
프레임워크 판이 바뀌어도 같은 자리에 남는다.

`ChatAnthropic` 을 그대로 쓰면 프레임워크가 Anthropic 을 직접 부르므로 `egress.guard`
의 동시 수·시간당 상한·사용자별 예산과 토큰 계수를 통째로 건너뛴다. 그래서 모델 자리에
우리 출구를 부르는 껍데기를 두고, 도구는 `asktools.run_tool` 을 그대로 감싼다.

langgraph 는 선택 의존이다. 안 깔려 있으면 `available()` 이 거짓이고 기존 반복문이 돈다.
"""

import asyncio
import json as _json
import logging

log = logging.getLogger("gateway.graph")


def available() -> bool:
    """이 서버에서 그래프 엔진을 쓸 수 있는가."""
    try:
        import langgraph  # noqa: F401
        import langchain_core  # noqa: F401
        return True
    except Exception:
        return False


def versions() -> dict:
    """무엇이 깔려 있는지. 판이 바뀌면 동작이 달라지므로 함께 남긴다."""
    out = {}
    for name in ("langgraph", "langchain_core"):
        try:
            import importlib.metadata as md
            out[name] = md.version(name.replace("_", "-"))
        except Exception:
            out[name] = ""
    return out


# ---------------------------------------------------------------------------
# 메시지 변환
#
# 프레임워크는 자기 메시지 형태를 쓰고 Anthropic 은 자기 형태를 쓴다. 변환을 한 곳에
# 모아 둔다 — 흩으면 도구 결과가 한쪽에서만 빠져 모델이 "조회 결과 없음" 으로 읽는다.
# ---------------------------------------------------------------------------

def to_anthropic(messages: list) -> list:
    """프레임워크 메시지 목록을 Anthropic `messages` 로. 시스템 문구는 빼서 따로 준다."""
    from langchain_core.messages import AIMessage, HumanMessage, SystemMessage, ToolMessage

    out = []
    for m in messages:
        if isinstance(m, SystemMessage):
            continue
        if isinstance(m, HumanMessage):
            out.append({"role": "user", "content": m.content})
        elif isinstance(m, AIMessage):
            blocks = []
            if isinstance(m.content, str) and m.content:
                blocks.append({"type": "text", "text": m.content})
            elif isinstance(m.content, list):
                blocks.extend(m.content)
            for call in (m.tool_calls or []):
                blocks.append({"type": "tool_use", "id": call.get("id"),
                               "name": call.get("name"),
                               "input": call.get("args") or {}})
            out.append({"role": "assistant", "content": blocks or ""})
        elif isinstance(m, ToolMessage):
            block = {"type": "tool_result", "tool_use_id": m.tool_call_id,
                     "content": m.content}
            # 도구 결과가 잇따르면 한 묶음으로 모은다. 따로 보내면 Anthropic 이 거부한다.
            if out and out[-1]["role"] == "user" and isinstance(out[-1]["content"], list):
                out[-1]["content"].append(block)
            else:
                out.append({"role": "user", "content": [block]})
    return out


def system_of(messages: list) -> str:
    from langchain_core.messages import SystemMessage
    for m in messages:
        if isinstance(m, SystemMessage):
            return m.content
    return ""


def to_ai_message(reply: dict):
    """Anthropic 응답을 프레임워크 메시지로."""
    from langchain_core.messages import AIMessage

    blocks = reply.get("content") or []
    text = "".join(b.get("text", "") for b in blocks
                   if isinstance(b, dict) and b.get("type") == "text")
    calls = [{"name": b.get("name", ""), "args": b.get("input") or {},
              "id": b.get("id"), "type": "tool_call"}
             for b in blocks if isinstance(b, dict) and b.get("type") == "tool_use"]
    return AIMessage(content=text, tool_calls=calls,
                     response_metadata={"usage": reply.get("usage") or {}})


def make_model(system: str, specs: list, user: str, model_fn=None):
    """모델 자리. **우리 출구를 지나야만 발신된다.**

    프레임워크가 도구 정의를 자기 형태로 바꾸는 것을 쓰지 않고 우리 `TOOL_SPECS` 를
    그대로 보낸다. 도구 설명은 사람이 읽고 고치는 문서이기도 해서, 변환을 한 겹 더 두면
    화면에 보이는 것과 모델이 받는 것이 갈린다.
    """
    from langchain_core.language_models.chat_models import BaseChatModel
    from langchain_core.outputs import ChatGeneration, ChatResult

    from . import egress, llm, store

    class GatewayChat(BaseChatModel):
        """Anthropic 을 직접 부르지 않고 게이트웨이 출구를 부른다."""

        @property
        def _llm_type(self) -> str:
            return "kinx-gateway"

        def bind_tools(self, tools, **kw):
            # 도구 정의는 우리 것을 쓴다. 프레임워크 변환을 거치지 않는다.
            return self

        def _generate(self, messages, stop=None, run_manager=None, **kw) -> "ChatResult":
            msgs = to_anthropic(messages)
            sysmsg = system_of(messages) or system

            def _call():
                if model_fn is not None:
                    return model_fn(sysmsg, msgs, specs)
                return llm.claude_tools(sysmsg, msgs, specs)

            res = egress.call_raw(_call, kind="ask", user=user)
            if not res["ok"]:
                raise ModelBlocked(res["reason"])
            reply = res["value"]
            u = reply.get("usage") or {}
            if u:
                # **실제로 쓴 토큰으로 센다.** 추정하지 않는다.
                store.record_tokens(
                    "ask", user, u.get("input_tokens"), u.get("output_tokens"),
                    cache_write=u.get("cache_creation_input_tokens") or 0,
                    cache_read=u.get("cache_read_input_tokens") or 0,
                    model=reply.get("model") or "")
            return ChatResult(generations=[ChatGeneration(message=to_ai_message(reply))])

    return GatewayChat()


class ModelBlocked(Exception):
    """출구가 막았거나 모델이 실패했다. 그래프 밖에서 사람이 읽을 문장으로 바꾼다."""


# ---------------------------------------------------------------------------
# 그래프
# ---------------------------------------------------------------------------

# 멈출 수 있는 이유. 모르는 값이 화면에 나가면 사람이 해석할 수 없다.
STOP_REASONS = frozenset(("", "budget", "llm_failed", "rounds", "deadline",
                          "cancelled", "end_turn", "invalid_state"))


def check_state(state: dict) -> str:
    """상태가 앞뒤가 맞는가. 어긋나면 사람이 읽을 사유, 맞으면 빈 문자열.

    동기분 코드(`InvestigationState.validate_graph_invariants`)와 같은 자리다. 단계마다
    검증해야 어긋난 상태가 그 자리에서 드러난다. 그냥 두면 사람은 틀린 답을 정상으로
    읽는다.
    """
    trace = state.get("trace") or []
    called = state.get("called") or {}
    if len(called) > len(trace):
        return ("조회 기록(%d)보다 중복 차단 표(%d)가 많다. 추적에서 조회가 빠졌다"
                % (len(trace), len(called)))
    ids = [im.get("id") for im in (state.get("images") or [])]
    if len(ids) != len(set(ids)):
        return "같은 그림을 두 번 붙였다"
    if int(state.get("spent") or 0) < 0:
        return "쓴 바이트가 음수다"
    if str(state.get("stopped") or "") not in STOP_REASONS:
        return "모르는 멈춤 사유다: %r" % state.get("stopped")
    return ""


def should_continue(state: dict, max_calls: int, stop_now, answered) -> bool:
    """도구를 더 부를까. **그래프 밖 순수 함수로 둔다.**

    클로저 안에 있으면 그래프를 세우지 않고는 단위 검사를 못 한다. 동기분 코드가
    `routing.py` 를 따로 둔 이유와 같다.
    """
    last = (state.get("messages") or [None])[-1]
    if not getattr(last, "tool_calls", None):
        return False
    if answered():                       # 답을 받았으면 더 돌 이유가 없다
        return False
    if stop_now():                       # 시간 상한·사람이 누른 멈춤
        return False
    return len(state.get("trace") or []) < max_calls


def build(system: str, specs: list, user: str, run_tool, model_fn=None,
          guard=None, result_bytes: int = 60000, max_calls: int = 6,
          answered=None):
    """`(state) -> state` 로 도는 그래프를 만든다.

    노드는 둘이다. 모델에게 묻는 자리와 도구를 실행하는 자리.

    **상한과 멈춤 판단은 상태가 아니라 클로저로 받는다.** 상태에 함수를 넣으면 나중에
    체크포인트를 켰을 때 직렬화할 수 없고, 상태 열쇠는 노드가 돌려준 것만 남으므로
    한 노드가 빠뜨리면 조용히 사라진다(2026-08-18 랩 실측: `guard` 가 사라져 그래프가
    통째로 실패했다).
    """
    from typing import Any, Dict, List

    try:                       # 3.9 는 typing 에 있고 상위 판은 typing_extensions 를 쓴다
        from typing import TypedDict
    except ImportError:        # pragma: no cover
        from typing_extensions import TypedDict

    from langgraph.graph import END, StateGraph

    model = make_model(system, specs, user, model_fn)
    stop_now = guard or (lambda: False)
    # 답 도구를 받았으면 더 돌 이유가 없다. 판단은 도구 실행부가 하고 여기서는 묻기만 한다.
    got_answer = answered or (lambda: False)

    class State(TypedDict, total=False):
        """상태에 담는 것은 **노드 사이를 오가는 값**뿐이다.

        열쇠를 여기 적어야 노드가 안 돌려준 값도 유지된다.
        """
        messages: List[Any]
        trace: List[Dict[str, Any]]
        images: List[Dict[str, Any]]
        spent: int
        called: Dict[str, int]
        stopped: str
        error: str

    async def ask_model(state: State) -> dict:
        try:
            reply = await asyncio.to_thread(model.invoke, state["messages"])
        except ModelBlocked as e:
            return {"stopped": "llm_failed", "error": str(e)}
        except Exception as e:              # 가짜 모델이 터지는 경우까지 사람 문장으로
            return {"stopped": "llm_failed", "error": str(e)}
        return {"messages": list(state["messages"]) + [reply]}

    async def use_tools(state: State) -> dict:
        from langchain_core.messages import ToolMessage

        last = state["messages"][-1]
        trace = list(state.get("trace") or [])
        images = list(state.get("images") or [])
        called = dict(state.get("called") or {})
        spent, stopped, outs = int(state.get("spent") or 0), "", []
        for call in (last.tool_calls or []):
            name, args = call.get("name", ""), (call.get("args") or {})
            image, out, blob = await run_tool(name, args, called, len(trace) + 1)
            if image:
                images.append(image)
            spent += len(blob)
            if spent > result_bytes:
                out = {"error": "조회 결과가 예산을 넘어 더 못 본다. 지금까지 본 것으로 답하라"}
                blob = _json.dumps(out, ensure_ascii=False)
                stopped = "budget"
            trace.append({"tool": name, "args": args,
                          "error": (out or {}).get("error", ""), "bytes": len(blob)})
            outs.append((call.get("id"), blob))
        msgs = list(state["messages"]) + [ToolMessage(content=b, tool_call_id=i)
                                          for i, b in outs]
        out = {"messages": msgs, "trace": trace, "images": images,
               "spent": spent, "called": called, "stopped": stopped}
        why = check_state(out)
        if why:
            # 예외를 그대로 올리면 사람은 답 대신 추적을 본다.
            log.warning("그래프 상태가 어긋났다: %s", why)
            out["stopped"], out["error"] = "invalid_state", why
        return out

    def route(state: State) -> str:
        if state.get("stopped"):
            return END
        return "tools" if should_continue(state, max_calls, stop_now,
                                          got_answer) else END

    g = StateGraph(State)
    g.add_node("model", ask_model)
    g.add_node("tools", use_tools)
    g.set_entry_point("model")
    g.add_conditional_edges("model", route, {"tools": "tools", END: END})
    g.add_edge("tools", "model")
    return g.compile()
