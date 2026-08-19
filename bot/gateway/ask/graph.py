"""LangGraph 로 도는 질의 반복문. 설계와 이관 근거는 bot/GATEWAY_GUIDE.md §28."""

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


def warmup() -> bool:
    """무거운 모듈을 미리 불러 둔다. 반환은 쓸 수 있는가."""
    try:
        from langchain_core.language_models.chat_models import BaseChatModel  # noqa: F401
        from langchain_core.messages import AIMessage  # noqa: F401
        from langgraph.graph import StateGraph  # noqa: F401
        return True
    except Exception as e:
        log.info("langgraph 를 못 불러왔다(%s) — 기존 반복문으로 돈다", e)
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


# 메시지 변환 — 한 곳에 모아 둔다. 흩으면 도구 결과가 한쪽에서만 빠진다

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
    # 토큰 수를 규약대로 싣는다 — response_metadata 에만 넣으면 추적 화면이 못 읽는다
    u = reply.get("usage") or {}
    usage = None
    if u:
        cache_read = int(u.get("cache_read_input_tokens") or 0)
        cache_write = int(u.get("cache_creation_input_tokens") or 0)
        inp = int(u.get("input_tokens") or 0) + cache_read + cache_write
        out = int(u.get("output_tokens") or 0)
        usage = {"input_tokens": inp, "output_tokens": out, "total_tokens": inp + out,
                 "input_token_details": {"cache_read": cache_read,
                                         "cache_creation": cache_write}}
    # 모델 이름도 규약대로 적는다 — 없으면 개수는 떠도 단가를 몰라 비용이 안 잡힌다
    return AIMessage(content=text, tool_calls=calls, usage_metadata=usage,
                     response_metadata={"usage": u,
                                        "ls_provider": "anthropic",
                                        "ls_model_name": reply.get("model") or ""})


def make_model(system: str, specs: list, user: str, model_fn=None):
    """모델 자리. **우리 출구를 지나야만 발신된다.**"""
    from langchain_core.language_models.chat_models import BaseChatModel
    from langchain_core.outputs import ChatGeneration, ChatResult

    from .. import egress, llm

    class GatewayChat(BaseChatModel):
        """Anthropic 을 직접 부르지 않고 게이트웨이 출구를 부른다."""

        @property
        def _llm_type(self) -> str:
            return "kinx-gateway"

        def _get_ls_params(self, stop=None, **kw):
            """추적에 실을 모델 정보. **비용은 이 값으로 계산된다.**"""
            from langchain_core.language_models.chat_models import LangSmithParams

            return LangSmithParams(ls_provider="anthropic", ls_model_type="chat",
                                   ls_model_name=llm.model_for("investigate"),
                                   ls_max_tokens=llm.MAX_TOKENS)

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
            return ChatResult(generations=[ChatGeneration(message=to_ai_message(reply))])

    return GatewayChat()


class ModelBlocked(Exception):
    """출구가 막았거나 모델이 실패했다. 그래프 밖에서 사람이 읽을 문장으로 바꾼다."""


# 그래프

# 멈출 수 있는 이유. 모르는 값이 화면에 나가면 사람이 해석할 수 없다.
STOP_REASONS = frozenset(("", "budget", "llm_failed", "rounds", "deadline",
                          "cancelled", "end_turn", "invalid_state"))


def check_state(state: dict) -> str:
    """상태가 앞뒤가 맞는가. 어긋나면 사람이 읽을 사유, 맞으면 빈 문자열."""
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
    """도구를 더 부를까. **그래프 밖 순수 함수로 둔다.**"""
    last = (state.get("messages") or [None])[-1]
    if not getattr(last, "tool_calls", None):
        return False
    if answered():                       # 답을 받았으면 더 돌 이유가 없다
        return False
    if stop_now():                       # 시간 상한·사람이 누른 멈춤
        return False
    from . import tools as asktools

    return asktools.query_count(state.get("trace")) < max_calls


def build(system: str, specs: list, user: str, run_tool, model_fn=None,
          guard=None, result_bytes: int = 60000, max_calls: int = 6,
          answered=None):
    """`(state) -> state` 로 도는 그래프를 만든다."""
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

    async def ask_model(state: State, config=None) -> dict:
        # 설정을 그대로 넘긴다 — 안 넘기면 추적에서 질문 하나가 여러 기록으로 흩어진다
        try:
            reply = await asyncio.to_thread(
                lambda: model.invoke(state["messages"], config=config))
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

    def after_tools(state: State) -> str:
        """도구를 돌린 뒤 모델로 돌아갈 것인가."""
        if state.get("stopped") or got_answer():
            return END
        return "model"

    g = StateGraph(State)
    g.add_node("model", ask_model)
    g.add_node("tools", use_tools)
    g.set_entry_point("model")
    g.add_conditional_edges("model", route, {"tools": "tools", END: END})
    g.add_conditional_edges("tools", after_tools, {"model": "model", END: END})
    return g.compile()
