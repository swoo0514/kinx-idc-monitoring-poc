"""LangGraph 안에서 마스킹이 새는지 보는 검사. **이관을 결정하는 통과 조건이다.**"""
import json
import os
import sys

# `bot/` 을 경로에 넣는다. 이 파일이 bot/tools/ 로 내려갔으므로 부모다.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from gateway import masking, proxy, nametable

REAL_HOST = "vm-p3-target-002.novalocal"
REAL_IP = "192.168.20.16"

nametable._terms = {REAL_HOST: "host"}
MK = proxy.build_masker()
TOKEN = MK._fwd[REAL_HOST]

SENT = []          # 모델이 받은 것 전부


def mask_text(t):
    return MK.mask(t) if isinstance(t, str) else t


# --- 우리 도구. 인자는 토큰으로 오고, 결과는 나가기 전에 가린다 -------------
def host_logs(host: str, window_m: int = 60) -> str:
    """그 호스트의 로그를 본다. host 는 [host-...] 토큰이다."""
    real = MK.unmask(host)                       # 여기서만 실명이 된다
    assert real == REAL_HOST, real
    raw = "%s 에서 %s 로 접속 실패" % (real, REAL_IP)   # 조회 원문(실명 포함)
    return MK.mask(raw)                          # 모델로 갈 때는 가린다


def main():
    from langchain_core.messages import AIMessage, HumanMessage, SystemMessage, ToolMessage
    from langchain_core.language_models.fake_chat_models import GenericFakeChatModel
    from langchain_core.tools import tool
    from langgraph.prebuilt import create_react_agent

    logs_tool = tool(host_logs)

    class Recording(GenericFakeChatModel):
        """모델 자리. 받은 것을 전부 기록하고, 우리 마스커를 거친 뒤에만 통과시킨다."""

        def _generate(self, messages, stop=None, run_manager=None, **kw):
            masked = []
            for m in messages:
                c = m.content
                masked.append(mask_text(c) if isinstance(c, str) else c)
            SENT.append(json.dumps([str(x) for x in masked], ensure_ascii=False))
            return super()._generate(messages, stop=stop, run_manager=run_manager, **kw)

        def bind_tools(self, tools, **kw):
            # 도구 목록은 모델 쪽 형식일 뿐이라 이 검사에서는 자기 자신을 돌려준다.
            return self

    replies = iter([
        AIMessage(content="", tool_calls=[{"name": "host_logs", "id": "1",
                                           "args": {"host": TOKEN, "window_m": 60}}]),
        AIMessage(content="%s 에서 접속 실패가 보인다" % TOKEN),
    ])
    model = Recording(messages=replies)
    agent = create_react_agent(model, [logs_tool])
    out = agent.invoke({"messages": [
        SystemMessage(content="너는 관제 도우미다"),
        HumanMessage(content=MK.mask("%s 로그 봐줘" % REAL_HOST)),
    ]})

    blob = "\n".join(SENT)
    leaked = [n for n in (REAL_HOST, REAL_IP) if n in blob]
    final = out["messages"][-1].content
    print("모델이 받은 묶음 수:", len(SENT))
    print("실명 누수:", leaked or "없음")
    print("최종 답(역치환 전):", final)
    print("최종 답(역치환 후):", MK.unmask(final))
    return 1 if leaked else 0


if __name__ == "__main__":
    sys.exit(main())
