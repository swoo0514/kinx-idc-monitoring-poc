"""알림 경로에서 심층 조사를 부르는 자리 — 모델·조회·마스커를 여기서 묶는다.

`run.investigate` 는 셋을 밖에서 받는다(검사가 갈아 끼울 수 있게). 실제 배선은 여기 한 곳에
모아 두어야 트리아지 쪽이 배선을 몰라도 된다.
"""

import json
import logging
import os

log = logging.getLogger("gateway.deep.entry")

# 심층 전용 시간당 상한. 트리아지와 같은 예산을 먹으면 폭주 때 알림 분석이 밀린다.
MAX_PER_HOUR = int(os.environ.get("DEEP_MAX_PER_HOUR", "20"))


def enabled() -> bool:
    return (os.environ.get("DEEP_ENABLED", "1") or "").strip() not in ("0", "false", "no")


async def _model_call(system: str, user: str, specs: list):
    """계획자·종합. **우리 출구를 지난다** — 사용량이 표에 남는다."""
    import asyncio

    from .. import egress, llm

    def _go():
        # 계획자 등급은 model_for 로 고른다 — claude_tools 는 kind 가 아니라 model 을 받는다
        return llm.claude_tools(system, [{"role": "user", "content": user}],
                                specs or [], model=llm.model_for("plan"))

    res = await asyncio.to_thread(egress.call_raw, _go, kind="deep",
                                  max_per_hour=MAX_PER_HOUR)
    if not res.get("ok"):
        raise RuntimeError(res.get("reason") or "계획자 호출이 막혔다")
    return res.get("value") or {}


async def _condense_call(system: str, user: str):
    """축약. **전용 체인(Luna → haiku)** 을 쓴다 — 판단 경로와 섞지 않는다."""
    import asyncio

    from .. import egress
    from . import condense

    res = await asyncio.to_thread(egress.call, condense.adapters(), system, user,
                                  kind="condense", max_per_hour=MAX_PER_HOUR)
    return {"ok": not res.get("degraded"), "text": res.get("text") or "",
            "reason": res.get("reason") or ""}


def _tool_runner(ctx: dict):
    """조회 — **ask 조회 계층을 지난다.** 임의 창을 받고 항목마다 마스킹이 걸린다."""
    from ..ask import tools as asktools

    async def run(name: str, args: dict):
        out = await asktools.run_tool(name, args or {}, ctx)
        return out, len(json.dumps(out, ensure_ascii=False))

    return run


async def investigate_incident(context: dict, host_token_hint: str = ""):
    """알림 사건 하나를 심층 조사한다. 반환은 `run.investigate` 결과 그대로."""
    from .. import masking
    from ..ask import build_table
    from ..ask.fetch.judgments import fetch_judgments
    from ..ask.fetch.loki import fetch_logs
    from ..ask.fetch.wazuh import fetch_security
    from ..ask.fetch.zabbix import fetch_metrics
    from . import run as deep_run

    mk = masking.Masker()
    table = await build_table(mk)
    if not table:
        return {"ok": False, "stopped": "no_targets",
                "error": "조회할 수 있는 대상이 없다"}

    ctx = {
        "table": table, "now": 0, "panel_span": None, "panel_refs": {},
        "fetch_logs": lambda q, a, b, lim: fetch_logs(q, a, b, lim, mk),
        "fetch_security": lambda body: fetch_security(body, mk),
        "fetch_judgments": lambda h, d: fetch_judgments(h, d, mk),
        "fetch_metrics": lambda ent, m, a, b: fetch_metrics(ent, m, a, b, mk),
    }
    return await deep_run.investigate(context, mk, _model_call, _condense_call,
                                      _tool_runner(ctx))
