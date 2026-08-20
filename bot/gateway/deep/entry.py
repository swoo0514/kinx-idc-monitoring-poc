"""알림 경로에서 심층 조사를 부르는 자리 — 모델·조회·마스커를 여기서 묶는다.

`run.investigate` 는 셋을 밖에서 받는다(검사가 갈아 끼울 수 있게). 실제 배선은 여기 한 곳에
모아 두어야 트리아지 쪽이 배선을 몰라도 된다.
"""

import json
import logging
import os

log = logging.getLogger("gateway.deep.entry")

# 심층 전용 시간당 상한. 트리아지와 같은 예산을 먹으면 폭주 때 알림 분석이 밀린다.
#
# **한 번의 조사가 축약을 최대 12번 부른다**(DEEP_CONDENSE_MAX). 그래서 20 으로 두면
# 두 번을 못 돈다 — 랩에서 실제로 그렇게 막혔다. 시간당 4~5회를 돌 수 있게 잡는다.
MAX_PER_HOUR = int(os.environ.get("DEEP_MAX_PER_HOUR", "60"))


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


def host_from_question(question: str, table: dict) -> str:
    """질문에 적힌 이름에서 대상 토큰을 찾는다.

    알림 경로는 사건에 호스트가 들어 있지만 **질의는 질문 안에 있다.** 이걸 안 풀면
    조사가 빈 대상으로 나가고 네 축이 통째로 실패한다 — 랩 첫 실행이 그랬다.
    """
    from ..ask.table import resolve_mentions

    resolved = resolve_mentions(question or "", table or {})
    hits = [tok for tok in (table or {}) if tok in resolved]
    if len(hits) == 1:
        return hits[0]
    if len(hits) > 1:
        log.info("질문에 대상이 여럿이다(%s) — 첫 번째를 쓴다", ", ".join(hits[:4]))
        return hits[0]
    return ""


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
    # 질의 경로는 사건에 호스트가 없다 — 질문에서 찾아 넣는다
    if not ((context.get("incident") or {}).get("host")):
        q = " ".join(str(a.get("name") or "") for a in (context.get("alerts") or []))
        tok = host_token_hint or host_from_question(q, table)
        if not tok:
            return {"ok": False, "stopped": "no_target",
                    "error": "질문에서 조회할 대상을 못 찾았다. 호스트 이름을 함께 적어라"}
        context = dict(context)
        context["incident"] = dict(context.get("incident") or {}, host=tok)

    return await deep_run.investigate(context, mk, _model_call, _condense_call,
                                      _tool_runner(ctx))
