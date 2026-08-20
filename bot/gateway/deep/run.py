"""심층 조사 진입점 — 준비·조사·종합·검증.

조회는 `ask` 조회 계층을 지난다. 그쪽이 임의 창을 받고, 항목마다 마스킹을 적용하고, 조회
상태를 함께 낸다. `collect_incident_context` 를 쓰지 않는 이유는 창이 하드코딩이고(Wazuh 는
서버 상대시각) **원문을 그대로 돌려주기 때문**이다 — 축 원문을 축약 모델에 그대로 주면
실명이 외부로 나간다.
"""

import json
import logging
import os
import time

from . import baseline, condense, graph as G, hypothesis as H, memory, state as S

log = logging.getLogger("gateway.deep.run")

# 조사에서 축마다 무엇을 볼지. 분류를 보지 않는다 — 게이트가 심층을 **신규** 사건에
# 발동시키므로 분류별 절차를 두면 정작 필요한 쪽(other)에 아무것도 없게 된다.
SURVEY = (
    ("metrics", "host_metrics"),
    ("logs", "host_logs"),
    ("security", "security_alerts"),
    ("history", "past_judgments"),
)


def prepare(context: dict, masker):
    """판정을 주입값으로 굳히고 **이름을 먼저 등록한다.**

    등록이 먼저여야 축 원문에 마스킹이 걸린다. 알림 경로는 이 등록을
    `build_llm_context` 안에서 하는데, 우리는 그보다 앞서 축약을 보내므로 여기서 한다.
    `_register_*` 가 모듈 함수라 그 함수를 리팩터링하지 않아도 된다.
    """
    from .. import masking

    masking._register_host(context.get("host") or {}, masker)
    masking._register_context(context, masker)

    inc = context.get("incident") or {}
    alerts = context.get("alerts") or []
    pj = next((a.get("prejudge") or {} for a in alerts if a.get("prejudge")), {})
    return {
        "host": masker.mask(inc.get("host") or context.get("host", {}).get("host", "")),
        "names": [masker.mask(a.get("name") or "") for a in alerts][:8],
        "classes": list(inc.get("classes") or []),
        "sev": inc.get("dominant_sev") or "",
        "scope": inc.get("scope") or "",
        "verdict": pj.get("verdict") or "",
        "statement": pj.get("statement") or "",
        "zbx_host": inc.get("host") or "",
    }


async def condense_axis(axis: str, subgoal: str, now_res: dict, base_res: dict,
                        record_id: str, call):
    """축 결과 둘을 기록 하나로. 반환 `(기록, 사유)`."""
    from .. import prompts

    system = prompts.load("deep_condense", "축을 한 덩이로 줄인다. JSON 하나만 낸다.")
    user = memory.condense_input(axis, subgoal, now_res, base_res)
    res = await call(system, user)
    if not res.get("ok"):
        return None, res.get("reason") or "축약 호출 실패"
    return condense.parse(res.get("text") or "", axis, record_id)


def verify(text: str, state: dict):
    """내보내기 전 코드가 보는 것. 반환 `(글, 사유)` — 사유가 있으면 막힌 것이다."""
    from .. import llm

    recs = state.get("records") or {}
    if not any((r.get("status") == H.EVIDENCE_OK) for r in recs.values()):
        return "", "조회에 성공한 축이 하나도 없다 — 종합하지 않는다"

    got = (text or "").strip()
    if not got:
        return "", "종합이 비었다"

    # 위험 명령은 지우지 않고 표시한다. 판단은 사람이 한다.
    ops = llm.destructive_ops(got)
    if ops:
        log.warning("심층 종합에 위험 명령이 섞였다: %s", ", ".join(ops))
        got = llm.mark_destructive(got)
    return got, ""


async def survey(st: dict, inc: dict, run_tool, condense_call, now: int) -> None:
    """조사 — 네 축 × (사건 창 + 정상 창). **축을 동시에 훑는다.**

    순차로 두면 축 넷의 시간이 그대로 더해진다. 사람이 화면에서 기다리는 경로라 여기가
    가장 큰 통제 지점이다. 축약 호출은 출구의 동시 상한에 걸려 알아서 줄 서므로 여기서
    따로 조이지 않는다.

    분류는 보지 않는다 — 게이트가 심층을 **신규** 사건에 발동시키므로 분류별 절차를 두면
    정작 필요한 쪽(`other`)에 아무것도 없게 된다.
    """
    import asyncio

    span = (now - 3600, now)
    bspan = baseline.window(*span)
    args = {"host": inc.get("host", "")}
    plan = [(axis, tool, memory.next_record_id(st, axis)) for axis, tool in SURVEY]

    async def one(axis, tool, rid):
        a, b = await asyncio.gather(
            run_tool(tool, dict(args, **{"range": "%d-%d" % span})),
            run_tool(tool, dict(args, **{"range": "%d-%d" % bspan})))
        return axis, await condense_axis(axis, condense.SUBGOAL.get(axis, ""),
                                         a[0], b[0], rid, condense_call)

    for axis, (rec, why) in await asyncio.gather(*[one(*p) for p in plan]):
        if rec:
            memory.put_record(st, rec)
            memory.add_step(st, "조사: %s — %s" % (axis, rec.get("finding", "")))
        else:
            memory.add_step(st, "조사: %s 를 줄이지 못했다(%s)" % (axis, why))


async def investigate(context: dict, masker, model_call, condense_call,
                      run_tool, now: int = 0):
    """조사 → 가설 → 검증을 한 번 돌린다.

    `model_call(system, user, specs)` · `condense_call(system, user)` ·
    `run_tool(name, args) -> (결과, 바이트)` 를 밖에서 받는다. 검사가 이 셋을 갈아 끼워
    유료 호출 없이 돈다.
    """
    from .. import masking, prompts

    if masking.cannot_mask(masker):
        return {"ok": False, "stopped": "no_mask",
                "error": "이름을 가릴 수 없어 축약을 보내지 않는다"}

    now = int(now or time.time())
    inc = prepare(context, masker)
    st = S.new_state(inc, {})
    started = time.monotonic()

    def guard():
        if time.monotonic() - started > G.DEADLINE_S:
            return "deadline"
        return ""

    await survey(st, inc, run_tool, condense_call, now)

    if not (st.get("records") or {}):
        return {"ok": False, "stopped": "no_evidence",
                "error": "네 축에서 아무 기록도 못 만들었다"}

    # ── 가설 → 검증 반복문
    async def _probe(req):
        res, size = await run_tool(req["tool"], req["args"])
        rid = memory.next_record_id(st, req["tool"].split("_")[-1])
        axis = next((ax for ax, t in SURVEY if t == req["tool"]), "metrics")
        return await condense_axis(axis, req.get("why") or "", res, {}, rid,
                                   condense_call)

    system = prompts.load("deep_plan", "조사 → 가설 → 검증으로 원인을 좁힌다.")
    app = G.build(model_call, _probe, guard, system=system)
    out = await app.ainvoke(st, {"recursion_limit": G.MAX_ROUNDS * 3 + 6})
    st = dict(out or st)

    # ── 종합
    vsys = prompts.load("deep_verdict", "조사 결과를 담당자가 읽을 글로 만든다.")
    res = await model_call(vsys, memory.render(st), [])
    text = "".join(b.get("text") or "" for b in (res.get("content") or [])
                   if isinstance(b, dict) and b.get("type") == "text")
    text, why = verify(text, st)
    if why:
        return {"ok": False, "stopped": st.get("stopped") or "no_evidence", "error": why,
                "rounds": st.get("round"), "records": len(st.get("records") or {})}

    return {"ok": True, "text": masker.unmask(text),
            "stopped": st.get("stopped") or "", "rounds": int(st.get("round") or 0),
            "records": len(st.get("records") or {}),
            "probes": len(st.get("probes") or []),
            "table": st.get("table") or [], "winner": H.winner(st.get("table") or []),
            "loop": G.loop_mode()}
