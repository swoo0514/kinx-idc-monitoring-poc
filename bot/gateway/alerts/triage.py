"""트리아지 오케스트레이터 — 수집 → LLM → Slack. app.py의 triage 경로가 호출."""

import asyncio
import logging
import time

from . import collector, incident as incident_mod, prior
from .. import llm, store
from ..integrations import grafana, holmes, keep, slack

log = logging.getLogger("gateway.triage")

# 선별 규칙이 바뀌면 올린다. 증거에 같이 남겨야 "그때 왜 저 줄이 실렸나"에 답할 수 있다.
SELECT_POLICY_VERSION = "log-select-v1"

# fire-and-forget 태스크의 강참조. 안 잡으면 GC 로 조용히 사라진다(공식 문서). 가이드 §10.
_bg_tasks: set = set()


def _sources_note(context: dict) -> str:
    """"logs:ok,security:unavailable" — 이 사건이 어느 축을 실제로 읽었는지 Keep 에 남긴다."""
    s = context.get("sources") or {}
    return ",".join("%s:%s" % (k, s[k]) for k in sorted(s)) if isinstance(s, dict) else ""


def _spawn_bg(coro) -> None:
    task = asyncio.create_task(coro)
    _bg_tasks.add(task)

    def _done(t: asyncio.Task) -> None:
        _bg_tasks.discard(t)
        if not t.cancelled() and t.exception() is not None:
            log.warning("background task crashed: %s", t.exception())

    task.add_done_callback(_done)


async def run(event_id: str, trigger_id: str, sev: str,
              host_display: str = "", alert_name: str = "") -> dict:
    """반환: 구간별 소요 + Slack 결과. 예외를 위로 던지지 않음(웹훅 200 유지)."""
    t0 = time.monotonic()
    timings = {}

    try:
        zbx = collector.ZabbixClient()
        context = await collector.collect_context(zbx, event_id, trigger_id)
    except Exception as e:
        log.warning("collect failed for event=%s: %s", event_id, e)
        # 조회를 못 한 것이므로 "신호 없음"이 아니라 "미상" — 가이드 §12
        context = {"event": {"name": alert_name}, "trigger": {}, "host": {},
                   "metrics": [], "prejudge": {}, "logs": [], "security": [],
                   "sources": {"logs": collector.SOURCE_UNAVAILABLE,
                               "security": collector.SOURCE_UNAVAILABLE}}
    timings["collect_s"] = round(time.monotonic() - t0, 2)

    t1 = time.monotonic()
    reply = llm.triage_reply(context, sev)
    timings["llm_s"] = round(time.monotonic() - t1, 2)

    ev = context.get("event", {}) or {}
    host = host_display or (context.get("host", {}) or {}).get("host", "") or ev.get("host", "")
    name = alert_name or ev.get("name", "(알림명 없음)")
    verdict = (context.get("prejudge", {}) or {}).get("verdict", "?")
    t2 = time.monotonic()
    posted = slack.post_triage(name, sev, host, verdict, reply["text"],
                               sources=context.get("sources"))
    timings["slack_s"] = round(time.monotonic() - t2, 2)
    keep.push_alert(name, sev, host, reply["text"], prejudge=str(verdict),
                    sources=_sources_note(context))

    timings["total_s"] = round(time.monotonic() - t0, 2)
    log.info("triage done event=%s provider=%s degraded=%s timings=%s",
             event_id, reply["provider"], reply["degraded"], timings)
    return {"provider": reply["provider"], "degraded": reply["degraded"],
            "timings": timings, "slack_ok": bool(posted.get("ok")),
            "thread_ts": posted.get("ts")}


def _push_gated(inc, context: dict, reason: str, jid=None) -> dict:
    """게이트에서 걸러진 사건도 Keep 에는 남긴다 — 근거는 가이드 §8 말미."""
    verdict = incident_mod.dominant_verdict(context) or "미상"
    classes = ", ".join(sorted(inc.classes()))
    note = (f"*분석 생략 — 봇 판단*\n"
            f"사유: {reason}\n"
            f"유형: {classes}  ·  알림 {len(inc.alerts)}건\n"
            f"교차 신호가 없어 LLM 을 호출하지 않았다. 판정과 유형만 기록한다.\n"
            f"판단이 틀렸다고 보면 Run Workflow 로 분석을 직접 요청한다.")
    return keep.push_alert(inc.alerts[0].alert_name or "(알림명 없음)",
                           inc.dominant_sev(), inc.host, note,
                           prejudge=verdict, fingerprint=inc.fingerprint(),
                           classes=classes, alert_count=len(inc.alerts),
                           sources=_sources_note(context),
                           playbook="analyze",
                           extra={"analyze_ref": analyze_ref(inc), "judgment_id": jid})


def analyze_ref(inc) -> str:
    """사람이 분석을 다시 요청할 때 사건을 되살릴 재료."""
    return "|".join("%s,%s,%s,%s" % (a.source, a.event_id, a.trigger_id or "",
                                     a.incident_class)
                    for a in inc.alerts)


async def _annotate(jid, inc, sev, headline: str, note: str, text: str,
                    event_ts: float) -> None:
    """판정을 관측 타임라인에 남긴다 (§25-4). 30초 예산 밖이라 배경으로 돈다."""
    body = "[%s] %s · %s\n%s" % (sev, headline, note, (text or "").strip()[:400])
    if jid:
        body += "\n(판정 #%s)" % jid
    # 사건 유형을 태그로 단다 — 패널이 자기 유형만 가져갈 수 있는 유일한 통로다
    tags = ["kinx-bot", sev, inc.host] + sorted(inc.classes())
    aid = await asyncio.to_thread(grafana.annotate, body, event_ts, tags)
    if aid and jid:
        await asyncio.to_thread(_finish, jid, {"annotation_id": aid})


def _record(inc, context, sev, fired, reason, origin, event_ts):
    """판정을 이력에 남기고 식별자를 돌려준다 (§24). 실패해도 흐름을 막지 않는다."""
    try:
        return store.record_judgment({
            "fingerprint": inc.fingerprint(), "host": inc.host,
            "ikey": "|".join(str(x) for x in (inc.key or ())),
            "realm": inc.key[0] if inc.key else "",
            "source": inc.alerts[0].source if inc.alerts else "",
            "classes": ",".join(sorted(inc.classes())),
            "alert_count": len(inc.alerts), "sev": sev,
            "verdict": incident_mod.dominant_verdict(context) or "",
            "gate_fired": 1 if fired else 0, "gate_reason": reason,
            "sources": _sources_note(context), "origin": origin,
            "event_ts": event_ts,
        })
    except Exception as e:
        log.warning("판정 이력 기록 실패: %s", e)
        return None


def _evidence(context: dict, reply: dict) -> str:
    """사람이 원문으로 되짚을 재료 (§25-7). 모델에는 안 간다."""
    import hashlib
    import json
    try:
        sel = [r for r in (context.get("logs") or []) if "line" in r]
        digest = hashlib.sha256(
            json.dumps([r["line"] for r in sel], ensure_ascii=False).encode()
        ).hexdigest()[:16]
        return json.dumps({
            "logql": context.get("logs_query", ""),
            "from": int(context.get("logs_from") or 0),
            "to": int(context.get("logs_to") or 0),
            "fetch_limit": collector.LOKI_FETCH_LIMIT,
            "send_limit": collector.LOKI_SEND_LIMIT,
            "fetched": context.get("logs_fetched"),
            "selected": context.get("logs_selected"),
            "fetch_capped": bool(context.get("logs_fetch_capped")),
            "clipped": context.get("logs_clipped"),
            "policy": SELECT_POLICY_VERSION,
            "digest": digest,
        }, ensure_ascii=False)
    except Exception as e:
        log.warning("증거 참조를 못 만들었다: %s", e)
        return ""


def _finish(jid, fields: dict) -> None:
    try:
        store.finish(jid, fields)
    except Exception as e:
        log.warning("판정 이력 갱신 실패: %s", e)


async def run_incident(inc, force: bool = False) -> dict:
    """병합 인시던트 트리아지 — 창 마감 후 IncidentManager.on_close 가 호출. 30초 예산 기준점."""
    t0 = time.monotonic()
    timings = {}
    sev = inc.dominant_sev()

    try:
        # 알림이 온 감시 서버에 되묻는다 — 서버가 둘 이상이면 이게 갈린다.
        zbx = collector.ZabbixClient(source=inc.alerts[0].source if inc.alerts else "")
        context = await collector.collect_incident_context(zbx, inc)
    except Exception as e:
        log.warning("collect_incident failed for %s: %s", inc.fingerprint(), e)
        context = {
            "incident": {"host": inc.host, "classes": sorted(inc.classes()),
                         "alert_count": len(inc.alerts), "merge_reason": inc.merge_reason(),
                         "fingerprint": inc.fingerprint(), "dominant_sev": sev},
            "host": {}, "alerts": [{"name": a.alert_name, "source": a.source,
                                    "sev": a.sev, "class": a.incident_class}
                                   for a in inc.alerts],
            "logs": [], "security": [],
            "sources": {"logs": collector.SOURCE_UNAVAILABLE,
                        "security": collector.SOURCE_UNAVAILABLE},
        }
    timings["collect_s"] = round(time.monotonic() - t0, 2)

    fire, reason = (True, "사람 요청") if force else incident_mod.should_triage(inc, context)
    # 카드보다 먼저 남긴다 — 카드에 실을 식별자가 여기서 나오고 죽어도 판정은 남는다
    event_ts = collector.reference_time(inc, int(time.time()))
    jid = await asyncio.to_thread(_record, inc, context, sev, fire, reason,
                                  "forced" if force else "auto", event_ts)
    if not fire:
        await asyncio.to_thread(_push_gated, inc, context, reason, jid)
        timings["total_s"] = round(time.monotonic() - t0, 2)
        await asyncio.to_thread(_finish, jid, {"total_s": timings["total_s"]})
        log.info("gate skip fp=%s alerts=%d reason=%s timings=%s",
                 inc.fingerprint(), len(inc.alerts), reason, timings)
        return {"fingerprint": inc.fingerprint(), "alert_count": len(inc.alerts),
                "gated_out": True, "reason": reason, "timings": timings}
    # 사유·조회 상태·연계 건수를 함께 남긴다 — 보수적 발동을 사후에 구분하려면 필요하다
    log.info("gate fire fp=%s alerts=%d reason=%s sources=%s open_links=%d",
             inc.fingerprint(), len(inc.alerts), reason, context.get("sources"),
             len(context.get("open_problems") or []))

    # 과거 결론을 붙인다. 방금 남긴 이 사건의 행은 빼고 고른다 (§25-6).
    try:
        context["prior"] = await asyncio.to_thread(prior.select, inc, jid)
    except Exception as e:
        log.warning("과거 결론 조회 실패: %s", e)
    t1 = time.monotonic()
    reply = await asyncio.to_thread(llm.triage_reply, context, sev)
    timings["llm_s"] = round(time.monotonic() - t1, 2)

    n = len(inc.alerts)
    headline = (f"{n}건이 1개 사건 · {inc.host}" if inc.is_merged()
                else inc.alerts[0].alert_name)
    merge_note = f"{n}건 병합" if inc.is_merged() else "단일"
    chronic = incident_mod.dominant_verdict(context) or "미상"
    classes = ", ".join(sorted(inc.classes()))
    fp = inc.fingerprint()
    t2 = time.monotonic()
    # 분석은 원시 신호 스레드의 답글로. 앵커가 없으면 최상위 게시로 자연 열화.
    anchor = getattr(inc, "anchor_ts", "") or None
    posted = await asyncio.to_thread(slack.post_triage, headline, sev, inc.host,
                                     f"{merge_note} · {chronic}", reply["text"], anchor,
                                     context.get("sources"), event_ts)
    timings["slack_s"] = round(time.monotonic() - t2, 2)
    # fingerprint 고정 → 심층조사가 별개 알림이 아니라 같은 행에 enrich 된다
    await asyncio.to_thread(keep.push_alert, headline, sev, inc.host, reply["text"],
                            chronic, fingerprint=fp, classes=classes,
                            alert_count=n, merge=merge_note,
                            sources=_sources_note(context),
                            extra={"judgment_id": jid})

    fire_h, reason_h = holmes.should_investigate(sev, reply["degraded"],
                                                 [a.source for a in inc.alerts],
                                                 merged=inc.is_merged(),
                                                 verdict=incident_mod.dominant_verdict(context))
    if fire_h:
        log.info("deep-dive scheduled fp=%s reason=%s", fp, reason_h)
        _spawn_bg(_deep_investigate(
            inc.host,
            holmes.build_question([a.alert_name for a in inc.alerts],
                                  inc.classes(), inc.window_s()),
            sev, fp, anchor or posted.get("ts"), context=context, jid=jid))

    timings["total_s"] = round(time.monotonic() - t0, 2)
    await asyncio.to_thread(_finish, jid, {
        "provider": reply.get("provider", ""),
        "degraded": 1 if reply.get("degraded") else 0,
        "total_s": timings["total_s"], "summary": reply.get("text", ""),
        "change": reply.get("change", ""),
        "prior_used": 1 if context.get("prior") else 0,
        "evidence": _evidence(context, reply)})
    # 게이트에서 걸러진 사건은 안 찍는다 — 다수라 타임라인이 노이즈와 같은 모양이 된다
    _spawn_bg(_annotate(jid, inc, sev, headline, f"{merge_note} · {chronic}",
                        reply.get("text", ""), event_ts))
    log.info("incident triage done fp=%s alerts=%d provider=%s degraded=%s timings=%s",
             inc.fingerprint(), n, reply["provider"], reply["degraded"], timings)
    return {"fingerprint": inc.fingerprint(), "alert_count": n,
            "provider": reply["provider"], "degraded": reply["degraded"],
            "timings": timings, "slack_ok": bool(posted.get("ok")),
            "thread_ts": posted.get("ts")}


async def _deep_investigate(host: str, question: str, sev: str,
                            fingerprint: str = "", thread_ts: str = None,
                            context: dict = None, jid: int = 0) -> None:
    """백그라운드 심층조사 → Slack 스레드 답글 + Keep Note enrich. 회수 경로는 가이드 §36.

    자체 심층 모드가 켜져 있으면 그쪽으로, 아니면 HolmesGPT 로 간다. 둘을 나란히 두는
    것은 같은 사건으로 비교해 보고 제거를 정하기 위해서다(설계서 단계 6).
    """
    from ..deep import entry as deep_entry

    t0 = time.monotonic()
    own = deep_entry.enabled() and context is not None
    if own:
        res = await deep_entry.investigate_incident(context)
        analysis = res.get("text") or ""
        label = "심층조사"
    else:
        res = await asyncio.to_thread(holmes.investigate, host, question)
        analysis = res.get("analysis") or ""
        label = "심층조사 — HolmesGPT"
    took = round(time.monotonic() - t0, 1)

    if not res.get("ok") or not analysis:
        # **실패도 남긴다.** 예전에는 로그 한 줄로 끝나서 담당자도 판정 행도 몰랐다.
        why = res.get("error") or "결과가 비었다"
        log.warning("deep-dive no result host=%s took=%ss stopped=%s err=%s",
                    host, took, res.get("stopped"), why)
        if jid:
            await asyncio.to_thread(_note_deep, jid, {
                "ok": 0, "took_s": took, "stopped": res.get("stopped") or "",
                "error": why, "own": 1 if own else 0})
        return

    await asyncio.to_thread(slack.post_triage, f"[{label}] {host}",
                            sev, host, "심층조사", analysis, thread_ts)
    if fingerprint:
        await asyncio.to_thread(keep.enrich_note, fingerprint, analysis)
    if jid:
        await asyncio.to_thread(_note_deep, jid, {
            "ok": 1, "took_s": took, "stopped": res.get("stopped") or "",
            "rounds": res.get("rounds"), "records": res.get("records"),
            "probes": res.get("probes"), "winner": res.get("winner"),
            "loop": res.get("loop"), "own": 1 if own else 0})
    log.info("deep-dive done host=%s took=%ss own=%s stopped=%s (slack thread + keep note)",
             host, took, own, res.get("stopped"))


def _note_deep(jid: int, fields: dict) -> None:
    """심층 조사 결과를 판정 행에 남긴다. **성공도 실패도 남는다.**

    예전에는 실패가 로그 한 줄로 끝나 담당자도 판정 행도 몰랐다. `store.finish` 를 쓰지
    않는 이유는 그쪽이 모르는 열을 **조용히 버려서** 기록이 안 남고도 성공으로 보이기
    때문이다. 판정 주석은 열을 안 늘려도 되고 나중에 집계로 읽힌다.
    """
    from .. import store

    ok = bool(fields.pop("ok", 0))
    note = " · ".join("%s=%s" % (k, v) for k, v in fields.items() if v not in (None, ""))
    try:
        store.record_feedback(jid, "deep", ok, note=note[:500], who="deep-mode")
    except Exception as e:                       # 기록 실패가 분석을 막으면 안 된다
        log.warning("심층 조사 기록 실패 jid=%s: %s", jid, e)
