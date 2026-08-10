"""트리아지 오케스트레이터 — 수집 → LLM → Slack. app.py의 triage 경로가 호출."""

import asyncio
import logging
import time

from . import collector, holmes, incident as incident_mod, keep, llm, slack

log = logging.getLogger("gateway.triage")

# fire-and-forget 태스크의 강참조. 안 잡으면 GC 로 조용히 사라진다(공식 문서). 가이드 §17.
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
        # 조회를 못 한 것이므로 "신호 없음"이 아니라 "미상" — 가이드 §15
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


def _push_gated(inc, context: dict, reason: str) -> dict:
    """게이트에서 걸러진 사건도 Keep 에는 남긴다 — 근거는 가이드 §14 말미."""
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
                           playbook="analyze", extra={"analyze_ref": analyze_ref(inc)})


def analyze_ref(inc) -> str:
    """사람이 분석을 다시 요청할 때 사건을 되살릴 재료.

    Keep 은 알림 속성을 문자열로 넘기므로 한 줄로 눌러 담는다. 사건을 통째로 저장해 두지
    않고 이 문자열로 되살리는 이유는, 요청 시점에 Zabbix 를 다시 읽어야 그동안 달라진
    상태가 분석에 들어오기 때문이다.
    """
    return "|".join("%s,%s,%s,%s" % (a.source, a.event_id, a.trigger_id or "",
                                     a.incident_class)
                    for a in inc.alerts)


async def run_incident(inc, force: bool = False) -> dict:
    """병합 인시던트 트리아지 — 창 마감 후 IncidentManager.on_close 가 호출. 30초 예산 기준점.

    LLM·Slack 은 블로킹이라 to_thread 로 감싼다 — 동시 인시던트 타이머를 막지 않게.
    예외를 위로 던지지 않는다.

    force 는 사람이 직접 요청한 경우다. 발동 조건을 건너뛰고 분석한다 — 봇이 안 하기로
    판단한 것을 사람이 뒤집는 경로이므로 조건을 다시 걸면 요청이 무시된다.
    """
    t0 = time.monotonic()
    timings = {}
    sev = inc.dominant_sev()

    try:
        zbx = collector.ZabbixClient()
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
    if not fire:
        await asyncio.to_thread(_push_gated, inc, context, reason)
        timings["total_s"] = round(time.monotonic() - t0, 2)
        log.info("gate skip fp=%s alerts=%d reason=%s timings=%s",
                 inc.fingerprint(), len(inc.alerts), reason, timings)
        return {"fingerprint": inc.fingerprint(), "alert_count": len(inc.alerts),
                "gated_out": True, "reason": reason, "timings": timings}
    # 사유와 조회 상태를 함께 남긴다 — 조회 실패로 인한 보수적 발동을 사후에 구분하려면 필요
    # 연계 건수도 남긴다 — sources 만으로는 몇 건 붙었는지 알 수 없다.
    log.info("gate fire fp=%s alerts=%d reason=%s sources=%s open_links=%d",
             inc.fingerprint(), len(inc.alerts), reason, context.get("sources"),
             len(context.get("open_problems") or []))

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
                                     context.get("sources"))
    timings["slack_s"] = round(time.monotonic() - t2, 2)
    # fingerprint 고정 → 심층조사가 별개 알림이 아니라 같은 행에 enrich 된다
    await asyncio.to_thread(keep.push_alert, headline, sev, inc.host, reply["text"],
                            chronic, fingerprint=fp, classes=classes,
                            alert_count=n, merge=merge_note,
                            sources=_sources_note(context))

    fire_h, reason_h = holmes.should_investigate(sev, reply["degraded"],
                                                 [a.source for a in inc.alerts],
                                                 merged=inc.is_merged(),
                                                 verdict=incident_mod.dominant_verdict(context))
    if fire_h:
        log.info("holmes deep-dive scheduled fp=%s reason=%s", fp, reason_h)
        _spawn_bg(_deep_investigate(
            inc.host,
            holmes.build_question([a.alert_name for a in inc.alerts],
                                  inc.classes(), inc.window_s()),
            sev, fp, anchor or posted.get("ts")))

    timings["total_s"] = round(time.monotonic() - t0, 2)
    log.info("incident triage done fp=%s alerts=%d provider=%s degraded=%s timings=%s",
             inc.fingerprint(), n, reply["provider"], reply["degraded"], timings)
    return {"fingerprint": inc.fingerprint(), "alert_count": n,
            "provider": reply["provider"], "degraded": reply["degraded"],
            "timings": timings, "slack_ok": bool(posted.get("ok")),
            "thread_ts": posted.get("ts")}


async def _deep_investigate(host: str, question: str, sev: str,
                            fingerprint: str = "", thread_ts: str = None) -> None:
    """백그라운드 심층조사 → Slack 스레드 답글 + Keep Note enrich. 회수 경로는 가이드 §17."""
    t0 = time.monotonic()
    res = await asyncio.to_thread(holmes.investigate, host, question)
    took = round(time.monotonic() - t0, 1)
    if not res.get("ok"):
        log.warning("holmes deep-dive no result host=%s took=%ss err=%s",
                    host, took, res.get("error"))
        return
    analysis = res["analysis"]
    await asyncio.to_thread(slack.post_triage, f"[심층조사] {host} — HolmesGPT",
                            sev, host, "심층조사", analysis, thread_ts)
    if fingerprint:
        await asyncio.to_thread(keep.enrich_note, fingerprint, analysis)
    log.info("holmes deep-dive done host=%s took=%ss (slack thread + keep note)", host, took)
