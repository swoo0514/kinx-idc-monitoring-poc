"""트리아지 오케스트레이터 — 수집 → LLM → Slack. app.py의 triage 경로가 호출."""

import asyncio
import logging
import time

from . import collector, holmes, incident as incident_mod, keep, llm, slack

log = logging.getLogger("gateway.triage")

# fire-and-forget 백그라운드 태스크 — 강참조 유지(GC 중도소멸 방지) + 완료 시 정리·예외로깅.
# 근거: docs.python.org asyncio.create_task "save a reference ... may be garbage collected".
_bg_tasks: set = set()


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
    except Exception as e:   # 수집 실패해도 최소 컨텍스트로 진행
        log.warning("collect failed for event=%s: %s", event_id, e)
        context = {"event": {"name": alert_name}, "trigger": {}, "host": {},
                   "metrics": [], "prejudge": {}}
    timings["collect_s"] = round(time.monotonic() - t0, 2)

    t1 = time.monotonic()
    reply = llm.triage_reply(context, sev)
    timings["llm_s"] = round(time.monotonic() - t1, 2)

    ev = context.get("event", {}) or {}
    host = host_display or (context.get("host", {}) or {}).get("host", "") or ev.get("host", "")
    name = alert_name or ev.get("name", "(알림명 없음)")
    verdict = (context.get("prejudge", {}) or {}).get("verdict", "?")
    t2 = time.monotonic()
    posted = slack.post_triage(name, sev, host, verdict, reply["text"])
    timings["slack_s"] = round(time.monotonic() - t2, 2)
    keep.push_alert(name, sev, host, reply["text"], prejudge=str(verdict))

    timings["total_s"] = round(time.monotonic() - t0, 2)
    log.info("triage done event=%s provider=%s degraded=%s timings=%s",
             event_id, reply["provider"], reply["degraded"], timings)
    return {"provider": reply["provider"], "degraded": reply["degraded"],
            "timings": timings, "slack_ok": bool(posted.get("ok")),
            "thread_ts": posted.get("ts")}


async def run_incident(inc) -> dict:
    """병합 인시던트 트리아지 — 창 마감 후 IncidentManager.on_close가 호출. 30초 예산 기준점.

    수집(3소스)→LLM(1회)→Slack(1회). LLM·Slack은 블로킹이라 to_thread로 이벤트 루프를
    막지 않는다(동시 인시던트 타이머 보호). 예외를 위로 던지지 않음.
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
        }
    timings["collect_s"] = round(time.monotonic() - t0, 2)

    # 발동조건 게이트 — 교차 상관할 게 있을 때만 LLM 호출 (§14 발동조건 게이트)
    fire, reason = incident_mod.should_triage(inc, context)
    if not fire:
        timings["total_s"] = round(time.monotonic() - t0, 2)
        log.info("gate skip fp=%s alerts=%d reason=%s timings=%s",
                 inc.fingerprint(), len(inc.alerts), reason, timings)
        return {"fingerprint": inc.fingerprint(), "alert_count": len(inc.alerts),
                "gated_out": True, "reason": reason, "timings": timings}

    t1 = time.monotonic()
    reply = await asyncio.to_thread(llm.triage_reply, context, sev)
    timings["llm_s"] = round(time.monotonic() - t1, 2)

    n = len(inc.alerts)
    headline = (f"{n}건이 1개 사건 · {inc.host}" if inc.is_merged()
                else inc.alerts[0].alert_name)
    verdict = f"{n}건 병합" if inc.is_merged() else "단일"
    fp = inc.fingerprint()
    t2 = time.monotonic()
    posted = await asyncio.to_thread(slack.post_triage, headline, sev, inc.host,
                                     verdict, reply["text"])
    timings["slack_s"] = round(time.monotonic() - t2, 2)
    # 봇 알림은 사건 fingerprint로 고정 → 홈즈 심층분석이 같은 행에 enrich (별개 알림 방지)
    await asyncio.to_thread(keep.push_alert, headline, sev, inc.host, reply["text"],
                            verdict, fingerprint=fp)

    # 심층조사 자동 발동(read=auto 규칙): SEV1/봇 열화 + 비-MSP → 백그라운드 HolmesGPT.
    # 결과는 별개 알림이 아니라 (1)Slack 원래 스레드 답글 (2)Keep 같은 알림 Note enrich 로.
    # 3.5분 수준이라 30초 예산과 분리, fire-and-forget. 승인 아님(읽기 전용).
    fire_h, reason_h = holmes.should_investigate(sev, reply["degraded"],
                                                 [a.source for a in inc.alerts],
                                                 merged=inc.is_merged())
    if fire_h:
        log.info("holmes deep-dive scheduled fp=%s reason=%s", fp, reason_h)
        _spawn_bg(_deep_investigate(inc.host, headline, sev, fp, posted.get("ts")))

    timings["total_s"] = round(time.monotonic() - t0, 2)
    log.info("incident triage done fp=%s alerts=%d provider=%s degraded=%s timings=%s",
             inc.fingerprint(), n, reply["provider"], reply["degraded"], timings)
    return {"fingerprint": inc.fingerprint(), "alert_count": n,
            "provider": reply["provider"], "degraded": reply["degraded"],
            "timings": timings, "slack_ok": bool(posted.get("ok")),
            "thread_ts": posted.get("ts")}


async def _deep_investigate(host: str, incident_summary: str, sev: str,
                            fingerprint: str = "", thread_ts: str = None) -> None:
    """백그라운드 HolmesGPT 심층조사 → (1)Slack 원래 알림 스레드 답글(읽기) (2)Keep 같은
    알림 Note enrich(실행 화면). 별개 알림을 만들지 않아 피드에 사건 1행 유지.
    블로킹 호출은 to_thread로 감싸 이벤트 루프 비차단. 실패해도 조용히 종료."""
    t0 = time.monotonic()
    res = await asyncio.to_thread(holmes.investigate, host,
                                  f"Incident: {incident_summary}.")
    took = round(time.monotonic() - t0, 1)
    if not res.get("ok"):
        log.warning("holmes deep-dive no result host=%s took=%ss err=%s",
                    host, took, res.get("error"))
        return
    analysis = res["analysis"]
    # (1) 읽기: 봇 초동분석이 올라간 Slack 스레드에 심층분석 답글
    await asyncio.to_thread(slack.post_triage, f"[심층조사] {host} — HolmesGPT",
                            sev, host, "심층조사", analysis, thread_ts)
    # (2) 실행 화면: 원래 Keep 알림에 Note로 첨부(fingerprint 매칭). 별개 알림 아님.
    if fingerprint:
        await asyncio.to_thread(keep.enrich_note, fingerprint, analysis)
    log.info("holmes deep-dive done host=%s took=%ss (slack thread + keep note)", host, took)
