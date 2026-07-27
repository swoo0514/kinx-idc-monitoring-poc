"""트리아지 오케스트레이터 — 수집 → LLM → Slack. app.py의 triage 경로가 호출."""

import asyncio
import logging
import time

from . import collector, llm, slack

log = logging.getLogger("gateway.triage")


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

    t1 = time.monotonic()
    reply = await asyncio.to_thread(llm.triage_reply, context, sev)
    timings["llm_s"] = round(time.monotonic() - t1, 2)

    n = len(inc.alerts)
    headline = (f"{n}건이 1개 사건 · {inc.host}" if inc.is_merged()
                else inc.alerts[0].alert_name)
    verdict = f"{n}건 병합" if inc.is_merged() else "단일"
    t2 = time.monotonic()
    posted = await asyncio.to_thread(slack.post_triage, headline, sev, inc.host,
                                     verdict, reply["text"])
    timings["slack_s"] = round(time.monotonic() - t2, 2)

    timings["total_s"] = round(time.monotonic() - t0, 2)
    log.info("incident triage done fp=%s alerts=%d provider=%s degraded=%s timings=%s",
             inc.fingerprint(), n, reply["provider"], reply["degraded"], timings)
    return {"fingerprint": inc.fingerprint(), "alert_count": n,
            "provider": reply["provider"], "degraded": reply["degraded"],
            "timings": timings, "slack_ok": bool(posted.get("ok")),
            "thread_ts": posted.get("ts")}
