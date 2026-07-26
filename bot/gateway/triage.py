"""트리아지 오케스트레이터 — 수집 → LLM → Slack. app.py의 triage 경로가 호출."""

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
