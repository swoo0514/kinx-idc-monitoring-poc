"""Slack 게시 (Block Kit). 환경변수: SLACK_BOT_TOKEN, SLACK_CHANNEL_ID. 없으면 로그만."""

import logging
import os

import httpx

from . import collector   # 조회 상태 상수(SOURCE_*) 단일 정의 참조

log = logging.getLogger("gateway.slack")

API = "https://slack.com/api/chat.postMessage"

_SEV_EMOJI = {"SEV1": "🔴", "SEV2": "🟠", "SEV3": "🟡", "SEV4": "🔵", "NONE": "⚪"}
_SOURCE_LABEL = {"logs": "로그(Loki)", "security": "보안(Wazuh)"}


def _source_note(sources: dict) -> str:
    """교차 소스 조회 실패를 카드에 드러낸다 — 빈 결과가 "이상 없음"으로 읽히는 것을 막는다 (G1)."""
    sources = sources or {}
    failed = [_SOURCE_LABEL[k] for k in _SOURCE_LABEL
              if sources.get(k) == collector.SOURCE_UNAVAILABLE]
    off = [_SOURCE_LABEL[k] for k in _SOURCE_LABEL
           if sources.get(k) == collector.SOURCE_DISABLED]
    parts = []
    if failed:
        parts.append(f"⚠️ 조회 실패: {', '.join(failed)} — 이 축은 '이상 없음'이 아니라 '미상'")
    if off:
        parts.append(f"미배선: {', '.join(off)}")
    return "  ·  ".join(parts)


def _grafana_link(host: str) -> str:
    """Slack 카드→Grafana 딥링크. GRAFANA_URL 설정 시만. 그 호스트·최근 창으로 필터(데모 A 재사용)."""
    base = os.environ.get("GRAFANA_URL", "").rstrip("/")
    dash = os.environ.get("GRAFANA_DASHBOARD", "kinx-overview")
    if not base or not host:
        return ""
    return f"{base}/d/{dash}?var-host={host}&from=now-30m&to=now"


def _blocks(alert_name: str, sev: str, host: str, verdict: str, body: str,
            sources: dict = None) -> list:
    head = f"{_SEV_EMOJI.get(sev, '⚪')} [{sev}] {alert_name}"
    context = f"host: {host}  ·  판정: {verdict}"
    blocks = [
        {"type": "header", "text": {"type": "plain_text", "text": head[:150], "emoji": True}},
        {"type": "context", "elements": [{"type": "mrkdwn", "text": context}]},
    ]
    note = _source_note(sources)
    if note:
        blocks.append({"type": "context", "elements": [{"type": "mrkdwn", "text": note}]})
    blocks += [
        {"type": "divider"},
        {"type": "section", "text": {"type": "mrkdwn", "text": body[:2900]}},  # Slack section 한도
    ]
    link = _grafana_link(host)
    if link:
        blocks.append({"type": "context", "elements": [
            {"type": "mrkdwn",
             "text": f"📊 <{link}|Grafana에서 이 호스트 원본(지표·로그·보안) 열기>"}]})
    return blocks


def post_triage(alert_name: str, sev: str, host: str, verdict: str, body: str,
                thread_ts: str = None, sources: dict = None) -> dict:
    """반환의 'ts'는 스레드 앵커 — thread_ts로 되넘기면 같은 스레드에 후속 게시.
    sources: 교차 소스 조회 상태(collect_* 결과의 sources) — 실패 시 카드에 경고 표기."""
    token = os.environ.get("SLACK_BOT_TOKEN", "")
    channel = os.environ.get("SLACK_CHANNEL_ID", "")
    blocks = _blocks(alert_name, sev, host, verdict, body, sources)

    if not token or not channel:
        log.info("[slack skipped: no token] %s / %s / %s\n%s", sev, host, verdict, body)
        return {"ok": False, "skipped": True}

    payload = {"channel": channel, "blocks": blocks,
               "text": f"[{sev}] {alert_name}"}  # 알림·접근성 폴백
    if thread_ts:
        payload["thread_ts"] = thread_ts

    try:
        r = httpx.post(API, headers={"Authorization": f"Bearer {token}",
                                     "Content-Type": "application/json; charset=utf-8"},
                       json=payload, timeout=10)
        data = r.json()
        if not data.get("ok"):
            log.warning("slack post failed: %s", data.get("error"))
        return data
    except Exception as e:
        log.warning("slack post exception: %s", e)
        return {"ok": False, "error": str(e)}
