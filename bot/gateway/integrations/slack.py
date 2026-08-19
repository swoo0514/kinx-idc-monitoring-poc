"""Slack 게시 (Block Kit). 환경변수: SLACK_BOT_TOKEN, SLACK_CHANNEL_ID. 없으면 로그만."""

import logging
import os

import httpx

from ..alerts import collector

log = logging.getLogger("gateway.slack")

LINK_PAD_S = 900   # 링크 창을 사건 앞뒤로 얼마나 벌릴지
API = "https://slack.com/api/chat.postMessage"

_SEV_EMOJI = {"SEV1": "🔴", "SEV2": "🟠", "SEV3": "🟡", "SEV4": "🔵", "NONE": "⚪"}
# 축이 늘 때 여기를 빠뜨리면 그 축이 통째로 실패해도 카드에 아무 표시가 안 난다.
# open_problems·metrics 가 실제로 그렇게 빠져 있었다.
_SOURCE_LABEL = {"logs": "로그(Loki)", "security": "보안(Wazuh)",
                 "metrics": "지표(Zabbix)", "open_problems": "선행 문제"}


def _source_note(sources: dict) -> str:
    """교차 소스 조회 실패를 카드에 드러낸다 — 빈 결과가 "이상 없음"으로 읽히는 것을 막는다 (G1)."""
    sources = sources or {}
    failed = [_SOURCE_LABEL[k] for k in _SOURCE_LABEL
              if sources.get(k) == collector.SOURCE_UNAVAILABLE]
    off = [_SOURCE_LABEL[k] for k in _SOURCE_LABEL
           if sources.get(k) == collector.SOURCE_DISABLED]
    unmatched = [_SOURCE_LABEL[k] for k in _SOURCE_LABEL
                 if sources.get(k) == collector.SOURCE_UNMATCHED]
    parts = []
    if failed:
        parts.append(f"⚠️ 조회 실패: {', '.join(failed)} — 이 축은 '이상 없음'이 아니라 '미상'")
    if unmatched:
        parts.append(f"⚠️ 이름 불일치: {', '.join(unmatched)} — 이 호스트를 그 이름으로 찾지 못했다")
    if off:
        parts.append(f"미배선: {', '.join(off)}")
    return "  ·  ".join(parts)


def _grafana_link(host: str, event_ts: float = 0) -> str:
    """Slack 카드→Grafana 딥링크. GRAFANA_URL 설정 시만. 그 호스트로 필터(데모 A 재사용).

    창은 **사건 시각 기준 절대 구간**이다. `now-30m` 같은 상대 구간을 쓰면 재기동 후
    대기 알림을 다시 넣었을 때 엉뚱한 구간이 열린다. 사건 시각을 모르면 그때만 상대
    구간으로 내려간다.
    """
    base = os.environ.get("GRAFANA_URL", "").rstrip("/")
    dash = os.environ.get("GRAFANA_DASHBOARD", "kinx-overview")
    if not base or not host:
        return ""
    if event_ts:
        frm = int((event_ts - LINK_PAD_S) * 1000)   # Grafana 는 밀리초를 받는다
        to = int((event_ts + LINK_PAD_S) * 1000)
        return f"{base}/d/{dash}?var-host={host}&from={frm}&to={to}"
    return f"{base}/d/{dash}?var-host={host}&from=now-30m&to=now"


def _blocks(alert_name: str, sev: str, host: str, verdict: str, body: str,
            sources: dict = None, event_ts: float = 0) -> list:
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
    link = _grafana_link(host, event_ts)
    if link:
        blocks.append({"type": "context", "elements": [
            {"type": "mrkdwn",
             "text": f"📊 <{link}|Grafana에서 이 호스트 원본(지표·로그·보안) 열기>"}]})
    return blocks


def post_raw(alert_name: str, sev: str, host: str, thread_ts: str = None) -> dict:
    """트리거 즉시 띄우는 원시 신호 카드 — LLM·수집 호출 없이 "무슨 일이 났다"만 (P1-A).

    병합 디바운스 창이 닫혀야 나오는 분석 카드는 최악 1분 이상 걸린다. 그동안 사람이 아무것도
    못 보는 것을 막는다. 반환의 'ts'가 스레드 앵커이며, 분석은 그 스레드 답글로 이어 붙는다.
    thread_ts 를 주면 후속 신호를 같은 스레드 답글로 단다(부모는 인시던트당 하나만 유지).
    """
    token = os.environ.get("SLACK_BOT_TOKEN", "")
    channel = os.environ.get("SLACK_CHANNEL_ID", "")
    head = f"{_SEV_EMOJI.get(sev, '⚪')} [{sev}] {alert_name}"
    note = ("추가 신호 — 같은 사건으로 묶임" if thread_ts
            else "원시 신호 · 분석은 이 스레드에 이어집니다")
    blocks = [
        {"type": "header", "text": {"type": "plain_text", "text": head[:150], "emoji": True}},
        {"type": "context", "elements": [{"type": "mrkdwn", "text": f"host: {host}  ·  {note}"}]},
    ]
    if not token or not channel:
        log.info("[slack skipped: no token] raw %s / %s", sev, host)
        return {"ok": False, "skipped": True}
    payload = {"channel": channel, "blocks": blocks, "text": f"[{sev}] {alert_name}"}
    if thread_ts:
        payload["thread_ts"] = thread_ts
    try:
        r = httpx.post(API, headers={"Authorization": f"Bearer {token}",
                                     "Content-Type": "application/json; charset=utf-8"},
                       json=payload, timeout=10)
        data = r.json()
        if not data.get("ok"):
            log.warning("slack raw post failed: %s", data.get("error"))
        return data
    except Exception as e:
        log.warning("slack raw post exception: %s", e)
        return {"ok": False, "error": str(e)}


def post_digest(alert_name: str, sev: str, host: str, note: str = "") -> dict:
    """덜 급한 알림(SEV3)을 별도 채널로 경량 게시. LLM·수집 호출 없음.

    채널이 설정돼 있지 않으면 **게시하지 않는다.** 메인 채널로 흘려보내면 노이즈를 걷어내려던
    목적이 정확히 뒤집히기 때문이다(진단 ① Warning 99.5%). 게시를 건너뛰어도 Keep 에는 남으므로
    기록이 사라지지는 않는다.
    """
    token = os.environ.get("SLACK_BOT_TOKEN", "")
    channel = os.environ.get("SLACK_CHANNEL_ID_DIGEST", "")
    if not token or not channel:
        log.info("[digest skipped: no SLACK_CHANNEL_ID_DIGEST] %s / %s / %s",
                 sev, host, alert_name)
        return {"ok": False, "skipped": True}

    head = f"{_SEV_EMOJI.get(sev, '⚪')} [{sev}] {alert_name}"
    ctx = f"host: {host}  ·  덜 급한 알림 — 즉시 조치 대상 아님"
    if note:
        ctx += f"  ·  {note}"
    blocks = [
        {"type": "header", "text": {"type": "plain_text", "text": head[:150], "emoji": True}},
        {"type": "context", "elements": [{"type": "mrkdwn", "text": ctx}]},
    ]
    link = _grafana_link(host)
    if link:
        blocks.append({"type": "context", "elements": [
            {"type": "mrkdwn", "text": f"📊 <{link}|Grafana에서 이 호스트 원본 열기>"}]})
    try:
        r = httpx.post(API, headers={"Authorization": f"Bearer {token}",
                                     "Content-Type": "application/json; charset=utf-8"},
                       json={"channel": channel, "blocks": blocks,
                             "text": f"[{sev}] {alert_name}"}, timeout=10)
        data = r.json()
        if not data.get("ok"):
            log.warning("slack digest post failed: %s", data.get("error"))
        return data
    except Exception as e:
        log.warning("slack digest post exception: %s", e)
        return {"ok": False, "error": str(e)}


def post_triage(alert_name: str, sev: str, host: str, verdict: str, body: str,
                thread_ts: str = None, sources: dict = None,
                event_ts: float = 0) -> dict:
    """반환의 'ts'는 스레드 앵커 — thread_ts로 되넘기면 같은 스레드에 후속 게시.
    sources: 교차 소스 조회 상태(collect_* 결과의 sources) — 실패 시 카드에 경고 표기."""
    token = os.environ.get("SLACK_BOT_TOKEN", "")
    channel = os.environ.get("SLACK_CHANNEL_ID", "")
    blocks = _blocks(alert_name, sev, host, verdict, body, sources, event_ts)

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
