"""데모 B·C 공용 알림 게이트웨이 (FastAPI). 실행·배선은 bot/GATEWAY_GUIDE.md."""

import asyncio
import hashlib
import hmac
import logging
import os
import time
from typing import Optional

from fastapi import BackgroundTasks, FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

from . import incident
from . import keep
from . import router as tag_router
from . import severity
from . import slack
from . import triage

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("gateway")

app = FastAPI(title="kinx-poc alert gateway", version="0.1.0")

# 규칙 로드는 incident 모듈 import 시점에 끝나는데, 그때는 아직 로깅이 설정 전이라
# 그 로그가 사라진다. **"예시값 사용 — 재측정 필요"가 정작 서비스에서는 안 보였다**
# (실측 2026-08-10). 기동 시 한 번 더 남겨 어느 규칙으로 도는지가 반드시 드러나게 한다.
log.info("열린 문제 연계 규칙 %d건 / 측정: %s",
         len(incident.OPEN_LINK_RULES), incident.OPEN_LINK_MEASURED)
if not os.environ.get("OPEN_LINK_RULES_FILE"):
    log.warning("OPEN_LINK_RULES_FILE 미지정 — 자리표시자로 동작한다. 운영 적용 전 재측정 필요")


async def _raw_ping(alert, thread_ts):
    """알림 도착 즉시 원시 신호 카드. 반환 ts 가 인시던트 스레드 앵커 (GATEWAY_GUIDE §18)."""
    # Slack 호출은 블로킹이라 to_thread 로 감싼다 — 인시던트 타이머 루프를 막지 않게.
    res = await asyncio.to_thread(slack.post_raw, alert.alert_name or "(알림명 없음)",
                                  alert.sev, alert.host, thread_ts)
    return res.get("ts")


_incidents = incident.IncidentManager(on_close=triage.run_incident, on_signal=_raw_ping)

IDEMPOTENCY_TTL_S = 3600
_seen: dict = {}  # (source, event_id, event_value) -> monotonic. 프로덕션은 Redis (가이드 §10)


def _token_ok(token: str) -> bool:
    expected = os.environ.get("GATEWAY_TOKEN", "")
    return bool(expected) and hmac.compare_digest(token or "", expected)


def _duplicate(key: tuple) -> bool:
    now = time.monotonic()
    for k in [k for k, ts in _seen.items() if now - ts > IDEMPOTENCY_TTL_S]:
        del _seen[k]
    if key in _seen:
        return True
    _seen[key] = now
    return False


class ZabbixEvent(BaseModel):
    source: str  # zabbix-internal | zabbix-msp
    event_id: str
    trigger_id: str = ""   # collector 조회 키. 없으면 수집 축소
    event_value: int = 1   # 1=problem, 0=recovery
    event_name: str = ""
    nseverity: Optional[int] = None   # 매크로 미해석 시 null 허용 → 아래에서 안전값 처리(422 회피)
    host: str = ""
    tags: list = []
    clock: str = ""


class WazuhEvent(BaseModel):
    alert_id: str
    rule_id: str = ""
    rule_level: int = Field(ge=0, le=15)
    rule_description: str = ""
    rule_groups: str = ""   # 콤마 문자열. 분류의 1차 신호
    agent_name: str = ""
    timestamp: str = ""


@app.get("/healthz")
def healthz():
    return {"ok": True, "version": app.version}


@app.post("/webhook/zabbix")
def webhook_zabbix(ev: ZabbixEvent, bg: BackgroundTasks, x_gateway_token: str = Header(default="")):
    if not _token_ok(x_gateway_token):
        raise HTTPException(status_code=401, detail="invalid token")
    if ev.source not in (severity.SOURCE_ZABBIX_INTERNAL, severity.SOURCE_ZABBIX_MSP):
        raise HTTPException(status_code=422, detail="unknown source")
    if _duplicate((ev.source, ev.event_id, ev.event_value)):
        return {"status": "duplicate", "event_id": ev.event_id}

    ns = ev.nseverity
    if ns is None:
        log.warning("event=%s nseverity 누락 — 미디어타입 {EVENT.NSEVERITY} 파라미터 확인. "
                    "안전값(triage)로 처리", ev.event_id)
        ns = 4   # 미상 → High 취급. severity.normalize 의 SEV2 페일세이프와 정합
    sev = severity.normalize(ev.source, ns)
    decision = tag_router.decide(sev, ev.tags, ev.event_value)
    _dispatch(bg, ev.source, ev.event_id, ev.trigger_id, ev.host, ev.event_name, sev,
              decision, ev.tags)
    return {"status": "accepted", "sev": sev, **decision, "event_id": ev.event_id}


@app.post("/webhook/wazuh")
def webhook_wazuh(ev: WazuhEvent, bg: BackgroundTasks, x_gateway_token: str = Header(default="")):
    if not _token_ok(x_gateway_token):
        raise HTTPException(status_code=401, detail="invalid token")
    if _duplicate((severity.SOURCE_WAZUH, ev.alert_id, 1)):
        return {"status": "duplicate", "event_id": ev.alert_id}

    sev = severity.normalize(severity.SOURCE_WAZUH, ev.rule_level)
    decision = tag_router.decide(sev, [], 1)
    _dispatch(bg, severity.SOURCE_WAZUH, ev.alert_id, "", ev.agent_name,
              ev.rule_description, sev, decision, groups=ev.rule_groups)
    return {"status": "accepted", "sev": sev, **decision, "event_id": ev.alert_id}


def _dispatch(bg, source, event_id, trigger_id, host, alert_name, sev, decision,
              tags=None, groups=None):
    """경로별 후속 처리를 백그라운드로 넘긴다 — 웹훅은 즉시 200(발송측 타임아웃 회피)."""
    route = decision["route"]
    cls = incident.classify(alert_name, tags=tags, groups=groups)
    log.info("event=%s source=%s host=%s sev=%s class=%s route=%s playbook=%s",
             event_id, source, host, sev, cls, route, decision["playbook"])
    if route == "triage":
        alert = incident.Alert(
            source=source, event_id=event_id, trigger_id=trigger_id, host=host,
            alert_name=alert_name, sev=sev,
            incident_class=cls, recv=time.monotonic())
        bg.add_task(_incidents.submit, alert)
    elif route in ("digest", "dashboard_only"):
        bg.add_task(_queue_low_severity, host, alert_name, sev, cls,
                    route == "digest")
    elif route == "remediate":
        bg.add_task(_queue_remediation, host, alert_name, sev, decision["playbook"],
                    tag_router.tag_value(tags or [], "service") or "")


def _queue_low_severity(host, alert_name, sev, cls, notify: bool):
    """SEV3(digest)·SEV4(dashboard_only) — 기록만 남기고 분석은 생략 (GATEWAY_GUIDE §19)."""
    # fingerprint 를 (호스트, 유형)으로 고정해 같은 종류가 한 행에 모이게 한다(반복 빈도 랭킹용).
    fp = hashlib.sha1(f"lowsev|{host}|{cls}".encode()).hexdigest()[:12]
    tier = "덜 급함(digest)" if notify else "대시보드 전용"
    note = (f"*{tier}*\n유형: `{cls}`  ·  호스트: `{host}`\n"
            f"심각도가 낮아 분석을 생략했다. 반복 빈도 집계를 위해 기록만 남긴다.")
    res = keep.push_alert(alert_name or "(알림명 없음)", sev, host, note,
                          fingerprint=fp, classes=cls)
    posted = slack.post_digest(alert_name, sev, host) if notify else {"skipped": True}
    log.info("low-sev queued host=%s sev=%s class=%s keep=%s slack=%s",
             host, sev, cls, res.get("ok"), posted.get("ok"))


def _queue_remediation(host, alert_name, sev, playbook, service):
    """조치 후보를 Keep 승인 큐에 등록. 승인·실행은 Keep 워크플로가 담당한다."""
    # fingerprint 를 (호스트·플레이북·서비스)로 고정 — 승인할 것이 한 줄로 모인다.
    fp = hashlib.sha1(f"remediate|{host}|{playbook}|{service}".encode()).hexdigest()[:12]
    note = (f"*조치 후보 — 승인 대기*\n"
            f"playbook: `{playbook}`  ·  host: `{host}`  ·  service: `{service or '미지정'}`\n"
            f"봇은 후보 등록까지만 수행한다. 승인(Run Workflow) 시 Ansible 이 조치하고 "
            f"조치 후 상태를 재검증한다.")
    res = keep.push_alert(alert_name or "(알림명 없음)", sev, host, note,
                          service=service, fingerprint=fp, playbook=playbook)
    log.info("remediation queued host=%s playbook=%s service=%s keep=%s",
             host, playbook, service or "-", res.get("ok"))
