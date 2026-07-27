"""데모 B·C 공용 알림 게이트웨이 (FastAPI). 실행·배선은 bot/GATEWAY_GUIDE.md."""

import hmac
import logging
import os
import time
from typing import Optional

from fastapi import BackgroundTasks, FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

from . import incident
from . import router as tag_router
from . import severity
from . import triage

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("gateway")

app = FastAPI(title="kinx-poc alert gateway", version="0.1.0")

# triage 경로 알림은 (host, class) 버퍼에 모여 디바운스 창 마감 시 병합 트리아지 1회 (§14)
_incidents = incident.IncidentManager(on_close=triage.run_incident)

IDEMPOTENCY_TTL_S = 3600
_seen: dict = {}  # (source, event_id, event_value) -> monotonic time. 프로덕션은 Redis (가이드 §10)


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
    nseverity: Optional[int] = None   # 매크로 미해석 시 null 허용 → 핸들러가 안전값 처리(422 회피)
    host: str = ""
    tags: list = []
    clock: str = ""


class WazuhEvent(BaseModel):
    alert_id: str
    rule_id: str = ""
    rule_level: int = Field(ge=0, le=15)
    rule_description: str = ""
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
        ns = 4   # 미상 → High 취급(SEV2, triage). severity.normalize 의 SEV2 페일세이프와 정합
    sev = severity.normalize(ev.source, ns)
    decision = tag_router.decide(sev, ev.tags, ev.event_value)
    _dispatch(bg, ev.source, ev.event_id, ev.trigger_id, ev.host, ev.event_name, sev, decision)
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
              ev.rule_description, sev, decision)
    return {"status": "accepted", "sev": sev, **decision, "event_id": ev.alert_id}


def _dispatch(bg, source, event_id, trigger_id, host, alert_name, sev, decision):
    # 웹훅은 즉시 200 (발송측 타임아웃 회피). triage는 인시던트 버퍼로, remediate(n8n)는 데모 B.
    route = decision["route"]
    log.info("event=%s source=%s host=%s sev=%s route=%s playbook=%s",
             event_id, source, host, sev, route, decision["playbook"])
    if route == "triage":
        alert = incident.Alert(
            source=source, event_id=event_id, trigger_id=trigger_id, host=host,
            alert_name=alert_name, sev=sev,
            incident_class=incident.classify(alert_name), recv=time.monotonic())
        bg.add_task(_incidents.submit, alert)
