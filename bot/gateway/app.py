"""데모 B·C 공용 알림 게이트웨이 (FastAPI). 실행·배선은 bot/GATEWAY_GUIDE.md."""

import asyncio
import hashlib
import hmac
import logging
import os
import threading
import time
from typing import Optional

from fastapi import BackgroundTasks, FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from . import ask
from . import collector
from . import heartbeat
from . import incident
from . import keep
from . import nametable
from . import pending
from . import proxy as llm_proxy
from . import registry
from . import router as tag_router
from . import store
from . import grafana
from . import severity
from . import slack
from . import triage

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("gateway")

app = FastAPI(title="kinx-poc alert gateway", version="0.1.0")

_grafana_state: dict = {}   # 기동 시 1회 확인. /healthz 가 참·거짓만 내보낸다.
_zabbix_state: dict = {}    # 감시 서버별 조회 가능 여부. 토큰 만료를 미리 본다.

# 규칙 로드는 import 시점이라 로깅 설정 전에 끝난다. 어느 규칙으로 도는지가 반드시
# 드러나도록 기동 시 한 번 더 남긴다.
log.info("열린 문제 연계 규칙 %d건 / 측정: %s",
         len(incident.OPEN_LINK_RULES), incident.OPEN_LINK_MEASURED)
if not os.environ.get("OPEN_LINK_RULES_FILE"):
    log.warning("OPEN_LINK_RULES_FILE 미지정 — 자리표시자로 동작한다. 운영 적용 전 재측정 필요")


async def _raw_ping(alert, thread_ts):
    """알림 도착 즉시 원시 신호 카드. 반환 ts 가 인시던트 스레드 앵커 (GATEWAY_GUIDE §9)."""
    # Slack 호출은 블로킹이라 to_thread 로 감싼다 — 인시던트 타이머 루프를 막지 않게.
    res = await asyncio.to_thread(slack.post_raw, alert.alert_name or "(알림명 없음)",
                                  alert.sev, alert.host, thread_ts)
    return res.get("ts")


async def _close_incident(inc):
    """분석까지 끝난 뒤에 대기 목록에서 뺀다.

    분석 전에 빼면 분석 도중 죽었을 때 알림이 사라진다. 뒤에 빼면 그 경우 재기동 후
    한 번 더 분석해 카드가 겹칠 수 있다. 겹치는 것은 눈에 보이고 사라지는 것은 안 보여서
    뒤에 빼는 쪽을 골랐다.
    """
    _beat.mark("incidents")
    res = await triage.run_incident(inc)   # 예외를 위로 던지지 않는다
    _beat.mark("skipped" if res and res.get("gated_out") else "analyzed")
    # 여기까지 와야 목록에서 뺀다. finally 에 두면 종료 중 취소됐을 때도 지워져서
    # 처리하지 않은 알림이 사라진다(종료 마감 시간 초과가 그 경우다).
    pending.drop([{"source": a.source, "event_id": a.event_id} for a in inc.alerts])
    return res


_incidents = incident.IncidentManager(on_close=_close_incident, on_signal=_raw_ping)
_beat = heartbeat.Beat()
_names = nametable.Refresher()
_pruner = store.Pruner()


@app.on_event("startup")
async def _start_heartbeat():
    # 명부 로드 결과를 여기서 남긴다. 명부는 모듈을 들여올 때 읽히는데 그때는 로깅
    # 설정 전이라 성공도 실패도 기록이 사라진다. 못 읽으면 환경변수 설정으로 조용히
    # 도는 것이 설계이므로, 기록이 없으면 잘못 도는 것을 아무도 모른다.
    st = registry.status()
    if not st["path"]:
        log.info("호스트 명부 미설정 — 환경변수 설정으로 동작한다(HOST_REGISTRY_FILE)")
    elif st["error"]:
        log.error("호스트 명부 %s 를 못 읽었다(%s) — 환경변수 설정으로 동작한다",
                  st["path"], st["error"])
    else:
        log.info("호스트 명부 %s — 호스트 %d건 / 감시 서버 %s",
                 st["path"], st["entries"], registry.source_names() or "미기재(단일)")
    if store.init():
        store.prune()
        _pruner.start()
    # 주석은 사건이 날 때만 나가므로, 안 되는 상태를 며칠 뒤에야 안다. 기동 때 한 번 본다.
    global _grafana_state
    _grafana_state = grafana.status()
    if not _grafana_state["configured"]:
        log.info("판정 주석 미설정 — %s (GATEWAY_GRAFANA_URL·GRAFANA_TOKEN)",
                 _grafana_state["error"])
    elif not _grafana_state["ok"]:
        log.error("Grafana 에 닿지 못했다(%s) — 판정 주석이 안 올라간다",
                  _grafana_state["error"])
    # 조회 토큰도 같은 이유로 기동 때 본다. 만료는 사건이 나기 전엔 안 보이고,
    # JSON-RPC 는 오류도 HTTP 200 이라 접근 로그에도 성공만 찍힌다.
    global _zabbix_state
    for name in (registry.source_names() or [""]):
        st = await collector.zabbix_probe(name)
        _zabbix_state[name or "default"] = st["ok"]
        if not st["ok"]:
            log.error("Zabbix 조회 실패 source=%s (%s) — 이 서버의 사건은 지표 미상으로 "
                      "기록된다", name or "기본", st["error"])
    _beat.start()
    # 이름 표는 조회가 몇 초 걸리므로 별도 스레드에서 만든다. 만들어지기 전에도
    # 캐시가 있으면 그걸로 돌고, 없으면 오늘까지의 동작(맥락 기반 등록)으로 돈다.
    _names.start()


@app.on_event("shutdown")
async def _flush_open_incidents():
    """정상 종료 — 대기 중인 사건을 마감하고 나간다 (GATEWAY_GUIDE §8-6).

    강제 종료는 대기 파일이 받아 준다(§8-4). 이 경로는 그 앞단이다 — 재기동 때마다
    창을 처음부터 다시 세고 재시도 횟수가 올라가는 것을 막는다.
    """
    _beat.stop()
    _names.stop()
    _pruner.stop()
    try:
        await _incidents.flush()
    except Exception as e:
        log.warning("종료 전 마감 실패: %s", e)


@app.on_event("startup")
async def _replay_pending():
    """재기동 전에 창이 안 닫힌 알림을 다시 넣는다."""
    recs = pending.take_for_replay()
    if not recs:
        return
    log.info("재기동 전 대기 알림 %d건을 다시 처리한다", len(recs))
    for r in recs:
        await _incidents.submit(incident.Alert(
            source=r.get("source", ""), event_id=r.get("event_id", ""),
            trigger_id=r.get("trigger_id", ""), host=r.get("host", ""),
            alert_name=r.get("alert_name", ""), sev=r.get("sev", "SEV2"),
            incident_class=r.get("class", "other"), recv=time.monotonic(),
            clock=_as_clock(r.get("clock"))))


IDEMPOTENCY_TTL_S = 3600
_seen: dict = {}  # (source, event_id, event_value) -> monotonic. 프로덕션은 Redis (가이드 §10)
_seen_lock = threading.Lock()


def _token_ok(token: str) -> bool:
    expected = os.environ.get("GATEWAY_TOKEN", "")
    return bool(expected) and hmac.compare_digest(token or "", expected)


def _duplicate(key: tuple) -> bool:
    """이미 처리한 알림인가. 확인과 등록이 한 동작이어야 한다.

    웹훅이 `async def` 가 아니라 동기 함수라 FastAPI 가 워커 스레드에서 돌린다. 즉 이
    함수는 처음부터 여러 스레드에서 동시에 불린다. 확인과 등록 사이에 틈이 있으면
    같은 알림이 둘 다 통과해 인시던트에 두 번 담기고, 그러면 병합으로 보여 발동 조건
    까지 바뀐다(병합은 상한을 안 거친다). 틈을 벌려 재현해 보니 8개가 전부 통과했다.

    낡은 항목을 지우는 순회도 같은 잠금 안에 둔다. 순회 중에 다른 스레드가 넣으면
    사전 크기가 바뀌어 예외가 나고, 그 알림은 500 으로 거절된다.
    """
    # 저장소가 열려 있으면 그쪽이 정본이다 — 재기동해도 창이 남는다 (§24-3).
    # 못 쓰면 메모리로 떨어진다. 그때도 알림은 흘러야 한다.
    if store.status()["open"]:
        return not store.seen_once("|".join(str(x) for x in key),
                                   ttl_s=IDEMPOTENCY_TTL_S)
    now = time.monotonic()
    with _seen_lock:
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
    # 값은 참·거짓만 싣는다. 인증이 없는 경로라 경로·주소·오류 문구를 내보내지 않는다.
    return {"ok": True, "version": app.version,
            "store": store.status()["open"],
            "annotations": bool(_grafana_state.get("ok")),
            "zabbix": all(_zabbix_state.values()) if _zabbix_state else None}


class AskRequest(BaseModel):
    question: str
    session: str = ""
    history: list = []


@app.post("/ask")
async def ask_endpoint(req: AskRequest, request: Request,
                       x_gateway_token: str = Header(default=""),
                       x_grafana_user: str = Header(default="")):
    """사람이 자연어로 묻는 창구 (§27).

    신원은 Grafana 가 프록시하면서 붙이는 헤더로 들어온다. **그 헤더는 Grafana 를 거친
    요청에서만 믿을 수 있으므로**, 이 포트를 Grafana 만 접근하도록 막는 것이 전제다.
    """
    if not _token_ok(x_gateway_token):
        raise HTTPException(status_code=401, detail="unauthorized")
    user = ask.who(x_grafana_user)
    ok, why = ask.user_budget_ok(user)
    if not ok:
        return JSONResponse(status_code=429, content={"error": why, "user": user})
    res = await ask.run_ask(req.question, history=req.history,
                            sid=req.session or user, user=user)
    log.info("ask user=%s rounds=%s stopped=%s", user, res.get("rounds"),
             res.get("stopped"))
    return res


@app.post("/v1/messages")
async def llm_messages(req: Request, x_api_key: str = Header(default=""),
                       x_gateway_token: str = Header(default="")):
    """외부 도구용 마스킹 수신 지점 (§23). 비동기인 이유는 §23-2."""
    if not (_token_ok(x_gateway_token) or _token_ok(x_api_key)):
        raise HTTPException(status_code=401, detail="invalid token")
    try:
        body = await req.json()
    except Exception:
        raise HTTPException(status_code=400, detail="invalid json")
    tenant = str(body.get("metadata", {}).get("user_id", "")).startswith("msp")
    status, resp = await llm_proxy.handle(body, tenant_scoped=tenant)
    return JSONResponse(status_code=status, content=resp)


@app.post("/webhook/zabbix")
def webhook_zabbix(ev: ZabbixEvent, bg: BackgroundTasks, x_gateway_token: str = Header(default="")):
    if not _token_ok(x_gateway_token):
        raise HTTPException(status_code=401, detail="invalid token")
    if ev.source not in (severity.SOURCE_ZABBIX_INTERNAL, severity.SOURCE_ZABBIX_MSP):
        raise HTTPException(status_code=422, detail="unknown source")
    ns = ev.nseverity
    if ns is None:
        log.warning("event=%s nseverity 누락 — 미디어타입 {EVENT.NSEVERITY} 파라미터 확인. "
                    "안전값(triage)로 처리", ev.event_id)
        ns = 4   # 미상 → High 취급. severity.normalize 의 SEV2 페일세이프와 정합
    sev = severity.normalize(ev.source, ns)
    decision = tag_router.decide(sev, ev.tags, ev.event_value)
    # 중복 판정보다 먼저 매긴다 — 중복도 라우팅 분모에 들어가야 한다 (§25-3).
    cls = incident.classify(ev.event_name, tags=ev.tags)
    dup = _duplicate((ev.source, ev.event_id, ev.event_value))
    _record_route(ev.source, ev.host, sev, cls, decision["route"], dup)
    if dup:
        return {"status": "duplicate", "event_id": ev.event_id}
    _dispatch(bg, ev.source, ev.event_id, ev.trigger_id, ev.host, ev.event_name, sev,
              decision, ev.tags, clock=ev.clock, cls=cls)
    return {"status": "accepted", "sev": sev, **decision, "event_id": ev.event_id}


@app.post("/webhook/wazuh")
def webhook_wazuh(ev: WazuhEvent, bg: BackgroundTasks, x_gateway_token: str = Header(default="")):
    if not _token_ok(x_gateway_token):
        raise HTTPException(status_code=401, detail="invalid token")
    sev = severity.normalize(severity.SOURCE_WAZUH, ev.rule_level)
    decision = tag_router.decide(sev, [], 1)
    cls = incident.classify(ev.rule_description, groups=ev.rule_groups,
                            rule_id=ev.rule_id)
    dup = _duplicate((severity.SOURCE_WAZUH, ev.alert_id, 1))
    _record_route(severity.SOURCE_WAZUH, ev.agent_name, sev, cls,
                  decision["route"], dup)
    if dup:
        return {"status": "duplicate", "event_id": ev.alert_id}
    _dispatch(bg, severity.SOURCE_WAZUH, ev.alert_id, "", ev.agent_name,
              ev.rule_description, sev, decision, groups=ev.rule_groups,
              rule_id=ev.rule_id, cls=cls)
    return {"status": "accepted", "sev": sev, **decision, "event_id": ev.alert_id}


def _as_clock(v) -> float:
    """발행 측이 준 시각을 초로. 못 읽으면 0 — 모른다고 두지 지어내지 않는다."""
    try:
        c = float(v)
    except (TypeError, ValueError):
        return 0.0
    return c if c > 0 else 0.0


def _record_route(source, host, sev, cls, route, dup) -> None:
    """알림 1건의 라우팅 판정. 실패해도 알림 처리를 막지 않는다 (§25-3)."""
    try:
        store.record_route({"source": source, "host": host, "sev": sev, "cls": cls,
                            "route": route, "dup": 1 if dup else 0})
    except Exception as e:
        log.warning("라우팅 기록 실패: %s", e)


def _dispatch(bg, source, event_id, trigger_id, host, alert_name, sev, decision,
              tags=None, groups=None, rule_id="", clock="", cls=None):
    """경로별 후속 처리를 백그라운드로 넘긴다 — 웹훅은 즉시 200(발송측 타임아웃 회피)."""
    route = decision["route"]
    _beat.mark_alert(source)
    # rule_id 를 빠뜨리면 분류 선언 파일의 wazuh 절이 통째로 죽는다. 파일은 정상
    # 로드되고 로그도 찍히므로, 설정한 사람은 적용됐다고 믿는다.
    if cls is None:
        cls = incident.classify(alert_name, tags=tags, groups=groups, rule_id=rule_id)
    log.info("event=%s source=%s host=%s sev=%s class=%s route=%s playbook=%s",
             event_id, source, host, sev, cls, route, decision["playbook"])
    if route == "triage":
        alert = incident.Alert(
            source=source, event_id=event_id, trigger_id=trigger_id, host=host,
            alert_name=alert_name, sev=sev,
            incident_class=cls, recv=time.monotonic(), clock=_as_clock(clock),
            # 계약 제약은 라우팅에서 쓰고 끝나면 안 된다 — 분석 문장에도 필요하다.
            scope=tag_router.tag_value(tags or [], tag_router.SCOPE_TAG) or "",
            automate=tag_router.tag_value(tags or [], tag_router.AUTOMATE_TAG) or "")
        # 이 경로만 기다린다. 기다리는 동안 죽으면 알림이 사라지므로 파일에 먼저 적고,
        # 적지 못하면 200 을 주지 않는다 — Zabbix 가 재시도하게 둔다.
        rec = {"source": source, "event_id": event_id, "trigger_id": trigger_id,
               "host": host, "alert_name": alert_name, "sev": sev, "class": cls,
               # 사건이 난 시각. 이게 없으면 재기동 후 다시 넣을 때 지금 시각으로
               # 잡혀 로그를 엉뚱한 구간에서 찾는다.
               "clock": _as_clock(clock)}
        if not pending.append(rec):
            raise HTTPException(status_code=503, detail="pending write failed")
        bg.add_task(_incidents.submit, alert)
    elif route in ("digest", "dashboard_only"):
        bg.add_task(_queue_low_severity, host, alert_name, sev, cls,
                    route == "digest", f"{source},{event_id},{trigger_id or ''},{cls}")
    elif route == "remediate":
        bg.add_task(_queue_remediation, host, alert_name, sev, decision["playbook"],
                    tag_router.tag_value(tags or [], "service") or "")


def _queue_low_severity(host, alert_name, sev, cls, notify: bool, ref: str = ""):
    """SEV3(digest)·SEV4(dashboard_only) — 기록만 남기고 분석은 생략 (GATEWAY_GUIDE §11)."""
    # fingerprint 를 (호스트, 유형)으로 고정해 같은 종류가 한 행에 모이게 한다(반복 빈도 랭킹용).
    fp = hashlib.sha1(f"lowsev|{host}|{cls}".encode()).hexdigest()[:12]
    tier = "덜 급함(digest)" if notify else "대시보드 전용"
    note = (f"*{tier}*\n유형: `{cls}`  ·  호스트: `{host}`\n"
            f"심각도가 낮아 분석을 생략했다. 반복 빈도 집계를 위해 기록만 남긴다.\n"
            f"확인이 필요하면 Run Workflow 로 분석을 직접 요청한다.")
    res = keep.push_alert(alert_name or "(알림명 없음)", sev, host, note,
                          fingerprint=fp, classes=cls,
                          playbook="analyze", extra={"analyze_ref": ref})
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
