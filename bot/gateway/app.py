"""데모 B·C 공용 알림 게이트웨이 (FastAPI). 실행·배선은 bot/GATEWAY_GUIDE.md."""

import asyncio
import functools
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

from . import ask, graph
from . import collector
from . import convo
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
    # 대화 이력 저장소. 못 붙으면 대화만 포기하고 질의는 그대로 돈다.
    if convo.use_redis():
        log.info("대화 이력 저장소 연결됨 (Redis)")
    else:
        log.warning("대화 이력 저장소 없음 — 질의는 되지만 대화가 안 남는다 (REDIS_URL)")
    _beat.start()
    # 무거운 모듈을 여기서 불러 둔다. 첫 질의가 임포트 값을 뒤집어쓰면 사람은 화면에서
    # 502 를 본다(2026-08-18 실측: langgraph 첫 임포트 95초). 기동은 사람이 기다리는
    # 시간이 아니다.
    import time as _t
    _t0 = _t.monotonic()
    if graph.warmup():
        log.info("질의 그래프 준비 완료 (%.1f초, %s)", _t.monotonic() - _t0,
                 graph.versions())
    # 이름 표는 조회가 몇 초 걸리므로 별도 스레드에서 만든다. 만들어지기 전에도
    # 캐시가 있으면 그걸로 돌고, 없으면 오늘까지의 동작(맥락 기반 등록)으로 돈다.
    _names.start()
    # 첫 질의가 느린 것을 기동 때 미리 치른다(2026-08-18 실측: 재기동 직후 첫 호출
    # 96초, 다음 호출 6초). 별도 스레드라 기동을 붙잡지 않는다. 켜고 끄는 값은
    # ASK_PREWARM 이며, 유료 호출이 한 번 나가므로 끄고 싶을 수 있다.
    if os.environ.get("ASK_PREWARM", "1") not in ("0", "false", "no"):
        threading.Thread(target=lambda: log.info("%s", ask.prewarm()),
                         name="ask-prewarm", daemon=True).start()


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


async def _off_loop(fn, *a, **kw):
    """이벤트 루프 밖에서 돌린다. 느린 저장소가 서버 전체를 세우지 않게.

    `/ask` 는 비동기인데 그 안에서 Redis 와 SQLite 를 그대로 불렀다. Redis 클라이언트는
    동기이고 시한이 2초라, 저장소가 늦으면 호출마다 루프가 서고 한 요청에 세 번이므로
    6초다. 그동안 웹훅 수신도 다른 질의도 인시던트 타이머 마감도 함께 멈춘다
    (2026-08-19 감사 E-5). SQLite 쪽은 더 나쁘다 — 알림이 몰려 워커가 전역 락을 잡고
    있으면 루프가 그 락을 기다리며 통째로 정지한다.
    """
    return await asyncio.to_thread(functools.partial(fn, *a, **kw))


def _as_bytes(v) -> bytes:
    return str(v or "").encode("utf-8", "ignore")


def _token_ok(token: str) -> bool:
    """웹훅·LLM 중계용 토큰인가.

    **질의용 토큰은 여기서 거부한다.** 화면이 지나는 Grafana 데이터소스 프록시는 선언한
    경로의 하위 경로를 전부 통과시킨다. 2026-08-19 랩 실측으로 Viewer 권한 계정이
    `/webhook/zabbix` 를 부르면 핸들러까지 닿았고 `/v1/messages` 는 회사 키로 실제 답을
    받았다. 토큰이 하나뿐이라 용도를 가릴 수 없었다.
    """
    expected = os.environ.get("GATEWAY_TOKEN", "")
    # **바이트로 견준다.** 문자열끼리 비교하면 아스키가 아닌 값이 들어왔을 때
    # `compare_digest` 가 예외를 던져 401 대신 500 이 나간다.
    return bool(expected) and hmac.compare_digest(_as_bytes(token), _as_bytes(expected))


def _ask_token_ok(token: str) -> bool:
    """질의용 토큰인가. 게이트웨이 토큰도 받는다.

    `ASK_TOKEN` 을 안 적은 배포는 예전처럼 하나로 돈다. 설정을 아직 안 나눈 곳이
    갑자기 멈추면 안 되기 때문이다. 나눠 적은 곳에서는 질의용 토큰이 웹훅을 못 연다.
    """
    ask = os.environ.get("ASK_TOKEN", "")
    if ask and hmac.compare_digest(_as_bytes(token), _as_bytes(ask)):
        return True
    return _token_ok(token)


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
    # 이름 표는 개수와 오류 여부까지 싣는다. 표가 얼어붙으면 질의 경로가 이름을 원문으로
    # 내보내는데, 그 상태를 밖에서 볼 방법이 없었다(2026-08-19 감사 E-9).
    _names = nametable.status()
    return {"ok": True, "version": app.version,
            "names": int(_names.get("terms") or 0),
            "names_error": bool(_names.get("error")),
            "store": store.status()["open"],
            "annotations": bool(_grafana_state.get("ok")),
            "zabbix": all(_zabbix_state.values()) if _zabbix_state else None,
            # 어느 반복문으로 도는지. 설치가 빠지면 조용히 되돌아가므로 밖에서 보여야 한다.
            "ask_engine": ask.engine_name()}


class AskRequest(BaseModel):
    question: str
    session: str = ""
    convo_id: str = ""      # 이어가는 대화. 비면 새로 만든다.
    history: list = []
    # 사람이 보고 있던 패널. 있으면 그 그림을 코드가 붙인다(모델 판단에 안 맡긴다).
    panel: dict = {}


@app.post("/ask")
async def ask_endpoint(req: AskRequest, request: Request,
                       x_gateway_token: str = Header(default=""),
                       x_grafana_user: str = Header(default="")):
    """사람이 자연어로 묻는 창구 (§27).

    신원은 Grafana 가 프록시하면서 붙이는 헤더로 들어온다. **그 헤더는 Grafana 를 거친
    요청에서만 믿을 수 있으므로**, 이 포트를 Grafana 만 접근하도록 막는 것이 전제다.
    """
    if not _ask_token_ok(x_gateway_token):
        raise HTTPException(status_code=401, detail="unauthorized")
    user = ask.who(x_grafana_user)
    ok, why = await _off_loop(ask.user_budget_ok, user)
    if not ok:
        return JSONResponse(status_code=429, content={"error": why, "user": user})
    # **이력은 서버가 읽는다.** 화면이 보낸 것을 그대로 믿으면 남의 대화도 실린다.
    cid = req.convo_id or await _off_loop(convo.create, user, req.question)
    stored = await _off_loop(convo.load, cid, user)
    hist = [{"role": m["role"], "content": m["content"]} for m in stored] or req.history
    # 화면이 무엇을 넘겼는지 남긴다. 구간이 안 오면 도구가 최근 창으로 떨어지는데,
    # 회신만 보면 그것이 화면 탓인지 게이트웨이 탓인지 가릴 수 없다(2026-08-18).
    log.info("ask panel keys=%s from=%r to=%r",
             sorted((req.panel or {}).keys()),
             (req.panel or {}).get("from"), (req.panel or {}).get("to"))
    res = await ask.run_ask(req.question, history=hist,
                            sid=req.session or cid or user, user=user, panel=req.panel)
    await _off_loop(convo.append, cid, user, "user", req.question)
    if res.get("text"):
        # 그림도 함께 남긴다. 안 남기면 새로고침한 순간 화면에서 사라진다.
        await _off_loop(convo.append, cid, user, "assistant", res["text"],
                        images=res.get("images"))
    res["convo_id"] = cid
    log.info("ask user=%s engine=%s rounds=%s stopped=%s", user, ask.engine_name(),
             res.get("rounds"), res.get("stopped"))
    return res


class ConvoRequest(BaseModel):
    id: str = ""
    title: str = ""


def _who(header: str) -> str:
    return ask.who(header)


@app.get("/ask/convos")
def convo_list(x_gateway_token: str = Header(default=""),
               x_grafana_user: str = Header(default="")):
    """내 대화 목록. 남의 것은 애초에 안 나온다."""
    if not _ask_token_ok(x_gateway_token):
        raise HTTPException(status_code=401, detail="unauthorized")
    return {"convos": convo.listing(_who(x_grafana_user)),
            "store": convo.status()["backend"]}


@app.get("/ask/convos/{cid}")
def convo_get(cid: str, x_gateway_token: str = Header(default=""),
              x_grafana_user: str = Header(default="")):
    if not _ask_token_ok(x_gateway_token):
        raise HTTPException(status_code=401, detail="unauthorized")
    return {"messages": convo.load(cid, _who(x_grafana_user))}


@app.post("/ask/convos/{cid}/rename")
def convo_rename(cid: str, req: ConvoRequest, x_gateway_token: str = Header(default=""),
                 x_grafana_user: str = Header(default="")):
    if not _ask_token_ok(x_gateway_token):
        raise HTTPException(status_code=401, detail="unauthorized")
    return {"ok": convo.rename(cid, _who(x_grafana_user), req.title)}


@app.post("/ask/convos/{cid}/delete")
def convo_delete(cid: str, x_gateway_token: str = Header(default=""),
                 x_grafana_user: str = Header(default="")):
    if not _ask_token_ok(x_gateway_token):
        raise HTTPException(status_code=401, detail="unauthorized")
    return {"ok": convo.remove(cid, _who(x_grafana_user))}


@app.post("/ask/cancel")
def ask_cancel(req: AskRequest, x_gateway_token: str = Header(default=""),
               x_grafana_user: str = Header(default="")):
    """사람이 멈춤 단추를 눌렀다. 다음 라운드에서 멈춘다.

    **누른 사람의 세션만 멈춘다.** 화면이 보내는 세션 이름은 새 대화의 첫 턴에 모두
    같으므로, 신원을 함께 넣지 않으면 한 사람의 멈춤이 남의 질문을 끊는다.
    """
    if not _ask_token_ok(x_gateway_token):
        raise HTTPException(status_code=401, detail="unauthorized")
    ask.cancel(ask.session_key(req.session or "-", ask.who(x_grafana_user)))
    return {"ok": True}


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
    # **호출자가 신고한 값으로 막을지 정하지 않는다.** 판단은 proxy 안에서 운영자 설정으로
    # 한다. 예전에는 metadata.user_id 가 "msp" 로 시작하는지를 봤다.
    status, resp = await llm_proxy.handle(body)
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
