"""대화형 질의 — 질문 위생과 세션 역치환. 설계는 bot/GATEWAY_GUIDE.md §27.

알림 경로는 컨텍스트를 `masking.build_llm_context` 화이트리스트가 지킨다. 질의 경로에는
그 보호가 없다. 사람은 호스트명이든 IP든 계정명이든 아무거나 친다.
"""

import logging
import os
import re
import threading
import time

from . import masking, proxy, registry

log = logging.getLogger("gateway.ask")

# 질의가 닿을 수 있는 감시 영역. 기본은 사내뿐이다. 넓히려면 환경변수로 적는다.
DEFAULT_ALLOWED_REALMS = "internal"

# 한 번에 받을 질문 길이. 이력까지 매 턴 다시 마스킹하므로 무한정 받을 수 없다.
QUESTION_MAX_CHARS = 500
# 세션 역치환 표를 얼마나 들고 있을지. 날아가도 사용자가 다시 물으면 되므로 짧게 잡는다.
SESSION_TTL_S = 1800

# 줄바꿈과 탭만 남기고 지운다. 프롬프트 구조를 흉내 내는 입력을 막는다.
_CTRL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

_sessions: dict = {}     # sid -> {"rev": {토큰: 원문}, "at": 단조시각}
_lock = threading.Lock()


def _now() -> float:
    return time.monotonic()


def allowed_realms() -> list:
    """질의가 닿을 수 있는 영역. 환경변수를 매번 읽는다 — 재기동 없이 좁힐 수 있어야 한다."""
    raw = os.environ.get("ASK_ALLOWED_REALMS", DEFAULT_ALLOWED_REALMS)
    return [r.strip() for r in raw.split(",") if r.strip()]


def target_allowed(source: str, host: str = "") -> tuple:
    """이 대상을 질의가 조회해도 되는가. 반환 `(허용 여부, 사유)`.

    **호출자가 신고한 값은 쓰지 않는다.** 영역은 명부와 환경변수로만 정해진다.
    `registry.realm()` 은 아무것도 안 적혔을 때 소스 이름을 그대로 돌려주므로, 영역을
    기재하지 않은 감시 서버는 허용 목록에 없는 값이 되어 **자동으로 막힌다.** 설정을
    빠뜨린 사람이 가장 위험해지면 안 된다.
    """
    from . import incident      # 순환 참조를 피해 쓰는 자리에서 들여온다

    rlm = registry.realm(source, host, incident.REALM_MAP)
    allowed = allowed_realms()
    if rlm in allowed:
        return True, ""
    return False, ("감시 영역 %r 은 질의 대상이 아니다 (허용: %s)"
                   % (rlm or "미상", ", ".join(allowed) or "없음"))


def allowed_sources() -> list:
    """질의가 물어도 되는 감시 서버 이름들."""
    return [n for n in registry.source_names() if target_allowed(n)[0]]


# 사람이 이름을 줄여 말할 때 쓰는 조각. 너무 짧으면 아무 데나 걸리므로 하한을 둔다.
MENTION_MIN = 4
_WORDY = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{%d,}" % (MENTION_MIN - 1))


def resolve_mentions(text: str, table: dict) -> str:
    """질문에 적힌 이름 조각을 대상 토큰으로 바꾼다.

    사람은 `vm-p3-target-002.novalocal` 을 `target-002` 로 줄여 말한다. 전체 이름과
    도메인 뗀 이름만 가려서는 그 조각이 안 풀리고, 모델은 "등록되지 않은 호스트" 라고
    답한 뒤 대화가 막힌다(2026-08-18 랩 실측).

    **여러 호스트에 걸리는 조각은 풀지 않는다.** 엉뚱한 기계를 짚는 것이 못 짚는 것보다
    나쁘다. 그때는 모델이 목록을 보고 되묻게 둔다.
    """
    out = str(text or "")
    for frag in sorted(set(_WORDY.findall(out)), key=len, reverse=True):
        low = frag.lower()
        hits = [tok for tok, ent in (table or {}).items()
                if low in str(ent.get("host", "")).lower()]
        if len(hits) == 1:
            out = out.replace(frag, hits[0])
    return out


def _alias(mk, name: str) -> None:
    """도메인 접미사를 뗀 짧은 이름을 **같은 토큰**에 묶는다.

    사람은 `vm-a.novalocal` 을 `vm-a` 로 줄여 친다. 안 묶으면 그 조각이 안 가려진 채
    모델로 가고, 모델은 그 문자열을 도구 인자로 넣어 '알 수 없는 대상' 으로 튕긴다.
    새 토큰을 만들지 않고 기존 토큰을 가리키게 해야 같은 기계로 읽힌다.
    """
    short = str(name or "").split(".")[0]
    if short and short != name and short not in mk._fwd:
        mk._fwd[short] = mk._fwd[name]
        mk._re = None


async def build_table(masker: masking.Masker = None, client_factory=None) -> dict:
    """질의가 조회할 수 있는 대상 표. `{토큰: {host, source, logs, security}}`.

    **표에 없으면 도구가 대상을 지정할 방법이 없다.** 그래서 이 표가 곧 경계다.
    허용된 감시 서버에만 묻는다 — 나머지 서버에는 조회 자체를 보내지 않는다.

    실패해도 예외를 던지지 않는다. 답을 못 하더라도 왜 못 하는지는 말해야 하므로,
    빈 표를 받은 쪽이 그 사실을 사람에게 전한다.
    """
    import httpx                                  # 모듈 들여오기를 쓰는 자리에 둔다

    from . import collector

    mk = masker if masker is not None else proxy.build_masker()
    factory = client_factory or (lambda source="": collector.ZabbixClient(source=source))
    table = {}
    for source in allowed_sources():
        try:
            zbx = factory(source=source)
            async with httpx.AsyncClient() as client:
                hosts = await zbx.call(client, "host.get", {
                    "output": ["hostid", "host", "name", "status"],
                    "selectInterfaces": ["ip", "dns"]})
        except Exception as e:
            log.warning("대상 표를 못 만들었다 source=%s: %s", source, e)
            continue
        for h in hosts or []:
            name = str(h.get("host") or "")
            if not name:
                continue
            mk.register("host", name)
            _alias(mk, name)
            table[mk._fwd[name]] = {
                "host": name,
                "source": source,
                # 축마다 이름이 다를 수 있다. 못 풀면 빈 값이고 그건 '없음'이 아니다.
                "logs": collector._resolve_label(name, h, source, "logs"),
                "security": collector._resolve_label(name, h, source, "security"),
            }
    return table


def session_masker(sid: str) -> masking.Masker:
    """이번 요청의 이름 표 + 이 세션이 이미 발행한 토큰을 합친 마스커.

    이름 표는 1시간마다 다시 만들어진다. 대화 도중 갱신되면 앞 턴에 발행한 토큰이
    표에서 사라져 역치환이 안 되고, 사람은 회신에서 토큰 문자열을 그대로 받는다.
    합집합으로 그 구멍을 메운다.
    """
    mk = proxy.build_masker()
    prune_sessions()
    with _lock:
        sess = _sessions.get(sid)
        old = dict(sess["rev"]) if sess else {}
    for tok, name in old.items():
        # 표에 살아 있는 이름이 우선이다. 세션 값은 빠진 것만 메운다.
        if tok not in mk._rev:
            mk._rev[tok] = name
            mk._fwd.setdefault(name, tok)
    mk._re = None
    return mk


def remember(sid: str, mk: masking.Masker) -> int:
    """이번 턴에 발행한 토큰을 세션에 쌓는다. 반환은 세션이 들고 있는 총 개수."""
    with _lock:
        sess = _sessions.setdefault(sid, {"rev": {}, "at": _now()})
        sess["rev"].update(mk._rev)
        sess["at"] = _now()
        return len(sess["rev"])


def prune_sessions(now: float = None) -> int:
    """오래된 세션을 지운다. 반환은 지운 개수."""
    now = _now() if now is None else now
    with _lock:
        dead = [k for k, v in _sessions.items() if now - v["at"] > SESSION_TTL_S]
        for k in dead:
            del _sessions[k]
    return len(dead)


def forget_all() -> None:
    with _lock:
        _sessions.clear()


def sanitize_question(text: str, mk: masking.Masker) -> dict:
    """질문 문자열을 보낼 수 있는 형태로 만든다.

    반환 `{"ok": bool, "text": str, "reason": str}`.

    **가린 뒤에도 아는 이름이 남으면 보내지 않고 거절한다.** 과거 결론 본문은 버려도
    나머지 근거가 남지만(`masking._prior_item`), 질문을 버리면 요청 자체가 뜻을 잃는다.
    그리고 이름 표의 통제 범위는 호스트명·그룹명·IP 뿐이라(§23-7) 계정명·경로·티켓번호는
    애초에 안 가려진다. 조용히 내보내는 것보다 사람에게 되묻는 편이 낫다.
    """
    raw = _CTRL_RE.sub("", str(text or "")).strip()
    if not raw:
        return {"ok": False, "text": "", "reason": "질문이 비어 있다"}
    if len(raw) > QUESTION_MAX_CHARS:
        return {"ok": False, "text": "",
                "reason": "질문 길이가 %d자를 넘는다 (%d자)" % (QUESTION_MAX_CHARS, len(raw))}
    masked = mk.mask(raw)
    if masking._leaks(masked):
        log.warning("질문에 가려지지 않은 이름이 남아 보내지 않는다")
        return {"ok": False, "text": "",
                "reason": "질문에 가려지지 않은 이름이나 주소가 남아 있다. "
                          "그 부분을 빼고 다시 물어달라"}
    return {"ok": True, "text": masked, "reason": ""}


# ---------------------------------------------------------------------------
# 실제 조회. 질의문은 asktools 가 만들고 여기서는 보내기만 한다.
#
# 반환에 항상 status 를 싣는다. 빈 결과가 "없었다" 인지 "못 봤다" 인지 구분되지 않으면
# 모델이 없음을 근거로 단언한다. 알림 경로에서 이미 겪은 문제다(조회 상태 계약).
# ---------------------------------------------------------------------------

async def fetch_logs(logql: str, start: int, end: int, limit: int,
                     masker: masking.Masker) -> dict:
    import httpx

    from . import collector

    url = os.environ.get("LOKI_URL", "").rstrip("/")
    if not url:
        return {"logs": [], "status": collector.SOURCE_DISABLED,
                "note": "로그 저장소가 연결돼 있지 않다"}
    try:
        async with httpx.AsyncClient() as c:
            r = await c.get(f"{url}/loki/api/v1/query_range", params={
                "query": logql,
                "start": str(int(start) * 1_000_000_000),
                "end": str(int(end) * 1_000_000_000),
                "limit": min(int(limit), collector.LOKI_FETCH_LIMIT),
                "direction": "backward"}, timeout=collector.TIMEOUT_S)
            r.raise_for_status()
            recs = [{"t": collector._loki_ts(ts),
                     "line": line[:collector.LOKI_LINE_MAX]}
                    for st in r.json().get("data", {}).get("result", [])
                    for ts, line in st.get("values", [])]
    except Exception as e:
        log.warning("로그 조회 실패: %s", e)
        return {"logs": [], "status": collector.SOURCE_UNAVAILABLE,
                "note": "조회하지 못했다. 이 결과를 '없음'으로 읽지 마라"}
    picked = collector.select_logs(sorted(recs, key=lambda r: r["t"]))
    return {"logs": [masking._log_item(x, masker.mask) for x in picked],
            "fetched": len(recs), "status": collector.SOURCE_OK}


async def fetch_security(body: dict, masker: masking.Masker) -> dict:
    import httpx

    from . import collector

    url = os.environ.get("WAZUH_INDEXER_URL", "").rstrip("/")
    if not url:
        return {"alerts": [], "status": collector.SOURCE_DISABLED,
                "note": "보안 저장소가 연결돼 있지 않다"}
    auth = (os.environ.get("WAZUH_INDEXER_USER", ""),
            os.environ.get("WAZUH_INDEXER_PASSWORD", ""))
    try:
        # 랩 인덱서가 자체 서명이라 검증을 끈다(알림 경로와 같은 조건).
        async with httpx.AsyncClient(verify=False) as c:
            r = await c.post(f"{url}/wazuh-alerts-*/_search", json=body, auth=auth,
                             timeout=collector.TIMEOUT_S)
            r.raise_for_status()
            hits = r.json().get("hits", {}).get("hits", [])
    except Exception as e:
        log.warning("보안 조회 실패: %s", e)
        return {"alerts": [], "status": collector.SOURCE_UNAVAILABLE,
                "note": "조회하지 못했다. 이 결과를 '없음'으로 읽지 마라"}
    return {"alerts": [masking._security_item(h.get("_source") or {}, masker.mask)
                       for h in hits],
            "status": collector.SOURCE_OK}


async def fetch_judgments(host: str, days: int, masker: masking.Masker,
                          now: float = None) -> dict:
    from . import collector, store

    if not store.status()["open"]:
        return {"judgments": [], "status": collector.SOURCE_UNAVAILABLE,
                "note": "판정 이력 저장소를 열지 못했다"}
    now = time.time() if now is None else now
    rows = store.judgments_in_realms(allowed_realms(), since=now - days * 86400,
                                     now=now, host=host)
    out = []
    for r in rows:
        out.append({"ts": int(r.get("ts") or 0),
                    "host": masker.mask(r.get("host") or ""),
                    "classes": r.get("classes") or "",
                    "sev": r.get("sev") or "",
                    "verdict": r.get("verdict") or ""})
    return {"judgments": out, "status": collector.SOURCE_OK}


# ---------------------------------------------------------------------------
# 도구 루프
#
# 상한이 셋이다 — 라운드 수, 전체 시간, 도구 결과 누적 글자 수. 어디에 닿든 **오류가
# 아니라 거기까지 본 것으로 답하게** 한다. 사람이 앞에서 기다리는 경로라 빈손으로
# 끝내는 것이 가장 나쁘다.
# ---------------------------------------------------------------------------

# 대화 이력을 얼마나 실을지. **다 보내면 턴이 쌓일수록 비용과 지연이 늘고, 상한에
# 닿으면 최신 질문이 밀린다.** 오래된 것부터 버리는 미끄럼창을 쓴다. 지금은 그대로
# 버리지만, 버린 구간을 요약해 한 줄로 접는 것이 다음 단계다(next-steps 참조).
HISTORY_MAX_MSGS = int(os.environ.get("ASK_HISTORY_MAX_MSGS", "12"))
HISTORY_MAX_CHARS = int(os.environ.get("ASK_HISTORY_MAX_CHARS", "8000"))
DROP_NOTE = "(앞선 대화 일부는 길이 때문에 생략되었다. 필요하면 다시 물어라)"

MAX_ROUNDS = int(os.environ.get("ASK_MAX_ROUNDS", "6"))
DEADLINE_S = float(os.environ.get("ASK_DEADLINE_S", "60"))
RESULT_BYTES = int(os.environ.get("ASK_RESULT_BYTES", "60000"))

ASK_SYSTEM = """\
당신은 KINX IDC 관제 담당자의 질문에 답하는 조회 도우미다. 도구로 지표·로그·보안
기록을 읽고 한국어로 답한다.

규칙:
- 호스트는 [host-...] 같은 가명 토큰으로만 지칭한다. 실명을 지어내지 마라.
- 대상 토큰을 모르면 list_hosts 를 먼저 부른다.
- **사람이 절대 시각을 말하면 window_m 이 아니라 from·to 로 넘겨라.** "8월 13일 12시",
  "어제 새벽" 처럼 특정 시점을 가리키는 질문에 상대 창을 쓰면 엉뚱한 날을 보게 된다.
- **도구 결과의 status 를 반드시 읽어라.** "ok" 일 때만 빈 결과를 "없었다"로 해석한다.
  "unavailable" 은 조회가 실패한 것이고 "disabled" 는 그 축이 없는 것이다. 둘 다
  "없었다"가 아니므로 그렇게 밝혀라.
- 도구가 error 를 돌려주면 그 지시를 읽고 고쳐서 다시 부른다.
- 근거로 쓴 조회를 답에 밝힌다. 확인하지 못한 것은 확인하지 못했다고 쓴다.
- 되돌릴 수 없는 명령(RESET SLAVE·DROP·rm -rf·kill -9 등)을 권하지 마라.
- 답은 공백 포함 1200자 이내로 쓴다."""


def trim_history(history) -> tuple:
    """이력을 창 안으로 자른다. 반환 `(자른 이력, 버렸는가)`.

    최신 것을 먼저 지키고 오래된 것부터 버린다. 개수와 글자 수 두 상한을 함께 보는
    이유는, 짧은 턴이 많은 대화와 긴 답이 몇 개인 대화가 서로 다른 방식으로 커지기
    때문이다.

    **버린 사실을 알린다.** 조용히 버리면 모델이 앞 대화를 다 기억한다고 여기고
    "아까 말한 그 호스트" 같은 말을 근거로 쓴다.
    """
    msgs = [m for m in (history or [])
            if isinstance(m, dict) and m.get("role") in ("user", "assistant")
            and isinstance(m.get("content"), str)]
    kept, chars = [], 0
    for m in reversed(msgs):
        if len(kept) >= HISTORY_MAX_MSGS or chars + len(m["content"]) > HISTORY_MAX_CHARS:
            break
        kept.append(m)
        chars += len(m["content"])
    kept.reverse()
    return kept, len(kept) < len(msgs)


def _blocks_text(content) -> str:
    return "\n".join(b.get("text", "") for b in (content or [])
                     if isinstance(b, dict) and b.get("type") == "text").strip()


async def run_ask(question: str, history=None, sid: str = "", table: dict = None,
                  model_fn=None, clock=None, now: int = None, user: str = "",
                  panel_fn=None) -> dict:
    """질문 하나에 답한다. 어떤 실패도 예외로 던지지 않는다.

    반환 `{"text", "trace", "rounds", "stopped", "error"}`.
    """
    import asyncio
    import json as _json

    from . import asktools, egress, llm

    tick = clock or time.monotonic
    started = tick()
    now = int(time.time()) if now is None else now
    mk = session_masker(sid or "-")

    # **표를 먼저 만든다.** 표를 만들면서 호스트 이름이 마스커에 등록되므로, 그 뒤에
    # 질문을 가려야 표에만 있고 이름 표에는 없는 호스트가 질문에서 안 새어 나간다.
    # 반대 순서로 뒀다가 랩에서 실제로 실명이 나갔다(2026-08-18).
    if table is None:
        table = await build_table(mk)
    else:
        for ent in table.values():
            mk.register("host", ent.get("host", ""))
            _alias(mk, ent.get("host", ""))
    if not table:
        return {"text": "", "trace": [], "rounds": 0, "images": [], "stopped": "no_targets",
                "error": "조회할 수 있는 대상이 없다. 감시 서버 연결과 허용 영역을 확인하라"}

    # 이름 조각을 먼저 토큰으로 바꾼다. 마스커는 등록된 이름만 보므로 줄여 쓴 말을
    # 못 잡는다. 여기서 풀어 두면 모델이 곧바로 도구를 부를 수 있다.
    question = resolve_mentions(question, table)
    clean = sanitize_question(question, mk)
    if not clean["ok"]:
        return {"text": "", "trace": [], "rounds": 0, "images": [], "stopped": "rejected",
                "error": clean["reason"]}

    ctx = {
        "table": table, "now": now,
        "fetch_logs": lambda q, a, b, lim: fetch_logs(q, a, b, lim, mk),
        "fetch_security": lambda body: fetch_security(body, mk),
        "fetch_judgments": lambda host, days: fetch_judgments(host, days, mk),
        "fetch_metrics": lambda ent, match, a, b: fetch_metrics(ent, match, a, b),
        "fetch_problems": lambda ent: fetch_problems(ent),
        "fetch_panel": (panel_fn or (lambda ent, m, a, b: fetch_panel(ent, m, a, b))),
    }

    hist, dropped = trim_history(history)
    images = []          # 화면이 그릴 그림. 모델에는 손잡이만 준다.
    messages = list(hist)
    if dropped:
        messages.insert(0, {"role": "user", "content": DROP_NOTE})
    messages.append({"role": "user", "content": clean["text"]})
    trace, spent, stopped = [], 0, "end_turn"
    text = ""

    def _model(msgs):
        if model_fn is not None:
            return model_fn(ASK_SYSTEM, msgs, asktools.TOOL_SPECS)
        return llm.claude_tools(ASK_SYSTEM, msgs, asktools.TOOL_SPECS)

    for _round in range(MAX_ROUNDS):
        if tick() - started > DEADLINE_S:
            stopped = "deadline"
            break
        res = await asyncio.to_thread(egress.call_raw, lambda: _model(messages),
                                      kind="ask", user=user)
        if not res["ok"]:
            return {"text": "", "trace": trace, "rounds": len(trace), "images": images,
                    "stopped": "llm_failed",
                    "error": "모델을 부르지 못했다: %s" % res["reason"]}
        reply = res["value"]
        text = _blocks_text(reply.get("content")) or text
        uses = [b for b in (reply.get("content") or [])
                if isinstance(b, dict) and b.get("type") == "tool_use"]
        if not uses:
            break
        messages = messages + [{"role": "assistant", "content": reply["content"]}]
        results = []
        for u in uses:
            # 모델이 준 인자는 토큰 상태 그대로 쓴다. 도구가 표에서 실명을 찾는다.
            out = await asktools.run_tool(u.get("name", ""), u.get("input") or {}, ctx)
            if isinstance(out, dict) and out.get("url"):
                # **주소는 모델에 주지 않는다.** 대시보드 식별자와 호스트 실명이 들어 있다.
                images.append(out)
                out = {"image": out.get("id"), "title": mk.mask(out.get("title", "")),
                       "note": "화면에 붙였다. 답에 이 id 를 적어라"}
            blob = _json.dumps(out, ensure_ascii=False)
            spent += len(blob)
            if spent > RESULT_BYTES:
                out = {"error": "조회 결과가 예산을 넘어 더 못 본다. 지금까지 본 것으로 답하라"}
                blob = _json.dumps(out, ensure_ascii=False)
                stopped = "budget"
            trace.append({"tool": u.get("name", ""), "args": u.get("input") or {},
                          "error": out.get("error", ""), "bytes": len(blob)})
            results.append({"type": "tool_result", "tool_use_id": u.get("id"),
                            "content": blob})
        messages = messages + [{"role": "user", "content": results}]
        if stopped == "budget":
            break
    else:
        stopped = "rounds"

    if stopped in ("rounds", "deadline", "budget") and not text:
        text = ("여기까지 확인했고 상한(%s)에 닿아 멈췄다. 조회한 것: %s"
                % (stopped, ", ".join(t["tool"] for t in trace) or "없음"))
    remember(sid or "-", mk)
    return {"text": mk.unmask(text), "trace": trace, "rounds": len(trace),
            "images": images, "stopped": stopped, "error": ""}


# ---------------------------------------------------------------------------
# 사용자별 사용량
#
# 게이트웨이 인증은 공유 토큰 하나다. 그것만으로는 누가 얼마나 썼는지 알 수 없다.
# 신원은 Grafana 가 프록시하면서 붙이는 `X-Grafana-User` 로 들어온다.
#
# **그 헤더는 Grafana 를 거친 요청에서만 믿을 수 있다.** 게이트웨이 포트를 Grafana 만
# 접근하도록 막지 않으면 누구나 헤더를 지어낸다. 그 방화벽 규칙이 이 계수의 전제다.
# ---------------------------------------------------------------------------

ANON = "(미상)"
USER_MAX_CHARS = 64
MAX_PER_USER_HOUR = int(os.environ.get("ASK_MAX_PER_USER_HOUR", "60"))

_USER_STRIP = re.compile(r"[\x00-\x1f\x7f]")


def who(header_value) -> str:
    """헤더 값을 계수에 쓸 이름으로 다듬는다.

    신원이 없으면 익명으로 **센다**. 안 세면 신원을 안 주는 쪽이 상한을 피해 간다.
    """
    name = _USER_STRIP.sub("", str(header_value or "")).strip()
    return name[:USER_MAX_CHARS] if name else ANON


def user_budget_ok(user: str, now: float = None) -> tuple:
    """이 사용자가 시간당 상한 안에 있는가. 반환 `(가능 여부, 사유)`."""
    from . import store

    if MAX_PER_USER_HOUR <= 0:
        return True, ""
    used = store.calls_since(3600, now=now, kind="ask", user=user)
    if used >= MAX_PER_USER_HOUR:
        return False, ("한 시간에 %d회까지 물을 수 있다. 지금까지 %d회 썼다"
                       % (MAX_PER_USER_HOUR, used))
    return True, ""


async def fetch_metrics(entry: dict, match: str, start: int, end: int) -> dict:
    """호스트의 지표 추이. 아이템 이름·키에 든 문자열로 고른다.

    `at` 을 주면 그 시각 앞뒤를 본다. 사람은 "어제 2시에 튀었다" 로 묻지 "지금부터
    몇 분" 으로 묻지 않는다.
    """
    import httpx

    from . import asktools, collector

    try:
        zbx = collector.ZabbixClient(source=entry.get("source", ""))
        async with httpx.AsyncClient() as c:
            hosts = await zbx.call(c, "host.get", {
                "filter": {"host": entry.get("host", "")}, "output": ["hostid"]})
            if not hosts:
                return {"metrics": [], "status": collector.SOURCE_UNMATCHED,
                        "note": "감시 서버가 이 호스트를 모른다"}
            params = {"hostids": hosts[0]["hostid"],
                      "output": ["itemid", "name", "key_", "value_type", "units",
                                 "lastvalue"],
                      "sortfield": "name"}
            if match:
                params["search"] = {"name": match, "key_": match}
                params["searchByAny"] = True
            items = await zbx.call(c, "item.get", params)
            if not items:
                return {"metrics": [], "status": collector.SOURCE_OK,
                        "note": "그 조건에 맞는 아이템이 없다. match 를 넓혀 보라"}
            out = []
            for it in items[:5]:
                vt = int(it.get("value_type", 3))
                hist = []
                if vt in (0, 3):         # 수치형만 추이가 뜻이 있다
                    # **구간 전체를 받아 놓고 줄인다.** 상한만큼만 최신순으로 받으면
                    # 앞부분이 잘려 먼저 난 스파이크를 못 본다(2026-08-18 실측).
                    hist = await zbx.call(c, "history.get", {
                        "itemids": it["itemid"], "history": vt,
                        "time_from": start, "time_till": end, "output": "extend",
                        "sortfield": "clock", "sortorder": "ASC",
                        "limit": asktools.HISTORY_FETCH_MAX})
                raw = [{"t": int(h["clock"]), "v": h["value"]} for h in hist]
                shown = asktools.downsample(raw)
                out.append({
                    "name": it.get("name"), "key": it.get("key_"),
                    "units": it.get("units"), "last": it.get("lastvalue"),
                    # 몇 점을 읽어 몇 점으로 줄였는지 함께 준다. 안 알리면 모델이
                    # 실린 점이 전부라고 여긴다.
                    "sampled_from": len(raw), "series": shown,
                })
    except Exception as e:
        log.warning("지표 조회 실패: %s", e)
        return {"metrics": [], "status": collector.SOURCE_UNAVAILABLE,
                "note": "조회하지 못했다. 이 결과를 '없음'으로 읽지 마라"}
    return {"metrics": out, "matched": len(items), "window": [start, end],
            "status": collector.SOURCE_OK}


async def fetch_problems(entry) -> dict:
    """지금 열려 있는 문제. 호스트를 안 주면 허용된 감시 서버 전체."""
    import httpx

    from . import collector

    try:
        sources = [entry["source"]] if entry else allowed_sources()
        out = []
        for src in sources:
            zbx = collector.ZabbixClient(source=src)
            async with httpx.AsyncClient() as c:
                params = {"output": ["eventid", "name", "severity", "clock"],
                          "sortfield": "eventid", "sortorder": "DESC", "limit": 50}
                if entry:
                    hosts = await zbx.call(c, "host.get", {
                        "filter": {"host": entry.get("host", "")}, "output": ["hostid"]})
                    if not hosts:
                        continue
                    params["hostids"] = hosts[0]["hostid"]
                for p in await zbx.call(c, "problem.get", params):
                    out.append({"name": p.get("name"), "sev": p.get("severity"),
                                "t": int(p.get("clock") or 0)})
    except Exception as e:
        log.warning("열린 문제 조회 실패: %s", e)
        return {"problems": [], "status": collector.SOURCE_UNAVAILABLE,
                "note": "조회하지 못했다. 이 결과를 '없음'으로 읽지 마라"}
    return {"problems": out, "status": collector.SOURCE_OK}


async def fetch_panel(entry: dict, match: str, start: int, end: int) -> dict:
    """관측 화면 한 장. 모델에는 손잡이만 가고 주소는 화면으로만 간다."""
    from . import grafana

    uid, panel_id, title = grafana.find_panel(match or "")
    if not uid:
        return {"error": "그 조건에 맞는 패널을 못 찾았다. match 를 바꿔 보라"}
    return {"id": "img-%d" % (abs(hash((uid, panel_id, start))) % 9000 + 1000),
            "title": title,
            "url": grafana.panel_url(uid, panel_id, entry.get("host", ""), start, end)}
