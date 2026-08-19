"""대화형 질의 — 질문 위생과 세션 역치환. 설계는 bot/GATEWAY_GUIDE.md §27.

알림 경로는 컨텍스트를 `masking.build_llm_context` 화이트리스트가 지킨다. 질의 경로에는
그 보호가 없다. 사람은 호스트명이든 IP든 계정명이든 아무거나 친다.
"""

import functools
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
_cancelled: dict = {}    # 세션 -> 멈춤을 누른 단조시각. 다음 라운드에서 확인한다.
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
                if any(low in str(ent.get(k) or "").lower()
                       for k in ("host", "logs", "security"))]
        if len(hits) == 1:
            out = out.replace(frag, hits[0])
    return out


def _alias(mk, name: str, *others) -> None:
    """한 기계의 여러 이름을 **같은 토큰**에 묶는다.

    두 가지를 함께 다룬다.

    사람은 `vm-a.novalocal` 을 `vm-a` 로 줄여 친다. 그리고 **같은 기계를 축마다 다르게
    부른다** — Zabbix 는 `node1`, Loki 와 Wazuh 는 FQDN 이다. 패널이 넘기는 값은 축
    이름이라, Zabbix 이름만 등록하면 안 가려진 채 나가고 대상도 못 찾는다.

    새 토큰을 만들지 않고 기존 토큰을 가리키게 해야 같은 기계로 읽힌다.
    """
    base = mk._fwd.get(name)
    if not base:
        return
    for other in (name,) + tuple(others):
        for cand in (other, str(other or "").split(".")[0]):
            if cand and cand != name and cand not in mk._fwd:
                mk._fwd[cand] = base
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
            # 축마다 이름이 다를 수 있다. 못 풀면 빈 값이고 그건 '없음'이 아니다.
            logs = collector._resolve_label(name, h, source, "logs")
            sec = collector._resolve_label(name, h, source, "security")
            _alias(mk, name, logs, sec)
            table[mk._fwd[name]] = {
                "host": name, "source": source, "logs": logs, "security": sec,
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
    prune_cancels(now)
    return len(dead)


def session_key(sid: str, user: str = "") -> str:
    """이 요청이 속한 세션의 열쇠.

    **화면이 보낸 이름만으로 나누지 않는다.** 화면은 새 대화의 첫 턴에 `'ui'` 를 보내므로
    그 값만 쓰면 모든 사람이 한 세션이 된다. 그러면 한 사람의 멈춤이 남의 질문을 끊고,
    역치환 표도 섞인다(2026-08-19 감사, 네 갈래가 같은 결론).
    """
    return "%s|%s" % (str(user or ANON), str(sid or "-"))


def cancel(sid: str) -> None:
    """사람이 멈춤 단추를 눌렀다. 다음 라운드에서 멈춘다.

    지금 도는 조회를 중간에 끊지는 않는다. 끊어도 이미 나간 호출의 비용은 그대로이고,
    받아 놓은 것을 버리면 사람에게 남는 것이 없다.
    """
    with _lock:
        _cancelled[str(sid or "-")] = _now()


def cancelled(sid: str, started: float) -> bool:
    """이 요청을 멈춰야 하는가. 맞으면 표시를 지우고 True.

    **요청이 시작된 뒤에 눌린 것만 인정한다.** 답이 끝난 뒤 도착한 멈춤을 그대로 두면
    다음 질문이 조회 한 번 못 하고 죽는다(2026-08-19 감사 C-3).
    """
    key = str(sid or "-")
    with _lock:
        at = _cancelled.get(key)
        if at is None:
            return False
        if at < float(started):          # 이미 지난 취소다
            del _cancelled[key]
            return False
        del _cancelled[key]
        return True


def prune_cancels(now: float = None) -> int:
    """오래된 취소 표시를 지운다. 반환은 지운 개수."""
    now = _now() if now is None else now
    with _lock:
        dead = [k for k, at in _cancelled.items() if now - at > SESSION_TTL_S]
        for k in dead:
            del _cancelled[k]
    return len(dead)


def forget_all() -> None:
    with _lock:
        _sessions.clear()
        _cancelled.clear()


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
    # **가릴 수 없으면 안 보낸다.** 표가 비면 아는 이름이 없어 누수 검사가 통과해 버린다.
    # 프록시 경로는 같은 상황을 이미 막는데 질의 경로에는 그 게이트가 없었다(2026-08-19).
    if masking.cannot_mask(mk):
        return {"ok": False, "text": "",
                "reason": ("이름 표가 비어 이름을 가릴 수 없다. 감시 서버 연결을 확인하라 "
                           "(가림 없이 보내려면 PROXY_ALLOW_UNMASKED=1)")}
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
            body_json = r.json()
            hits = body_json.get("hits", {}).get("hits", [])
            total = (body_json.get("hits", {}).get("total") or {}).get("value")
    except Exception as e:
        log.warning("보안 조회 실패: %s", e)
        return {"alerts": [], "status": collector.SOURCE_UNAVAILABLE,
                "note": "조회하지 못했다. 이 결과를 '없음'으로 읽지 마라"}
    out = {"alerts": [masking._security_item(
                          collector.flatten_alert(h.get("_source") or {}), masker.mask)
                      for h in hits],
           "status": collector.SOURCE_OK}
    if total is not None:
        # **구간의 총 건수를 함께 준다.** 실린 것만 세면 50건을 넘을 때 조용히 적게 센다.
        out["total"] = int(total)
        if int(total) > len(hits):
            out["note"] = ("이 구간의 경보는 모두 %d건인데 최근 %d건만 실렸다. 건수는 "
                           "total 을 쓰고, 종류별로 세는 것은 실린 범위 안에서만 하라."
                           % (int(total), len(hits)))
    return out


def judgment_body(row: dict, mk: masking.Masker) -> str:
    """과거 판정의 분석 문장. 실을 수 없으면 빈 문자열.

    시각과 유형만 주면 "예전에도 있었다" 까지밖에 못 말한다. **무엇이라고 판단했는지가
    값이다.** 다만 그 문장에는 호스트명이 섞이므로 가린 뒤 누수 검사를 통과할 때만
    싣는다. 못 실어도 구조화 값은 그대로 가므로 판정 자체는 보인다(prior 와 같은 규칙).
    """
    raw = str(row.get("summary") or "")[:600]
    if not raw:
        return ""
    masked = mk.mask(raw)
    return "" if masking._leaks(masked) else masked


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
        item = {"ts": int(r.get("ts") or 0),
                "host": masker.mask(r.get("host") or ""),
                "classes": r.get("classes") or "",
                "sev": r.get("sev") or "",
                "verdict": r.get("verdict") or ""}
        body = judgment_body(r, masker)
        if body:
            item["summary"] = body
        else:
            # 서술은 30일이면 지워진다(보관 정책). 없는 것과 못 실은 것을 구분한다.
            item["summary_note"] = "본문 없음(보관 기간 경과 또는 가림 실패)"
        out.append(item)
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

# 상한에 닿았을 때 마지막으로 한 번 더 부르며 붙이는 말. 조회는 못 하게 하고
# 지금까지 본 것으로만 답하게 한다.
# 예열 호출의 상한(초). 사람이 안 기다리므로 넉넉히 둔다. 도구 정의가 바뀐 뒤 첫
# 호출은 캐시를 새로 쓰느라 느리고, 그 대가를 여기서 치르는 것이 목적이다.
PREWARM_TIMEOUT_S = float(os.environ.get("ASK_PREWARM_TIMEOUT_S", "180"))

CAP_NOTE = ("조회 상한에 닿았다. 더 조회할 수 없다. 지금까지 확인한 것만으로 answer 를 "
            "불러 답하라. 확인하지 못한 것은 확인하지 못했다고 쓴다.")

MAX_ROUNDS = int(os.environ.get("ASK_MAX_ROUNDS", "6"))
DEADLINE_S = float(os.environ.get("ASK_DEADLINE_S", "60"))
RESULT_BYTES = int(os.environ.get("ASK_RESULT_BYTES", "60000"))

ASK_SYSTEM = """\
당신은 KINX IDC 관제 담당자의 질문에 답하는 조회 도우미다. 도구로 지표·로그·보안
기록을 읽고 한국어로 답한다.

규칙:
- 호스트는 [host-...] 같은 가명 토큰으로만 지칭한다. 실명을 지어내지 마라.
- **범위를 지킨다.** 너는 이 회사의 관측 데이터(지표·로그·보안 기록)에 대해서만
  답한다. 관측과 무관한 질문(일반 지식·잡담·다른 주제)에는 답하지 말고, 무엇을 물어야
  하는지 한 문장으로 알려 준 뒤 끝내라. 길게 사양하지 마라.
- **그림은 도움이 될 때만 붙인다.** panel_image 는 사람이 보고 있는 화면을 답과 함께
  보여 줄 때, 또는 추이·모양을 말로 설명하기 어려울 때 한 번만 부른다. 같은 대화에서
  이미 붙였으면 다시 붙이지 마라. "없다"·"정상이다" 만 말하는 답에는 붙이지 마라.
- **사람이 보고 있는 패널에 대해 물었는데 조회가 비었으면, 사람에게 화면을 확인하라고
  미루지 말고 네가 panel_image 로 그 패널을 먼저 봐라.** 화면에는 값이 있는데 다른 축을
  조회해 비었을 수 있다.
- **로그에서 여러 낱말 중 하나를 찾을 때는 contains 에 `failed|invalid user` 처럼
  세로줄로 이어라.** 다섯 개까지 된다.
- **답은 answer 도구로 낸다.** 조사가 끝나면 산문으로 쓰지 말고 answer 를 불러라.
  `summary` 에 결론, `findings` 에 조회로 확인한 근거, `window_utc` 에는 도구가 돌려준
  구간을 그대로 옮기고, 그림을 붙였으면 `image_ids` 에 panel_image 가 준 id 를 적는다.
  조회를 안 했으면 `window_utc` 는 비운다. 지어내면 거부되고 다시 물어야 한다.
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


# 관측 지식 조각. 우리 환경의 사실을 적어 프롬프트에 실는다. 없어도 창구는 돌아야 한다.
FACTS_FILE = os.environ.get(
    "ASK_FACTS_FILE",
    os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                 "ask_facts.yml"))


@functools.lru_cache(maxsize=1)
def load_facts() -> str:
    """지식 조각을 한 덩어리 글로 읽는다. 못 읽으면 빈 문자열.

    YAML 로 적되 파서를 쓰지 않는다. 값이 전부 여러 줄 글이고, 우리가 하는 일은
    그것을 이어 붙이는 것뿐이라 의존성을 늘릴 이유가 없다.
    """
    try:
        with open(FACTS_FILE, encoding="utf-8") as f:
            raw = f.read()
    except OSError as e:
        log.warning("관측 지식 조각을 못 읽었다(%s) — 없이 진행한다", e)
        return ""
    out = []
    for line in raw.splitlines():
        if line.startswith("#") or not line.strip():
            continue
        out.append(line.rstrip().lstrip("|").rstrip("|") if line.endswith("|") else line)
    return chr(10).join(x for x in out if x.strip()).strip()


# 그림 손잡이. 화면은 그림을 따로 그리므로 본문에 남으면 지저분한 글자일 뿐이다.
_HANDLE_RE = re.compile(r"\[?img-[0-9a-z]+\]?")
_MD_IMAGE_RE = re.compile(r"!\[[^\]]*\]\(\s*\[?img-[0-9a-z]+\]?\s*\)")


def chosen_images(images: list, answer: dict) -> list:
    """화면에 붙일 그림. 답이 고른 것만 붙인다.

    답 도구를 안 쓰고 글로 끝낸 경우에는 만든 것을 전부 붙인다. 예전 동작이다.
    """
    picked = (answer or {}).get("image_ids")
    if not answer or picked is None:
        return images
    keep = set(picked)
    return [im for im in images if im.get("id") in keep]


# 조회가 한 건도 성공하지 않았을 때 답에 붙이는 말. 사람이 화면에서 보는 문장이다.
NO_EVIDENCE = ("※ 이 답은 조회가 한 건도 성공하지 않은 상태에서 작성됐다. "
               "없다는 뜻이 아니라 확인하지 못했다는 뜻이다.")


def render_answer(args: dict, had_evidence: bool = True) -> str:
    """답 도구의 필드를 사람이 읽는 글로. 손잡이와 구간을 산문에서 뺀 대가로 여기서 만든다.

    **근거가 하나도 없으면 그 사실을 붙인다.** 2026-08-19 랩 실측으로 모델이 인자를
    깨뜨려 보내 도구가 전부 거부했는데도 "그 시간대 로그가 없습니다" 로 답을 닫았다.
    사람에게는 조회가 된 것처럼 보인다. 판정은 코드가 한다 — 성공한 조회가 있었는지는
    세면 되는 값이다.
    """
    a = args or {}
    parts = [str(a.get("summary") or "").strip()]
    for f in (a.get("findings") or []):
        line = str(f).strip()
        if line:
            parts.append("- " + line)
    win = str(a.get("window_utc") or "").strip()
    if win:
        parts.append("조회 구간: " + win)
    if not had_evidence:
        parts.append(NO_EVIDENCE)
    return (chr(10)).join(p for p in parts if p)


def strip_handles(text: str) -> str:
    """답에서 그림 손잡이를 걷어 낸다. 앞뒤 공백도 정리한다."""
    # 마크다운 그림 표기는 통째로 걷어 낸다. 손잡이만 빼면 `![image]()` 가 남아
    # 화면에 "!(image)" 로 찍힌다(2026-08-18 실측). 그림은 따로 붙는다.
    out = _MD_IMAGE_RE.sub("", str(text or ""))
    out = _HANDLE_RE.sub("", out)
    # 손잡이가 괄호 안에 있었으면 빈 괄호가 남는다 — "패널()의" 가 화면에 그대로
    # 나왔다(2026-08-18 실측).
    out = re.sub(r"\(\s*\)|\[\s*\]", "", out)
    out = re.sub(r"[ \t]{2,}", " ", out)
    out = re.sub(r"[ \t]+([,.!?)\]])", r"\1", out)
    return re.sub(r"\n{3,}", "\n\n", out).strip()


def system_prompt() -> str:
    """모델에 줄 지시문. 기본 규칙 뒤에 우리 환경의 사실을 붙인다.

    규칙 본문은 `bot/prompts/ask.md` 에서 읽는다. 파일이 없으면 아래 상수로 돈다.
    """
    from . import prompts

    base = prompts.load("ask", ASK_SYSTEM)
    facts = load_facts()
    if not facts:
        return base
    return base + (chr(10) * 2) + "[이 환경의 사실]" + chr(10) + facts


def _blocks_text(content) -> str:
    return "\n".join(b.get("text", "") for b in (content or [])
                     if isinstance(b, dict) and b.get("type") == "text").strip()


async def run_ask(question: str, history=None, sid: str = "", table: dict = None,
                  model_fn=None, clock=None, now: int = None, user: str = "",
                  panel_fn=None, panel: dict = None) -> dict:
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
            _alias(mk, ent.get("host", ""), ent.get("logs", ""), ent.get("security", ""))
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

    # 세션 열쇠에 신원을 넣는다. 화면이 보내는 이름만으로는 사람이 안 나뉜다.
    sid = session_key(sid, user)

    # 사람이 보던 구간. 화면이 넘겨 주므로 모델에게 받아 적으라고 시키지 않는다.
    panel_span = None
    pf = asktools.parse_when((panel or {}).get("from"))
    pt = asktools.parse_when((panel or {}).get("to"))
    if pf is not None and pt is not None and pf < pt:
        panel_span = (pf, pt)
    # 화면에서 열지 않고 질문 글만 붙여 넣는 일이 잦다. 그러면 패널 맥락이 아예 안 오고
    # 도구는 최근 창을 본다. 사람이 글에 적어 놓은 구간을 읽어 쓴다(지어내지 않는다).
    if panel_span is None:
        panel_span = asktools.span_in_text(clean["text"])

    ctx = {
        "table": table, "now": now, "panel_span": panel_span,
        "fetch_logs": lambda q, a, b, lim: fetch_logs(q, a, b, lim, mk),
        "fetch_security": lambda body: fetch_security(body, mk),
        "fetch_judgments": lambda host, days: fetch_judgments(host, days, mk),
        "fetch_metrics": lambda ent, match, a, b: fetch_metrics(ent, match, a, b, mk),
        "fetch_problems": lambda ent: fetch_problems(ent, mk),
        # 패널 손잡이는 이번 턴 안에서만 뜻이 있다. 모델은 pnl-3 만 보고 대시보드
        # 식별자는 서버가 들고 있는다.
        "panel_refs": {},
        "fetch_panel": (panel_fn or (
            lambda ent, target, a, b: fetch_panel(ent, target, a, b, panel))),
        "list_panels": (lambda dash: fetch_panel_list(dash, mk)),
    }

    images = []          # 화면이 그릴 그림. 모델에는 손잡이만 준다.
    # 사람이 보고 있던 패널은 **맥락으로만** 알려 준다. 무조건 붙이면 이어지는
    # 질문마다 같은 그림이 다시 그려진다. 붙일지는 모델이 정하고, 판단 기준은 지시문에
    # 적었다.
    # **지금이 언제인지 알려 준다.** 사람은 "어제 오후 3시" 처럼 상대 시각으로 말하는데,
    # 모델이 오늘 날짜를 모르면 조회를 못 하고 되묻는다(2026-08-19 랩 실측). 서버 시각을
    # 주면 모델이 계산해서 range 로 넘긴다.
    viewing = "[지금] %s UTC%s" % (asktools.window_label(now, now).split(" → ")[0],
                                   chr(10))
    if panel and panel.get("uid"):
        span = ""
        if panel_span:
            span = " 조회 구간은 %s 이며 도구가 기본으로 그 구간을 본다." % (
                asktools.window_label(*panel_span))
        viewing += ("[사람이 보고 있는 패널] %s — 이 화면을 그림으로 붙이려면 "
                    "panel_image 를 부르면 된다.%s" + chr(10)
                    ) % (mk.mask(str(panel.get("title") or "제목 없음")), span)

    hist, dropped = trim_history(history)
    # **이력도 가린다.** 화면은 사람이 읽는 글(실명으로 되돌린 것)을 이력으로
    # 되보낸다. 그대로 실으면 앞 턴의 실명이 모델에 가고, 모델은 그 이름을 도구
    # 인자로 쓴다(2026-08-18 실측).
    messages = [{"role": m["role"], "content": mk.mask(m["content"])} for m in hist]
    if dropped:
        messages.insert(0, {"role": "user", "content": DROP_NOTE})
    messages.append({"role": "user", "content": viewing + clean["text"]})
    trace, spent, stopped = [], 0, "end_turn"
    # 같은 조회를 두 번 하지 않는다. 라운드와 비용을 태우고, 결과가 같으므로 얻는 것도 없다.
    called = {}
    text = ""
    # 이번 요청의 도구 정의. 대상 토큰이 스키마에 박히므로 표 밖의 이름은 표현할 수 없다.
    specs = asktools.build_tool_specs(table)
    # 답 도구가 참조할 수 있는 값. 턴 중에 생기므로 스키마가 아니라 코드가 지킨다.
    made_images, seen_windows, final = set(), set(), {}
    # 성공한 조회 수. 답이 근거 없이 "없다" 로 닫히는 것을 막는 데 쓴다.
    ok_queries = {"n": 0}

    async def _exec_query(name, args, seen, idx):
        """조회 도구 한 번. 반환 `(화면에 붙일 그림, 모델에 줄 결과, 직렬화한 글자)`.

        **두 엔진이 이 함수를 함께 쓴다.** 중복 차단·그림 분리·마스킹이 한 곳에 있어야
        엔진을 갈아 끼울 때 한쪽만 빠지지 않는다.
        """
        key = _json.dumps([name, args], ensure_ascii=False, sort_keys=True)
        if key in seen:
            out = {"error": "이미 같은 조회를 했다. 그 결과를 쓰고 다음으로 넘어가라",
                   "previous_round": seen[key]}
        else:
            seen[key] = idx
            out = await asktools.run_tool(name, args, ctx)
        image = None
        if isinstance(out, dict) and out.get("url"):
            # **주소는 모델에 주지 않는다.** 대시보드 식별자와 호스트 실명이 들어 있다.
            # 같은 패널을 두 번 찾아오면 그림은 한 장만 붙인다. 두 번 붙이면 상태 검사가
            # 이상으로 보고 답이 통째로 버려진다(2026-08-18 실측: invalid_state).
            image = None if out.get("id") in made_images else out
            made_images.add(out.get("id"))
            out = {"image": out.get("id"), "title": mk.mask(out.get("title", "")),
                   "note": "화면에 붙였다. answer 의 image_ids 에 이 id 를 적어라"}
        if isinstance(out, dict) and out.get("window_utc"):
            seen_windows.add(out["window_utc"])
        if isinstance(out, dict) and not out.get("error"):
            ok_queries["n"] += 1
        return image, out, _json.dumps(out, ensure_ascii=False)

    async def exec_tool(name, args, seen, idx):
        """도구 하나. 답 도구는 조회가 아니라 마무리라서 따로 본다."""
        if name == "answer":
            ok, why = asktools.check_answer(args, made_images, seen_windows)
            if not ok:
                return None, {"error": why}, _json.dumps({"error": why}, ensure_ascii=False)
            final.update(args or {})
            out = {"ok": True, "note": "답을 받았다. 더 부르지 마라"}
            return None, out, _json.dumps(out, ensure_ascii=False)
        return await _exec_query(name, args, seen, idx)

    if engine_name() == "graph":
        return await _run_graph(
            system_prompt(), messages, mk, sid, user, exec_tool, model_fn,
            started, tick, specs, final, made_images)

    def _model(msgs):
        if model_fn is not None:
            return model_fn(system_prompt(), msgs, specs)
        return llm.claude_tools(system_prompt(), msgs, specs)

    for _round in range(MAX_ROUNDS + 1):
        # 답 도구는 조회가 아니라 마무리라 상한에 세지 않는다. 두 엔진이 같은 셈법을 쓴다.
        if asktools.query_count(trace) >= MAX_ROUNDS:
            stopped = "rounds"
            break
        if tick() - started > DEADLINE_S:
            stopped = "deadline"
            break
        if cancelled(sid, started):
            stopped = "cancelled"
            break
        res = await asyncio.to_thread(egress.call_raw, lambda: _model(messages),
                                      kind="ask", user=user)
        if not res["ok"]:
            return {"text": "", "trace": trace, "rounds": len(trace), "images": images,
                    "stopped": "llm_failed",
                    "error": "모델을 부르지 못했다: %s" % res["reason"]}
        reply = res["value"]
        # **실제로 쓴 토큰으로 센다.** 추정하지 않고 응답에 실려 온 값을 남긴다.
        u = reply.get("usage") or {}
        if u:
            from . import store
            store.record_tokens(
                    "ask", user, u.get("input_tokens"), u.get("output_tokens"),
                    cache_write=u.get("cache_creation_input_tokens") or 0,
                    cache_read=u.get("cache_read_input_tokens") or 0,
                    model=reply.get("model") or "")
        text = _blocks_text(reply.get("content")) or text
        uses = [b for b in (reply.get("content") or [])
                if isinstance(b, dict) and b.get("type") == "tool_use"]
        if not uses:
            break
        messages = messages + [{"role": "assistant", "content": reply["content"]}]
        results = []
        for u in uses:
            # 모델이 준 인자는 토큰 상태 그대로 쓴다. 도구가 표에서 실명을 찾는다.
            image, out, blob = await exec_tool(u.get("name", ""), u.get("input") or {},
                                               called, len(trace) + 1)
            if image:
                images.append(image)
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
        if final:
            text = render_answer(final, ok_queries["n"] > 0)
            break
        if stopped == "budget":
            break
    else:
        stopped = "rounds"

    # **상한에 닿았어도 답은 준다.** 조회한 것이 있는데 마무리를 안 하면 사람에게
    # 가는 글이 모델의 중간 생각이 된다.
    if stopped in ("rounds", "deadline", "budget") and not final and trace:
        if await force_answer(system_prompt(), messages, specs, user,
                              model_fn, exec_tool, trace):
            text = render_answer(final, ok_queries["n"] > 0)
    if stopped in ("rounds", "deadline", "budget", "cancelled", "invalid_state") and not final:
        text = (stall_note(stopped, trace)
                + ((chr(10) * 2 + text) if text else ""))
    remember(sid or "-", mk)
    return {"text": strip_handles(mk.unmask(text)), "trace": trace,
            "rounds": len(trace),
            "images": chosen_images(images, final), "stopped": stopped, "error": ""}



def prewarm() -> str:
    """기동 뒤 첫 질의가 느린 것을 미리 치른다. 반환은 사람이 읽을 결과 한 줄.

    2026-08-18 랩 실측으로 재기동 직후 첫 호출이 96초, 다음 호출은 6초였다. 접두사
    캐시가 비어 있고 연결도 처음이라 그렇다. 사람이 기다릴 시간이 아니므로 기동 때
    작은 호출로 대신 치른다.

    실패해도 조용히 넘어간다. 예열이 안 되면 첫 질의가 느릴 뿐이고, 기동을 막을 일은
    아니다.
    """
    import asyncio

    from . import asktools, egress, llm

    try:
        table = asyncio.run(build_table(proxy.build_masker()))
        if not table:
            return "대상 표가 비어 예열을 건너뛴다"
        specs = asktools.build_tool_specs(table)
        last = ""
        # 한 번 실패했다고 그만두면 예열이 안 된 채로 사람이 첫 질의를 받는다. 배경에서
        # 도는 일이라 한 번 더 해도 사람이 기다리지 않는다.
        for _try in range(2):
            # **같은 출구를 지난다.** 여기만 빠지면 기동 때마다 동시 수·시간당 상한·
            # 토큰 계수 밖에서 도는 호출이 생긴다(2026-08-19 감사).
            res = egress.call_raw(
                lambda: llm.claude_tools(system_prompt(),
                                         [{"role": "user", "content": "준비"}], specs,
                                         timeout_s=PREWARM_TIMEOUT_S),
                kind="ask", user="(예열)")
            if res["ok"]:
                return "질의 예열 완료 (대상 %d개)" % len(table)
            last = res["reason"]
        return "질의 예열 실패: %s" % last
    except Exception as e:
        return "질의 예열 실패: %s" % e


def stall_note(stopped: str, trace: list) -> str:
    """상한에 걸렸을 때 사람에게 하는 말.

    조회를 하나도 못 했으면 "조회한 것: 없음" 은 사람에게 아무 도움이 안 된다. 그 경우는
    대개 모델 응답이 늦은 것이다(2026-08-18 실측: 한 호출이 96초). 무엇을 하라는 말까지
    적는다.
    """
    if not trace:
        if stopped == "deadline":
            return "모델 응답이 늦어 조회를 시작하지 못했다. 다시 물어보라."
        return "조회를 시작하지 못한 채 상한(%s)에 닿았다. 다시 물어보라." % stopped
    return ("여기까지 확인했고 상한(%s)에 닿아 멈췄다. 조회한 것: %s"
            % (stopped, ", ".join(t["tool"] for t in trace)))


def drop_dangling(msgs: list) -> list:
    """결과가 안 붙은 도구 요청을 끝에서 걷어 낸다.

    상한에 걸려 멈추면 마지막 남는 것이 **모델이 부르려던 도구 요청**이다. 그 요청은
    실행되지 않았으므로 결과 블록이 없고, 그대로 다시 보내면 Anthropic 이 400 으로
    거부한다(2026-08-18 랩 실측: `tool_use ids were found without tool_result blocks`).
    그러면 마무리 호출이 통째로 실패해 사람은 또 답을 못 받는다.
    """
    out = list(msgs or [])
    while out:
        m = out[-1]
        blocks = m.get("content")
        if m.get("role") != "assistant" or not isinstance(blocks, list):
            break
        if not any(isinstance(b, dict) and b.get("type") == "tool_use" for b in blocks):
            break
        out.pop()
    return out


async def force_answer(system: str, msgs: list, specs: list, user: str,
                       model_fn, exec_tool, trace: list) -> bool:
    """상한에 닿았으면 **한 번만 더** 불러 답을 받는다. 반환은 답을 받았는가.

    안 하면 사람이 받는 글이 모델의 중간 생각이다. 2026-08-18 랩 실측으로 라운드를 다
    쓴 질의의 회신이 "레벨을 더 낮춰서 전체 보안 이벤트를 확인하겠습니다." 한 줄이었다.
    조회는 열 번 했는데 그 결과가 사람에게 하나도 안 갔다.

    이 호출에는 **answer 도구만 준다.** 조회 도구를 남겨 두면 모델이 상한을 넘겨 또
    조회하려 든다.
    """
    import asyncio

    from . import egress, llm

    only = [t for t in (specs or []) if t.get("name") == "answer"]
    if not only:
        return False
    last = drop_dangling(msgs) + [{"role": "user", "content": CAP_NOTE}]

    def _model():
        if model_fn is not None:
            return model_fn(system, last, only)
        return llm.claude_tools(system, last, only)

    res = await asyncio.to_thread(egress.call_raw, _model, kind="ask", user=user)
    if not res["ok"]:
        log.warning("마무리 호출 실패: %s", res["reason"])
        return False
    reply = res["value"]
    for b in (reply.get("content") or []):
        if isinstance(b, dict) and b.get("type") == "tool_use" and b.get("name") == "answer":
            _img, out, blob = await exec_tool("answer", b.get("input") or {},
                                              {}, len(trace) + 1)
            trace.append({"tool": "answer", "args": b.get("input") or {},
                          "error": out.get("error", ""), "bytes": len(blob)})
            return not out.get("error")
    return False

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


def metric_item(it: dict, raw: list, shown: list, kind: str, mask) -> dict:
    """지표 아이템 하나의 전송 형태.

    **이름과 키를 이름 표에 거친다.** 인증서 감시 아이템 키가
    `web.certificate.get[<도메인>,443]` 형태라, 가리지 않으면 "인증서 며칠 남았어" 한 마디에
    고객 도메인이 통째로 나간다(2026-08-19 감사).
    """
    return {"name": mask(str(it.get("name") or "")),
            "key": mask(str(it.get("key_") or "")),
            "units": it.get("units"), "last": it.get("lastvalue"),
            # 몇 점을 읽어 몇 점으로 줄였는지, 그리고 **무엇을 읽었는지** 준다.
            # 안 알리면 모델이 실린 점이 전부라고 여기고 간격도 지어낸다.
            "sampled_from": len(raw), "series": shown,
            "source_kind": kind,
            "point_meaning": ("1시간 최대값(추세). avg·min 동봉"
                              if kind == "trend" else "원본 측정값")}


def metrics_result(items: list, series: dict, masker: masking.Masker = None) -> dict:
    """지표 결과 한 벌. 조회 없이 조립만 한다 — 검사가 실경로와 같은 조립을 쓰게."""
    from . import asktools

    mask = masker.mask if masker is not None else (lambda x: x)
    out = []
    for it in items or []:
        raw = list((series or {}).get(str(it.get("itemid"))) or [])
        out.append(metric_item(it, raw, asktools.downsample(raw), "history", mask))
    return {"metrics": out}


def problems_result(rows: list, masker: masking.Masker = None) -> dict:
    """열린 문제 결과 한 벌.

    Zabbix 문제명은 매크로가 풀린 문장이라 `Zabbix agent is not available on <호스트명>`
    처럼 호스트명이 박혀 있다. 같은 값을 알림 경로는 이미 가린다(masking.py).
    """
    from . import collector

    mask = masker.mask if masker is not None else (lambda x: x)
    return {"problems": [{"name": mask(str(p.get("name") or "")),
                          "sev": p.get("severity"),
                          "t": int(p.get("clock") or 0)} for p in rows or []],
            "status": collector.SOURCE_OK}


async def fetch_metrics(entry: dict, match: str, start: int, end: int,
                        masker: masking.Masker = None) -> dict:
    """호스트의 지표 추이. 아이템 이름·키에 든 문자열로 고른다.

    특정 시각을 물으면 `range` 로 절대 구간이 온다. 사람은 "어제 2시에 튀었다" 로 묻지
    "지금부터 몇 분" 으로 묻지 않는다.
    """
    import httpx

    from . import asktools, collector

    mask = masker.mask if masker is not None else (lambda x: x)
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
            # **가나다순 앞에서 자르지 않는다.** 랩 실측으로 `cpu` 는 17개가 걸리고
            # 앞 5개가 guest·idle 시간으로 채워져 CPU utilization 이 한 번도 안 들어왔다.
            items = asktools.rank_items(items, match)
            total = len(items)
            dropped = [mask(str(x.get("name") or "")) for x in items[asktools.ITEM_LIMIT:]]
            out = []
            for it in items[:asktools.ITEM_LIMIT]:
                vt = int(it.get("value_type", 3))
                raw, kind = [], ""
                if vt in (0, 3):         # 수치형만 추이가 뜻이 있다
                    if asktools.use_trend(start, end):
                        # **긴 구간은 추세로 본다.** 이력 보관이 짧아 90일을 이력으로
                        # 물으면 비거나 잘린다. 추세는 시간 단위 집계라 가볍다.
                        rows = await zbx.call(c, "trend.get", {
                            "itemids": it["itemid"], "time_from": start,
                            "time_till": end, "output": "extend",
                            "limit": asktools.HISTORY_FETCH_MAX})
                        rows.sort(key=lambda r: int(r.get("clock", 0)))
                        # 값은 시간별 **최대**를 쓴다. 평균으로 줄이면 한 시간 안에
                        # 튄 자리가 묻혀 "정상입니다" 가 나온다.
                        raw = [{"t": int(r["clock"]), "v": r.get("value_max"),
                                "avg": r.get("value_avg"), "min": r.get("value_min")}
                               for r in rows]
                        kind = "trend"
                    else:
                        # **구간 전체를 받아 놓고 줄인다.** 상한만큼만 최신순으로 받으면
                        # 앞부분이 잘려 먼저 난 스파이크를 못 본다(2026-08-18 실측).
                        hist = await zbx.call(c, "history.get", {
                            "itemids": it["itemid"], "history": vt,
                            "time_from": start, "time_till": end, "output": "extend",
                            "sortfield": "clock", "sortorder": "ASC",
                            "limit": asktools.HISTORY_FETCH_MAX})
                        raw = [{"t": int(h["clock"]), "v": h["value"]} for h in hist]
                        kind = "history"
                out.append(metric_item(it, raw, asktools.downsample(raw), kind,
                                       mask))
    except Exception as e:
        log.warning("지표 조회 실패: %s", e)
        return {"metrics": [], "status": collector.SOURCE_UNAVAILABLE,
                "note": "조회하지 못했다. 이 결과를 '없음'으로 읽지 마라"}
    return asktools.note_if_cut(
        {"metrics": out, "matched": total, "window": [start, end],
         "status": collector.SOURCE_OK},
        total=total, shown=len(out), dropped=dropped)


async def fetch_problems(entry, masker: masking.Masker = None) -> dict:
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
                out.extend(problems_result(
                    await zbx.call(c, "problem.get", params), masker)["problems"])
    except Exception as e:
        log.warning("열린 문제 조회 실패: %s", e)
        return {"problems": [], "status": collector.SOURCE_UNAVAILABLE,
                "note": "조회하지 못했다. 이 결과를 '없음'으로 읽지 마라"}
    return {"problems": out, "status": collector.SOURCE_OK}


def var_host_of(entry: dict, panel: dict) -> str:
    """대시보드 변수에 넣을 호스트 값. 화면이 준 값이 먼저다.

    Zabbix 축 이름을 넣으면 Loki·Wazuh 패널이 빈 그래프로 나오고 사람은 "아무 일도
    없었다" 로 읽는다(축마다 이름이 다르다 — collector._resolve_label 참고).
    """
    return str((panel or {}).get("host") or "") or (entry or {}).get("host", "")


async def fetch_panel(entry: dict, target, start: int, end: int,
                      panel: dict = None) -> dict:
    """관측 화면 한 장. 모델에는 손잡이만 가고 주소는 화면으로만 간다.

    `target` 이 있으면 그 패널을(list_panels 가 준 손잡이를 서버가 푼 값), 없으면
    사람이 보고 있는 패널을 그린다. **제목으로 찾는 길은 없다.**
    """
    from . import asktools, grafana

    if target:
        uid, panel_id, title = target
        note = "사람이 보고 있는 패널이 아니라 목록에서 고른 패널이다"
    else:
        uid, panel_id = asktools.panel_pick(panel)
        title, note = str((panel or {}).get("title") or ""), ""
    if not uid:
        return {"error": "어느 패널인지 모른다. list_panels 로 목록을 받아 ref 를 골라 "
                         "panel_ref 에 넣어라"}
    out = {"id": "img-%d" % (abs(hash((uid, panel_id, start))) % 9000 + 1000),
           "title": title,
           "url": grafana.panel_url(uid, panel_id, var_host_of(entry, panel), start, end)}
    if note:
        out["note"] = note
    return out


async def fetch_panel_list(dash: str, masker: masking.Masker) -> tuple:
    """볼 수 있는 패널 목록과 조회 상태. 손잡이는 부르는 쪽이 붙인다.

    제목에 고객사명이나 호스트명이 들어 있을 수 있으므로 이름 표를 거쳐 내보낸다.
    """
    import asyncio

    from . import grafana

    from . import collector

    # **조회 실패와 "없음" 을 구분한다.** 다른 네 축은 이미 상태를 싣는데(§12) 이 축만
    # 빠져 있어, 주소가 없거나 Grafana 가 죽어도 "그 조건에 맞는 패널이 없다" 로 나갔다.
    # 사람은 화면에서 그 패널을 보고 있는데 봇이 없다고 답한다(2026-08-19 감사).
    try:
        items = await asyncio.to_thread(grafana.list_panels, dash)
    except Exception as e:
        log.warning("패널 목록 조회 실패: %s", e)
        return [], collector.SOURCE_UNAVAILABLE
    # 빈 목록일 때만 설정을 본다. 먼저 보면 조회 자체를 건너뛰게 되어, 목록을 대신 채워
    # 넣는 검사가 통째로 지나가 버린다.
    if not items and not grafana._base():
        return [], collector.SOURCE_DISABLED
    # 질의문에는 호스트명이 그대로 들어 있는 일이 있다. 이름 표를 거쳐 내보낸다.
    return [dict(it, title=masker.mask(str(it.get("title") or "")),
                 dashboard=masker.mask(str(it.get("dashboard") or "")),
                 query=masker.mask(str(it.get("query") or "")))
            for it in items], collector.SOURCE_OK


def engine_name() -> str:
    """질의 반복문을 무엇으로 돌릴까. `graph`(LangGraph, 기본) 또는 `loop`(직접 구현).

    프레임워크가 안 깔린 서버에서는 기존 반복문으로 돈다. 설정이나 설치가 빠진 사람이
    답을 아예 못 받는 상황이 가장 나쁘다. `ASK_ENGINE=loop` 이 되돌리는 길이며,
    두 엔진이 같은 답을 내는지는 셀프테스트가 지킨다.
    """
    from . import graph

    want = os.environ.get("ASK_ENGINE", "graph").strip().lower()
    if want == "loop":
        return "loop"
    if graph.available():
        return "graph"
    log.warning("langgraph 가 없어 기존 반복문으로 돈다")
    return "loop"


async def _run_graph(system: str, messages: list, mk, sid: str, user: str,
                     exec_tool, model_fn, started: float, tick,
                     specs=None, final=None, made_images=None) -> dict:
    """LangGraph 로 도는 경로. 반환 계약은 기존 반복문과 같다.

    상한·멈춤·마스킹·도구는 전부 우리 것을 그대로 쓴다. 프레임워크가 맡는 것은 모델과
    도구 사이를 오가는 흐름뿐이다.
    """
    from langchain_core.messages import AIMessage, HumanMessage, SystemMessage

    from . import asktools
    from . import graph as G

    def guard() -> bool:
        """더 돌면 안 되는가. 시간 상한과 사람이 누른 멈춤을 함께 본다."""
        if tick() - started > DEADLINE_S:
            _stop["why"] = "deadline"
            return True
        if cancelled(sid, started):
            _stop["why"] = "cancelled"
            return True
        return False

    _stop = {"why": ""}
    lc = [SystemMessage(content=system)]
    for m in messages:
        # 이력의 assistant 는 글만 남아 있다. 도구 호출 이력은 다시 싣지 않는다.
        lc.append(AIMessage(content=m["content"]) if m["role"] == "assistant"
                  else HumanMessage(content=m["content"]))
    app = G.build(system, specs if specs is not None else asktools.TOOL_SPECS,
                  user, exec_tool, model_fn,
                  guard=guard, result_bytes=RESULT_BYTES, max_calls=MAX_ROUNDS,
                  answered=lambda: bool(final))
    state = {"messages": lc, "trace": [], "images": [], "spent": 0, "called": {},
             "stopped": "", "error": ""}
    try:
        # 노드가 라운드마다 둘이라 프레임워크 상한은 넉넉히 두고, 실제 제한은 우리
        # `route` 가 건다. 프레임워크 상한에 먼저 닿으면 사람이 이유를 못 읽는다.
        out = await app.ainvoke(state, {"recursion_limit": MAX_ROUNDS * 2 + 4})
    except Exception as e:
        log.warning("그래프 실행 실패: %s", e)
        return {"text": "", "trace": [], "rounds": 0, "images": [],
                "stopped": "llm_failed", "error": "질의를 끝내지 못했다: %s" % e}
    trace = out.get("trace") or []
    if out.get("stopped") == "llm_failed":
        return {"text": "", "trace": trace, "rounds": len(trace),
                "images": out.get("images") or [], "stopped": "llm_failed",
                "error": "모델을 부르지 못했다: %s" % out.get("error", "")}
    text = ""
    if final:
        # 답 도구로 받았으면 그것이 답이다. 산문에서 손잡이를 걷어 낼 일이 없다.
        text = render_answer(final, ok_queries["n"] > 0)
    else:
        for m in reversed(out.get("messages") or []):
            if isinstance(m, AIMessage) and isinstance(m.content, str) and m.content.strip():
                text = m.content
                break
    stopped = _stop["why"] or out.get("stopped") or "end_turn"
    # 답을 받았으면 상한 표시를 붙이지 않는다. 마지막 라운드에 답한 것을 "멈췄다" 로
    # 적으면 기록을 보는 사람이 답이 잘린 줄 안다.
    if stopped == "end_turn" and not final and len(trace) >= MAX_ROUNDS:
        stopped = "rounds"
    if stopped in ("rounds", "deadline", "budget") and not final and trace:
        if await force_answer(system, G.to_anthropic(out.get("messages") or []),
                              specs, user, model_fn, exec_tool, trace):
            text = render_answer(final, ok_queries["n"] > 0)
    if stopped in ("rounds", "deadline", "budget", "cancelled", "invalid_state") and not final:
        text = (stall_note(stopped, trace)
                + ((chr(10) * 2 + text) if text else ""))
    remember(sid or "-", mk)
    return {"text": strip_handles(mk.unmask(text)), "trace": trace,
            "rounds": len(trace),
            "images": chosen_images(out.get("images") or [], final),
            "stopped": stopped, "error": ""}
