"""전송 마스킹·화이트리스트 — docs/02-design/llm-data-contract.md의 코드 구현. 표 개정 시 문서 먼저."""

import logging
import re

from .alerts import collector

log = logging.getLogger("gateway.masking")

IP_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")


class Masker:
    """요청 단위 가역 마스킹. 맵은 게이트웨이 밖으로 나가지 않음."""

    def __init__(self, token_fn=None):
        self._fwd = {}   # 원문 → 토큰
        self._rev = {}   # 토큰 → 원문
        self._counts = {}
        self._re = None
        self._lower = {}
        # 토큰을 만드는 방법. 기본은 등록 순서 일련번호이고, 요청 하나 안에서만
        # 쓰이므로 그것으로 충분하다. 여러 턴에 걸친 대화에서는 순서가 달라져
        # 같은 토큰이 다른 대상을 가리키므로, 그 경로가 이름에서 산출하는 함수를 준다.
        self._token_fn = token_fn

    def register(self, kind: str, original: str):
        if original and original not in self._fwd:
            if self._token_fn is not None:
                tok = self._token_fn(kind, original)
            else:
                n = self._counts.get(kind, 0) + 1
                self._counts[kind] = n
                tok = f"[{kind}-{n}]"
            self._fwd[original] = tok
            self._rev[tok] = original
            self._re = None

    def _matcher(self):
        """등록 원문을 낱말 경계로 잡는 정규식.

        전에는 단순 문자열 치환이었다. 그러면 `db01` 을 등록했을 때 `mydb01`·`db011`
        안에서도 바뀌어 문장이 망가지고, 반대로 `DB01` 은 안 잡혔다.

        경계는 `\\b` 대신 비낱말 문자 lookaround 를 쓴다. 호스트명에 `-`·`.` 이 흔한데
        `\\b` 는 그 경계를 다르게 본다. 이 형태는 Presidio 의 금지 목록 인식기와 같다.

        긴 것부터 나열하는 순서가 중요하다. 정규식 선택지는 앞에 적힌 것이 먼저 맞으므로,
        `report-Customer-B` 가 `customer-b` 보다 앞에 있어야 통째로 잡힌다.
        """
        if self._re is None and self._fwd:
            terms = sorted(self._fwd, key=len, reverse=True)
            self._re = re.compile(
                r"(?:^|(?<=\W))(" + "|".join(re.escape(t) for t in terms) + r")(?:(?=\W)|$)",
                re.IGNORECASE)
            self._lower = {t.lower(): self._fwd[t] for t in terms}
        return self._re

    def mask(self, text: str) -> str:
        if not text:
            return text
        text = str(text)
        rx = self._matcher()
        if rx is not None:
            text = rx.sub(lambda m: self._lower.get(m.group(1).lower(), m.group(1)), text)

        def _ip(m):
            self.register("ip", m.group(0))
            return self._fwd[m.group(0)]
        return IP_RE.sub(_ip, text)

    def unmask(self, text: str) -> str:
        if not text:
            return text
        for tok, orig in self._rev.items():
            text = text.replace(tok, orig)
        return text


_STATUS_KEYS = ("logs", "security", "open_problems", "metrics")
_STATUS_VALUES = (collector.SOURCE_OK, collector.SOURCE_UNAVAILABLE,
                  collector.SOURCE_DISABLED, collector.SOURCE_UNMATCHED)


def _sources(context: dict) -> dict:
    """교차 소스 조회 상태만 통과시킨다 — 키·값 모두 알려진 것으로 한정(화이트리스트 유지).
    상태 문자열에는 식별자가 없어 마스킹 대상이 아니다. LLM이 빈 목록의 의미를 알려면 필요하다."""
    src = context.get("sources") or {}
    return {k: (src[k] if src.get(k) in _STATUS_VALUES else "unknown")
            for k in _STATUS_KEYS if k in src}


def _open_problem_item(p: dict, m) -> dict:
    """열린 문제 1건의 전송 형태. 이름은 반드시 마스킹을 거친다(실 호스트명 포함).

    연계 수치는 식별자가 아니라 원값으로 보내되 측정 조건 문자열을 함께 싣는다.
    """
    link = p.get("link") or {}
    return {"name": m(p.get("name")), "class": p.get("class"),
            "open_for_s": p.get("open_for_s"), "stale": bool(p.get("stale")),
            "link": {"rate": link.get("rate"), "days": link.get("days"),
                     "overlaps": link.get("overlaps"),
                     "open_class": link.get("open_class"),
                     "followed_class": link.get("followed_class"),
                     "measured": link.get("measured")}}


def _security_item(s: dict, m) -> dict:
    """보안 경보 1건의 전송 형태 — 항목별 근거는 위 문서(전송 데이터 계약)."""
    return {"level": s.get("level"), "desc": m(s.get("desc")), "ts": s.get("ts"),
            "rule_id": s.get("rule_id"), "groups": s.get("groups"),
            "path": m(s.get("path")), "change": s.get("change")}


def _log_item(rec, m) -> dict:
    """로그 1줄의 전송 형태.

    문자열만 보내면 모델은 그 40줄이 창의 전부인 줄 안다. 왜 뽑혔는지(`why`)와 같은
    형태가 창에 몇 줄이었는지(`n`)를 같이 보낸다. 시각은 줄 사이 간격을 보라고 준다.
    """
    if not isinstance(rec, dict):
        return {"line": m(rec)}
    if "gap" in rec:   # 안 실린 구간 표시 — 식별자가 없어 마스킹 대상이 아니다
        return {"t": int(rec.get("t") or 0), "gap": int(rec["gap"]),
                "to": int(rec.get("to") or 0)}
    out = {"t": int(rec.get("t") or 0), "line": m(rec.get("line", "")),
           "why": rec.get("why", "")}
    lvl = rec.get("level") or ""
    if lvl:
        out["level"] = lvl
    if (rec.get("n") or 1) > 1:
        out["n"] = rec["n"]
    return out


def _leaks(text: str) -> bool:
    """가린 뒤에도 아는 이름이 남았는가 — 남으면 본문을 통째로 버린다 (§25-6)."""
    if IP_RE.search(text or ""):
        return True
    try:
        from . import nametable
        low = (text or "").lower()
        return any(name.lower() in low for name, _kind in nametable.terms())
    except Exception as e:
        log.warning("잔여 이름 검사를 못 했다: %s", e)
        return True


def cannot_mask(masker=None) -> bool:
    """지금 이름을 가릴 수 없는 상태인가.

    **`_leaks` 로는 이것을 알 수 없다.** 그 함수는 "아는 이름이 남았나" 를 보므로 표가
    비면 볼 이름이 없어 "누수 없음" 이 된다(`any([])`). 볼 이름이 없는 것과 가렸다는 것은
    다르다(2026-08-19 감사).

    표가 비는 상황은 드물지만 있다. 재기동 직후 캐시 파일이 없고 첫 갱신이 전부 실패하면
    그렇다. 그때 그룹명은 아무도 안 가린다. 프록시 경로는 같은 상황을 이미 막는다.
    """
    from . import nametable, proxy

    # 이번 요청의 마스커가 이름을 들고 있으면 가릴 수 있다. 대상 표를 만들 때 호스트명이
    # 등록되므로, 전역 표가 비어도 그 이름들은 가려진다.
    if masker is not None and any(str(k).strip()
                                  for k in (getattr(masker, "_fwd", None) or {})):
        return False
    try:
        if list(nametable.terms()):
            return False
    except Exception as e:
        log.warning("이름 표를 읽지 못했다: %s", e)
        return True
    return proxy.blocked_when_empty()


def _prior_item(p: dict, m) -> dict:
    """과거 결론 1건의 전송 형태.

    구조화 필드에는 자유 서술이 없어 유출면이 없다. 본문은 조건을 전부 만족할 때만
    싣는다 — 이름 표가 살아 있고, 가린 뒤 아는 이름이 남지 않을 때다. 하나라도
    어긋나면 본문을 버리고 구조화 필드만 보낸다.
    """
    from . import nametable
    from .alerts import prior
    body = ""
    raw = (p.get("summary") or "")[:prior.MAX_BODY_CHARS]
    if raw:
        if not nametable.terms():
            log.warning("이름 표가 비어 과거 결론 본문을 뺀다 (판정 %s)", p.get("id"))
        else:
            masked = m(raw)
            if _leaks(masked):
                log.warning("과거 결론 본문에 가리지 못한 이름이 남아 뺀다 (판정 %s)",
                            p.get("id"))
            else:
                body = masked
    return {"match": p.get("match"), "verdict": p.get("verdict"),
            "classes": m(p.get("classes")), "sev": p.get("sev"),
            "days_ago": p.get("days_ago"),
            "확인": "사람 확인됨" if p.get("confirmed") else
                    ("사람이 오답으로 표시함" if p.get("wrong") else "미확인(봇 출력)"),
            "summary": body}


def _register_host(host: dict, masker: Masker):
    masker.register("host", host.get("host"))
    masker.register("host", host.get("name"))
    for iface in host.get("interfaces", []) or []:
        masker.register("ip", iface.get("ip"))
        masker.register("host", iface.get("dns"))
    for g in host.get("hostgroups", []) or []:
        masker.register("group", g.get("name"))


def _register_context(context: dict, masker: Masker) -> None:
    """호스트 객체 밖의 이름을 등록하고 마지막으로 전역 표를 건다 (§22)."""
    inc = context.get("incident", {}) or {}
    masker.register("host", inc.get("host"))
    for k in ("loki_label", "wazuh_label"):
        masker.register("host", context.get(k))
    try:
        from . import nametable
        nametable.apply_to(masker)
    except Exception as e:
        log.warning("전역 이름 표를 적용하지 못했다: %s", e)


def build_llm_context(context: dict, sev: str, masker: Masker) -> dict:
    """마스킹된 전송용 dict 생성. 이 함수가 화이트리스트 자체 — 없는 필드는 전송 안 됨."""
    if "alerts" in context and "incident" in context:
        return _build_incident_context(context, sev, masker)
    host = context.get("host", {}) or {}
    _register_host(host, masker)
    _register_context(context, masker)

    event = context.get("event", {}) or {}
    trigger = context.get("trigger", {}) or {}
    m = masker.mask
    return {
        "alert": {
            "name": m(event.get("name")),
            "sev": sev,
            "clock": event.get("clock"),
            "host": m(host.get("host", "")),
            "host_groups": [m(g.get("name")) for g in host.get("hostgroups", []) or []],
        },
        "trigger": {
            "description": m(trigger.get("description")),
            "expression": m(trigger.get("expression")),
        },
        "metrics": [
            {
                "key": m(it.get("key")),
                "units": it.get("units"),
                "lastvalue": it.get("lastvalue"),
                "recent": it.get("recent", []),
            }
            for it in context.get("metrics", []) or []
        ],
        "logs": [_log_item(r, m) for r in (context.get("logs") or [])],   # Loki — 라인 내 IP·호스트 마스킹
        "security": [_security_item(s, m) for s in (context.get("security") or [])],
        "prejudge": {
            "verdict": (context.get("prejudge") or {}).get("verdict"),
            "statement": (context.get("prejudge") or {}).get("statement"),
        },
        "sources": _sources(context),
        # 로그를 어디까지 읽었고 그중 얼마를 보냈는가. 상태(ok)만으로는 구분되지 않는다.
        "logs_fetched": int(context.get("logs_fetched") or 0),
        "logs_selected": int(context.get("logs_selected") or 0),
        "logs_fetch_capped": bool(context.get("logs_fetch_capped")),
        "logs_window_guessed": bool(context.get("logs_window_guessed")),
        "logs_clipped": int(context.get("logs_clipped") or 0),
        "prior": [_prior_item(p, m) for p in (context.get("prior") or [])],
    }


def _build_incident_context(context: dict, sev: str, masker: Masker) -> dict:
    """병합 인시던트 전송용 dict. 알림 배열 + 호스트 단위 로그·보안."""
    host = context.get("host", {}) or {}
    _register_host(host, masker)
    _register_context(context, masker)
    m = masker.mask
    inc = context.get("incident", {}) or {}

    alerts = []
    for a in context.get("alerts", []) or []:
        trig = a.get("trigger", {}) or {}
        pj = a.get("prejudge", {}) or {}
        alerts.append({
            "name": m(a.get("name")),
            "source": a.get("source"),
            "sev": a.get("sev"),
            "class": a.get("class"),
            "trigger_desc": m(trig.get("description")),
            "trigger_expr": m(trig.get("expression")),
            "metrics": [
                {"key": m(it.get("key")), "units": it.get("units"),
                 "lastvalue": it.get("lastvalue"), "recent": it.get("recent", [])}
                for it in a.get("metrics", []) or []
            ],
            "prejudge": {"verdict": pj.get("verdict"), "statement": pj.get("statement")},
            # 수집기가 실패를 표시해도 화이트리스트에 없으면 프롬프트에 안 실린다.
            # 그러면 모델은 "지표 이상 없음"으로 읽는다.
            "error": a.get("error"),
        })

    return {
        "incident": {
            "host": m(inc.get("host", "")),
            "classes": inc.get("classes", []),
            "alert_count": inc.get("alert_count"),
            "merge_reason": inc.get("merge_reason"),
            "dominant_sev": inc.get("dominant_sev", sev),
            # 계약 제약과 자동 조치 가능 여부. 값이 식별자가 아니라 라벨이라 마스킹하지
            # 않는다. 이 둘이 없으면 모델이 조치 권고와 자동화 가능 여부를 근거 없이 쓴다.
            "scope": inc.get("scope") or "",
            "automate": bool(inc.get("automate")),
        },
        "alerts": alerts,
        "logs": [_log_item(r, m) for r in (context.get("logs") or [])],
        "security": [_security_item(s, m) for s in (context.get("security") or [])],
        "open_problems": [_open_problem_item(p, m)
                          for p in (context.get("open_problems") or [])],
        "sources": _sources(context),
        # 로그를 어디까지 읽었고 그중 얼마를 보냈는가. 상태(ok)만으로는 구분되지 않는다.
        "logs_fetched": int(context.get("logs_fetched") or 0),
        "logs_selected": int(context.get("logs_selected") or 0),
        "logs_fetch_capped": bool(context.get("logs_fetch_capped")),
        "logs_window_guessed": bool(context.get("logs_window_guessed")),
        "logs_clipped": int(context.get("logs_clipped") or 0),
        "prior": [_prior_item(p, m) for p in (context.get("prior") or [])],
    }
