"""전송 마스킹·화이트리스트 — docs/02-design/llm-data-contract.md의 코드 구현. 표 개정 시 문서 먼저."""

import logging
import re

from . import collector   # 조회 상태 상수(SOURCE_*) 단일 정의 참조

log = logging.getLogger("gateway.masking")

IP_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")


class Masker:
    """요청 단위 가역 마스킹. 맵은 게이트웨이 밖으로 나가지 않음."""

    def __init__(self):
        self._fwd = {}   # 원문 → 토큰
        self._rev = {}   # 토큰 → 원문
        self._counts = {}
        self._re = None      # 등록 원문을 한 번에 잡는 정규식 (아래에서 만든다)
        self._lower = {}     # 소문자 원문 → 토큰. 대소문자가 달라도 찾으려고 둔다

    def register(self, kind: str, original: str):
        if original and original not in self._fwd:
            n = self._counts.get(kind, 0) + 1
            self._counts[kind] = n
            tok = f"[{kind}-{n}]"
            self._fwd[original] = tok
            self._rev[tok] = original
            self._re = None   # 목록이 바뀌었으니 다음 치환 때 다시 만든다

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


def _register_host(host: dict, masker: Masker):
    masker.register("host", host.get("host"))
    masker.register("host", host.get("name"))
    for iface in host.get("interfaces", []) or []:
        masker.register("ip", iface.get("ip"))
        masker.register("host", iface.get("dns"))
    for g in host.get("hostgroups", []) or []:
        masker.register("group", g.get("name"))


def _register_context(context: dict, masker: Masker) -> None:
    """호스트 객체 밖에 있는 이름들을 등록하고, 마지막으로 전역 표를 건다.

    세 가지가 빠져 있었다.
    - 수집이 전건 실패하면 host 객체가 비는데 `incident.host` 는 그대로 전송된다.
      그때 등록이 0건이라 마스킹이 사실상 항등 함수가 됐다. 장애가 클수록 그렇다.
    - Loki 라벨·Wazuh 에이전트명은 Zabbix 호스트명과 다를 수 있는데, 로그 라인 본문에는
      그 이름이 들어 있다.
    - 사건 당사자가 아닌 호스트명(로그에 섞인 다른 서버)은 애초에 등록 대상이 아니었다.

    앞의 둘은 여기서, 마지막은 전역 표가 맡는다. **표를 맨 뒤에 거는 이유**는 이 사건의
    호스트가 낮은 번호를 받아야 카드를 읽는 사람이 헷갈리지 않기 때문이다.
    """
    inc = context.get("incident", {}) or {}
    masker.register("host", inc.get("host"))
    for k in ("loki_label", "wazuh_label"):
        masker.register("host", context.get(k))
    try:
        from . import nametable
        nametable.apply_to(masker)
    except Exception as e:      # 표가 없어도 오늘까지의 동작으로 돈다
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
        "logs": [m(line) for line in (context.get("logs") or [])],   # Loki — 라인 내 IP·호스트 마스킹
        "security": [_security_item(s, m) for s in (context.get("security") or [])],
        "prejudge": {
            "verdict": (context.get("prejudge") or {}).get("verdict"),
            "statement": (context.get("prejudge") or {}).get("statement"),
        },
        "sources": _sources(context),
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
        },
        "alerts": alerts,
        "logs": [m(line) for line in (context.get("logs") or [])],
        "security": [_security_item(s, m) for s in (context.get("security") or [])],
        "open_problems": [_open_problem_item(p, m)
                          for p in (context.get("open_problems") or [])],
        "sources": _sources(context),
    }
