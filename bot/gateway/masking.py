"""전송 마스킹·화이트리스트 — private/docs/llm_data_spec.md의 코드 구현. 표 개정 시 문서 먼저."""

import re

from . import collector   # 조회 상태 상수(SOURCE_*) 단일 정의 참조

IP_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")


class Masker:
    """요청 단위 가역 마스킹. 맵은 게이트웨이 밖으로 나가지 않음."""

    def __init__(self):
        self._fwd = {}   # 원문 → 토큰
        self._rev = {}   # 토큰 → 원문
        self._counts = {}

    def register(self, kind: str, original: str):
        if original and original not in self._fwd:
            n = self._counts.get(kind, 0) + 1
            self._counts[kind] = n
            tok = f"[{kind}-{n}]"
            self._fwd[original] = tok
            self._rev[tok] = original

    def mask(self, text: str) -> str:
        if not text:
            return text
        text = str(text)
        # 긴 원문부터 치환(부분 문자열 오치환 방지) + 미등록 IP 일괄 토큰화
        for orig in sorted(self._fwd, key=len, reverse=True):
            text = text.replace(orig, self._fwd[orig])
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


_STATUS_KEYS = ("logs", "security")
_STATUS_VALUES = (collector.SOURCE_OK, collector.SOURCE_UNAVAILABLE, collector.SOURCE_DISABLED)


def _sources(context: dict) -> dict:
    """교차 소스 조회 상태만 통과시킨다 — 키·값 모두 알려진 것으로 한정(화이트리스트 유지).
    상태 문자열에는 식별자가 없어 마스킹 대상이 아니다. LLM이 빈 목록의 의미를 알려면 필요하다."""
    src = context.get("sources") or {}
    return {k: (src[k] if src.get(k) in _STATUS_VALUES else "unknown")
            for k in _STATUS_KEYS if k in src}


def _security_item(s: dict, m) -> dict:
    """보안 경보 1건의 전송 형태 — 이 함수가 보안 축의 화이트리스트다.

    rule_id·groups 는 룰 번호와 그룹명이라 식별자가 없어 원값으로 보낸다. path 는 파일
    경로라 호스트명·IP 가 섞일 수 있으므로 반드시 마스킹을 거친다(llm_data_spec.md 반영).
    """
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


def build_llm_context(context: dict, sev: str, masker: Masker) -> dict:
    """마스킹된 전송용 dict 생성. 이 함수가 화이트리스트 자체 — 없는 필드는 전송 안 됨."""
    if "alerts" in context and "incident" in context:
        return _build_incident_context(context, sev, masker)
    host = context.get("host", {}) or {}
    masker.register("host", host.get("host"))
    masker.register("host", host.get("name"))
    for iface in host.get("interfaces", []) or []:
        masker.register("ip", iface.get("ip"))
        masker.register("host", iface.get("dns"))
    for g in host.get("hostgroups", []) or []:
        masker.register("group", g.get("name"))

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
        "sources": _sources(context),
    }
