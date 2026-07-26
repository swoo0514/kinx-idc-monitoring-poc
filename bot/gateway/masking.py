"""전송 마스킹·화이트리스트 — private/docs/llm_data_spec.md의 코드 구현. 표 개정 시 문서 먼저."""

import re

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


def build_llm_context(context: dict, sev: str, masker: Masker) -> dict:
    """마스킹된 전송용 dict 생성. 이 함수가 화이트리스트 자체 — 없는 필드는 전송 안 됨."""
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
        "prejudge": {
            "verdict": (context.get("prejudge") or {}).get("verdict"),
            "statement": (context.get("prejudge") or {}).get("statement"),
        },
    }
