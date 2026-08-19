"""HolmesGPT 온디맨드 심층조사 어댑터 — 서버 모드의 HTTP API 호출. 읽기 전용."""

import logging
import os

import httpx

from .. import egress
from ..alerts import severity

log = logging.getLogger("gateway.holmes")


def should_investigate(sev: str, degraded: bool, sources, merged: bool = False,
                       verdict: str = "") -> tuple:
    """자동 발동 조건(승인 아님 — 읽기 전용이므로). 반환 (bool, reason)."""
    if os.environ.get("HOLMES_ENABLED", "") != "1":
        return False, "disabled"
    # 이 플래그는 마스킹을 켜지 않는다 — investigate() 는 호스트명을 원문으로 보낸다
    allow_raw = os.environ.get("HOLMES_ALLOW_MSP_RAW", "") == "1"
    if severity.SOURCE_ZABBIX_MSP in (sources or []) and not allow_raw:
        return False, "msp-tenant(원문 전송이라 차단 — HOLMES_ALLOW_MSP_RAW)"
    if sev == severity.SEV1:
        return True, "sev1"
    if degraded:
        return True, "bot-degraded"
    if verdict == "만성":
        return False, "chronic-known(조사 아낌 — 반복 확인된 문제)"
    if verdict == "신규":
        return True, "novel(지식 공백 — 조사 가치 최대)"
    if merged:
        return True, "merged-incident"
    return False, "criteria-not-met"


def build_question(alert_names, classes, window_s: float) -> str:
    """홈즈에게 넘길 사건 서술 — 조사 대상을 이 사건으로 고정한다.

    건수와 호스트만 넘기면 그 호스트에서 그 순간 활성인 아무 문제나 조사한다(실측). 가이드 §10.
    """
    names = "; ".join("(%d) %s" % (i + 1, n) for i, n in enumerate(alert_names) if n)
    cls = ", ".join(sorted(c for c in (classes or []) if c))
    return (
        "Incident: %d alert(s) merged on this host within a %.0f second window ending just now. "
        "Alert names: %s. Incident type(s): %s. "
        "Investigate ONLY these alerts and this time window. "
        "Do NOT report on unrelated problems that merely happen to be active on this host — "
        "if you find such problems, ignore them."
        % (len(alert_names), window_s, names or "(unnamed)", cls or "(unclassified)")
    )


class HolmesAdapter:
    """심층조사 도구를 다른 LLM 어댑터와 같은 모양으로 감싼다."""

    name = "holmes"

    def __init__(self, host: str):
        self.host = host
        self.url = os.environ.get("HOLMES_URL", "").rstrip("/")
        self.timeout = int(os.environ.get("HOLMES_TIMEOUT_S", "300"))

    def available(self) -> bool:
        return bool(self.url)

    def complete(self, _system: str, user: str) -> str:
        body = {"ask": user, "stream": False}
        model = os.environ.get("HOLMES_MODEL", "")
        if model:
            body["model"] = model
        headers = {"Content-Type": "application/json"}
        key = os.environ.get("HOLMES_API_KEY", "")
        if key:
            headers["X-API-Key"] = key
        r = httpx.post(f"{self.url}/api/chat", headers=headers, json=body,
                       timeout=self.timeout)
        if r.status_code >= 300:
            raise RuntimeError("http %s: %s" % (r.status_code, r.text[:200]))
        return (r.json() or {}).get("analysis", "")


def investigate(host: str, question: str) -> dict:
    """심층조사(읽기 전용). 블로킹·분 단위 — 호출측이 백그라운드로 감쌀 것."""
    adapter = HolmesAdapter(host)
    if not adapter.available():
        log.info("[holmes skipped: no HOLMES_URL] host=%s", host)
        return {"ok": False, "skipped": True}
    ask = (f"Investigate host {host}. {question} "
           "State the root cause and what remediation must NOT be performed.")
    res = egress.call([adapter], "", ask, kind="holmes")
    if res["degraded"]:
        log.warning("holmes 실패 host=%s 사유=%s", host, res["reason"])
        return {"ok": False, "error": res["reason"]}
    return {"ok": bool(res["text"]), "analysis": res["text"]}


if __name__ == "__main__":   # 격리 테스트: HOLMES_URL 세팅 후 python -m gateway.holmes <host>
    import sys
    h = sys.argv[1] if len(sys.argv) > 1 else "vm-p3-target-002.novalocal"
    res = investigate(h, "Investigate the current problems on this host.")
    print("ok:", res.get("ok"), "error:", res.get("error"))
    print((res.get("analysis") or "")[:2000])
