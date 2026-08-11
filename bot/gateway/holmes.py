"""HolmesGPT 온디맨드 심층조사 어댑터 — 서버 모드의 HTTP API 호출. 읽기 전용.

발동 조건·질문 구성·결과 회수 경로는 bot/GATEWAY_GUIDE.md §10.
환경변수는 bot/.env.example, 도입 판정은 docs/02-design/decisions/adr-002-holmesgpt.md.
API 근거: holmesgpt.dev `/dev/reference/http-api/` (POST /api/chat → {analysis,...}).
"""

import logging
import os

import httpx

from . import severity

log = logging.getLogger("gateway.holmes")


def should_investigate(sev: str, degraded: bool, sources, merged: bool = False,
                       verdict: str = "") -> tuple:
    """자동 발동 조건(승인 아님 — 읽기 전용이므로). 반환 (bool, reason).

    **조건의 순서에 의미가 있다.** 위중·열화는 지식 여부와 무관하므로 만성 억제보다 앞이고,
    MSP 테넌트 경계는 그보다도 앞이다. 근거는 가이드 §10.
    """
    if os.environ.get("HOLMES_ENABLED", "") != "1":
        return False, "disabled"
    masked = os.environ.get("HOLMES_MASKED", "") == "1"
    if severity.SOURCE_ZABBIX_MSP in (sources or []) and not masked:
        return False, "msp-tenant(no-masking)"
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


def investigate(host: str, question: str) -> dict:
    """HolmesGPT HTTP API로 심층조사(읽기 전용). 블로킹·분 단위 — 호출측이 백그라운드로 감쌀 것."""
    url = os.environ.get("HOLMES_URL", "").rstrip("/")
    if not url:
        log.info("[holmes skipped: no HOLMES_URL] host=%s", host)
        return {"ok": False, "skipped": True}
    timeout = int(os.environ.get("HOLMES_TIMEOUT_S", "300"))
    ask = (f"Investigate host {host}. {question} "
           "State the root cause and what remediation must NOT be performed.")
    body = {"ask": ask, "stream": False}
    model = os.environ.get("HOLMES_MODEL", "")
    if model:
        body["model"] = model
    headers = {"Content-Type": "application/json"}
    key = os.environ.get("HOLMES_API_KEY", "")
    if key:
        headers["X-API-Key"] = key
    try:
        r = httpx.post(f"{url}/api/chat", headers=headers, json=body, timeout=timeout)
        if r.status_code >= 300:
            log.warning("holmes http %s host=%s: %s", r.status_code, host, r.text[:200])
            return {"ok": False, "error": f"http {r.status_code}"}
        analysis = (r.json() or {}).get("analysis", "")
        return {"ok": bool(analysis), "analysis": analysis}
    except httpx.TimeoutException:
        log.warning("holmes timeout host=%s (%ss)", host, timeout)
        return {"ok": False, "error": "timeout"}
    except Exception as e:
        log.warning("holmes exception host=%s: %s", host, e)
        return {"ok": False, "error": str(e)}


if __name__ == "__main__":   # 격리 테스트: HOLMES_URL 세팅 후 python -m gateway.holmes <host>
    import sys
    h = sys.argv[1] if len(sys.argv) > 1 else "vm-p3-target-002.novalocal"
    res = investigate(h, "Investigate the current problems on this host.")
    print("ok:", res.get("ok"), "error:", res.get("error"))
    print((res.get("analysis") or "")[:2000])
