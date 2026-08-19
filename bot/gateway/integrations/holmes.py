"""HolmesGPT 온디맨드 심층조사 어댑터 — 서버 모드의 HTTP API 호출. 읽기 전용.

발동 조건·질문 구성·결과 회수 경로는 bot/GATEWAY_GUIDE.md §10.
환경변수는 bot/.env.example, 도입 판정은 docs/02-design/decisions/adr-002-holmesgpt.md.
API 근거: holmesgpt.dev `/dev/reference/http-api/` (POST /api/chat → {analysis,...}).
"""

import logging
import os

import httpx

from .. import egress
from ..alerts import severity

log = logging.getLogger("gateway.holmes")


def should_investigate(sev: str, degraded: bool, sources, merged: bool = False,
                       verdict: str = "") -> tuple:
    """자동 발동 조건(승인 아님 — 읽기 전용이므로). 반환 (bool, reason).

    **조건의 순서에 의미가 있다.** 위중·열화는 지식 여부와 무관하므로 만성 억제보다 앞이고,
    MSP 테넌트 경계는 그보다도 앞이다. 근거는 가이드 §10.
    """
    if os.environ.get("HOLMES_ENABLED", "") != "1":
        return False, "disabled"
    # 이 플래그는 마스킹을 켜지 않는다. investigate() 는 호스트명을 원문으로 보낸다.
    # 예전 이름은 HOLMES_MASKED 였는데, 이름과 예시 파일 주석이 "켜면 가려진다"로
    # 읽혀서 그대로 두면 MSP 고객사 이름이 나간다. 실제 의미대로 이름을 바꾸고
    # 기본을 차단으로 둔다. 마스킹이 붙으면 이 플래그 자체가 없어져야 한다.
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
    """심층조사 도구를 다른 LLM 어댑터와 같은 모양으로 감싼다.

    이렇게 해야 출구(`egress.call`)를 그대로 지나간다. 예전에는 이 호출만 출구 밖이라
    두 가지가 새고 있었다. 호출량 지표에 안 잡혀 사용량이 실제보다 적게 보고됐고,
    동시 호출 제한 밖이라 폭주 때 인시던트마다 최대 300초짜리 호출이 무제한으로 떠
    공용 스레드를 다 차지했다.

    ⚠ 반출은 여기서 막지 못한다. 이 도구는 **받은 호스트명으로 감시 서버를 직접
    조회하고 그 결과를 자기 키로 모델에 보낸다.** 우리가 보내는 문장을 가려 봐야
    도구가 스스로 가져가는 자료는 그대로다. 게다가 이름을 가리면 조회 자체를 못 해
    도구가 일을 못 한다. 통제하려면 그 도구의 모델 호출 주소를 우리 쪽으로 돌려야
    한다 — 그때까지 고객사 대상은 차단을 유지한다(should_investigate).
    """

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
