"""HolmesGPT 온디맨드 심층조사 어댑터 — HTTP API(/api/chat) 호출, 읽기 전용·자동 조건부.

HolmesGPT를 서버 모드(컨테이너)로 띄우고 HTTP API를 부른다(subprocess·stdout 파싱 아님).
응답 JSON의 `analysis` 필드가 최종 조사 결과(마크다운). 서버의 LLM을 마스킹 프록시로 가리키면
MSP도 허용 가능(task #6). keep.py·slack.py와 동일한 httpx 패턴.

환경변수: HOLMES_ENABLED(1이면 자동 발동), HOLMES_URL(예: http://<holmes>:8000),
HOLMES_API_KEY(선택), HOLMES_MODEL(서버 modelList의 모델명, 마스킹 프록시면 그 모델 예: masked-claude),
HOLMES_MASKED(1이면 홈즈 서버 LLM이 마스킹 프록시 경유 → MSP도 심층조사 허용), HOLMES_TIMEOUT_S.
근거: holmesgpt.dev/dev/reference/http-api/ (POST /api/chat → {analysis,...}). 마스킹 트랙: masking_track.md.
"""

import logging
import os

import httpx

from . import severity

log = logging.getLogger("gateway.holmes")


def should_investigate(sev: str, degraded: bool, sources, merged: bool = False,
                       verdict: str = "") -> tuple:
    """자동 발동 조건(승인 아님, read=auto 규칙). (bool, reason).

    MSP는 마스킹 프록시(HOLMES_MASKED=1)가 붙어 있을 때만 허용 — 없으면 원문 유출이라 제외.
    (마스킹 실측·한계는 masking_track.md. 홈즈 서버 LLM을 마스킹 프록시로 가리키고 이 플래그 on.)

    **발동 기준을 지식 공백에 맞춘다 (G9).** 종래에는 병합(=사람이 룰로 넣은 조합)이 주
    발동 경로였는데, 그러면 가장 비싼 분석이 "이미 아는 문제"에만 돌아간다. 그래서 선판정을
    양방향으로 쓴다 — 만성(아는 문제)은 억제하고 신규(처음 보는 문제)는 발동시킨다.
    판정은 prejudge 가 이미 계산해 둔 값이라 새 지능이 필요 없다.

    순서에 의미가 있다. 위중(SEV1)과 봇 열화는 지식 여부와 무관하게 조사가 필요하므로
    만성 억제보다 앞에 둔다.
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
