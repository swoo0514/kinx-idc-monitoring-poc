"""HolmesGPT 온디맨드 심층조사 어댑터 — 읽기 전용, 자동 조건부(read=auto 규칙).

게이트웨이가 조건 충족 시(SEV1 또는 봇 분석 열화, 비-MSP) 백그라운드로 호출 → 결과를
Keep 알림에 enrich. HolmesGPT는 에이전틱이라 분 단위 소요 → 반드시 비동기/백그라운드.
마스킹 없으므로 MSP 테넌트는 발동 제외(데이터 거버넌스 조건, 안전 승인 아님).

환경변수: HOLMES_ENABLED(1이면 사용), HOLMES_IMAGE, HOLMES_MODEL, HOLMES_TIMEOUT_S.
docker CLI로 온프렘 컨테이너 실행(벤치마크와 동일 경로: ~/.holmes/config.yaml toolset).
"""

import logging
import os
import subprocess

from . import severity

log = logging.getLogger("gateway.holmes")

_DEFAULT_IMAGE = "us-central1-docker.pkg.dev/genuine-flight-317411/devel/holmes"


def should_investigate(sev: str, degraded: bool, sources) -> tuple:
    """자동 발동 조건(승인 아님). (bool, reason). MSP 소스면 마스킹 없어 제외."""
    if os.environ.get("HOLMES_ENABLED", "") != "1":
        return False, "disabled"
    if severity.SOURCE_ZABBIX_MSP in (sources or []):
        return False, "msp-tenant(no-masking)"
    if sev == severity.SEV1:
        return True, "sev1"
    if degraded:
        return True, "bot-degraded"
    return False, "criteria-not-met"


def investigate(host: str, question: str) -> dict:
    """HolmesGPT 심층조사(읽기 전용). 블로킹·분 단위 — 호출 측이 백그라운드로 감쌀 것."""
    image = os.environ.get("HOLMES_IMAGE", _DEFAULT_IMAGE)
    model = os.environ.get("HOLMES_MODEL", "anthropic/claude-opus-4-8")
    timeout = int(os.environ.get("HOLMES_TIMEOUT_S", "300"))
    prompt = f"Investigate host {host}. {question} State the root cause and what remediation must NOT be performed."
    cmd = ["docker", "run", "--rm", "--net=host",
           "-e", "ANTHROPIC_API_KEY",
           "-v", os.path.expanduser("~/.holmes") + ":/root/.holmes",
           image, "ask", prompt, "--model", model, "--refresh-toolsets"]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        analysis = _extract_final(r.stdout or "")
        if not analysis:
            log.warning("holmes empty output host=%s rc=%s", host, r.returncode)
        return {"ok": bool(analysis), "analysis": analysis}
    except subprocess.TimeoutExpired:
        log.warning("holmes timeout host=%s (%ss)", host, timeout)
        return {"ok": False, "error": "timeout"}
    except Exception as e:
        log.warning("holmes exception host=%s: %s", host, e)
        return {"ok": False, "error": str(e)}


def _extract_final(out: str) -> str:
    """HolmesGPT stdout는 도구호출 로그 + 최종 답이 섞임. 마지막 'AI:' 이후를 최종 답으로."""
    marker = "\nAI:"
    idx = out.rfind(marker)
    text = out[idx + len(marker):] if idx != -1 else out
    text = text.strip()
    return text[-3500:]   # Keep 필드·토큰 보호용 상한


if __name__ == "__main__":   # 격리 테스트: python -m gateway.holmes <host>
    import sys
    h = sys.argv[1] if len(sys.argv) > 1 else "vm-p3-target-002"
    res = investigate(h, "Investigate the current problems on this host.")
    print("ok:", res.get("ok"), "error:", res.get("error"))
    print(res.get("analysis", "")[:2000])
