"""LLM 어댑터 — Claude → Ollama → 열화 모드(전멸 시 선판정만). 상세는 GATEWAY_GUIDE.md §11.

환경변수: ANTHROPIC_API_KEY / LLM_CLAUDE_MODEL(기본 claude-opus-4-8) / LLM_TIMEOUT_S(20) /
          OLLAMA_URL / OLLAMA_MODEL(기본 qwen3:8b).
드라이런(외부 전송 없이 전문 확인): python -m gateway.llm
"""

import json
import logging
import os
import time

from .masking import Masker, build_llm_context

log = logging.getLogger("gateway.llm")

TRIAGE_SYSTEM = """\
당신은 KINX IDC 모니터링 트리아지 봇이다. 알림 컨텍스트를 근거로 초동 분석을
한국어로 회신한다.

규칙:
- 만성/신규 판정은 이미 코드가 계산해서 준다(prejudge). 그 값을 그대로 쓰고 재판정하지 않는다.
- 컨텍스트에 없는 사실을 지어내지 않는다. 모르면 "컨텍스트 부족"이라고 쓴다.
- 호스트명·IP·그룹명은 [host-1]·[ip-1]·[group-1] 형태의 가명 토큰이다. 토큰을 그대로
  사용하라(복원하려 하지 마라 — 시스템이 회신을 역치환한다).
- 회신 형식(Slack 게시용):
  1) 한 줄 요약 (심각도 이모지 포함)
  2) 추정 원인 (근거 데이터 인용)
  3) 지금 즉시 실행할 확인 명령 3개
  4) 권장 조치 (자동 조치 가능 여부 포함)
  5) 만성/신규 코멘트 (prejudge.statement 인용)
- 전체 길이는 공백 포함 1500자 이내."""

DEFAULT_TIMEOUT_S = 20  # 실측 최대 14.8s(llm_latency_20260726.md) + 여유
MAX_TOKENS = 2048


class ClaudeAdapter:
    name = "claude"

    def __init__(self):
        self.model = os.environ.get("LLM_CLAUDE_MODEL", "claude-opus-4-8")
        self.timeout = float(os.environ.get("LLM_TIMEOUT_S", DEFAULT_TIMEOUT_S))

    def available(self) -> bool:
        return bool(os.environ.get("ANTHROPIC_API_KEY"))

    def complete(self, system: str, user: str) -> str:
        import anthropic
        client = anthropic.Anthropic(timeout=self.timeout, max_retries=0)  # 재시도 금지(30초 예산)
        resp = client.messages.create(
            model=self.model, max_tokens=MAX_TOKENS,
            system=system, messages=[{"role": "user", "content": user}])
        return "".join(b.text for b in resp.content if b.type == "text")


class OllamaAdapter:
    name = "ollama"

    def __init__(self):
        self.url = os.environ.get("OLLAMA_URL", "").rstrip("/")
        self.model = os.environ.get("OLLAMA_MODEL", "qwen3:8b")

    def available(self) -> bool:
        return bool(self.url)

    def complete(self, system: str, user: str) -> str:
        import httpx
        r = httpx.post(f"{self.url}/api/chat", timeout=120, json={
            "model": self.model, "stream": False,
            "messages": [{"role": "system", "content": system},
                         {"role": "user", "content": user}],
            "options": {"num_predict": MAX_TOKENS}})
        r.raise_for_status()
        return r.json().get("message", {}).get("content", "")


def build_user_prompt(masked_ctx: dict) -> str:
    return ("다음 알림 컨텍스트로 초동 분석을 회신하라.\n\n"
            + json.dumps(masked_ctx, ensure_ascii=False, indent=1))


def triage_reply(context: dict, sev: str) -> dict:
    """마스킹 → Claude/Ollama/열화 → 역치환 → 회신 dict. 예외를 위로 던지지 않음."""
    masker = Masker()
    masked = build_llm_context(context, sev, masker)
    user = build_user_prompt(masked)
    t0 = time.monotonic()

    for adapter in (ClaudeAdapter(), OllamaAdapter()):
        if not adapter.available():
            continue
        try:
            text = adapter.complete(TRIAGE_SYSTEM, user)
            return {"text": masker.unmask(text), "provider": adapter.name,
                    "elapsed_s": round(time.monotonic() - t0, 2), "degraded": False}
        except Exception as e:  # 타임아웃·429·529 포함 — 전부 다음 어댑터로 폴백
            log.warning("llm adapter %s failed: %s", adapter.name, e)

    pj = context.get("prejudge") or {}
    text = ("(LLM 분석 불가 — 코드 판정만 회신)\n"
            f"판정: {pj.get('verdict', '?')} — {pj.get('statement', '')}")
    return {"text": text, "provider": "none",
            "elapsed_s": round(time.monotonic() - t0, 2), "degraded": True}


if __name__ == "__main__":
    # 드라이런: 외부 전송 없이 "실제로 나가는 전문"을 출력 — 전송 명세표 시연용
    sample = {
        "event": {"eventid": "10583", "name": "Filesystem /data 사용률 92% on lab-web01",
                  "clock": "1753500000"},
        "trigger": {"description": "디스크 사용률 임계 초과",
                    "expression": "last(/lab-web01/vfs.fs.size[/data,pused])>90"},
        "host": {"host": "lab-web01", "name": "lab-web01",
                 "interfaces": [{"ip": "192.0.2.5", "dns": ""}],
                 "hostgroups": [{"name": "KINX WEB"}]},
        "metrics": [{"key": "vfs.fs.size[/data,pused]", "units": "%", "lastvalue": "92.3",
                     "recent": [{"clock": "1753496400", "value": "61.2"},
                                {"clock": "1753498200", "value": "85.1"}]}],
        "prejudge": {"verdict": "신규",
                     "statement": "최근 90일 내 동일 트리거 발생 이력 없음 — 처음 보는 문제이므로 즉시 확인 권장."},
    }
    masker = Masker()
    masked = build_llm_context(sample, "SEV2", masker)
    print("=== LLM으로 전송되는 전문 (시스템 프롬프트 + 아래 사용자 프롬프트) ===")
    print(build_user_prompt(masked))
    print("\n=== 가명 맵 (게이트웨이 내부에만 존재, 전송 안 됨) ===")
    print(json.dumps(masker._rev, ensure_ascii=False, indent=1))
