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
당신은 KINX IDC 모니터링 트리아지 봇이다. 컨텍스트는 세 시스템에서 모은 조각이다 —
metrics(Zabbix), logs(Loki), security(Wazuh 경보). 이들을 시간축에서 결합해 초동 분석을
한국어로 회신한다.

규칙:
- **인시던트 병합**: 여러 축의 신호가 같은 호스트·같은 시간창에 겹치면 개별 장애가 아니라
  하나의 사건으로 판단하고, 그렇게 명시하라(예: "이 3건은 1개 사건"). 축 간 인과를 추정하되
  근거(어느 축의 무슨 신호)를 함께 대라.
- **빈 값의 의미는 sources 상태로만 판단하라.** sources.security 가 "ok" 인데 security 가 비어
  있을 때만 "침해·비인가 변경 흔적 없음"으로 해석하고 순수 운영 문제 판단에 활용한다(없음도
  정보다). 상태가 "unavailable"(조회 실패) 또는 "disabled"(미배선)면 **침해 여부를 판단하지 말고
  "보안 축 조회 불가 — 침해 여부 미상"이라고 명시하라.** 조회 실패를 근거로 안심시키는 것은
  금지한다. 상태가 "unmatched" 면 조회는 됐지만 그 소스가 이 호스트를 다른 이름으로 부르고
  있다는 뜻이다. 이때도 "없음"으로 읽지 말고 **"호스트 이름이 맞지 않아 조회되지 않았다"**
  라고 밝히고, 확인 명령에 이름 대조를 넣어라. logs 와 sources.logs 도 같은 규칙을 따른다.
- **보안 경보가 있다고 곧바로 침해로 읽지 마라.** security 항목의 `groups` 와 `level` 로 성격을
  가른다. `syscheck`(파일 무결성)·`sca`(설정 준수)는 레벨 5~9의 일상 이벤트인 경우가 많아
  그 자체로는 침해 신호가 아니다. 다만 **다른 축과 겹치면 의미가 달라진다** — 예를 들어
  로그인 실패가 쌓인 뒤 `path` 가 `/etc/ssh`·`/etc/passwd` 인 변경이 있으면 그건 한 사건으로
  보고 그렇게 말하라. 레벨 10 이상이거나 인증·침입 관련 그룹이면 우선 다뤄라.
- 만성/신규 판정은 코드가 계산해 준다(prejudge). 그 값을 그대로 쓰고 재판정하지 않는다.
- **open_problems 는 이번 알림보다 먼저 열려 있던 문제다.** 병합된 알림이 아니라 참고 정보이며,
  각 항목의 `link` 에 담긴 비율·일수는 과거 이력에서 실제로 측정된 값이다(`measured` 에 측정
  조건이 있다). 그 수치를 근거로 **선행 가능성을 제시하되 인과를 단정하지 마라.** 확인 방법을
  함께 제시한다. 예: "디스크 문제가 3시간째 열려 있고, 과거 측정상 이 상태에서 자원 압박이
  13일에 걸쳐 96% 비율로 뒤따랐다 — 먼저 디스크를 확인하라." `sources.open_problems` 가
  "ok" 가 아니면 **선행 문제 유무를 판단하지 말고 "확인 불가"로 명시하라.**
  `stale: true` 인 항목은 오래 방치된 문제다. **선행 원인으로 쓰지 말고** 별건으로 짧게
  언급하라(예: "디스크 문제가 N일째 미해소 상태 — 이번 사건과 별개로 정리 필요").
- 컨텍스트에 없는 사실을 지어내지 않는다. 모르면 "컨텍스트 부족"이라고 쓴다.
- 호스트명·IP·그룹명은 [host-1]·[ip-1] 형태의 가명 토큰이다. 그대로 사용하라(복원 금지 —
  시스템이 회신을 역치환한다).
- 회신 형식(Slack 게시용):
  1) 한 줄 요약 (심각도 이모지 + "N건이 1개 사건" 여부)
  2) 추정 원인·인과 (어느 축의 무슨 신호를 근거로)
  3) 지금 즉시 실행할 확인 명령 3개
  4) 권장 조치 (하지 말아야 할 오조치 포함, 자동 조치 가능 여부)
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
    if "alerts" in masked_ctx and "incident" in masked_ctx:
        head = ("다음은 코드가 하나의 인시던트로 병합한 복수 알림이다. 병합 근거는 "
                "incident.merge_reason 에 있다. 개별 장애가 아니라 한 사건으로 보고, 축 간 "
                "인과를 추정해 초동 분석을 회신하라.\n\n")
    else:
        head = "다음 알림 컨텍스트로 초동 분석을 회신하라.\n\n"
    return head + json.dumps(masked_ctx, ensure_ascii=False, indent=1)


MONTHLY_SYSTEM = """\
당신은 MSP 월간 운영 리포트의 분석 절을 쓴다. 입력은 한 고객사의 한 달치 **사건 집계**이며,
개별 사건의 초동 분석은 이미 끝나 있다. 같은 내용을 다시 쓰지 말고, **한 달을 관통하는
판단**만 쓴다. 읽는 사람은 고객사 담당자다.

반드시 이 네 절만, 이 순서로, 한국어로 쓴다. 전체 900자 이내.

**1) 이번 달 한 줄**
숫자를 나열하지 말고 이 달의 성격을 한 문장으로.

**2) 반복 패턴과 근본 원인 후보**
같은 유형이 반복됐다면 무엇이 공통 원인일 수 있는지. 근거가 약하면 "가능성"으로 쓴다.

**3) 다음 달 권고 (최대 3개)**
고객이 실제로 결정할 수 있는 것만. 우선순위 순.

**4) 판단의 한계**
집계에서 빠졌거나 근거가 부족한 부분을 스스로 밝힌다.

규칙:
- 입력에 없는 수치·호스트·원인을 지어내지 않는다. 모르면 "집계 범위 밖"이라고 쓴다.
- 사건 이름은 입력에 있는 그대로 인용한다. 토큰([host-1] 등)은 그대로 두면 된다.
- 계약 범위를 넘는 조치(고객 시스템 변경 지시)를 단정하지 않는다. "협의"로 쓴다.
- 보안 절의 상태가 "조회 불가"면 보안에 대해 안전하다고 쓰지 않는다.
"""


def build_monthly_context(stats: dict, incidents: list, masker: Masker) -> dict:
    """월간 분석 화이트리스트. 여기 없는 필드는 구조적으로 전송되지 않는다(전송 명세표 원칙).

    개별 로그 라인·보안 경보 원문은 **의도적으로 제외**한다. 월 단위 판단에 필요 없고,
    고객 문서로 나가는 경로라 반출 표면을 최소로 유지한다.
    """
    # 승인 대기 자리표시자("검토 대기")는 넣지 않는다 — 모델이 그것을 사실로 읽는다.
    skip = ("report.summary", "report.insight")
    out = {k[len("report."):]: v for k, v in stats.items()
           if k.startswith("report.") and k not in skip}
    out["incidents"] = [
        {"name": masker.mask(str(a.get("name") or "")),
         "verdict": str(a.get("prejudge") or "")[:20],
         "alert_count": int(a.get("alert_count") or 1),
         "classes": str(a.get("classes") or ""),
         "sources": str(a.get("sources") or "")}
        for a in incidents[:30]
    ]
    return out


def monthly_reply(stats: dict, incidents: list) -> dict:
    """월간 종합 분석 1회. 사건별 분석 재활용과 별개로 '달 전체'를 입력으로 한 번만 부른다."""
    masker = Masker()
    for a in incidents:
        masker.register("host", str(a.get("host") or ""))
    payload = build_monthly_context(stats, incidents, masker)
    user = ("다음은 한 고객사의 한 달치 사건 집계다. 월간 리포트의 분석 절을 작성하라.\n\n"
            + json.dumps(payload, ensure_ascii=False, indent=1))
    t0 = time.monotonic()
    for adapter in (ClaudeAdapter(), OllamaAdapter()):
        if not adapter.available():
            continue
        try:
            text = adapter.complete(MONTHLY_SYSTEM, user)
            return {"text": masker.unmask(text), "provider": adapter.name,
                    "elapsed_s": round(time.monotonic() - t0, 2), "degraded": False}
        except Exception as e:
            log.warning("monthly adapter %s failed: %s", adapter.name, e)
    # 열화 — 리포트는 실시간이 아니므로 빈 문장 대신 "생성 실패"를 그대로 남긴다.
    return {"text": "(월간 분석 생성 실패 — LLM 응답 없음. 집계 수치는 유효하다.)",
            "provider": "none", "elapsed_s": round(time.monotonic() - t0, 2), "degraded": True}


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

    inc = context.get("incident")
    if inc:
        text = ("(LLM 분석 불가 — 코드 판정만 회신)\n"
                f"{inc.get('alert_count', '?')}건 병합 사건 — {inc.get('merge_reason', '')}")
    else:
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
        "logs": ["2026-07-27T02:00 lab-web01 backup[3121]: mysqldump start from 192.0.2.9",
                 "2026-07-27T02:03 lab-web01 kernel: task blocked on I/O for 120s"],
        "security": [],   # 경보 0건 — 아래 sources.security 가 ok 라서 "침해 배제"로 읽어도 되는 경우
        "sources": {"logs": "ok", "security": "ok"},   # 조회 상태(G1) — 실패면 "미상"으로 해석됨
        "prejudge": {"verdict": "신규",
                     "statement": "최근 90일 내 동일 트리거 발생 이력 없음 — 처음 보는 문제이므로 즉시 확인 권장."},
    }
    masker = Masker()
    masked = build_llm_context(sample, "SEV2", masker)
    print("=== LLM으로 전송되는 전문 (시스템 프롬프트 + 아래 사용자 프롬프트) ===")
    print(build_user_prompt(masked))
    print("\n=== 가명 맵 (게이트웨이 내부에만 존재, 전송 안 됨) ===")
    print(json.dumps(masker._rev, ensure_ascii=False, indent=1))
