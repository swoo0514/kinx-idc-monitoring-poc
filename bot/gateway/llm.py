"""LLM 어댑터 — Claude → Ollama → 열화 모드(전멸 시 선판정만). 상세는 GATEWAY_GUIDE.md §11."""

import json
import logging
import os
import re
import time

from . import egress
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
- **`sources.metrics` 가 "unavailable" 이면 감시 서버 조회 자체가 실패한 것이다.** 지표·트리거
  설명·과거 이력이 통째로 비어 있을 뿐 정상이라는 뜻이 아니다. 이때는 원인을 추정하지 말고
  **"감시 서버 조회 실패 — 지표 확인 불가"** 를 먼저 밝히고, 확인 명령에 감시 서버 상태 점검을
  넣어라. 알림별 `error: "collect_failed"` 도 같은 뜻이다.
- **보안 경보가 있다고 곧바로 침해로 읽지 마라.** security 항목의 `groups` 와 `level` 로 성격을
  가른다. `syscheck`(파일 무결성)·`sca`(설정 준수)는 레벨 5~9의 일상 이벤트인 경우가 많아
  그 자체로는 침해 신호가 아니다. 다만 **다른 축과 겹치면 의미가 달라진다** — 예를 들어
  로그인 실패가 쌓인 뒤 `path` 가 `/etc/ssh`·`/etc/passwd` 인 변경이 있으면 그건 한 사건으로
  보고 그렇게 말하라. 레벨 10 이상이거나 인증·침입 관련 그룹이면 우선 다뤄라.
- **logs 는 창의 전부가 아니라 고른 것이다.** 각 항목의 `why` 가 뽑힌 이유다 —
  `fold`(같은 모양이 반복되어 대표만 실림. **평상시에는 전부 이것이다**), 그리고 접어도
  분량이 예산을 넘어 더 골라야 했을 때만 나타나는 `error`(등급), `novel`(경고),
  `pre`(첫 오류 직전 문맥), `recent`(최신). **`fold` 만 보인다면 버려진 것은 반복된 줄뿐이고
  서로 다른 내용은 다 실렸다는 뜻이다.** `n` 은 **같은 모양의 줄이 읽어 온 범위에 몇 개 있었는지**
  이며, 실린 것은 그중 일부다. `n` 이 크면 그 줄은 한 번이 아니라 반복된 것이므로 빈도로
  읽어라. `logs_fetch_capped` 가 true 면 읽어 온 범위 자체가 잘렸으므로 **`n` 도 실제보다
  작다** — 그때는 하한으로만 읽어라.
  `t` 는 초 단위 시각이다. `{"gap": 223, "t": ..., "to": ...}` 항목은 **그 구간에서
  223줄이 안 실렸다**는 뜻이다. 그 구간을 근거로 쓰지 말고, 앞뒤 항목을 이어진 사건으로
  읽지 마라.
- 만성/신규 판정은 코드가 계산해 준다(prejudge). 그 값을 그대로 쓰고 재판정하지 않는다.
- **open_problems 는 이번 알림보다 먼저 열려 있던 문제다.** 병합된 알림이 아니라 참고 정보이며,
  각 항목의 `link` 에 담긴 비율·일수는 과거 이력에서 실제로 측정된 값이다(`measured` 에 측정
  조건이 있다). 그 수치를 근거로 **선행 가능성을 제시하되 인과를 단정하지 마라.** 확인 방법을
  함께 제시한다. 예: "디스크 문제가 3시간째 열려 있고, 과거 측정상 이 상태에서 자원 압박이
  13일에 걸쳐 96% 비율로 뒤따랐다 — 먼저 디스크를 확인하라." `sources.open_problems` 가
  "ok" 가 아니면 **선행 문제 유무를 판단하지 말고 "확인 불가"로 명시하라.**
  `stale: true` 인 항목은 오래 방치된 문제다. **선행 원인으로 쓰지 말고** 별건으로 짧게
  언급하라(예: "디스크 문제가 N일째 미해소 상태 — 이번 사건과 별개로 정리 필요").
- **되돌릴 수 없는 명령을 권고하지 마라.** `RESET SLAVE`·`RESET MASTER`·`DROP DATABASE`·
  `TRUNCATE TABLE`·`rm -rf`·`kill -9`·`mkfs` 는 상태나 데이터를 지운다. 복제가 늦은 것과
  복제가 깨진 것은 다르며, 늦은 복제는 원인을 없애면 따라잡는다. 되살리는 조치는 원인을
  확인하고 사람이 판단할 일이므로, 확인 명령과 "무엇을 보고 판단할지"까지만 쓴다.
- 컨텍스트에 없는 사실을 지어내지 않는다. 모르면 "컨텍스트 부족"이라고 쓴다.
- 호스트명·IP·그룹명은 [host-1]·[ip-1] 형태의 가명 토큰이다. 그대로 사용하라(복원 금지 —
  시스템이 회신을 역치환한다).
- 회신 형식(Slack 게시용):
  1) 한 줄 요약 (심각도 이모지 + "N건이 1개 사건" 여부)
  2) 추정 원인·인과 (어느 축의 무슨 신호를 근거로)
  3) 지금 즉시 실행할 확인 명령 3개
  4) 권장 조치 (하지 말아야 할 오조치 포함). 자동 조치 가능 여부는 **추측하지 말고
     `incident.automate` 를 그대로 읽어라** — true 면 "자동 조치 등록됨", false 면
     "자동 조치 미등록". 계약 제약이 있으면 아래 규칙이 우선한다.
  5) 만성/신규 코멘트 (prejudge.statement 인용)
- 전체 길이는 공백 포함 1500자 이내."""

DEFAULT_TIMEOUT_S = 20  # 실측 최대 14.8s(llm_latency_20260726.md) + 여유
MAX_TOKENS = 2048


# 용도마다 모델 등급을 나눈다 — 나누는 자리는 서로 다른 호출 사이뿐이다(캐시가 모델별)
# 판단은 싼 모델에 맡기지 않는다 — 실측 근거는 GATEWAY_GUIDE §29
_MODEL_ENV = {
    "investigate": "LLM_MODEL_INVESTIGATE",   # 질의 반복문·트리아지
    "triage": "LLM_MODEL_INVESTIGATE",
    "write": "LLM_MODEL_WRITE",               # 월간 리포트 서사
    "route": "LLM_MODEL_ROUTE",               # 짧은 판단(별도 호출을 만들 때)
}


def model_for(kind: str = "") -> str:
    """그 용도로 쓸 모델. 용도별 값이 없으면 기존 값으로 떨어진다.

    설정을 안 바꾼 배포가 멈추면 안 된다.
    """
    base = os.environ.get("LLM_CLAUDE_MODEL", "claude-opus-4-8")
    name = os.environ.get(_MODEL_ENV.get(kind or "", ""), "").strip()
    return name or base


class ClaudeAdapter:
    name = "claude"

    def __init__(self, model: str = "", kind: str = ""):
        self.model = model or model_for(kind)
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
    if (masked_ctx.get("logs_fetch_capped") or masked_ctx.get("logs_clipped")
            or (masked_ctx.get("logs_fetched") or 0)
            > (masked_ctx.get("logs_selected") or 0)):
        head += TRUNCATION_RULE
    if masked_ctx.get("logs_window_guessed"):
        head += WINDOW_GUESSED_RULE
    if (masked_ctx.get("incident") or {}).get("scope") == "notify_only":
        head += NOTIFY_ONLY_RULE
    if masked_ctx.get("prior"):
        head += PRIOR_INSTRUCTION
    return head + json.dumps(masked_ctx, ensure_ascii=False, indent=1)


# 조회 창이 사건 시각이 아니라 지금으로 떨어졌을 때만 붙는다.
WINDOW_GUESSED_RULE = (
    "**이 사건의 로그·보안 조회 창은 사건이 난 시각이 아니라 조회를 돌린 시각 기준이다.**"
    " 사건 시각을 아무도 주지 않아 지금을 기준으로 잡았다. 따라서 이 창에 신호가 없다는"
    " 사실을 근거로 쓰지 마라 — 사건이 없던 시간대를 본 것일 수 있다. 로그 축은"
    " '확인 불가'로 다뤄라.\n\n")

# 로그가 잘렸을 때만 붙는다. 안 잘렸는데 의심하게 만들면 그것도 오도다.
TRUNCATION_RULE = (
    "이 사건의 로그는 **일부만 실려 있다**. `logs_fetched` 가 창에서 읽은 줄 수이고"
    " `logs_selected` 가 실제로 실린 줄 수다. 둘이 다르면 나머지는 골라내지 않은 것이다."
    " `logs_fetch_capped` 가 true 면 조회 자체가 상한에 닿아 창에 더 많은 줄이 있었다는"
    " 뜻이고, `logs_clipped` 는 길이 제한으로 뒷부분이 잘린 줄 수다."
    " 따라서 **실린 로그에 없다는 이유로 '흔적 없음'이라고 쓰지 마라.**"
    " 로그 축을 근거로 삼을 때는 '실린 범위에서는' 이라고 밝히고, 확인 명령에 원본 로그를"
    " 더 넓게 보는 명령을 넣어라.\n\n")

# 위탁 계약이 임의 조치를 금지한 고객사에만 붙는다 — 실행 차단과 별개로 문장도 막는다
NOTIFY_ONLY_RULE = (
    "이 사건은 위탁 계약상 **우리가 시스템을 변경할 수 없는 대상**이다"
    "(incident.scope = notify_only). 재기동·설정 변경·프로세스 종료처럼 상태를 바꾸는"
    " 행위를 권고하지 마라. 4)번 절은 '권장 조치' 대신 **고객사에 전달할 내용과 확인 요청**"
    "으로 쓴다. 우리가 할 수 있는 것은 조회와 통보뿐이므로, 확인 명령도 읽기 전용으로만"
    " 낸다. 자동 조치 가능 여부는 '계약상 불가'로 쓴다.\n\n")


# 과거 결론이 붙었을 때만 나가는 지시문. 마지막 줄의 형식이 extract_change 와 짝이다.
PRIOR_INSTRUCTION = (
    "prior 는 같은 대상에 대한 과거 판정이다. match 가 매칭 강도이고(동일 사건 · 같은 유형 ·"
    " 같은 호스트), '확인' 이 사람 검증 여부다. 미확인 결론은 봇이 예전에 쓴 문장일 뿐이므로"
    " 사실로 취급하지 말고, 사람이 오답으로 표시한 결론은 그 방향을 따라가지 마라."
    " summary 가 비어 있으면 본문이 제공되지 않은 것이지 내용이 없는 것이 아니다.\n"
    "회신 마지막 줄에 반드시 이 형식 한 줄을 붙인다:\n"
    "변화: 동일 | 달라짐 — 무엇이 같고 무엇이 달라졌는지 한 문장\n\n")

# 회신에 섞이면 안 되는 복구 명령 — 되돌릴 수 없거나 상태를 지우는 것만 넣는다
# 판정과 안전은 코드가 진다. 모델 등급을 내려도 이 목록은 그대로다
_DESTRUCTIVE = (
    (re.compile(r"\bRESET\s+(SLAVE|REPLICA|MASTER)\b", re.IGNORECASE),
     "복제 위치·설정이 지워진다"),
    (re.compile(r"\bDROP\s+(DATABASE|TABLE)\b", re.IGNORECASE), "데이터가 지워진다"),
    (re.compile(r"\brm\s+-[a-z]*[rf][a-z]*\s+/", re.IGNORECASE), "파일이 지워진다"),
    (re.compile(r"\bkill\s+-9\b", re.IGNORECASE), "정리 없이 죽어 손상이 남을 수 있다"),
    (re.compile(r"\bmkfs|\bfdisk\b", re.IGNORECASE), "저장 장치를 다시 만든다"),
    (re.compile(r"\bTRUNCATE\s+TABLE\b", re.IGNORECASE), "표의 내용이 지워진다"),
)
# 금지를 설명하는 문장까지 잡으면 안 된다. "복제 리셋은 하지 마십시오" 는 경고다.
_NEGATED = re.compile(r"(하지\s*마|금지|말\s*것|안\s*된다|권장하지)")

DESTRUCTIVE_NOTE = ("\n\n⚠️ **위 조치 중 되돌릴 수 없는 명령이 있다** — %s."
                    " 실행 전에 사람이 확인한다.")


def destructive_ops(text: str) -> list:
    """회신에서 되돌릴 수 없는 명령을 찾는다. 금지를 설명하는 문장은 빼고 본다."""
    found = []
    for line in (text or "").splitlines():
        if _NEGATED.search(line):
            continue
        for rx, why in _DESTRUCTIVE:
            m = rx.search(line)
            if m and why not in found:
                found.append(why)
    return found


def mark_destructive(text: str) -> str:
    """찾았으면 회신 끝에 표시를 붙인다. 문장을 지우지는 않는다 — 판단은 사람이 한다."""
    found = destructive_ops(text)
    return text + DESTRUCTIVE_NOTE % ", ".join(found) if found else text


CHANGE_RE = re.compile(r"^\s*변화\s*:\s*(.+)$", re.MULTILINE)


def extract_change(text: str) -> str:
    """회신 마지막 줄의 변화 판정. 없으면 빈 문자열 — 지어내지 않는다."""
    found = CHANGE_RE.findall(text or "")
    return found[-1].strip()[:200] if found else ""


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
    """월간 분석 화이트리스트. 여기 없는 필드는 구조적으로 전송되지 않는다(전송 명세표 원칙)."""
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
    res = egress.call(_adapters("write"), _prompt("monthly", MONTHLY_SYSTEM),
                      user, kind="monthly")
    if not res["degraded"]:
        return {**res, "text": masker.unmask(res["text"])}
    # 열화 — 리포트는 실시간이 아니므로 실패 사유까지 그대로 남긴다
    return {**res, "text": f"(월간 분석 생성 실패 — {_reason_text(res['reason'])}. "
                           "집계 수치는 유효하다.)"}


def _adapters(kind: str = ""):
    """폴백 순서. 두 경로가 같은 체인을 쓰도록 한 곳에 둔다.

    용도를 주면 그 등급의 모델을 쓴다. 안 주면 기존 값이라 동작이 안 바뀐다.
    """
    return (ClaudeAdapter(kind=kind), OllamaAdapter())


def _reason_text(reason: str) -> str:
    """열화 사유를 사람 문장으로. 왜 없는지가 안 적히면 이유를 물어봐야 한다."""
    if reason == egress.BLOCKED_HOUR:
        return (f"최근 1시간 호출이 상한 {egress.MAX_PER_HOUR}건에 닿아 부르지 않았다."
                " 폭주 제동이며, 위중(SEV1) 사건은 이 상한을 받지 않는다")
    if reason == egress.BLOCKED_QUEUE:
        return (f"동시 호출 {egress.MAX_CONCURRENCY}건이 {egress.QUEUE_WAIT_S:.0f}초 넘게"
                " 차 있어 대기를 포기했다")
    return "LLM 응답 없음"


def triage_reply(context: dict, sev: str) -> dict:
    """마스킹 → Claude/Ollama/열화 → 역치환 → 회신 dict. 예외를 위로 던지지 않음."""
    masker = Masker()
    masked = build_llm_context(context, sev, masker)
    user = build_user_prompt(masked)

    # 용도를 어댑터에도 넘긴다 — 계수용으로만 넘기면 매핑이 있어도 기본값으로 떨어진다
    res = egress.call(_adapters("triage"), _prompt("triage", TRIAGE_SYSTEM), user,
                      exempt=(sev == "SEV1"), kind="triage")
    if not res["degraded"]:
        text = masker.unmask(res["text"])
        # 프롬프트로 막았어도 모델이 쓸 수 있다. 실제로 그랬다(2026-08-13).
        found = destructive_ops(text)
        if found:
            log.warning("회신에 되돌릴 수 없는 명령이 있어 표시를 붙인다: %s", ", ".join(found))
        text = mark_destructive(text)
        return {**res, "text": text, "change": extract_change(text)}

    note = f" — {_reason_text(res['reason'])}" if res["reason"] != egress.BLOCKED_NONE else ""
    inc = context.get("incident")
    if inc:
        text = (f"(LLM 분석 불가 — 코드 판정만 회신{note})\n"
                f"{inc.get('alert_count', '?')}건 병합 사건 — {inc.get('merge_reason', '')}")
    else:
        pj = context.get("prejudge") or {}
        text = (f"(LLM 분석 불가 — 코드 판정만 회신{note})\n"
                f"판정: {pj.get('verdict', '?')} — {pj.get('statement', '')}")
    return {**res, "text": text}


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


def _prompt(name: str, fallback: str) -> str:
    """프롬프트를 파일에서. 없으면 코드에 있는 예비 문구."""
    from . import prompts

    return prompts.load(name, fallback)


# 캐시 유효 시간. 기본 5분은 쓰기가 1.25배, 1시간은 2배이고 읽기는 둘 다 0.1배다.
# 읽을 때마다 시간이 갱신된다. 근거와 실측은 GATEWAY_GUIDE §29.
CACHE_TTLS = ("5m", "1h")


def cache_ttl() -> str:
    """실어 보낼 유효 시간. 기본값(5m)이면 빈 문자열 — 값을 안 싣는다."""
    v = os.environ.get("LLM_CACHE_TTL", "").strip().lower()
    return v if v in CACHE_TTLS and v != "5m" else ""


def cached_system(system: str):
    """시스템 문구를 캐시 표시가 붙은 블록으로. 끄면 문자열 그대로."""
    if os.environ.get("LLM_CACHE", "1").strip().lower() in ("0", "false", "no"):
        return system
    cc = {"type": "ephemeral"}
    ttl = cache_ttl()
    if ttl:
        cc["ttl"] = ttl
    return [{"type": "text", "text": system, "cache_control": cc}]


def claude_tools(system: str, messages: list, tools: list,
                 model: str = "", timeout_s: float = 0) -> dict:
    """도구를 쓸 수 있는 호출. 반환은 응답 본문 그대로(content 블록·stop_reason)."""
    import anthropic
    ad = ClaudeAdapter(model=model, kind="investigate")
    # 질의는 사람이 기다린다 — 알림용 여유 시간을 쓰면 느린 응답 한 번이 마감을 넘긴다
    # 예열처럼 사람이 안 기다리는 호출은 더 오래 기다려도 된다
    timeout = float(timeout_s) or min(ad.timeout,
                                      float(os.environ.get("ASK_LLM_TIMEOUT_S", "30")))
    client = anthropic.Anthropic(timeout=timeout, max_retries=0)
    resp = client.messages.create(model=ad.model, max_tokens=MAX_TOKENS,
                                  system=cached_system(system),
                                  messages=messages, tools=tools)
    return resp.model_dump()
