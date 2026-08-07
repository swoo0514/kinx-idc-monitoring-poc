# latency_bench.py — 데모 C LLM 응답시간 실측 가이드

## 1. 목적 및 검증 배경

데모 C(AI 초동 분석) 시나리오의 목표 지표인 **"알림 수신 후 30초 이내 Slack 분석 결과 회신"**에 대한 성능 검증을 수행합니다. 총 30초의 지연 시간(Latency) 예산은 아래 개별 처리 단계 소요 시간의 합산으로 구성됩니다:

```text
게이트웨이 수신 ➔ 컨텍스트 수집 (Zabbix/Loki API) ➔ 코드 선판정 ➔ LLM 연산 및 생성 ➔ Slack 메시지 게시
```

이 중 가장 변동성이 큰 **LLM 생성 소요 시간**을 사전 실측하여 지연 시간 리스크를 검증(De-risk)합니다. 동일한 평가 프롬프트를 기준으로 Claude API(메인 분석 경로)와 Ollama(온프레미스 폴백 경로)의 응답 성능을 비교 측정합니다.

---

## 2. 주요 측정 지표

- **TTFT (Time To First Token):** 최초 요청 전송 시점부터 첫 번째 텍스트 토큰 수신 시점까지의 소요 시간 (스트리밍 UX 응답성 평가 지표)
- **총 소요 시간 (Total Latency):** 요청 전송 시점부터 응답 생성 완료 시점까지의 전체 소요 시간 (Slack 메시지는 완성본 형태로 게시되므로 30초 지연 시간 KPI 산출 기준 지표로 활용)
- **출력 토큰 수 및 처리 속도 (Tokens/sec):** 생성된 토큰 수 및 초당 토큰 처리 속도 (Ollama의 경우 `eval_count` 및 `eval_duration` 메타데이터 기반 산출)
- **모델 로딩 시간 (`load_duration`, Ollama 전용):** Cold Start와 Warm State 간 소요 시간 구별 (초기 1회차 지연이 클 경우 모델 로딩 비용에 해당하며, 실제 봇 운용 시 Keep-alive 설정을 통해 회피 가능)

---

## 3. 사용 방법 및 CLI 옵션

```bash
# Claude 메인 경로 측정 (로컬 PC 실행, ANTHROPIC_API_KEY 환경변수 필요)
pip install anthropic
python bot/latency_bench.py --provider claude --runs 3

# Ollama 폴백 경로 측정 (랩 VM 환경 실행, 'ollama pull qwen3:8b' 사전 실행 필요)
python3 bot/latency_bench.py --provider ollama --ollama-model qwen3:8b --runs 3

# 통합 비교 측정 (Ollama가 로컬 환경에 구성된 경우)
python bot/latency_bench.py --provider both --json-out bench_result.json
```

### 주요 CLI 옵션 명세

- `--claude-model`: Claude 적용 모델 지정 (기본값: `claude-opus-4-8`)
- `--thinking`: Claude Adaptive Thinking 기능 활성화 측정 (기본값: 비활성화)
- `--target`: KPI 목표 응답 시간 지정 (기본값: `30`초)
- `--runs`: 반복 측정 횟수 지정 (기본값: `3`회)

---

## 4. 평가 및 판정 기준

- **통과 (Pass):** 최대 소요 시간 ≤ 목표 예산(30초). 게이트웨이 파이프라인 및 컨텍스트 수집 소요 시간을 고려할 때 안정적 수용 범위 충족.
- **조건부 통과 (Conditional Pass):** 중앙값은 목표를 충족하나 최대 소요 시간이 30초를 초과함. 시연은 가능하나 재시도 및 지연 시간 리스크 존재.
- **미달 (Fail):** 중앙값이 30초 목표를 초과함. 해당 경로는 메인 분석 경로로 부적합하며, 인프라 사양 상향 필요성을 기술 문서에 정직하게 명시함 (인수인계 및 핸드오프 원칙 준수).

> **[주의사항]**  
> 본 스크립트는 LLM 연산 구간 단독 지연 시간을 측정합니다. 실제 최종 평가 시에는 `LLM 연산 시간 + 컨텍스트 수집 시간 (Zabbix API 5종 asyncio 병렬 수집, 수 초 소요) + Slack API 전송 시간 (1초 이내)`을 합산하여 평가합니다. LLM 연산 단독 시간이 20초를 초과할 경우 전체 30초 예산 준수가 위태로워질 수 있습니다.

---

## 5. 아키텍처 설계 결정 및 기술적 근거

1. **Claude API 스트리밍 수집 (공식 `anthropic` Python SDK):** 장시간 응답 생성 시 발생할 수 있는 HTTP 타임아웃을 방지하고 TTFT를 정밀 측정하기 위해 스트리밍 방식을 적용합니다. `client.messages.stream()` 및 `get_final_message()` 패턴은 Anthropic 공식 권장 사양입니다 ([Anthropic Streaming Documentation](https://platform.claude.com/docs/en/build-with-claude/streaming) 참조).
2. **기본 평가 모델 지정 (`claude-opus-4-8`):** 2026년 7월 기준 표준 Opus 모델 ($5/$25 per MTok)을 기본 모델로 사용하며, CLI 옵션을 통해 `--claude-model claude-haiku-4-5` 등 타 모델과의 비교 측정을 지원합니다 ([Claude Models Overview](https://platform.claude.com/docs/en/about-claude/models/overview) 참조).
3. **샘플링 파라미터 제약 준수:** Opus 4.7 이후 사양에 따라 `temperature`, `top_p`, `top_k` 파라미터 전달 시 HTTP 400 에러가 발생하므로 전달을 배제합니다. Thinking 옵션은 `{"type": "adaptive"}` 지정만 허용되며, 기본값은 분석 지연 최소화를 위해 비활성화하고 `--thinking` 옵션을 통해 지연 시간 대비 품질 트레이드오프를 평가합니다 ([Claude Migration Guide](https://platform.claude.com/docs/en/about-claude/models/migration-guide) 참조).
4. **Ollama 표준 API 연동 (`/api/chat` 스트리밍 & `urllib`):** 외부 파이썬 의존성 없이 랩 VM 환경에 스크립트 복사만으로 즉시 실행 가능하도록 표준 라이브러리(`urllib`)를 활용합니다 (30분 이내 환경 재현성 원칙 준수). 최종 응답 청크의 `eval_count`, `eval_duration`, `load_duration` 메타데이터 필드를 기반으로 성능을 산출합니다 ([Ollama API Documentation](https://github.com/ollama/ollama/blob/main/docs/api.md#generate-a-chat-completion) 참조).
5. **데모 C 실전 페이로드 시뮬레이션:** 단순 테스트 문자열이 아닌 알림 메타데이터, 코드 선판정 결과, 메트릭, Loki 로그, Wazuh 보안 컨텍스트가 포함된 약 1.5KB 크기의 입력 프롬프트를 적용하고 Slack 단일 메시지 분량 제한 지시를 부여하여 실제 운영 지연 시간을 정확히 측정합니다. (전송 데이터는 가상 랩 값(`lab-web01`)을 사용하여 보안 유출 위험을 차단합니다.)
6. **구조화된 출력 (Pydantic Schema) 별도 분리:** 스키마 적용 시 최초 1회 컴파일 연산 비용이 발생하고 이후 24시간 동안 캐싱되는 특성으로 인해 지연 시간 측정 편차가 발생할 수 있어 본 측정 대상에서 제외합니다. 실제 게이트웨이 구현 시에는 고정 스키마 캐싱을 적용하여 운영합니다 ([Claude Structured Outputs Documentation](https://platform.claude.com/docs/en/build-with-claude/structured-outputs) 참조).

---

## 6. 측정 결과 기록 및 보존

측정된 결과 데이터는 LLM 경로 선택 및 성능 판정의 핵심 기술 근거로 활용되므로, 실행 시점의 측정 타임스탬프와 함께 [`docs/02-design/decisions/adr-005-llm-path.md`](../docs/02-design/decisions/adr-005-llm-path.md) 문서에 기록합니다. `--json-out` 옵션을 통해 원시 데이터를 JSON 형태로 저장하여 추후 결과 재산출 및 검증 가능성을 보장합니다 (수치는 원본에서 재계산 가능해야 한다는 문서화 원칙 준수).