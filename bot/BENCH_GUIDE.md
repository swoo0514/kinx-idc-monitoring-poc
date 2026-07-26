# latency_bench.py — 데모 C LLM 응답시간 실측 가이드

## 목적

데모 C(AI 초동 분석)의 연출은 "알림 발생 30초 안에 Slack 회신"임. 30초 예산은
`게이트웨이 수신 → 컨텍스트 수집(Zabbix/Loki API) → 만성/신규 코드 선판정 → LLM 생성
→ Slack 게시`의 합이므로, 가장 변동 큰 구간인 **LLM 생성 시간**을 먼저 실측해
de-risk함. Claude API(주 경로)와 Ollama(온프레 폴백)를 같은 프롬프트로 비교함.

## 측정 항목

- **TTFT** (Time To First Token): 요청 → 첫 텍스트 토큰까지. 스트리밍 UX 판단용.
- **총 시간**: 요청 → 응답 완료. Slack 회신은 완성본을 게시하므로 30초 판정은 이 값 기준.
- **출력 토큰 수 / tok/s** (Ollama는 `eval_count`·`eval_duration`으로 재계산 가능).
- Ollama 한정: **모델 로드 시간**(`load_duration`) — 콜드스타트와 웜 상태를 구분해야 함.
  1회차만 크게 느리면 모델 로드 비용이며, 봇 운용 시 keep-alive로 회피 가능.

## 사용법

```bash
# Claude 경로 (로컬 PC, ANTHROPIC_API_KEY 필요)
pip install anthropic
python bot/latency_bench.py --provider claude --runs 3

# Ollama 경로 (랩 VM에서 — ollama pull qwen3:8b 선행)
python3 bot/latency_bench.py --provider ollama --ollama-model qwen3:8b --runs 3

# 둘 다 (Ollama가 로컬에 있을 때)
python bot/latency_bench.py --provider both --json-out bench_result.json
```

주요 옵션: `--claude-model`(기본 `claude-opus-4-8`), `--thinking`(Claude adaptive
thinking 켜고 측정 — 기본은 끔), `--target`(판정 기준 초, 기본 30), `--runs`(기본 3).

## 판정 기준

- **통과**: 총 시간 최대값 ≤ 목표(30s). 게이트웨이·컨텍스트 수집 여유까지 안전.
- **조건부**: 중앙값은 통과하나 최대값 초과. 데모는 가능하되 재시도/스톱워치 리스크 있음.
- **초과**: 중앙값도 초과. 이 경로는 데모 주 경로로 부적합 → 로드맵에 사양 상향 필요를
  정직하게 기재(핸드오프 원칙: "30초 초과 시 온프레는 사양 상향 필요로 기재").

주의: 30초 예산에서 LLM 몫만 재는 것이므로, 실전 판정은 `LLM 총 시간 + 컨텍스트 수집
(Zabbix API 5종 asyncio 병렬, 수 초 예상) + Slack 게시(1초 미만)`로 환산해 볼 것.
LLM이 20초를 넘으면 전체 30초가 위태로움.

## 설계 결정과 근거

- **Claude 호출은 공식 `anthropic` Python SDK + 스트리밍**. 스트리밍은 장시간 생성 시
  HTTP 타임아웃 회피 겸 TTFT 측정 수단. `client.messages.stream()` +
  `get_final_message()` 패턴은 공식 문서의 권장 사용법임.
  - 근거: https://platform.claude.com/docs/en/build-with-claude/streaming
- **기본 모델 `claude-opus-4-8`** (2026-07 현재 표준 Opus 모델, $5/$25 per MTok).
  같은 스크립트로 `--claude-model claude-haiku-4-5` 등 비교 측정 가능.
  - 근거: https://platform.claude.com/docs/en/about-claude/models/overview
- **`temperature` 등 샘플링 파라미터 미사용**: Opus 4.7 이후 모델은 `temperature`/
  `top_p`/`top_k` 전달 시 400 에러. thinking은 `{"type": "adaptive"}`만 허용
  (`budget_tokens`는 제거됨). 기본값은 thinking 끔(트리아지 지연 최소화),
  `--thinking`으로 품질-지연 트레이드오프 비교 가능.
  - 근거: https://platform.claude.com/docs/en/about-claude/models/migration-guide
- **Ollama는 `/api/chat` 스트리밍 + 표준 라이브러리 `urllib`**: 랩 VM에 의존성 없이
  복사만으로 실행 가능하게 함(리포 원칙: 30분 재현). 최종 청크의 `eval_count`/
  `eval_duration`/`load_duration`이 공식 응답 필드임.
  - 근거: https://github.com/ollama/ollama/blob/main/docs/api.md#generate-a-chat-completion
- **프롬프트는 데모 C 실제 페이로드 모사**: 알림 + 코드 선판정 결과 + 메트릭 + Loki
  로그 + Wazuh 컨텍스트를 포함한 ~1.5KB 입력, Slack 1메시지 분량 출력 제한.
  짧은 "hello" 프롬프트로 재면 실전 지연을 과소평가하므로 실 사용 형태로 측정.
  데이터는 전부 가짜 랩 값(lab-web01)이며 실환경 정보 없음 — 전송 데이터 명세표
  관점에서도 안전.
- **구조화 출력(Pydantic 스키마)은 이번 측정에서 제외**: 스키마 첫 요청에 1회성 컴파일
  비용이 있고 이후 24시간 캐시되므로 측정이 흔들림. 본 게이트웨이 구현 시 스키마를
  고정해 캐시가 유지되게 하고, 필요하면 스키마 포함 재측정.
  - 근거: https://platform.claude.com/docs/en/build-with-claude/structured-outputs

## 결과 기록

측정 결과 수치는 EXECUTION_PLAN/STRATEGY 근거로 쓰이므로, 실행 후 측정 창(일시)과
함께 `private/docs/`에 기록하고 CLAUDE.md 진행 상태를 갱신할 것. `--json-out`으로
원시 데이터를 남겨 재계산 가능하게 함(작업 원칙 6: 수치는 원본에서 재계산 가능해야).
