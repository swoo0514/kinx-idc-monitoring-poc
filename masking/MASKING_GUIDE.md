# 마스킹 이그레스 프록시 (HolmesGPT/외부LLM MSP 빗장 해제)

외부 LLM으로 나가는 데이터에서 식별자(호스트·IP·고객사·DB명)를 **가역 마스킹**해, HolmesGPT
같은 마스킹 없는 도구도 MSP 데이터에 쓸 수 있게 하는 계층. **밑바닥 구현이 아니라 OSS 조립** —
Presidio(탐지·익명화) + LiteLLM(프록시·역치환). 평가 판정은 `private/docs/`에 기록.

## 왜 이 조합

- HolmesGPT는 내부적으로 **LiteLLM**으로 LLM을 부른다 → 별도 LiteLLM 프록시를 앞에 세우고
  HolmesGPT를 그 프록시(OpenAI-호환)로 가리키면 자연스럽게 마스킹이 삽입된다.
- **OpenAI-호환 경로**라, 앞서 확인한 "Anthropic 네이티브 경로 `output_parse_pii` 이슈"를
  우회할 가능성이 크다(이 우회가 되는지가 핵심 검증점 = task #4).

## 체인

```
HolmesGPT --(OpenAI호환, OPENAI_API_BASE=proxy:4000)--> LiteLLM proxy
   → Presidio 마스킹(요청)  → Anthropic  → Presidio 역치환(응답, output_parse_pii)  → HolmesGPT
```

## 기동 (마스킹 프록시 호스트, 예: keep VM)

```bash
export ANTHROPIC_API_KEY=...      # .env source, 로그·커밋 금지
docker compose up -d              # presidio-analyzer/anonymizer + litellm:4000
# 헬스: Presidio 탐지 확인
curl -s -X POST http://localhost:4000/health -H "Authorization: Bearer sk-masking-lab"
```

## HolmesGPT를 프록시 경유로 (core, docker run)

```bash
docker run --rm --net=host \
  -e OPENAI_API_KEY=sk-masking-lab \
  -e OPENAI_API_BASE=http://<proxy-host>:4000 \
  -v ~/.holmes:/root/.holmes \
  <holmes-image> ask "..." --model="openai/masked-opus" --refresh-toolsets
```

## 검증점 (여기가 진짜 평가)

1. **마스킹 발생** — LiteLLM `--detailed_debug` 로그에서 Anthropic으로 나간 프롬프트에 실
   호스트/IP가 아니라 `<IP_ADDRESS>`·`<PERSON>` 토큰인지.
2. **역치환(가역) + 에이전틱 루프** — Claude가 마스킹 토큰으로 만든 tool-call이 실행 전 실
   값으로 역치환돼 HolmesGPT 조사가 **정상 동작**하는지. 안 되면 에이전트가 토큰으로 조회해
   깨진다 → 이게 앞서 우려한 지점. 여기서 막히면 우회/구현할 곳이 확정된다.
3. **커버리지** — 기본 엔티티(IP·PERSON)로 파이프라인 증명 후, KINX 커스텀 recognizer
   (사설 IP 대역·고객사명·DB명) 추가(task #5). fail-closed 정책.

## 종착점

되면 `holmes.py`가 이 프록시를 경유하게 하고, `should_investigate`의 MSP 제외 게이트를 완화
(마스킹되니 MSP도 허용) → **MSP 데이터로도 HolmesGPT 심층조사 가능**(task #6).
