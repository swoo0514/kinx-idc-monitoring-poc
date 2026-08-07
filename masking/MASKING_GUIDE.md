# 마스킹 이그레스 프록시 (Masking Egress Proxy) — 외부 LLM 데이터 보안 파이프라인

본 문서는 외부 LLM(OpenAI, Anthropic 등)으로 송신되는 관측 텔레메트리 데이터 내 민감 식별자(호스트명, IP 주소, 고객사명, DB 식별자)를 **가역적 가명화(Reversible Masking)**하여 통제하는 이그레스 프록시 계층의 구축 가이드입니다.

자체 마스킹 기능이 없는 에이전틱 도구(HolmesGPT 등)도 MSP 테넌트 데이터 분석에 안전하게 활용할 수 있도록 **Presidio(탐지·익명화) + LiteLLM(OpenAI 호환 프록시·역치환)** 오픈소스 조합으로 구성되었습니다.

*(데이터 송수신 및 마스킹 보안 규약: [`docs/02-design/llm-data-contract.md`](../docs/02-design/llm-data-contract.md) 참조)*

---

## 1. 아키텍처 및 선정 배경

- **LiteLLM 프록시 레이어 활용:** HolmesGPT는 내부적으로 LiteLLM을 통해 LLM 호출을 수행하므로, 전면에 OpenAI API 호환 LiteLLM 프록시를 배치하고 엔드포인트를 지정하면 별도의 코드 수정 없이 마스킹 파이프라인이 투명하게 주입됩니다.
- **Anthropic 네이티브 파서 이슈 우회:** OpenAI API 호환 응답 규격을 이용함으로써, 기존 Anthropic 네이티브 호출 시 발생하던 `output_parse_pii` 파싱 예외 항목을 구조적으로 회피합니다.

---

## 2. 데이터 처리 체인 (Data Flow)

```text
HolmesGPT (OpenAI 호환 API)
   │
   ▼ (OPENAI_API_BASE=http://<proxy-host>:4000)
LiteLLM Proxy
   │
   ├── [요청 단계] Presidio Anonymizer ➔ 민감 식별자 마스킹 ([IP_ADDRESS], [HOST_NAME])
   │
   ▼ (마스킹된 프롬프트 전송)
Anthropic API (Claude Model)
   │
   ▼ (마스킹 상태의 분석 및 Tool-Call 응답 회신)
LiteLLM Proxy
   │
   ├── [응답 단계] Presidio Deanonymizer ➔ 마스킹 토큰을 원본 식별자로 역치환
   │
   ▼ (복원된 분석 결과 및 Tool-Call 회신)
HolmesGPT (실제 식별자 기반 후속 도구 실행 및 조사 완주)
```

---

## 3. 기동 및 배포 절차 (마스킹 프록시 호스트)

```bash
# 환경변수 로드 (로그 및 코드 내 자격 증명 포함 금지)
set -a; source .env; set +a

# Presidio (Analyzer/Anonymizer) 및 LiteLLM 서비스 기동
docker compose up -d

# 프록시 헬스체크 및 Presidio 연동 검증
curl -s -X POST http://localhost:4000/health \
  -H "Authorization: Bearer sk-masking-lab"
```

---

## 4. HolmesGPT 프록시 경유 실행 절차 (`core` 노드)

```bash
docker run --rm --net=host \
  -e OPENAI_API_KEY=sk-masking-lab \
  -e OPENAI_API_BASE=http://<PROXY_HOST_IP>:4000 \
  -v ~/.holmes:/root/.holmes \
  <HOLMES_IMAGE_NAME> ask "..." --model="openai/masked-opus" --refresh-toolsets
```

---

## 5. 핵심 기술 검증 지표 (Evaluation Criteria)

1. **송신 프롬프트 가명화 검증 (Masking Ingestion):**  
   LiteLLM 디버그 로그(`--detailed_debug`) 분석을 통해 외부 API로 전송되는 프롬프트 내의 실체 호스트명/IP 주소가 `<IP_ADDRESS>`, `<PERSON>` 등 마스킹 토큰으로 정상 치환되어 반출되는지 검증합니다.
2. **응답 역치환 및 에이전틱 루프 정합성 (Deanonymization & Tool-Call Loop):**  
   Claude가 마스킹된 토큰으로 생성한 Tool-Call 연산이 HolmesGPT 전달 전 프록시 계층에서 원본 식별자로 정상 역치환되어, 후속 조사가 오류 없이 실행 완주되는지 정밀 검증합니다.
3. **인프라 맞춤형 감지 범위 확장 (Custom Recognizer Coverage):**  
   기본 엔티티(IP, Person) 검증 후, 사내 전용 Recognizer(사설 IP 대역, MSP 고객사명, DB 인스턴스 식별자)를 추가하여 Fail-closed 보안 정책을 충족시킵니다.

---

## 6. 기대 효과 및 시스템 적용

검증 완료 시 `holmes.py` 파이프라인의 이그레스 경로를 해당 마스킹 프록시로 일원화하고, 기존 `should_investigate` 내의 **"MSP 테넌트 데이터 심층 조사 제약 조건"을 완화**합니다. 이를 통해 보안 유출 위험 없이 MSP 멀티테넌트 환경에서도 HolmesGPT 기반의 에이전틱 심층 조사를 전면 적용할 수 있습니다.