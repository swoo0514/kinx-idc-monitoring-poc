# 설계 근거 — 주요 아키텍처 의사결정 배경 (Design Rationale)

본 문서는 개별 디렉토리의 가이드 문서에서 다루는 '구현 결과'를 제외하고, **해당 아키텍처 및 기술 스택을 선택한 기술적 배경과 의사결정 이유(Rationale)**를 기술합니다.

---

## 1. 의사결정 인덱스 (Decision Index)

| 의사결정 항목 | 최종 결론 | 주요 근거 및 참조 문서 |
|---|---|---|
| **관측 시스템 간 심각도 통합** | 통합 표준 눈금 SEV1~4 + NONE 적용<br/>*(사내 Warning: SEV4 / MSP Warning: SEV3)* | [severity-normalization.md](severity-normalization.md) |
| **외부 LLM 반출 데이터 범주** | 단일 반출 경로 + 화이트리스트 필드 + 양방향 가명화 적용 | [llm-data-contract.md](llm-data-contract.md) |
| **로직(규칙)과 LLM 간 역할 분담** | **판단 및 선판정은 코드, 설명 생성만 LLM 전담** | [rules-inventory.md](rules-inventory.md) |
| **주장 및 지표의 출처 표기 방식** | `[문서]`, `[코드]`, `[제안]` 3단계 구분 명시 | [evidence-policy.md](evidence-policy.md) |
| **알림 저장·UI·승인 관제 플랫폼** | **Keep 솔루션 채택**<br/>*(자체 게이트웨이 전처리 후 Push 연동)* | [ADR-001](decisions/adr-001-keep-adopt.md) |
| **오픈소스 원인 분석 솔루션 도입** | **하이브리드 채택**<br/>*(실시간·MSP: 자체 봇 / 심층 조사: 에이전틱)* | [ADR-002](decisions/adr-002-holmesgpt.md) |
| **AIOps 솔루션 자체 구축 (Build vs Buy)** | PoC 단계 자체 구축 채택<br/>*(요구사항 검증용 자산이며 영구 유지 제품은 아님)* | [ADR-003](decisions/adr-003-build-vs-buy.md) |
| **네트워크 계층 패킷 관측 확장** | **1순위: dnsdist 네이티브 관측 활성화**<br/>*(Suricata는 보완용으로 한정)* | [ADR-004](decisions/adr-004-suricata-defer.md) |
| **LLM 호출 파이프라인 구성** | Claude 메인 + Ollama 폴백 + **열화 모드**<br/>*(API 재시도 미적용)* | [ADR-005](decisions/adr-005-llm-path.md) |

---

## 2. 주요 의사결정 관통 원칙 (Core Principles)

1. **판단은 코드, 설명은 LLM (Deterministic Judgement, Generative Interpretation):**  
   알림 병합 규칙, 만성/신규 장애 선판정 등 핵심 판단은 코드 기반 결정론적(Deterministic) 로직으로 처리하여 동일 입력에 대한 동일한 결과를 보장합니다. LLM은 확정된 인시던트에 대한 **인과관계 설명 생성**만을 전담하며 판단 결과 자체를 뒤집을 수 없습니다. LLM 환각(Hallucination) 통제는 '프롬프트 제어'가 아닌 **'구조적 권한 분리'**를 통해 달성합니다.

2. **하드 요건(Hard Requirements) 기반 실측 채택 (Evidence-based Selection):**  
   Keep 및 HolmesGPT 등 주요 솔루션 도입 검토 시 단순 서류 비교가 아닌 **동일 랩 및 동일 시나리오 기반의 실측 검증**을 수행했습니다. 검증 결과에 따라 단일 채택 또는 하이브리드 역할을 부여했으며, 실증 데이터에 기반한 선택 결과 자체가 본 산출물의 기술적 가치입니다.

3. **가설에 대한 스펙 기반 정정 (Fact-based Correction):**  
   프로젝트 진행 시 세운 초기 가설을 공식 사양 검증을 통해 지속적으로 검증하고 정정했습니다 ([evidence-policy.md](evidence-policy.md) 참조). 오류가 입증된 초기 가설 역시 이력으로 기록하여 명확한 설계 근거로 활용합니다.

4. **기존 오픈소스 자원의 적극적 활용 (Leveraging Existing Substrates):**  
   Zabbix의 예측 기능, Keep의 저장 및 승인 워크플로 등 검증된 오픈소스 자원(Substrate)을 최대한 활용하고, 자체 파이프라인 계층에는 **통합 분석 지능(정규화·병합·선판정)**만을 최소한으로 구축하여 시스템 비대화를 방지했습니다.

---

## 3. 명시적 제외 범위 (Out of Scope)

설계 단계에서 의도적으로 제외(Inactivation) 처리한 기능 목록입니다.

- **규칙 없는 이상 탐지 (Unsupervised Anomaly Detection):** 기각. 환각 및 오탐 위험이 '코드 기반 선판정' 원칙에 위배됩니다.
- **별도 GUI 워크플로 엔진 추가 (n8n 등):** 제외. Keep의 승인 제어 계층을 재사용(자동 조치 및 리포트)하여 시스템 복잡도를 최소화했습니다.
- **Suricata 랩 직접 구축:** 제외. 관측 사각지대 분석을 통해 네이티브 관측 활성화라는 고효율 대안을 선순위로 정의했습니다.
- **Active Response 및 외부 해시 연동 (VirusTotal 등):** 제외. Active Response 는 **MSP 계약상 임의 조치가 금지된 대상이 실재**하여 제외했고, 외부 해시 연동은 데이터 반출 통제 원칙에 위배되어 제외했습니다.
- **컨테이너 및 클라우드 커넥터 확장:** 제외. 현재 온프레미스 VM 및 물리 인프라 관측 대상 범위를 준수합니다.

---

## 4. 관련 참조 문서

- 본 아키텍처의 **구조적 약점 및 한계점:** [`../03-pitfalls/`](../03-pitfalls/README.md)
- 게이트웨이 파이프라인의 **실제 구현 및 배선 가이드:** [`bot/GATEWAY_GUIDE.md`](../../bot/GATEWAY_GUIDE.md)