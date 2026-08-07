# ADR-001 — Keep(keephq)의 알림 저장·UI·승인 서브스트레이트(Substrate) 채택

**결정 사항: 채택 (단, "게이트웨이 연동 푸시(Push)" 방식 적용)**  
Keep이 Zabbix 데이터를 직접 수집(Pull)하지 않고, 자체 게이트웨이에서 정제 및 전처리 후 Generic Webhook을 통해 Keep으로 전송(Push)하는 아키텍처를 채택합니다.

---

## 1. 검토 배경 및 목적

인시던트 저장, 관제 UI 제공, 만성 장애 기반 자동화 대상 식별, 심층 조사 연동 기능이 요구되었으며, 해당 기능을 자체 스키마 설계로 직접 구현할 경우 Keep의 Alerts/Incidents/Correlation 기능 영역과 완전히 중복되는 문제가 발생합니다.

사전에 중복 구현에 따른 리소스 낭비를 방지하고자 실증 평가를 통해 채택 여부를 결정했습니다. HolmesGPT 검증 방식과 동일하게 **핵심 필수 요건(Hard Requirements) 기준 평가 후 통과 시 도입**하는 검증 원칙을 적용했습니다.

---

## 2. Keep 제공 주요 기능 (공식 스펙 기준)

- **정규화 데이터 스키마:** Alerts / Incidents / Correlation Groups 정규화 테이블 제공
- **다중 DB 백엔드 지원:** SQLite, MariaDB, PostgreSQL, MS SQL Server (기존 관측 코어의 MariaDB 재사용 가능)
- **독립 인프라 배포:** 단일 노드 Docker Compose 기반 셀프 호스팅 지원 (Kubernetes 미요구, 온프레미스 VM 환경 적합)
- **관제 기능 수요 충족:** 내장 관제 UI, 중복 제거(Fingerprint), 연관 관계 분석, 워크플로 엔진(YAML 기반 Trigger/Step/Action) 제공
- **Zabbix Provider 연동:** Zabbix 6.0+ 공식 연동 지원

---

## 3. 요건별 평가 결과 (Evaluation Checklist)

| 평가 요건 | 요건 구분 | 평가 결과 및 상세 판단 내용 |
|---|---|---|
| **KR-1** Zabbix 알림 실제 수집 | 필수 | **PASS (제한적)** — 장애 항목이 Alerts 목록으로 수집되나 KR-3의 식별자 부족 문제 존재 |
| **KR-2** 마스킹 경계 (MSP) | **하드** | **PASS (조건부)** — Pull 모드는 데이터 내 호스트명/IP가 미포함되어 저위험군이나, Push 모드 전환 시 마스킹 필수 ➔ 게이트웨이 전처리 계층에서 마스킹 수행 |
| **KR-3** 상관 관계 역할 중복 | 필수 | **FAIL (기본 설정 제약)** — 기본 Fingerprint 로직이 단순 설명(Description) 기준 동작함에 따라, 서로 다른 고객사의 동일 트리거가 호스트 구분 없이 1건으로 병합되는 현상 발생 (상세 화면 내 호스트 식별 불가로 멀티테넌트 환경 부적합) |
| **KR-4** 만성 장애 자동화 후보 식별 | 필수 | **미지원** — Keep 자체 기능 미지원 ➔ 자체 분석 계층(게이트웨이)에서 해당 역할 수행 |
| **KR-5** 조치·읽기 전용 권한 원칙 | **하드** | **FAIL (기본 연동 제약)** — Keep의 Zabbix 통합 모듈이 Write 권한을 요구함 (Media type/Script/Action 자동 생성). 운영 환경의 'Read-Only' 권한 제약과 충돌 ➔ Push-Only 전용 계정으로 권한 제한 필요 |
| **KR-6** HITL 승인 + Ansible 연동 | 필수 | **PASS (실증 완료)** — 세부 내용은 아래 KR-6 실증 항목 참조 |
| **KR-7** 심층 조사 결과 Enrichment | 참고 | **PASS** — API 및 워크플로를 통한 확장 지원 |
| **KR-8** 온프레미스 배포 및 규모 가용성 | 참고 | **PASS** — Docker Compose 기반 온프레미스 배포 적합 (고용량 알림 환경 DB 커넥션 이슈 보고가 있으나 본 프로젝트 수집 규모에서는 미영향) |

### 주요 결함 사항 — Zabbix 7.0 연동 시 네이티브 Provider 버그 발생

Zabbix Push 웹훅 설치 실행 결과: 설치 요청은 HTTP 200을 반환하나 **`Keep` 미디어 타입이 정상 생성되지 않으며**, Provider가 `Invalid parameter "/": cannot be empty.` / `the parameter "eventids" is missing.` 오류를 5초 주기 반복 출력하는 현상이 확인되었습니다. Zabbix 7.0이 Provider의 호출 요청을 거부함에 따라 초기 일부 수집을 제외한 다수의 호출이 실패했습니다.

➔ **Zabbix 7.0 환경에서 Keep 네이티브 Provider 직접 연동은 부적합함**으로 판단했습니다.

### KR-6 실증 결과 — Keep 워크플로 기반 Ansible 연동 검증

* **실행 경로:** Keep SSH Provider (paramiko) ➔ 관측 코어 (Ansible Control Node) ➔ `ansible-playbook remediate_service.yml`
* **실행 결과 반환:** Keep Step 출력으로 결과 확인 (`PLAY RECAP ok=7 changed=1 failed=0`, `before: inactive -> after: active`)

**기술적 의의:** Keep 단일 도구로 **"알림 저장 + 관제 UI + 승인 관리 + Ansible 자동 조치"**를 통합 수행할 수 있습니다. 데모 B (HITL 자가 치유 시나리오)를 Keep 기반으로 구현할 수 있게 됨에 따라 별도 GUI 워크플로 엔진(n8n) 추가 도입 필요성이 소멸되었으며, 주 관제 화면이 Grafana 및 Keep으로 일원화됩니다.

**운영 제약 사항 및 고려 요소:**
1. UI 내 "새 워크플로 생성" 메뉴 실행 시 500 에러 발생 (파일 직접 수정 또는 API 호출 방식으로 우회 필요)
2. SSH Provider 설정 항목 내 개인키 원문 저장 필요
3. 워크플로 정의 파일 수정 사항은 **Keep 서비스 재시작 시점에만 반영됨**

---

## 4. 최종 판정 및 아키텍처 수립

**판정 결과: 채택 유효 (단, 턴키 도입이 아닌 "채택 후 정제 연동" 방식 적용)**

저장소, UI, 중복 제거, 워크플로, 양방향 액션 기능을 상용 수준으로 제공받아 자체 스키마 직접 개발 대비 공수를 대폭 절감했습니다. 네이티브 Provider 버그, 호스트 식별자 부족, 마스킹 제약 등의 문제점은 **단일 아키텍처 전환(게이트웨이 전처리 후 Push)을 통해 동시 해결**합니다.

```text
게이트웨이 (마스킹 · 분류 · 만성 판정 · Host 라벨 포함)
        │ Generic Webhook Push
        ▼
      Keep (저장 · UI · 중복 제거 · 워크플로 승인)  ←  심층 조사 결과 Enrichment
```

**시스템별 역할 분담:**
* **Keep:** 데이터 저장, 중복 제거, 관제 UI, 승인 워크플로 서브스트레이트
* **자체 게이트웨이:** 실시간 30초 처리, 데이터 마스킹, 만성 장애 판정 (Keep 미지원 영역 보완)
* **심층 조사 (HolmesGPT):** 온디맨드 분석 데이터 보강 (Enrichment)

---

## 5. 의사결정 재사용 규칙 (Decision Rules)

본 ADR의 판단 기준을 향후 다른 컴포넌트 검토 시 재사용하기 위한 규칙은 다음과 같습니다.

* **핵심 필수 요건(마스킹 및 Read-Only 제약)이 전처리 계층으로 해소 가능**하고 기능 요건을 충족하는 경우 ➔ 해당 솔루션을 채택하고 자체 스키마 개발은 폐기함
* Keep 전단에 마스킹 레이어를 배치할 수 없는 경우 ➔ MSP Multi-tenant 데이터 직접 투입 불가 (사내 전용 채택 또는 프록시 구축 선행)
* 운영 환경 DB Write 권한 부여가 제한되는 경우 ➔ Push-Only 방식 및 전용 Restricted 계정으로 권한 최소화
* 상기 대안이 모두 불가한 경우 ➔ 최소 기능의 자체 스토리지 구조로 후퇴하되, 표준 정규화 스키마를 유지하여 향후 이관 비용을 최소화함

---

## 6. 참고 공식 문서

* Keep 개요 및 DB 배포 스펙: <https://github.com/keephq/keep>, <https://docs.keephq.dev>
* Docker 배포 가이드 (3개 컨테이너): <https://docs.keephq.dev/deployment/docker>
* Zabbix Provider 연동 사양: <https://docs.keephq.dev/providers/documentation/zabbix-provider>
* 상세 연동 배선 절차: [`keep/KEEP_GUIDE.md`](../../../keep/KEEP_GUIDE.md)