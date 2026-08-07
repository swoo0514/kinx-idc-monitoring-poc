# 심각도 정규화 매핑표 — 통합 심각도 체계 및 소스별 매핑 명세

본 문서는 사내 Zabbix, MSP Zabbix, Wazuh 등 3개 관측 시스템의 서로 다른 심각도 눈금(Scale)을 단일 통합 심각도(SEV) 체계로 정규화하기 위한 **Single Source of Truth (Owner) 명세서**입니다.

> **[운영 원칙]** 본 매핑표는 게이트웨이 모듈(`bot/gateway/severity.py`), Grafana 정규화 대시보드, LLM 분석 프롬프트의 통합 심각도 표기 기준이 됩니다. 본 기준 변경 시 문서를 우선 개정한 후 관련 코드를 반영합니다.

---

## 1. 정규화 도입 배경 및 필요성

- **사내 Zabbix (Warning):** 실측 데이터 분석 결과, 전체 이벤트의 99.5%를 차지하는 노이즈성 알림이며 상위 2개 트리거가 전체의 78.6%를 발생시킵니다. 관제 인력이 실시간 대응해야 할 핵심 신호(Signal)로 보기 어렵습니다.
- **MSP Zabbix (Warning):** 심각도 분포가 고르며 고객 통보 대상에 해당하는 실질적 관제 신호입니다.
- **Wazuh 경보 레벨 (0~15):** Zabbix와 상이한 평가 척도를 사용하며, 운영 정책상 레벨 10 이상의 경보만 Slack 알림 대상으로 지정되어 있습니다.

동일한 명칭의 "Warning" 레벨이라도 사내 인프라에서는 노이즈로 분류되고, MSP 인프라에서는 고객 통보용 신호로 처리됩니다. 따라서 단일 심각도 기준의 단순 정렬 패널 구성을 지양하고, 본 정규화 매핑 레이어를 통해 도메인 특성을 반영한 필터링 및 라우팅을 수행합니다.

---

## 2. 통합 심각도(SEV) 정의 및 파이프라인 제어 정책

| SEV 등급 | 명칭 | 정의 및 위험도 | 파이프라인 제어 동작 |
|---|---|---|---|
| **SEV1** | Critical | 즉시 대응 필요 (오탐 가능성 매우 낮음) | Slack 실시간 알림 + 봇 초동 분석 실행 (만성 여부와 무관하게 즉시 통보) |
| **SEV2** | High | 주요 장애 조치 필요 | Slack 실시간 알림 + 봇 초동 분석 실행 (만성 항목은 "만성 N회" 코멘트 첨부하여 메시지 톤 조절) |
| **SEV3** | Moderate | 조사 대상 (즉시 대응성 낮음) | 일일 다이제스트 집계 + 대시보드 표출 (봇 분석은 수동/온디맨드 실행) |
| **SEV4** | Info | 참고용 지표 | 대시보드 표출 전용 |
| **NONE** | — | 시스템 기록 전용 | DB 저장 전용 (알림 및 화면 표출 차단) |

- **만성/신규 장애 상태와의 관계:** 만성/신규 장애 선판정은 SEV 등급과 독립적으로 관리되는 별도 직교 축입니다. SEV는 "위험도 기반 라우팅 경로"를 결정하고, 만성/신규 판정은 "알림 메시지 톤 및 심층 조사 발동 여부"를 제어합니다.
- **MSP 계약 제약 조건:** MSP 환경의 경우 계약 형태에 따른 통제 축(`scope: notify_only | remediate`)이 추가 직교 적용됩니다.

---

## 3. 관측 소스별 매핑 명세

### 3-1. 사내 Zabbix (0~5) ➔ 통합 SEV 매핑

| Zabbix 등급 | 원본 값 | Mapped SEV | 매핑 근거 및 판단 이유 |
|---|---|---|---|
| Disaster | 5 | **SEV1** | Zabbix 공식 스펙 준수 ("Severe incident, immediate action") |
| High | 4 | **SEV2** | Zabbix 공식 스펙 준수 (단, 커스텀 트리거의 39%가 비활성 아이템을 참조하는 정비 미비 상태로 실제 발화 빈도는 낮음) |
| Average | 3 | **SEV3** | Zabbix 공식 스펙 준수 ("Addressed relatively soon") |
| **Warning** | 2 | **SEV4** | **정책적 하향 조정:** 전체 이벤트의 99.5%를 차지하는 노이즈 성격이 강하므로 다이제스트 및 대시보드 전용으로 등급 강등 |
| Information | 1 | **SEV4** | 참고용 데이터 |
| Not classified | 0 | **NONE** | 미분류 항목 |

### 3-2. MSP Zabbix (0~5) ➔ 통합 SEV 매핑 (사내 환경과의 비대칭성)

| Zabbix 등급 | 원본 값 | Mapped SEV | 매핑 근거 및 판단 이유 |
|---|---|---|---|
| Disaster | 5 | **SEV1** | Zabbix 공식 스펙 준수 |
| High | 4 | **SEV2** | Zabbix 공식 스펙 준수 |
| Average | 3 | **SEV3** | Zabbix 공식 스펙 준수 |
| **Warning** | 2 | **SEV3** | **사내 환경과의 차별화:** MSP Warning은 실측상 고른 분포를 보이며 고객 통보 대상에 해당함 (정규화 레이어의 필요성을 입증하는 핵심 항목) |
| Information | 1 | **SEV4** | 참고용 데이터 |
| Not classified | 0 | **NONE** | 미분류 항목 |

### 3-3. Wazuh 룰 레벨 (0~15) ➔ 통합 SEV 매핑

| Wazuh 레벨 | 공식 분류 명세 | Mapped SEV | 매핑 근거 및 판단 이유 |
|---|---|---|---|
| 15 | Severe attack ("No chances of false positives") | **SEV1** | 공식 스펙 준수 (즉시 대응) |
| 14 | High importance security event (상관 분석 기반) | **SEV1** | 공식 스펙 준수 ("Indicating an attack") |
| 12~13 | High importance event / Unusual error | **SEV2** | 고심각 구간 (12~15) 하단 영역 매핑 |
| **10~11** | Multiple user generated errors / Integrity·Rootkit warning | **SEV2** | **기존 관제 정책 유지:** 레벨 10 = 연속 로그인 실패 (Brute-force 시뮬레이션), 레벨 11 = 파일 변조 및 루트킷 탐지 |
| 7~9 | Bad word / First-time-seen / Invalid source | **SEV3** | 보안 연관성 존재하나 단순 확인 대상 |
| 3~6 | 정상 및 저우선순위 이벤트 | **SEV4** | 대시보드 기록용 |
| 0~2 | Ignored / 무관 알림 | **NONE** | 오탐 방지용 명시적 무시 항목 |

*검증 기준:* Slack 실시간 발송 대상(`SEV1` + `SEV2`)은 Wazuh 레벨 10 이상으로 설정되어, 기존 운영 관제 정책의 기준선과 정확히 일치합니다.

---

### 3-4. Wazuh 모듈별 레벨 특성 및 수집 영향도 분석

Wazuh 모듈별로 생성하는 기본 룰 레벨대가 상이하므로 모듈 적용 시 아래와 같은 수집 특성을 고려해야 합니다.

| 관측 모듈 | 대표 룰 ID 및 내용 | 룰 레벨 | Mapped SEV | 컷오프(10) 통과 여부 | 파이프라인 처리 결과 |
|---|---|---|---|---|---|
| **FIM (파일 변경)** | 550 파일 수정 | 7 | SEV3 | 미달 (미통과) | Digest 채널 요약 |
| | 553 파일 삭제 | 7 | SEV3 | 미달 (미통과) | Digest 채널 요약 |
| | 554 파일 추가 | 5 | SEV4 | 미달 (미통과) | 대시보드 전용 기록 |
| **SCA (보안 설정)** | 19007 개별 검사 실패 | 7 | SEV3 | 미달 (미통과) | Digest 채널 요약 |
| | **19011 통과➔실패 (하드닝 회귀)** | **9** | **SEV3** | **미달 (예외 승격)** | **Slack 알림 (예외 승격)** |
| | 19001~19005 스캔 요약 | 3~9 | SEV3·SEV4 | 미달 (미통과) | 대시보드 전용 기록 |
| **취약점 탐지** | 23503 Low | 5 | SEV4 | 미달 (미통과) | 대시보드 전용 기록 |
| | 23504 Medium | 7 | SEV3 | 미달 (미통과) | Digest 채널 요약 |
| | **23505 High** | **10** | **SEV2** | **통과** | **Slack 실시간 알림** |
| | **23506 Critical** | **13** | **SEV2** | **통과** | **Slack 실시간 알림** |

**모듈별 특징 및 처리 지침:**
* **취약점 탐지 모듈:** 룰 레벨이 CVSS 심각도와 직접 연동되어 있어, High(레벨 10) 및 Critical(레벨 13) 항목이 별도 튜닝 없이 컷오프를 통과합니다.
* **FIM 및 SCA 모듈:** 기본 최고 룰 레벨이 각각 7과 9로 구성되어 컷오프(10)를 통과하지 못합니다. (채널 계층화(Digest/Dashboard) 설정이 선행되어야 관측 유효성이 확보됩니다.)
* **주요 예외 처리 (SCA 19011 및 주요 FIM):** 기존 통과하던 검사가 실패로 전환되는 SCA 19011 항목 및 주요 보안 설정 파일(`/etc/passwd`, `sshd_config`) 변경 FIM 이벤트는 규칙 승격을 통해 Slack 실시간 알림으로 처리합니다.

> **운영 원칙:** *"모든 파일 변경을 통보하지 않으며, 보안상 변경이 불가한 핵심 자산 항목만 선별 통보한다 (수집은 광범위하게, 알림은 엄격하게)."*

*(참고: Wazuh 공식 스펙의 "Level 11 = Integrity checking warning"은 레벨 정의 문구이며, 실제 FIM 룰 레벨은 5~7로 할당되어 있습니다.)*

---

## 4. 설계 원칙 및 과도기적 특성

- **과도기 어댑터로서의 역할:** 사내 Zabbix Warning 레벨을 SEV4로 하향 조정한 것은 현재 발생하는 노이즈 알림을 보정하기 위한 임시적 조치입니다. 근본적인 해결은 발행 측(Zabbix 트리거 심각도 재설계)에서 이루어져야 하며, 개선 완료 시 사내 매핑 기준을 MSP 수준으로 복원합니다.
- **심각도 기반 라우팅 신설:** 실측 결과 사내 Zabbix Action에는 심각도 조건이 부여되어 있지 않았으나, 본 정규화 레이어를 통해 SEV 기반의 체계적인 라우팅 제어 계층을 확립합니다.

---

## 5. 참고 공식 문서 및 기준

- [Zabbix 7.0 Trigger Severities 명세](https://www.zabbix.com/documentation/7.0/en/manual/config/triggers/severity)
- [Wazuh Rules Classification 명세 (0~15)](https://documentation.wazuh.com/current/user-manual/ruleset/rules/rules-classification.html)
- 운영 관제 정책: Wazuh 레벨 10 이상 Slack 실시간 통보
- Wazuh 공식 룰셋: `0015-ossec_rules.xml` (FIM), `0570-sca_rules.xml` (SCA), `0520-vulnerability-detector_rules.xml` (취약점) v4.14 태그