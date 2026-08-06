# 심각도 정규화 매핑표

세 시스템이 서로 다른 눈금을 쓰고, **같은 이름이 다른 의미**를 가집니다. 이 표가 그것을 하나의
눈금으로 옮기는 유일한 원본입니다.

> **이 표가 유일 원본입니다(이중 진실 금지).** 게이트웨이 상수(`bot/gateway/severity.py`),
> Grafana 정규화 패널, 봇 프롬프트의 SEV 표기가 전부 여기서 파생됩니다.
> **표를 고칠 때는 문서를 먼저 고치고 코드를 따라오게 합니다.**

## 1. 왜 필요한가

- **사내 Zabbix의 Warning** = 실측상 **노이즈**입니다. Warning이 이벤트의 99.5%를 차지하고
  상위 2개 트리거가 78.6%를 만듭니다. "사람이 볼 신호"가 아닙니다.
- **MSP Zabbix의 Warning** = **신호**입니다. 심각도 분포가 고르고 고객 통보 대상입니다.
- **Wazuh 레벨(0~15)** = 아예 **별개 척도**입니다. 팀 현행 정책은 레벨 10 이상만 Slack 발송입니다.

**같은 "Warning"이 한쪽에선 버릴 것이고 다른 쪽에선 고객에게 보낼 것입니다.** 그래서
"단일 심각도 정렬 패널"이 금지이고, 그 결정의 구현체가 이 매핑입니다.

## 2. 통합 눈금 (SEV) 과 파이프라인 행동

| SEV | 이름 | 의미 | 파이프라인 행동 |
|---|---|---|---|
| **SEV1** | Critical | 즉시 대응 필요, 오탐 가능성 낮음 | Slack 즉시 + 봇 초동 분석. 만성이어도 통보 |
| **SEV2** | High | 조치 필요 | Slack + 봇 초동 분석. 만성이면 "만성 N회" 코멘트로 톤 조절 |
| **SEV3** | Moderate | 조사 대상, 즉시성 낮음 | 일일 다이제스트 + 대시보드. 봇 분석은 온디맨드 |
| **SEV4** | Info | 참고 | 대시보드 표시만 |
| **NONE** | — | 기록만 | 저장만, 어디에도 표출 안 함 |

- **만성/신규 판정은 SEV와 직교하는 별도 축**입니다. SEV는 "얼마나 위험한가"(라우팅 결정),
  만성/신규는 "이미 아는 문제인가"(메시지 톤 결정). **섞지 않습니다.**
- MSP는 여기에 계약 축(`scope: notify_only | remediate`)이 하나 더 직교합니다.

## 3. 소스별 매핑

### 사내 Zabbix (0~5) → SEV

| Zabbix | 값 | SEV | 근거 |
|---|---|---|---|
| Disaster | 5 | SEV1 | 공식 의미("severe incident, immediate action") 그대로 |
| High | 4 | SEV2 | 공식 의미 그대로. 단 커스텀 트리거의 39%가 비활성 아이템을 참조해 발화 불가라, 정비 전까지 High 계층의 실발화가 드묾 |
| Average | 3 | SEV3 | 공식 의미("addressed relatively soon") |
| **Warning** | 2 | **SEV4** | **정책 판단**: Warning이 이벤트의 99.5%를 차지하는 노이즈라 다이제스트·대시보드 전용으로 강등 |
| Information | 1 | SEV4 | |
| Not classified | 0 | NONE | |

### MSP Zabbix (0~5) → SEV — 사내와의 비대칭이 핵심

| Zabbix | 값 | SEV | 근거 |
|---|---|---|---|
| Disaster | 5 | SEV1 | |
| High | 4 | SEV2 | |
| Average | 3 | SEV3 | |
| **Warning** | 2 | **SEV3** | **사내와 다릅니다.** MSP Warning은 실측상 신호(분포가 고르고 고객 통보 대상). **이 한 줄이 정규화 레이어의 존재 증명입니다.** |
| Information | 1 | SEV4 | |
| Not classified | 0 | NONE | |

### Wazuh 룰 레벨 (0~15) → SEV

| Wazuh 레벨 | 공식 분류 | SEV | 근거 |
|---|---|---|---|
| 15 | Severe attack ("no chances of false positives") | SEV1 | 공식: 즉시 대응 |
| 14 | High importance security event (상관 기반) | SEV1 | 공식: "indicates an attack" |
| 12~13 | High importance event / unusual error | SEV2 | 공식 고심각 구간(12~15)의 하단 |
| **10~11** | Multiple user generated errors / integrity·rootkit warning | **SEV2** | **팀 현행 컷라인 보존.** 10 = 연속 로그인 실패(데모 브루트포스가 정확히 여기), 11 = 바이너리 변조·루트킷 |
| 7~9 | bad word / first-time-seen / invalid source | SEV3 | 보안 관련성은 있으나 미분류 다수 |
| 3~6 | 정상·저우선 이벤트 | SEV4 | |
| 0~2 | ignored / 무관 알림 | NONE | 0은 오탐 회피용 명시적 무시 |

검증 포인트: **Slack 발송 대상 = SEV1+SEV2 = Wazuh 레벨 10 이상**으로, 팀 현행 정책과 정확히
일치합니다. **게이트웨이가 기존 정책을 바꾸는 것이 아니라 코드로 명문화하는 것입니다.**

### 3-1. 모듈별 레벨 지형 — 같은 "Wazuh를 켠다"가 정반대 결과를 낳는다

위 표는 레벨만 다룹니다. 그런데 **Wazuh 모듈마다 만들어내는 레벨대가 완전히 다릅니다.**
모듈을 켜기 전에 이 지형을 먼저 봐야 합니다.

| 모듈 | 룰 | 레벨 | SEV | 컷라인(10) | 결과 |
|---|---|---|---|---|---|
| **FIM** | 550 파일 수정 | 7 | SEV3 | 미달 | digest 채널 |
| | 553 파일 삭제 | 7 | SEV3 | 미달 | digest 채널 |
| | 554 파일 추가 | 5 | SEV4 | 미달 | 대시보드만 |
| **SCA** | 19007 개별 검사 실패 | 7 | SEV3 | 미달 | digest 채널 |
| | **19011 통과→실패(하드닝 회귀)** | **9** | SEV3 | 미달 | **승격 대상** |
| | 19001~19005 스캔 요약 | 3~9 | SEV3·SEV4 | 미달 | 대시보드만 |
| **취약점** | 23503 Low | 5 | SEV4 | 미달 | 대시보드만 |
| | 23504 Medium | 7 | SEV3 | 미달 | digest 채널 |
| | **23505 High** | **10** | **SEV2** | **통과** | Slack |
| | **23506 Critical** | **13** | **SEV2** | **통과** | Slack |

**읽는 법 — 세 모듈이 서로 다른 문제를 갖습니다.**

- **취약점만 이미 맞게 설계돼 있습니다.** 룰 레벨이 CVSS 심각도를 따라가고 High가 정확히
  10이라, 팀 컷라인이 자동으로 High·Critical만 통과시킵니다. **튜닝할 것이 없습니다.**
- **FIM과 SCA는 최고 레벨이 각각 7과 9라 컷라인을 못 넘습니다.** 즉 켜도 사람에게 아무것도
  안 보입니다. **문제는 폭증이 아니라 소실입니다.** 이것이 채널 계층화(digest·dashboard_only)가
  Wazuh 고도화의 **선행 조건**인 이유입니다.
- 예외로 **SCA 19011(통과하던 검사가 실패로 돌아섬)** 하나만 의도적으로 승격해 Slack에
  보냅니다. 랩 실측상 현재 0건이라 켜도 조용하고, **하드닝이 풀리는 순간에만** 울립니다.
  FIM도 `sshd_config`·`/etc/passwd` 변경만 같은 방식으로 승격합니다.

> **원칙: 모든 파일 변경을 알리지 않는다. 바뀌면 안 되는 것 몇 개만 알린다.**
> — "수집은 넓게, 알림은 좁게"

**주의 — 레벨 11에 대한 오해.** 공식 분류표의 "11 = integrity checking warning"은 레벨의
**의미 설명**이지 FIM 룰의 실제 레벨이 아닙니다. 실제 FIM 룰은 5~7입니다. 이 혼동 때문에
"FIM을 켜면 Slack이 터진다"고 **잘못 판단했던 이력이 있고**, 룰셋 원문 대조로 정정했습니다.

근거: 공식 룰셋 `ruleset/rules/0015-ossec_rules.xml`(FIM), `0570-sca_rules.xml`(SCA),
`0520-vulnerability-detector_rules.xml`(취약점) v4.14 태그 원문.

## 4. 설계 원칙

- **이 매핑은 과도기 어댑터입니다.** 사내 Warning을 SEV4로 강등하는 것은 현행 노이즈에 대한
  보정이지 옳은 최종 상태가 아닙니다. 근본 해결은 **발행 측**(트리거 심각도 재설계)이고,
  그것이 끝나면 사내 매핑을 MSP와 동일하게 회복합니다. **"실환경을 못 바꾸는 PoC가 소비
  측에서 보정하는 장치"** 라는 점을 숨기지 않습니다.
- **없던 계층을 신설하는 것입니다.** 실측상 사내 활성 Slack 액션에는 심각도 조건이 아예
  없고 호스트그룹 조건만 있습니다. SEV 기반 라우팅은 현행에 존재하지 않던 층입니다.

## 5. 근거 (공식 문서)

- [Zabbix 7.0 트리거 심각도 0~5](https://www.zabbix.com/documentation/7.0/en/manual/config/triggers/severity)
- [Wazuh 룰 레벨 분류 0~15](https://documentation.wazuh.com/current/user-manual/ruleset/rules/rules-classification.html)
- 팀 정책 "Wazuh 레벨 10 이상 Slack" — 팀 현행 운영 기준
- 사내/MSP 심각도 분포 — 실환경 정찰 실측(비공개 보관, 이 문서에는 비율만 인용)
