# 알림 게이트웨이 기술 명세서 (데모 B·C 공용)

## 1. 시스템 개요 및 위치

본 모듈은 사내 및 MSP Zabbix, Wazuh 관측 시스템의 알림 데이터를 단일 접점에서 수집하여 **통합 심각도 정규화(SEV) ➔ 멱등성 검증 ➔ 태그 기반 라우팅**을 전담하는 공용 알림 게이트웨이(Egress Gateway)입니다. AI 기반 초동 분석(데모 C) 및 승인 기반 자가 치유 파이프라인(데모 B)의 공통 백엔드로 동작합니다.

```text
Zabbix Webhook Media Type ─┐
                           ├─▶ [통합 게이트웨이] 토큰 검증 ➔ 멱등성 검사 ➔ SEV 정규화 ➔ 태그 라우팅
Wazuh Integrator ──────────┘                                            │
                                 ┌──────────────────────────────────────┴──────────────────────────────────────┐
                                 ▼                                      ▼                                      ▼
                      triage (데모 C 트리아지)               remediate (데모 B 자가 치유)                digest / dashboard_only
```

---

## 2. 파일 구조 및 구성 모듈

| 파일 경로 | 주요 역할 및 담당 기능 |
|---|---|
| `gateway/app.py` | FastAPI 웹 애플리케이션 — REST 엔드포인트 제공, 토큰 검증, 멱등성 처리, 비동기 디스패치 |
| `gateway/severity.py` | 통합 심각도 정규화 상수 정의 — [`severity-normalization.md`](../docs/02-design/severity-normalization.md)의 코드 구현체 |
| `gateway/router.py` | 태그 기반 라우팅 로직 — `automate`, `scope` 태그 조합을 통한 처리 경로 분기 |
| `gateway/selftest.py` | 파이프라인 순수 제어 로직 독립 검증 모듈 (FastAPI 의존성 없이 실행) |
| `gateway/zabbix_media_webhook.js` | Zabbix 서버에 등록하는 Webhook 미디어 타입 연동 스크립트 |
| `gateway/collector.py` | Zabbix, Loki, Wazuh 텔레메트리 데이터 비동기 교차 수집기 |
| `gateway/prejudge.py` | 과거 90일 발생 이력 기반 결정론적 만성/신규 장애 선판정 모듈 |
| `gateway/incident.py` | (호스트, 알림 유형) 기반 디바운스 창 제어 및 알림 병합(Incident Merging) 모듈 |
| `gateway/llm.py` | Claude/Ollama LLM 어댑터 및 양방향 가명화(Masking) 파이프라인 |
| `gateway/slack.py` | Slack Block Kit 기반 알림 카드 및 트리아지 결과 회신 모듈 |
| `gateway/triage.py` | 수집 ➔ 가명화 ➔ LLM 연산 ➔ Slack 회신 전체 파이프라인 오케스트레이터 |

---

## 3. 실행 및 검증 방법

```bash
# bot/ 디렉토리 이동 및 가상환경 설정
cd bot
source ~/bot-venv/bin/activate
pip install -r requirements.txt

# 게이트웨이 인증 토큰 설정 (코드 내 하드코딩 금지)
export GATEWAY_TOKEN="<임의의_긴_랜덤_문자열>"

# 게이트웨이 데몬 기동 (단일 Worker 프로세스로 실행)
python -m uvicorn gateway.app:app --host 0.0.0.0 --port 8800
```

### 독립 검증 명령

```bash
# 순수 로직 단위 테스트 실행 (2026-07-26 기준 29건 전체 통과)
python -m gateway.selftest

# 헬스체크 엔드포인트 호출 검증
curl http://localhost:8800/healthz
```

---

## 4. REST API 엔드포인트 명세

### 4-1. POST `/webhook/zabbix`

Zabbix 웹훅 액션으로부터 알림 데이터를 수신합니다 (헤더 `X-Gateway-Token` 인증 필수).

**요청 페이로드 예시:**
```json
{
  "source": "zabbix-internal",
  "event_id": "12345",
  "event_value": 1,
  "event_name": "Filesystem /data usage is high on lab-web01",
  "nseverity": 4,
  "host": "lab-web01.novalocal",
  "tags": [
    {"tag": "automate", "value": "service_restart"},
    {"tag": "scope", "value": "full"}
  ]
}
```

**응답 페이로드 예시 (신규 수신):**
```json
{
  "status": "accepted",
  "sev": "SEV2",
  "route": "remediate",
  "playbook": "service_restart"
}
```

**응답 페이로드 예시 (중복 수신):**
```json
{
  "status": "duplicate"
}
```
*(동일 `(source, event_id, event_value)` 조합 수신 시 HTTP 200 `duplicate`를 반환하여 Zabbix의 불필요한 재전송을 즉시 중단시킵니다.)*

### 4-2. POST `/webhook/wazuh`

Wazuh Manager 커스텀 연동 스크립트로부터 경보 데이터를 수신합니다. (`alert_id`, `rule_id`, `rule_level`, `agent_name` 전달)

---

## 5. Zabbix 미디어 타입 배선 명세

Zabbix Administration ➔ Media types ➔ Create Media Type: Type = **Webhook**, Script = `zabbix_media_webhook.js`

### 설정 파라미터 매핑표

| 파라미터 명칭 | 설정값 (Zabbix 매크로) | 검증 상태 및 비고 |
|---|---|---|
| `gateway_url` | `http://<게이트웨이_IP>:8800` | 환경별 IP 지정 |
| `token` | `{$GATEWAY_TOKEN}` | DB 저장 파라미터 |
| `source` | `zabbix-internal` 또는 `zabbix-msp` | 소스 구별 매크로 |
| `event_id` | `{EVENT.ID}` | 공식 매크로 검증 완료 |
| `nseverity` | `{EVENT.NSEVERITY}` | Numeric event severity 매크로 검증 완료 |
| `event_name` | `{EVENT.NAME}` | 공식 매크로 검증 완료 |
| `tags_json` | `{EVENT.TAGSJSON}` | JSON Array event tags 매크로 검증 완료 |
| `host` | `{HOST.HOST}` | FQDN 호스트명 매크로 검증 완료 |
| `event_value` | `{EVENT.VALUE}` | 장애(1)/해소(0) 구분 매크로 |

---

## 6. 핵심 아키텍처 의사결정 및 기술적 근거

1. **`severity.py` 단일 구현체 적용 (Single Source of Truth):**  
   사내 Zabbix Warning ➔ `SEV4` (노이즈 강등), MSP Warning ➔ `SEV3` (고객 통보 신호 유지), Wazuh 레벨 10+ ➔ `SEV2` 정규화 규칙을 코드 수준에서 엄격히 보장합니다.
2. **미지 소스 및 예외 상태의 페일세이프(Fail-safe) 정규화:**  
   미정의 소스 또는 스펙 범위를 벗어난 데이터 수신 시 과소평가로 인한 장애 누락을 방지하고자 `SEV2`로 상향 정규화합니다.
3. **상수 시간 비교를 통한 타이밍 공격 차단 (`hmac.compare_digest`):**  
   인증 토큰 비교 시 단순 `==` 연산자 대신 `hmac.compare_digest`를 적용하여 타이밍 부채널(Timing Side-channel) 공격 위험을 차단합니다.
4. **인메모리 1시간 TTL 멱등성 버퍼 연산:**  
   동일 알림 재전송 시 중복 LLM API 호출 및 중복 Slack 카드 발송을 차단합니다. (프로덕션 환경 적용 시 Redis/DB 지속화 스토리지로 마이그레이션 추진)
5. **계약 조건의 코드화 (`scope` 우선순위 제어):**  
   트리거에 `automate` 태그가 존재하더라도 위탁 계약 속성이 `scope=notify_only`일 경우, `router` 단에서 자동 조치 경로 진입을 차단하고 `triage` 경로로 강제 라우팅합니다.

---

## 7. 컨텍스트 수집기 및 선판정 로직 (`collector.py` / `prejudge.py`)

트리아지 경로 진입 시 LLM 연산에 필요한 재료 데이터를 3개 소스로부터 비동기 교차 수집하고 결정적 선판정을 수행합니다.

### 7-1. 교차 소스 텔레메트리 수집 (Multi-source Context Collection)

- **Loki (로그 축):** `/loki/api/v1/query_range` 엔드포인트를 통해 `{host=~"<host>.*"}` 조건으로 최근 15분간의 로그 최대 40줄(라인당 300자 제한)을 수집합니다.
- **Wazuh (보안 축):** OpenSearch `wazuh-alerts-*/_search` 엔드포인트를 통해 `agent.name` 조건으로 최근 15분간 발생한 보안 경보 최대 20건을 수집합니다.
- **조회 실패 및 미배선 처리:** API 호출 실패 시 예외를 삼키지 않고 `sources` 메타데이터에 `unavailable` 상태를 기록하여, 거짓 안심(False Confidence) 기반 분석을 차단합니다.

### 7-2. Zabbix API 읽기 전용 5종 병렬 조회

1. `event.get`: 현재 이벤트 상세 및 태그 수집
2. `trigger.get`: 트리거 조건식 및 메트릭 역참조 정보 수집
3. `item.get` ➔ `history.get`: 관련 메트릭 최근 1시간 수치 추이(20개 데이터 포인트) 수집
4. `event.get` (90일 창): 동일 트리거의 과거 누적 발생 이력 조회 (선판정 연산 입력값)
5. `host.get`: 호스트 메타데이터 및 그룹 정보 수집

*①~④ 항목은 `asyncio.gather`를 통해 병렬 호출되며, 개별 콜 타임아웃을 5초로 제한하여 30초 처리 예산 내 구동을 보장합니다.*

### 7-3. 결정적 만성/신규 선판정 규칙 (`prejudge.py`)

과거 90일간 동일 트리거의 누적 발생 횟수를 바탕으로 결정론적 판정을 내리며, LLM이 이를 재판정하거나 변경할 수 없습니다.

| 최근 90일 발생 횟수 | 최종 판정 | LLM 회신 톤 및 출력 메시지 |
|---|---|---|
| 0회 | **신규 (New)** | *"처음 관측된 미지 장애 — 즉시 원인 확인 권장"* |
| 1~4회 | **재발 (Recurrent)** | *"최근 90일 내 N회 재발된 장애 — 이전 발생 건과의 공통점 점검"* |
| 5회 이상 | **만성 (Chronic)** | *"알려진 만성 반복 장애 (90일간 N회 발생) — 정비 대상 항목"* |

---

## 8. 알림 병합 메커니즘 (`incident.py`)

### 8-1. 알림 병합 및 브리지 규칙 (Incident Merging & Bridge Rules)

단일 알림 단위 트리아지의 한계를 극복하기 위해 동일 호스트 및 연관 유형의 알림들을 디바운스 창(Debounce Window) 동안 수집하여 **단일 인시던트로 병합 처리**합니다.

- **기본 병합 키:** `incident_key(host, class) = (host, bridge_id(class))`
- **연관 브리지 규칙 (`BRIDGE_GROUPS`):**
  - `{replication, cpu_io_pressure}`: DB 복제 지연 알림과 CPU/IO 자원 경합 알림을 단일 사건으로 병합
  - `{disk_space, service_down}`: 디스크 용량 초과 알림과 서비스 중단 알림을 단일 사건으로 병합
  - `auth_security` (보안 경보) 항목은 브리지 그룹에 포함하지 않고 항상 독립 사건으로 격리 처리합니다.

### 8-2. 디바운스 창 제어 (Debounce Window Control)

- **일반 디바운스 대기:** 마지막 알림 수신 후 `INCIDENT_DEBOUNCE_S`(기본 90초) 동안 추가 알림이 없을 경우 인시던트 마감
- **최대 창 허용 시간:** 알림이 지속 수신되더라도 `INCIDENT_MAX_WINDOW_S`(기본 300초) 도달 시 강제 마감 및 트리아지 실행
- **우선순위 단축 대기:** `SEV1` 알림 포함 시 `INCIDENT_PRIORITY_DEBOUNCE_S`(기본 15초)로 대기 시간 단축

---

## 9. 실시간 원시 알림 표출 (Fast-Path Pipeline)

디바운스 창 마감 대기 시간으로 인한 초동 통보 지연을 방지하기 위해 **원시 알림 Fast-Path 파이프라인**을 제공합니다.

```text
알림 수신 ──▶ [0초] 원시 알림 카드 즉시 게시 (Slack 최상위 메시지)
   │
   ├─▶ 후속 알림 수신 ──▶ 동일 Slack 스레드 답글로 추가 표출
   │
   └─▶ 디바운스 창 마감 ──▶ LLM 초동 분석 결과를 동일 스레드 답글로 최종 회신
```

인시던트 버퍼 생성 시 최상위 Slack 메시지를 즉시 생성하고, 이후 수집되는 알림 및 최종 LLM 분석 결과를 해당 메시지의 스레드(Thread) 답글로 병합하여 메시지 파편화를 방지합니다.

---

## 10. HolmesGPT 심층 조사 연동 (`holmes.py`)

선판정 결과를 활용하여 분석 가치가 높은 미지 장애 및 긴급 장애에 심층 조사 리소스를 효율적으로 배분합니다.

### 심층 조사 발동 순서 및 조건

1. `scope=notify_only` 및 마스킹 미배치 조건 ➔ **발동 차단** (보안 유출 방지)
2. `SEV1` 긴급 장애 ➔ **무조건 발동**
3. 게이트웨이 1차 분석 열화(`degraded`) 상태 ➔ **무조건 발동** (분석 품질 보완)
4. 선판정 결과 **만성 (Chronic)** 장애 ➔ **억제** (기지 장애에 대한 리소스 남용 방지)
5. 선판정 결과 **신규 (New)** 장애 ➔ **우선 발동** (정보 이득 극대화)
6. 복수 알림 병합 사건 ➔ **발동**

심층 조사 결과는 신규 알림 카드를 생성하지 않고, 1차 분석 결과가 게시된 **Slack 스레드의 답글 및 Keep 인시던트 Note 항목**에 비동기(`asyncio.create_task`)로 첨부됩니다.

---

## 11. 자가 치유 조치 후보 경로 연동 (`router.py` / `keep.py`)

트리거 내 `automate` 태그가 정의되고 계약 제약이 없는 경우, 게이트웨이는 알림을 `remediate` 경로로 라우팅하고 Keep 승인 큐에 등록합니다.

```text
Zabbix 트리거 (automate=service_restart)
  │
  ▼
게이트웨이 라우팅 (route=remediate) ──▶ Keep 승인 큐 등록 (상태: 승인 대기)
                                               │
                                      [관제 담당자 승인 클릭]
                                               │
                                               ▼
                                   Keep 워크플로 실행 ➔ Ansible 플레이북 실행 ➔ 상태 재검증
```

### Keep 워크플로 동적 매크로 연동

Ansible 실행 파라미터 하드코딩을 제거하고, Keep 알림 객체의 동적 필드를 매핑하여 플레이북을 호출합니다:
- `target_host`: `{{ alert.host }}`
- `service_name`: `{{ alert.service }}`
- `playbook_name`: `{{ alert.playbook }}`

워크플로 시작부에 `if: "'{{ alert.playbook }}' == 'service_restart'"` 안전 게이트를 배치하여, 지정된 플레이북 외의 무단 실행을 차단합니다.

---

## 12. 교차 소스 조회 상태 계약 (Source Status Contract)

수집기(`collector.py`)의 외부 API 조회 연산 결과를 3가지 명시적 상태로 구분하여 데이터 부재에 따른 오판을 차단합니다.

| 수집 상태 (`sources`) | 정의 및 상태 의미 | LLM 분석 및 프롬프트 해석 지침 |
|---|---|---|
| `ok` | API 정상 조회 완료 | 데이터 부재 시 **"이상/침해 흔적 없음"**으로 판정 가능 |
| `unavailable` | API 연동 실패 또는 라벨 불일치 | 데이터 부재 시 **"조회 실패에 따른 미상 상태"**로 명시 (안심 단정 금지) |
| `disabled` | 미연동 설정 상태 | 해당 관측 축 분석 대상에서 제외 |

수집 상태 정보는 마스킹 파이프라인을 거쳐 LLM 프롬프트 및 Slack 알림 카드 배지(⚠️ 조회 실패 배지)로 전파되어, 시스템 장애 상황에서의 거짓 안심(False Confidence) 발생을 차단합니다.