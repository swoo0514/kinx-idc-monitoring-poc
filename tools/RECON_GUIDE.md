# Zabbix 읽기 전용 정찰 도구 가이드 (tools/)

본 디렉토리는 운영 중인 Zabbix 모니터링 시스템의 인프라 변경 없이, API를 통해 감시 설정 현황 및 알림 발화/통보 지표를 객관적으로 정찰하기 위한 전용 스크립트 모음입니다.

*(본 문서는 도구의 사용법 및 기술 사양만을 기술하며, 실행 결과 수치 및 실환경 데이터는 보관 규약에 따라 본 문서에 포함하지 않습니다.)*

---

## 1. 보안 및 안전 규약 (Read-Only Policy)

운영 관제 시스템에 대한 무단 설정 변경은 인프라 장애를 유발할 수 있으며 변경 이력 추적을 저해합니다. 따라서 본 도구 세트는 읽기 전용 API(`.get` 계열)만을 호출하도록 구현되었습니다.

- **CUD API 호출 철저 차단:** `*.create`, `*.update`, `*.delete` 등 변경/삭제 계열 API를 일절 호출하지 않습니다.
- **최소 권한 원칙(Least Privilege) 적용:** 읽기 권한(Read-only)만 부여된 전용 계정의 API 토큰 사용을 권장합니다.
- **예외 처리 및 부분 결과 출력 지원:** 특정 API(액션 라우팅 등)에 대한 권한 부족으로 호출이 실패하더라도, 전체 스크립트가 중단되지 않고 가용 권한 범위 내 결과를 정상 출력하도록 비상 포획(Exception Catch) 처리되었습니다.

> **[참고]**  
> 게이트웨이 수집 모듈(`bot/gateway/collector.py`) 역시 동일한 원칙이 적용되어, 소스 코드 수준에서 `.get` 외의 API 호출을 거부하도록 구현되어 있습니다.

---

## 2. 사전 준비 및 환경변수 설정

본 스크립트 세트는 타사 라이브러리 의존성 없이 **Python 표준 라이브러리(3.6 이상)**만으로 구동되므로 대상 환경에서 즉시 실행이 가능합니다. Zabbix 5.0~7.x 버전을 자동 감지하며, 6.4 이상 버전에서는 `Authorization: Bearer` 토큰 인증 방식을 적용합니다.

### 토큰 발급 경로
Zabbix Web UI ➔ User settings (또는 Administration) ➔ **API tokens** ➔ Create API Token (읽기 전용 권한 계정으로 발급)

### 환경변수 설정

```bash
# Linux / macOS (Bash)
export ZABBIX_URL="https://<ZABBIX_HOST_IP>/zabbix"     # /api_jsonrpc.php 경로 생략 가능
export ZABBIX_TOKEN="<READ_ONLY_API_TOKEN>"
```

```powershell
# Windows (PowerShell)
$env:ZABBIX_URL="https://<ZABBIX_HOST_IP>/zabbix"
$env:ZABBIX_TOKEN="<READ_ONLY_API_TOKEN>"
```

* 사설 CA 또는 자체 서명 인증서 환경에서는 `--insecure` CLI 옵션을 추가하여 SSL 검증을 우회합니다.
* 다중 관측 대상 인프라 검증 시, URL 및 Token 환경변수를 교체하여 개별 실행합니다.

---

## 3. 스크립트별 세부 사양 및 실행 가이드

### 3-1. `zabbix_snapshot.py` — 구성 및 알림 현황 스냅샷

관측 대상 호스트 구성 및 장애 알림 발화 통계를 포함한 전체 현황을 집계합니다.

```bash
python3 zabbix_snapshot.py --days 30 --top 20 -o snapshot.md
```

- **집계 항목:** 호스트 그룹별 호스트 수, 템플릿 연동 현황(아이템/트리거 수), 최근 N일간 Problem 이벤트의 심각도 분포, 최다 발화 트리거 Top N (Zabbix Reports ➔ Top 100 Triggers 상응)
- **주요 옵션:**
  - `--deep`: 템플릿 외 커스텀 아이템, 트리거 조건식, 매크로 오버라이드 항목 상세 수집
  - `--mask REGEX`: 고객사명, 호스트 그룹명 등 민감 식별자 마스킹 적용
  - `--days`: 집계 대상 과거 기간 (일) / `--top`: 상위 출력 건수

> **[마스킹 적용 시 유의사항]**  
> `--mask` 정규식에 지정된 패턴만 가명화 처리되므로, 호스트명 또는 지표 내 포함된 IP/고객사명이 누락되지 않았는지 최종 출력물(`snapshot.md`)을 반드시 확인합니다.

---

### 3-2. `zabbix_serverstats.py` — 인프라 수집 규모 및 라우팅 정찰

Zabbix 서버 성능 지표, 프록시 토폴로지, 알림 액션 라우팅 내역을 API로 정찰합니다.

```bash
python3 zabbix_serverstats.py -o serverstats.md
```

- **NVPS (New Values Per Second):** `zabbix[requiredperformance]`, `zabbix[wcache,values*]` 내부 지표 기반 성능 측정
- **프록시 집계:** `proxy.get` API 기반 분산 프록시 할당 현황 파악
- **액션 라우팅 및 통보 건수:** `action.get` 및 `alert.get` API를 통해 최근 N일간 실제 발송된 알림 건수, 성공/실패 수치, 미디어 타입별 실적 집계

> **[분석 기술적 의의]**  
> Zabbix UI 상에 표출되는 "Problem 이벤트 발생 건수(트리거 발화 횟수)"와 "실제 외부로 통보된 수치(Alert Sent Count)"는 액션 조건 필터링에 의해 큰 차이가 발생합니다. 정밀 진단을 위해 두 지표를 명확히 구별하여 분석합니다.

---

### 3-3. `zabbix_alert_crosscheck.py` — 알림 발송 결과 교차 검산

`serverstats` 지표 중 외부 발송 결과를 미디어 타입 및 실패 사유별로 정밀 교차 검증합니다.

```bash
python3 tools/zabbix_alert_crosscheck.py --days 30
```

- 미디어 타입 × 전송 상태(Status) 교차표 생성
- 실패 사유(`error` 필드) 정밀 분석 (미디어 비활성화, 스크립트 실행 에러, 네트워크 타임아웃 구별)
- 미디어별 최초/최종 발송 시도 타임스탬프 산출 (통보 파이프라인 단락 시점 식별)

*(주의: Zabbix `alert` 객체의 `error` 필드 내에 스크립트 실행 오류 로그 및 웹훅 URL 등 자격 증명이 포함될 수 있으므로, 결과 파일은 gitignore 대상인 `private/` 디렉토리에 보관합니다.)*

---

### 3-4. `zabbix_mediatype_check.py` — 통보 미디어 파이프라인 판별

```bash
python3 tools/zabbix_mediatype_check.py
```

등록된 미디어 타입의 연동 유형(Email, Script, SMS, Webhook) 및 활성화 상태를 일단위 조회합니다. Slack 통보가 표준 Webhook 방식이 아닌 커스텀 Script 방식으로 연동되어 있는지 여부를 사전 판별하여 통보 이력 로그의 파싱 경로를 확정합니다.

---

### 3-5. `zabbix_replication_check.py` — DB 복제 감시 깊이 판별

DB 복제 모니터링이 단순 프로세스 생존 여부(Status 1/0)에 그치는지, 실질적인 복제 지연 시간(`Seconds_Behind_Master`)까지 관측하는지 정밀 평가합니다.

```bash
python3 zabbix_replication_check.py --history -o repl_check.md
```

- **판별 기준:** 수집 지표 단위가 `s`(초)이거나 가변 시계열 수치인 경우 ➔ **지연 시간 관측**, 지표값이 0/1 정수로 고정된 경우 ➔ **단순 상태 관측**
- 호스트 직접 정의 커스텀 아이템과 공식 템플릿 상속 아이템의 출처 구별 표출

---

## 4. 정찰 수행 순서 및 데이터 처리 지침

인프라 정찰 시 아래의 표준 순서를 준수합니다:

```text
1. zabbix_snapshot.py      (전체 구성 및 Problem 발화 스냅샷 수집)
         │
         ▼
2. zabbix_mediatype_check.py (알림 통보 수단 및 연동 유형 확정)
         │
         ▼
3. zabbix_serverstats.py   (수집 규모, 액션 조건, 실제 발송 건수 집계)
         │
         ▼
4. zabbix_alert_crosscheck.py (미디어별 발송 성공/실패 사유 교차 검산)
         │
         ▼
5. zabbix_replication_check.py (특정 핵심 지표의 감시 깊이 정밀 평가)
```

> **[데이터 정합성 유지 원칙]**  
> 보고서 작성 시 수치 지표와 함께 **조회 기간 창(Time Window, 예: 최근 30일)**을 반드시 명시합니다. 데이터 원본의 재현성을 보장하기 위해 정찰 스크립트 실행 원시 결과 파일을 함께 보관합니다.

---

## 5. 정찰 산출물 보안 관리 규약

본 정찰 스크립트의 산출물(Markdown 및 JSON 파일)에는 실제 호스트명, IP 주소, 고객사 식별 정보가 포함되므로 **Git 공용 저장소 커밋을 엄격히 금지**합니다.

- 산출물 저장 경로: `private/` 디렉토리 하위 (Git 버전 관리 제외 대상)
- 문서/발표자료 인용 시: 절대 수치는 제외하고 **비율(%), 패턴, 아키텍처 구조** 중심으로 변환하여 인용
- 데이터 재현성 확보: 도구 출력 원시 데이터를 사내 보안 스토리이에 보존

---

## 6. 프로비저닝 및 리포트 생성 유틸리티 (`lab/` 전용)

아래 스크립트들은 조회가 아닌 Zabbix/Grafana **설정 생성(Write) API**를 호출하므로, 실환경에 적용하지 않고 **실험 인프라(랩) 환경에서만 사용**합니다.

| 스크립트명 | 담당 역할 및 주요 기능 |
|---|---|
| `zabbix_report_dashboard.py` | MSP 리포트용 Zabbix 대시보드 및 Trapper 아이템 자동 생성 |
| `gen_msp_report_dashboard.py` | MSP 리포트용 Grafana 대시보드 매니페스트(JSON) 자동 생성 |

*(상세 실행 가이드 및 안전 가드는 [`ansible/DEPLOY_GUIDE.md`](../ansible/DEPLOY_GUIDE.md)의 MSP 월간 리포트 절을 참조합니다.)*