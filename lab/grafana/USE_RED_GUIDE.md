# Grafana USE / RED 대시보드 표준 구성 명세서

본 문서는 발표 장표(Grafana 고도화 ① — 대시보드 표준화) 생성을 위한 대시보드 구성 절차이자, 통합 관제 환경의 가시성 표준으로 활용하기 위한 기술 명세서입니다. 대시보드 구성 완료 후 산출물 JSON은 `lab/grafana/provisioning/dashboards/json/kinx-use-red.json` 경로에 반영하여 Git 기반으로 관리합니다.

> **[참조 스펙 및 공식 가이드 (2026-08-03 검증)]**
> - [Grafana Official Dashboard Best Practices — USE/RED Definition](https://grafana.com/docs/grafana/latest/dashboards/build-dashboards/best-practices/)
> - [Grafana Zabbix Plugin Documentation — Query Editor & Template Variables](https://grafana.com/docs/plugins/alexanderzobnin-zabbix-app/latest/)

---

## 1. 관측 방법론 근거 (USE vs RED)

- **USE 프레임워크 (자원/하드웨어 관점):**
    - **U (Utilization):** 자원이 작업에 투입되어 사용 중인 시간 비율 (%)
    - **S (Saturation):** 처리되지 못하고 대기열(Queue)에 밀린 작업의 양 (Node Load, Queue Length)
    - **E (Errors):** 자원 레벨에서 발생한 오류 이벤트 수
    - *적용 대상:* CPU, 메모리, 디스크 I/O, 네트워크 인터페이스 등 인프라 하드웨어 레이어
- **RED 프레임워크 (서비스/애플리케이션 관점):**
    - **R (Rate):** 초당 요청 수 (Requests / Traffic Volume)
    - **E (Errors):** 처리 실패한 요청 수 (HTTP 5xx, DB Error Rate)
    - **D (Duration):** 요청 처리에 소요된 시간 (Response Time, Latency)
    - *적용 대상:* 웹 서비스, API, DB 서비스 등 애플리케이션 및 트랜잭션 레이어
- **가시성 표준 구성 원칙:**
    - **USE는 장애의 근본 원인(Cause)을, RED는 사용자가 체감하는 증상(Symptom)을 표출합니다.**
    - **장애 알림 임계치는 RED 대시보드에 설정하는 것을 원칙으로 합니다 (증상 기반 알림 수립 원칙).**
- **시나리오 연계:**  
  데모 C(DB 복제 지연 시나리오)는 **RED 관점의 증상(복제 지연 시간 급증)**과 **USE 관점의 원인(CPU 사용률 95~98%, Load Average 5.25)**이 명확히 결합된 사례이며, 분석 봇이 두 관점의 신호를 단일 인시던트로 통합 병합합니다.

---

## 2. Zabbix 패널 쿼리 에디터 설정 필드 명세

Grafana 내 Zabbix 데이터소스 쿼리 에디터 구성 필드별 정의 및 적용 기준은 다음과 같습니다.

| 쿼리 필드 | 필드 정의 및 역할 | 본 표준 대시보드 설정값 |
|---|---|---|
| **Query Mode** | 조회할 데이터의 유형 지정 (Metrics, Text, Services, Item ID, Triggers, Problems, User macros) | **Metrics** (전체 시계열 패널 공통) |
| **Group** | 수집 호스트가 속한 Zabbix 호스트 그룹 필터 (`/정규식/` 및 템플릿 변수 지원) | 랩 대상 호스트 그룹 선택 (`/정규식/` 지정 가능) |
| **Host tag** | Zabbix 5.4+ 호스트 객체 태그 필터 (Exists/Equals/Contains 연산 지원) | **비움 (미사용)** *(참고: 인시던트 분류 태그 및 `automate`/`scope` 태그는 아이템/트리거 태그이므로 호스트 태그와 분리됨)* |
| **Host** | 대상 호스트 필터 (`/정규식/` 및 템플릿 변수 지원, 단순 문자열 입력 시 완전 일치 매칭) | **`$host`** (템플릿 변수 참조) |
| **Item tag** | Zabbix 5.4+ 아이템 객체 태그 필터 (구 Application 필드 대체) | **비움** (특정 아이템 범주 정제 시에만 선별 적용) |
| **Item** | 조회 대상 아이템명 필터 (`/정규식/` 및 템플릿 변수 지원, 미감싸기 시 완전 일치 매칭) | 드롭다운 내 대상 아이템 선택 (§4 패널 명세 참조) |
| **Functions** | 수집 지표 후처리 연산 함수 추가 (`+` 버튼: `rate`, `delta`, `scale`, `groupBy`, `movingAverage` 등) | 카운터(누적값) 아이템에 한해 **`delta` 또는 `rate`** 함수 적용하여 초당 변화량으로 변환 |
| **Options ➔ Trends** | 트렌드(Trends) 테이블 참조 제어 (Default / True / False) | **Default** (장기 수집 지표 조회 시 `useTrends=false` 지정) |
| **Options ➔ Show disabled items** | Zabbix 비활성 아이템 드롭다운 표출 여부 | Default (Off) |
| **Options ➔ Use Zabbix value mapping** | Zabbix 쪽에 정의된 값 매핑(예: 1=Up) 적용 여부 | Default (On) |
| **Options ➔ Disable data alignment** | 수집 주기에 맞춘 시계열 데이터 정렬 비활성화 여부 | Default (Off) |

---

## 3. 대시보드 템플릿 변수 (`$host`) 구성 절차

1. 새 대시보드 생성 ➔ 우측 상단 톱니바퀴 버튼(**Dashboard settings**) 클릭 ➔ **Variables** ➔ **New variable** 선택
2. 변수 속성 설정:
    - **Name:** `host` (패널 쿼리 내 `$host` 구문으로 참조)
    - **Type:** `Query`
    - **Data source:** `Zabbix`
    - **Query type:** `Host`
    - **Group:** 랩 관측 대상 호스트 그룹 지정
    - **Host:** `/.*/` (그룹 내 전체 호스트 정규식 매칭)
    - **Multi-value / Include All:** **Option Enabled** (복수 선택 시 Zabbix 플래그가 자동 정규식 구문으로 전환)
3. **Run query** 실행 후 하단에 호스트 목록 정상 추출 여부 확인 ➔ **Apply** 클릭
4. **검증:** 대시보드 상단 `$host` 드롭다운 변경 시 전체 패널의 지표가 동적으로 변경되는지 확인

---

## 4. 대시보드 패널 레이아웃 및 지표 매핑 명세

대시보드 내 2개의 Row를 생성하고 아래와 같이 패널 6개를 배치합니다.
- **Row 1:** `USE — 서버 자체 (자원 레이어)`
- **Row 2:** `RED — 서버 수행 작업 (요청/서비스 레이어)`

```text
+-----------------------------------------------------------------------------------+
| Row 1: USE — 서버 자체 (자원 레이어)                                              |
| +-----------------------+ +-----------------------+ +---------------------------+ |
| | U · CPU 사용률 (%)    | | S · Load Average (1m) | | E · 인터페이스 에러/초    | |
| +-----------------------+ +-----------------------+ +---------------------------+ |
+-----------------------------------------------------------------------------------+
| Row 2: RED — 서버 수행 작업 (요청/서비스 레이어)                                  |
| +-----------------------+ +-----------------------+ +---------------------------+ |
| | R · DB 처리량 (B/s)   | | E · 오류 로그/초      | | D · 복제 지연 (초)       | |
| +-----------------------+ +-----------------------+ +---------------------------+ |
+-----------------------------------------------------------------------------------+
```

### Row 1: USE 패널 명세

#### 패널 1) `U · CPU 사용률 (%)`
- **Data source:** Zabbix | **Group:** 랩 대상 그룹 | **Host:** `$host`
- **Item:** `CPU utilization` (Linux 표준 템플릿 항목)
- **Panel Unit:** `Percent (0-100)` *(부하 주입 시 임계치 95~98% 관측)*

#### 패널 2) `S · Load Average (1m)`
- **Data source:** Zabbix | **Group:** 랩 대상 그룹 | **Host:** `$host`
- **Item:** `Load average (1m avg)`
- **Thresholds:** **`2.0`** 설정 (실험 VM 2 코어 기준 한계 임계선 명시, 부하 주입 시 5.25 관측)

#### 패널 3) `E · 인터페이스 에러/초` (아래 2가지 구성 중 선택)
- **구성 ⓐ (서버 NIC 직접 감시):**  
  Item을 네트워크 인터페이스 Rx/Tx 에러 카운터로 지정 ➔ Functions `+` ➔ Transform ➔ `delta` 또는 `rate` 지정하여 초당 변화량으로 변환
- **구성 ⓑ (네트워크 스위치 에러 연동 — 시연 발표 권장):**  
  `kinx-noise` 대시보드의 에러 패널 쿼리(`lab-switch1` 장비 지표)를 복사하여 적용 (단, 패널 부제에 네트워크 스위치 대상 지표임을 명시)

---

### Row 2: RED 패널 명세

#### 패널 4) `R · DB 처리량 (Bytes received/s)`
- **Data source:** Zabbix | **Group:** 랩 대상 그룹 | **Host:** `$host`
- **Item:** `kinx-msp` 대시보드의 MySQL 처리량 아이템(`Bytes received`) 쿼리 매핑

#### 패널 5) `E · 오류 로그/초`
- **Data source:** **Loki**
- **LogQL Query:** `sum(rate({host=~"$host"} |= "ERROR" [1m]))` (`error_burst.sh` 장애 주입을 통한 에러율 상승 시각화)

#### 패널 6) `D · 복제 지연 (초)`
- **Data source:** Zabbix | **Group:** 랩 대상 그룹 | **Host:** `$host`
- **Item:** `Seconds Behind Master` (`kinx-overview` 대시보드 쿼리 참조)
- **Panel Unit:** `seconds` *(정상 0초 ➔ 부하 주입 시 최대 6분 13초 증가 관측)*

---

## 5. 트러블슈팅 및 장애 방지 지침 (Pitfalls)

- **Grafana Zabbix 데이터소스 캐시 지연 (`cacheTTL`):**  
  기본 조회 캐시(`cacheTTL`)가 1시간으로 설정되어 있을 경우 시계열 데이터가 정지된 것처럼 보입니다. 데이터소스 설정에서 **`1m` 이하로 단축 조정**합니다.
- **호스트 및 그룹 필터 매칭 기준:**  
  Group 및 Host 필드는 Zabbix의 기술명(Technical Name)이 아닌 **표시명(Visible Name)**을 기준으로 매칭됩니다.
- **아이템 필터 정규식 구문:**  
  Item 필드에 슬래시(`/.../`)를 포함하지 않을 경우 **완전 일치(Exact Match)**로 처리되어 지표 조회가 누락될 수 있습니다.
- **Go Regexp 엔진의 부정 Lookahead 미지원:**  
  Grafana Zabbix 백엔드가 Go 언어의 `regexp` 패키지를 사용하므로, 부정 Lookahead 구문 `(?!...)` 사용 시 에러 없이 필터링이 무효화됩니다.

---

## 6. Q&A 대비 및 지표 기술적 한계 명시

- **D (Duration) 지표의 대리 지표(Proxy Metric) 활용 사유:**  
  교과서적인 Duration은 End-to-End HTTP 웹 요청 응답시간(Latency)을 의미하나, 현재 실험 인프라 환경에는 HTTP 패킷 레벨 Latency 계측 모듈(`httptest`)이 미배치되어 있습니다. 따라서 **요청 처리 지연을 파이프라인 데이터 동기화 지연(DB 복제 지연 시간)으로 대체 계측**하였습니다. (웹 요청 응답시간 계측은 향후 로드맵 과제로 정의)
- **기존 관제 정책과의 정합성:**  
  "알림 임계치는 RED 대시보드에 부여한다"는 원칙에 따라, 현재 DB 복제 지연 트리거(High Severity)가 RED 계층에 정상 배치되어 운영 정책과 정합성을 이룹니다.

---

## 7. 발표 장표용 스크린샷 캡처 절차

1. **혼합 장애 주입 스크립트 실행:**  
   `chaos/repl_lag_contention.sh` (U·S·R·D 통합 부하) + `error_burst.sh` (E-RED 부하) + `snmp_iface_error.sh` (E-USE 부하) 동시 수행
2. **데이터 수집 대기:**  
   주입 후 5~10분간 대기하여 시계열 데이터 상에 패턴이 형성되면 조회 창을 **`Last 1 hour`**로 고정
3. **Grafana 다크 테마 적용 확인:** 기존 장표 톤과 일치하도록 Dark Theme 상태 유지
4. **분할 스크린샷 캡처:**
    - **Row 1 (USE 3개 패널):** Fit 캡처 ➔ 발표 7번 장 **좌측 카드 영역** 배치
    - **Row 2 (RED 3개 패널):** Fit 캡처 ➔ 발표 7번 장 **우측 카드 영역** 배치
5. **장표 자막 명시:** 하단 자막에 *"실험(PoC) 인프라 환경에서 인위적으로 주입한 부하 시뮬레이션 결과"* 문구 표기
6. **동일 타임라인 검증:** 동일 시점 내 6개 패널이 동시 반응하는 시각적 증적을 통해 USE(원인)와 RED(증상)의 통합 상관관계를 증명합니다.

---

## 8. 완성 검증 체크리스트

- [ ] `$host` 변수 변경 시 대시보드 내 6개 패널 지표가 상응하여 동적 변환되는가
- [ ] 장애 주입 시간 창 내에서 6개 패널이 모두 동시 반응하는가
- [ ] 캡처된 스크린샷 2장이 발표 7번 장 Placeholder에 명확히 대체되었는가
- [ ] 프로비저닝용 대시보드 JSON 파일이 `lab/grafana/provisioning/dashboards/json/kinx-use-red.json` 경로에 커밋되었는가