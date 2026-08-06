# Grafana USE / RED 대시보드 구성 가이드

발표 7번 장(Grafana 고도화 ① — 대시보드 표준화)의 캡처 2장을 만들기 위한 구성 절차이자,
이후 표준 대시보드로 재사용하기 위한 기준 문서다. 완성되면 JSON 을
`lab/grafana/provisioning/dashboards/json/kinx-use-red.json` 으로 내려받아 Git 으로 관리한다.

근거 문서 (2026-08-03 확인):
- Grafana 공식 "Dashboard best practices" — USE/RED 정의
  (https://grafana.com/docs/grafana/latest/dashboards/build-dashboards/best-practices/)
- Zabbix 플러그인 공식 문서 — 쿼리 에디터 필드·템플릿 변수
  (https://grafana.com/docs/plugins/alexanderzobnin-zabbix-app/latest/ 의
  Query editor / Template variables 페이지)

## 1. 방법론 근거

- **USE** — 자원(하드웨어)마다: **U**tilization(자원이 바쁜 시간 비율), **S**aturation(밀린 일의 양
  — 큐 길이, node load), **E**rrors(오류 이벤트 수). CPU·메모리 같은 인프라 하드웨어에 적합.
- **RED** — 서비스마다: **R**ate(초당 요청), **E**rrors(실패 요청 수), **D**uration(요청 소요 시간).
  서비스 환경에 적합.
- **공식 핵심 권고**: "USE 는 문제의 **원인**을, RED 는 사용자 경험 즉 **증상**을 보여준다.
  알림은 **RED 대시보드에** 걸어라(증상 기반 알림 원칙)."
- 우리와의 연결: 데모 C 복제 경합이 정확히 "RED 증상(복제 지연) + USE 원인(CPU 95~98%,
  Load 5.25)"이었고 봇이 이 둘을 한 사건으로 병합했다. Q&A 에서 "왜 두 관점을 나누냐"가
  나오면 이 문장으로 답한다.

## 2. 사전 지식 — Zabbix 패널 쿼리 에디터의 필드 전부

패널을 만들면 Zabbix 데이터소스 쿼리 에디터에 아래 필드들이 위에서 아래로 나온다.
하나씩 뜻과 우리 설정값:

| 필드 | 뜻 | 우리 값 |
|---|---|---|
| **Query Mode** | 무엇을 조회할지 선택: Metrics(숫자 시계열) · Text(문자 값) · Services(SLA) · Item ID · Triggers · Problems · User macros | **Metrics** (전 패널) |
| **Group** | 호스트가 속한 Zabbix **호스트 그룹**으로 거르는 필터. `/정규식/` 과 변수 지원 | 랩 대상 그룹 이름 (드롭다운에서 선택) |
| **Host tag** | **호스트 오브젝트에 붙인 태그**로 거르는 필터 (Zabbix 5.4+). Exists/Equals/Contains 와 부정 연산, 복수 조건 AND/OR | **비움** — 우리 랩은 호스트 태그를 쓰지 않는다. ※ 우리가 프로젝트에서 쓴 "분류 태그"(1,880→146)와 automate/scope 는 **아이템·트리거 태그**라 이 필드와 별개다 |
| **Host** | 호스트 필터. `/정규식/` 과 변수 지원, **정규식 없이 쓰면 완전일치** | **`$host`** (아래 §3 변수) |
| **Item tag** | **아이템에 붙은 태그**로 거르는 필터 (Zabbix 5.4+, 구버전의 Application 필드를 대체) | **비움** (아이템이 너무 많이 잡힐 때만 좁히는 용도) |
| **Item** | 아이템 이름 필터. `/정규식/` 과 변수 지원, **정규식 없이 쓰면 완전일치** (우리가 리포트 대시보드에서 실측한 함정) | 드롭다운에서 아이템 이름 선택 (§4 표) |
| **Functions** | `+` 버튼으로 후처리 함수 추가: rate, delta, scale, groupBy, movingAverage 등 | 기본 없음. 에러 **카운터**(누적값) 아이템만 `delta` 또는 `rate` 를 걸어 "초당"으로 변환 |
| **Options → Trends** | 이 쿼리만 트렌드 사용을 강제/금지 (Default/True/False). 데이터소스 기본은 7일 이전 구간을 trends 로 조회 — 리포트 대시보드에서 `useTrends=false` 로 껐던 그 옵션 | **Default** (캡처는 최근 1시간이라 무관) |
| **Options → Show disabled items** | 비활성 아이템도 드롭다운에 표시 | 기본(끔) |
| **Options → Use Zabbix value mapping** | Zabbix 쪽 값 매핑(1=Up 같은 번역)을 그대로 적용 | 기본 |
| **Options → Disable data alignment** | 수집 주기에 맞춘 데이터 정렬을 끔 | 기본 |

## 3. 따라 하기 ① — `$host` 변수 만들기

1. 새 대시보드 → 우상단 톱니(Dashboard settings) → **Variables** → **New variable**
2. 필드별 입력:
   - **Name**: `host` (패널에서 `$host` 로 참조됨)
   - **Type**: `Query`
   - **Data source**: Zabbix
   - **Query type**: `Host` (호스트 목록을 뽑는 변수라는 뜻. Group/Item 등 다른 타입은 각각 그룹 목록/아이템 목록용)
   - **Group**: 랩 대상 그룹 이름 (이 그룹 안의 호스트만 목록에 나옴)
   - **Host**: `/.*/` (그룹 안 전부)
   - 구식 문자열 문법도 동작한다: `{그룹명}{*}` — `{중괄호}` 4칸이 그룹·호스트·앱·아이템 순서고 `*` 는 전부라는 뜻. 폼 방식이 있으니 굳이 쓸 필요는 없음
   - **Multi-value / Include All**: 켜도 됨 — 멀티 선택 시 플러그인이 자동으로 정규식으로 변환해 준다(공식)
3. **Run query** 로 호스트 목록이 뜨는지 확인 → Apply.
4. 검증: 대시보드 상단에 host 드롭다운이 생기고, 패널을 만든 뒤 값을 바꾸면 전 패널이 따라 바뀌어야 한다.

## 4. 따라 하기 ② — 패널 6개

행 2개를 먼저 만든다: **Add → Row** 두 번, 행 제목을 각각 `USE — 서버 자체(자원)`,
`RED — 서버가 하는 일(요청)` 으로. 패널을 만들면 드래그로 행 안에 배치.

각 패널의 설정값 (명시 안 한 필드는 §2의 "우리 값" = 기본):

### Row 1 — USE

**패널 1) `U · CPU 사용률 (%)`**
- Datasource: Zabbix / Group: 랩 그룹 / Host: `$host` / Item: 드롭다운에서 **CPU utilization** (표준 Linux 템플릿)
- Unit(패널 우측 옵션): Percent (0-100). 실측 근거: 부하 주입 시 95~98%

**패널 2) `S · Load Average (1m)`**
- Item: **Load average (1m avg)**
- Thresholds(우측 옵션)에 **2.0** 추가 (랩 VM 2코어 = 코어 수 기준선) → 선 넘으면 "포화"가 화면에서 읽힘. 실측: 5.25

**패널 3) `E · 인터페이스 에러/초`** — 둘 중 하나
- ⓐ `$host` 서버 NIC: Item 을 네트워크 인터페이스 에러 카운터로 선택. **카운터(누적)면 Functions `+` → Transform → `delta` 또는 `rate`** 를 걸어 초당으로 변환. 평시 0 (정상도 정보)
- ⓑ `lab-switch1`: kinx-noise 대시보드의 에러 패널을 열어(Edit) 쿼리를 그대로 복사. 캡처에 움직임이 생기므로 발표용 권장. **다른 호스트(네트워크 장비)임을 패널 부제에 명시** — USE 는 자원마다 적용하는 방법이라 장비 NIC 도 대상이 맞다

### Row 2 — RED

**패널 4) `R · DB 처리량 (Bytes received/s)`**
- kinx-msp 의 "DB 처리량" 패널 Edit → 쿼리 복사 (표준 MySQL 템플릿 Bytes received). Host 는 `$host` 로 교체

**패널 5) `E · 오류 로그/초`**
- **Datasource 를 Loki 로** 바꾸고 기존 오류율 패널 쿼리 복사 (`{host=~"$host"}` 의 ERROR rate — error_burst 로 상승 재현 가능)

**패널 6) `D · 복제 지연 (초)`**
- kinx-overview 의 "복제 지연(Seconds Behind Master)" 패널 쿼리 복사. Host `$host`. Unit: seconds. 실측: 0 → 6분 13초

기존 패널 쿼리 복사 방법: 해당 대시보드 → 패널 제목 클릭 → **Edit** → 쿼리 에디터의 필드 값을
그대로 옮겨 적는다 (또는 패널 우측 메뉴 → More → Copy 후 새 대시보드에 Paste).

## 5. 함정 (우리 실측, 재발 방지)

- **cacheTTL 기본 1h** — 값이 안 바뀌는 것처럼 보임(2회 사고). Zabbix 데이터소스 설정에서 **1m** 으로.
- Host/Group 필드는 **표시명(visible name)** 매칭. 기술명 넣으면 빈 패널.
- Item 필드는 `/.../` 없으면 **완전일치**.
- 부정 lookahead `(?!...)` 정규식은 조용히 무시됨 (백엔드 Go regexp) — 필터에 쓰지 말 것.

## 6. 정직성 주의 (Q&A 대비)

- **D = 대리 지표**: 교과서적 Duration 은 요청 응답시간인데 랩에 웹 응답시간 계측은 없다
  (httptest 미구축). 질문이 나오면 "요청 지연은 파이프라인 지연(복제)으로 먼저 검증했고,
  웹 응답시간은 로드맵"이라고 답한다. 단정 금지.
- 공식 권고("알림은 RED 에")와 현행 정합: 복제 지연 트리거(High)가 이미 있다 — 어긋나지 않는다.

## 7. 캡처 절차 (발표 7번 장 채우기)

1. chaos 동시 주입: `chaos/repl_lag_contention.sh` (U·S·R·D 동시 반응) + 오류 로그 주입
   (error_burst → E-RED) + snmp 인터페이스 에러 플래핑 (E-USE ⓑ).
2. 주입 후 5~10분 대기 → 그래프에 산이 생기면 시간 범위 **Last 1 hour** 고정.
3. 다크 테마로 캡처 (기존 장표 스크린샷과 톤 통일).
4. **Row 1(USE 3패널)만 fit 하게 1장 → 7번 장 좌측 카드**, **Row 2(RED 3패널) 1장 → 우측 카드**.
5. 장표 자막에 "랩(PoC) 환경에서 인위적으로 주입한 부하 결과" 명시 (기존 원칙).
6. 같은 시간창이면 여섯 패널이 한 사건에 같이 반응하는 장면 = USE(원인)·RED(증상) 동시
   움직임 = 데모 C 병합의 시각적 예고편까지 한 번에 증빙된다.

## 8. 완료 기준

- [ ] `$host` 변경 시 6패널 전부 따라 바뀜 (변수 스코프 검증)
- [ ] 부하 주입 시간창에서 6패널 모두 반응 확인
- [ ] 캡처 2장 → 발표 7번 장 placeholder 교체
- [ ] 대시보드 JSON 내려받아 `kinx-use-red.json` 커밋
