# tools/ — Zabbix 읽기 전용 정찰 도구

운영 중인 Zabbix를 **건드리지 않고** API로 현황을 파악하기 위한 스크립트 모음입니다.
"무엇을 감시하고 있고, 무엇이 실제로 통보되는가"를 UI를 뒤지는 대신 근거 있는 표로 뽑습니다.

이 문서는 **도구 사용법**만 다룹니다. 실행 결과(수치·호스트명)는 여기에 적지 않습니다 — §5.

---

## 1. 안전 규약 — 왜 읽기 전용인가

운영 중인 감시 시스템에 설정 변경을 가하면, 그 변경 자체가 장애 원인이 될 수 있고 무엇보다
**되돌릴 근거가 남지 않습니다.** 그래서 이 도구들은 전부 `.get` 계열 API만 호출합니다.

- **쓰기 API를 일절 호출하지 않습니다.** `*.create` / `*.update` / `*.delete` 없음.
- **읽기 전용 계정으로 발급한 토큰**을 씁니다. 권한 자체를 없애 두는 것이 코드 규약보다
  강한 방어입니다.
- 일부 조회(액션 라우팅 등)는 계정 권한이 모자라면 실패합니다. **실패해도 나머지 절은 정상
  출력**되도록 만들었습니다 — 권한을 올리려고 계정을 손대지 않기 위해서입니다.

> 게이트웨이(`bot/gateway/collector.py`)도 같은 원칙을 코드로 강제합니다 — `.get` 외의
> 메서드는 호출 자체가 거부됩니다.

## 2. 준비

**표준 라이브러리만 씁니다.** `pip install`이 필요 없어 대상 서버에서 바로 돌릴 수 있습니다
(Python 3.6+). Zabbix 5.0~7.x를 자동 감지하며, 6.4 이상에서는 `Authorization: Bearer` 헤더로
인증합니다.

토큰 발급: Zabbix UI → User settings(또는 Administration) → **API tokens** → Create.
**조회 권한만 가진 별도 계정**으로 발급하는 것을 권합니다.

```bash
# bash
export ZABBIX_URL="https://<zabbix-host>/zabbix"     # /api_jsonrpc.php 는 생략 가능
export ZABBIX_TOKEN="****"
```

```powershell
# PowerShell
$env:ZABBIX_URL="https://<zabbix-host>/zabbix"
$env:ZABBIX_TOKEN="****"
```

자체 서명 인증서를 쓰는 환경이면 각 스크립트에 `--insecure`를 붙입니다.

**감시 세트가 둘이면 두 번 돌립니다.** URL·토큰만 바꿔 각각 실행하고 결과를 따로 보관합니다.

---

## 3. 스크립트

### `zabbix_snapshot.py` — 구성·알림 현황 스냅샷

무엇을 감시하고 있고 어떤 알림이 얼마나 터지는지의 전체 그림.

```bash
python3 zabbix_snapshot.py --days 30 --top 20 -o snapshot.md
```

- 호스트그룹별 호스트 수 / 연결 템플릿 목록(호스트·아이템·트리거 수)
- 최근 N일 Problem 이벤트의 **심각도 분포**와 **최다 발화 트리거 Top N**
  (웹 UI의 Reports → Top 100 triggers에 해당)
- `--deep`: 템플릿 밖 **커스텀** 아이템·트리거(조건식 포함)·매크로 오버라이드까지
- `--mask REGEX`: 그룹명 등 민감 명칭을 일관되게 익명화

주요 인자 — `--days`(기간) / `--top`(상위 N) / `--user`·`--password`(토큰 대신 계정 인증) /
`--insecure`

> **`--mask`의 한계를 알고 씁니다.** 정규식에 걸리는 문자열만 익명화되므로, 호스트명에 박힌
> 고객사명이나 IP는 패턴을 따로 주지 않으면 그대로 남습니다. 마스킹했다고 안심하지 말고
> 출력물을 눈으로 확인합니다.

### `zabbix_serverstats.py` — 규모·경로 자가 확인

인터뷰로 묻지 않고 API로 확인할 수 있는 것들.

```bash
python3 zabbix_serverstats.py -o serverstats.md
```

- **NVPS**: `zabbix[requiredperformance]` · `zabbix[wcache,values*]` 내부 아이템의 최근 값
- **프록시 사용 여부**: `proxy.get` + 호스트의 프록시 배정 집계
- **알림 라우팅**: `action.get`으로 트리거 액션의 조건(심각도/호스트그룹)과 통보 대상
- **실제 발송량**: `alert.get`으로 최근 N일 발송 건수·성공/실패·미디어 타입별 집계

**마지막 항목이 이 도구의 핵심입니다.** "Problem 이벤트 수(트리거가 발화한 횟수)"와
"실제로 통보된 수"는 전혀 다른 값인데, UI에서는 앞엣것만 눈에 띕니다. 액션 조건을 통과한
것만 발송되므로 **두 수치를 같은 것처럼 쓰면 진단이 통째로 틀립니다.**

### `zabbix_alert_crosscheck.py` — 발송 결과 교차 검산

`serverstats`의 발송 집계를 미디어×상태로 쪼개 검산합니다.

```bash
python3 tools/zabbix_alert_crosscheck.py --days 30
```

- 미디어 × 상태 교차표 — 성공분이 **어느 미디어**에서 나온 것인지
- 실패의 **사유**(`error` 필드) — "미디어 비활성"인지 "스크립트 실행 실패"인지
- 미디어별 최초/최종 시도 시각 — **시도가 언제 끊겼는지**

> `error` 필드에 스크립트 stderr가 담겨 **웹훅 URL 같은 크리덴셜이 섞일 수 있습니다.**
> 출력을 저장한다면 `private/` 아래에만 둡니다.

근거: [alert 오브젝트](https://www.zabbix.com/documentation/7.0/en/manual/api/reference/alert/object)
(status 0=미발송, 1=성공, 2=재시도 후 실패, 3=신규 / error=실패 사유)

### `zabbix_mediatype_check.py` — 발송 경로 판별

```bash
python3 tools/zabbix_mediatype_check.py
```

미디어 타입의 종류(Email/Script/SMS/Webhook)와 활성 여부를 1콜로 확인합니다.
**Slack을 표준 웹훅이 아니라 커스텀 스크립트로 보내는 경우**가 있는데, 그러면 발송 기록이
어디에 남는지가 달라져 위 두 도구의 해석이 바뀝니다. 그것을 먼저 확정하는 용도입니다.

> Script형 미디어의 실행 인자(`parameters`)에는 **웹훅 URL이 들어 있을 수 있어** 기본
> 조회에서 제외했습니다.

근거: [mediatype.get](https://www.zabbix.com/documentation/7.0/en/manual/api/reference/mediatype/get)

### `zabbix_replication_check.py` — 복제 감시의 깊이 판별

DB 복제를 **"돌아가는가(1/0)"** 로만 보는지 **"몇 초 밀렸는가"** 까지 보는지 구분합니다.

```bash
python3 zabbix_replication_check.py --history -o repl_check.md
```

이름만으로는 구분되지 않기 때문에 **아이템 정의와 실제 수집값으로 판별**합니다.

- 단위가 `s`이거나 자료형이 float이고 값이 오르내리면 → **지연(초)**
- 값이 0/1 정수로 고정이면 → **상태 플래그**
- 유래(호스트 직접 정의 vs 템플릿 상속)도 함께 표시 — 자작 아이템과 표준 템플릿 아이템을
  구분하기 위해서입니다. 표준 MySQL 템플릿은 지연 아이템을 원래 포함하므로, 자작이 없어도
  이미 보고 있을 수 있습니다.

`item.get` / `history.get`만 호출합니다.

> 출력에 실제 호스트명이 포함되므로 결과 파일은 `private/`에 보관합니다.

---

## 4. 정찰 순서

의존 관계가 있어 순서가 있습니다.

1. **`zabbix_snapshot.py`** — 전체 그림. 여기서 "무엇을 더 봐야 하는지"가 정해집니다.
2. **`zabbix_mediatype_check.py`** — 발송 경로 확정. 3번의 해석 전제입니다.
3. **`zabbix_serverstats.py`** — 규모·라우팅·발송량.
4. **`zabbix_alert_crosscheck.py`** — 3번의 발송 수치 검산.
5. **`zabbix_replication_check.py`** — 필요할 때만. 특정 감시 항목의 깊이를 파는 예시입니다.

**수치를 쓸 때는 측정 창을 함께 적습니다.** 같은 도구라도 실행 날짜가 다르면 30일 창이 달라져
값이 바뀝니다. 서로 다른 창의 수치를 한 문장에 섞으면 안 됩니다.

## 5. 결과물 취급

**이 도구들의 출력은 리포에 커밋하지 않습니다.** 실 호스트명·IP·고객사명·크리덴셜 조각이
섞이며, `--mask`를 써도 완전하지 않습니다.

- 저장 위치는 `private/` 아래 (`.gitignore` 대상)
- 문서·발표에 쓸 때는 **비율·구조만** 옮깁니다. 호스트 대수·총 이벤트 건수 같은 모수는
  조직을 식별할 수 있는 값이라 옮기지 않습니다.
- 수치는 원본 데이터에서 **재계산 가능해야** 합니다. 도구 출력 원본을 함께 보관합니다.

## 6. 이 디렉토리의 다른 스크립트

정찰이 아니라 **생성**하는 도구라 위 안전 규약이 적용되지 않습니다. 쓰기 API를 호출하므로
**랩에서만** 씁니다.

| 스크립트 | 하는 일 |
|---|---|
| `zabbix_report_dashboard.py` | MSP 리포트용 Zabbix 자원(호스트·아이템) 생성 |
| `gen_msp_report_dashboard.py` | MSP 리포트 Grafana 대시보드 JSON 생성 |

둘 다 실행 대상 URL을 코드에서 확인하는 가드가 있습니다. 관련 문서는
[`ansible/DEPLOY_GUIDE.md`](../ansible/DEPLOY_GUIDE.md)의 MSP 월간 리포트 절.
