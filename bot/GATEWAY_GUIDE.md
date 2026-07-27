# 알림 게이트웨이 (데모 B·C 공용) — 가이드

## 1. 목적과 위치

Zabbix(사내/MSP)·Wazuh의 알림을 한 곳에서 받아 **정규화(SEV) → 멱등 → 라우팅**하는
공용 관문. 데모 C(트리아지 봇)와 데모 B(n8n 승인→Ansible)가 이 위에 얹힌다.

```
Zabbix 웹훅 미디어타입 ─┐
                        ├→ [게이트웨이] 토큰검증 → 멱등 → SEV 정규화 → 태그 라우팅
Wazuh integration ──────┘                                     │
                              triage(데모 C 봇) / remediate(데모 B n8n) /
                              digest / dashboard_only / resolve / drop
```

## 2. 파일 구성

| 파일 | 역할 |
|---|---|
| `gateway/app.py` | FastAPI 앱 — 엔드포인트, 토큰 검증, 멱등, 디스패치 |
| `gateway/severity.py` | 심각도 정규화 상수 — **private/docs/severity_map.md의 코드 구현** (표 개정 시 문서 먼저) |
| `gateway/router.py` | 태그 라우팅 — automate/scope 태그로 B·C 경로 분기 |
| `gateway/selftest.py` | 순수 로직 검증 (fastapi 불필요) |
| `gateway/zabbix_media_webhook.js` | 랩 Zabbix에 등록할 웹훅 미디어타입 스크립트 |

## 3. 실행

```powershell
# bot/ 디렉토리에서. 토큰은 환경변수로만 (코드·커밋 금지)
python -m pip install -r requirements.txt
$env:GATEWAY_TOKEN = "임의의 긴 랜덤 문자열"
python -m uvicorn gateway.app:app --host 0.0.0.0 --port 8800
```

검증:

```powershell
python -m gateway.selftest        # 순수 로직 29건 (2026-07-26 통과 확인)
curl http://localhost:8800/healthz
```

## 4. 엔드포인트

### POST /webhook/zabbix  (헤더 `X-Gateway-Token` 필수)

```json
{
  "source": "zabbix-internal | zabbix-msp",
  "event_id": "123", "event_value": 1,
  "event_name": "...", "nseverity": 4,
  "host": "lab-web01",
  "tags": [{"tag": "automate", "value": "service_restart"}]
}
```

응답: `{"status":"accepted","sev":"SEV2","route":"remediate","playbook":"service_restart",...}`
동일 (source, event_id, event_value) 재수신 시 `{"status":"duplicate"}` (200 — Zabbix 재시도 중단 목적).

### POST /webhook/wazuh — `alert_id, rule_id, rule_level(0~15), agent_name` (배선은 후속)

## 5. 랩 Zabbix 배선 (미디어타입)

Administration → Media types → Create: type=**Webhook**, script=`zabbix_media_webhook.js`,
파라미터:

| 파라미터 | 값 | 검증 상태 |
|---|---|---|
| `gateway_url` | `http://<게이트웨이 호스트>:8800` | — |
| `token` | GATEWAY_TOKEN 값 | ⚠ Zabbix 설정 DB에 저장됨 — 랩 한정 허용, 실환경은 Vault류 검토(로드맵) |
| `source` | `zabbix-internal` (랩 본체) / `zabbix-msp` (MSP 데이터소스) | — |
| `event_id` | `{EVENT.ID}` | 공식 확인 |
| `nseverity` | `{EVENT.NSEVERITY}` | 공식 확인 ("Numeric value of the event severity") |
| `event_name` | `{EVENT.NAME}` | 공식 확인 |
| `tags_json` | `{EVENT.TAGSJSON}` | 공식 확인 ("A JSON array containing event tag objects") |
| `host` | `{HOST.HOST}` | 목록 존재 확인 |
| `event_value` | `{EVENT.VALUE}` | **미확인(추정)** — 문서 페이지 잘림. 랩 배선 시 실값 확인, 안 되면 Operations/Recovery operations에서 각각 1/0 리터럴 주입으로 대체 |

이후 Action(트리거 조건) → Operations에 이 미디어타입 지정. 랩 검증 컷:
`error_burst`/브루트포스 주입 → 게이트웨이 로그에 `sev=... route=...` 찍히는지 확인.

## 6. 설계 결정과 근거

- **severity.py = severity_map.md의 단일 구현** (이중 진실 금지). 사내 Warning→SEV4 vs
  MSP Warning→SEV3 비대칭, Wazuh 10+=SEV2(팀 Slack 컷라인 보존)가 셀프테스트로 고정됨.
- **미지 소스·범위 밖 레벨은 SEV2 페일세이프**: 과소평가로 놓치는 것보다 과대평가로
  시끄러운 쪽. 놓친 알림은 복구 불가지만 시끄러운 알림은 튜닝 가능.
- **토큰 비교는 `hmac.compare_digest`**: 단순 `==` 비교의 타이밍 부채널 회피 (파이썬
  공식 문서가 비밀 비교에 권장: https://docs.python.org/3/library/hmac.html).
- **멱등은 인메모리 TTL 1시간**: Zabbix가 실패 시 재발송해도 중복 트리아지(=중복 LLM
  비용·중복 Slack) 방지. **한계**: 게이트웨이 재시작 시 캐시 소실 — PoC 허용,
  프로덕션화 시 Redis/DB로 교체(로드맵 "게이트웨이 프로덕션화" 항목).
- **복구 이벤트(event_value=0)는 `resolve` 경로**로 분리 — 통보 스레드 갱신용(후속 구현).
- **triage/remediate는 현재 스텁**: 다음 단계 = 컨텍스트 수집기(Zabbix API 병렬) +
  만성/신규 선판정 + LLM 어댑터. LLM 호출은 **타임아웃 20s, 재시도 대신 폴백**
  (실측 근거: private/docs/llm_latency_20260726.md — 총 시간 최대 14.8s, 재시도 시 30s 초과).
- **scope 태그가 automate보다 우선**: MSP 계약 `notify_only`면 automate 태그가 있어도
  조치 경로 차단(A-6 "임의 조치 불가"의 코드화). customer.yml의 scope가 태그로 상속되는
  구조(agent_msp_enhancement A-2 태그 설계)와 연결.

## 7. 공식 문서 근거

- Zabbix 웹훅 미디어타입: https://www.zabbix.com/documentation/7.0/en/manual/config/notifications/media/webhook
- Zabbix 매크로 위치별 지원({EVENT.ID}/{EVENT.NSEVERITY}/{EVENT.TAGSJSON} 등, 2026-07-26 확인):
  https://www.zabbix.com/documentation/7.0/en/manual/appendix/macros/supported_by_location
- Zabbix 심각도 0~5: https://www.zabbix.com/documentation/7.0/en/manual/config/triggers/severity
- Wazuh 룰 레벨 0~15: https://documentation.wazuh.com/current/user-manual/ruleset/rules/rules-classification.html
- FastAPI: https://fastapi.tiangolo.com/ (Header 파라미터·pydantic 검증·TestClient)

## 8. 검증 이력

- 2026-07-26: `selftest` 29건 + TestClient HTTP 스모크 10건 전부 통과
  (401/422 거부, 사내·MSP Warning 비대칭, automate/scope 분기, 멱등 duplicate,
  Wazuh 레벨 10→SEV2/triage).
- 2026-07-26(2차): selftest 34건으로 확장 — 만성/신규 선판정 4경계(신규/재발/만성/창
  밖 이력 무시) + 수집기 읽기 전용 가드(`.get` 외 메서드 코드 레벨 거부) 통과.
  수집기 실 API 통합 테스트는 랩 Zabbix 기동 후(§9 절차).

## 9. 컨텍스트 수집기 + 만성/신규 선판정 (`collector.py` / `prejudge.py`)

triage 경로가 LLM을 부르기 전에 재료를 모으고 결정적 판정을 끝내는 계층.
**2026-07-27: Loki 로그 + Wazuh 경보 조회 추가 — 봇이 세 시스템을 다 읽어 인시던트 병합.**

### 교차 소스 (인시던트 병합용, 2026-07-27 신설)
- **Loki**: `LOKI_URL` 설정 시 `/loki/api/v1/query_range`로 `{host=~"<host>.*"}` 최근 15분
  로그 40줄(라인 300자 제한). 호스트 라벨은 FQDN 정규화 전제(demo A). 미설정·실패 시 [] (열화).
- **Wazuh**: `WAZUH_INDEXER_URL`(+USER/PASSWORD) 설정 시 OpenSearch `wazuh-alerts-*/_search`로
  `agent.name` 최근 15분 경보 20건. 랩은 자체서명 TLS라 `verify=False`(프로덕션은 사내 CA).
  미설정·실패 시 [] = **"침해 배제" 신호로 해석**(없음도 정보).
- 두 소스 모두 **선택적** — 없으면 Zabbix만으로 열화 진행(하위 호환). 로그 원문은 `masking.py`가
  라인 단위로 가명화 후 전송(전송 명세표 §3 이행).

### Zabbix API 5종 (전부 읽기 전용 `.get` — 코드 가드로 강제)

| # | 호출 | 목적 |
|---|---|---|
| ① | `event.get` (eventids) | 현재 이벤트 상세 + 태그 |
| ② | `trigger.get` (expandExpression) | 트리거 정의·조건식 — "무엇이 기준을 넘었나" |
| ③ | `item.get` → `history.get` (최근 1h, 20점) | 관련 메트릭 추이 — "어떻게 변해왔나" (수치형만) |
| ④ | `event.get` (objectids, 90일 창) | 동일 트리거 과거 발생 이력 → 선판정 입력 |
| ⑤ | `host.get` (그룹·인터페이스) | 호스트 메타 — MSP 고객 식별·대시보드 링크용 |

①②③④는 `asyncio.gather` 병렬, ⑤만 트리거 응답의 hostid 의존이라 후행. 콜당
타임아웃 5초 — 수집 전체가 30초 예산을 갉지 않게 함(실측상 LLM 몫 최대 15초).

- 인증: `Authorization: Bearer <ZABBIX_TOKEN>` 헤더 (Zabbix 7.0 API 토큰 방식).
  랩에서도 조회 전용 계정의 토큰을 쓴다 — 실환경 습관 그대로.
- 근거: https://www.zabbix.com/documentation/7.0/en/manual/api (JSON-RPC,
  event/trigger/item/history/host.get). 리포 기존 도구(tools/zabbix_snapshot.py)와
  동일 API 면.

### 선판정 규칙 (`prejudge.py`) — 결정적, LLM 재판정 금지

| 조건 (90일 창) | 판정 | 봇 회신 톤 |
|---|---|---|
| 발생 0회 | **신규** | "처음 보는 문제 — 즉시 확인 권장" |
| 1~4회 | **재발** | "간헐 재발 N회 — 이전 발생과 공통점 확인" |
| **5회 이상** | **만성** | "알려진 반복 문제 N회 — 정비 대상, 긴급도 낮을 수 있음" |

기준값 근거 (창 90일): ① 정찰 스냅샷과 동일 창 — 실환경 데이터로 판정 역검증 가능
(재계산 원칙) ② "High 111건이 31~90일 전 구간에 매장" 진단이 90일 창 분석 — 만성이
만성으로 보이는 검증된 관측 깊이 ③ 월 주기 반복 장애를 3회 관측 가능한 최소 창(30일이면
1회="신규" 오판). 만성 하한 5회: 실측 만성군(KDA 디스크 90일 57회 등)은 수십 회 단위라
보수적. **단 90/5는 실측 정합이지 도출값은 아니므로 변수화됨** — 환경변수
`PREJUDGE_WINDOW_DAYS`(기본 90)·`PREJUDGE_CHRONIC_MIN`(기본 5), 호출별 오버라이드
인자(window_s/chronic_min)도 지원. 수집기의 90일 이력 조회(④)는 같은 상수를 참조하므로
설정 한 곳으로 판정·조회 창이 함께 움직인다(이중 진실 금지).
판정 결과의 `statement` 문장이 LLM 프롬프트에 그대로 주입되고, 시스템 프롬프트가
"그 값을 그대로 쓰고 재판정하지 않는다"를 강제한다(발표 방어: 만성/신규는 환각 불가).

### 랩 통합 테스트 절차 (랩 Zabbix 기동 후)

```powershell
$env:ZABBIX_URL = "http://<랩 호스트>:8080"; $env:ZABBIX_TOKEN = "<조회 전용 토큰>"
python -c "import asyncio; from gateway.collector import ZabbixClient, collect_context; \
  print(asyncio.run(collect_context(ZabbixClient(), '<event_id>', '<trigger_id>')))"
```

error_burst/repl_lag 트리거 발화 1건으로 ①~⑤ 응답과 선판정 문장을 확인한다.

## 10. 실무 배치 구상 (로드맵 "게이트웨이 프로덕션화"의 구체화)

- **위치**: Zabbix 서버 호스트가 아닌 **관제망 내 별도 VM/컨테이너**. 기존 Zabbix
  HA(VIP 2대)는 운영 중인 검증된 층이라 무접촉. 외부 통신(LLM·Slack)이 이 한 곳에만
  존재 → 전송 데이터 명세표의 "AI 통신은 게이트웨이 1곳" 답변과 정합.
- **새 SPOF 인식과 대응(정직 기재)**: ① 거의 무상태 설계 — 재시작=복구(멱등 캐시만
  소실, 실무는 Redis/DB로 교체) ② **게이트웨이 자신을 Zabbix가 감시** — `/healthz`
  HTTP 체크(self-diagnosing "감시자를 감시" 항목에 편입) ③ **전환기 병행 운영** —
  기존 slack.sh 경로를 즉시 끊지 않고 안정화까지 병행(빅뱅 전환 금지).
- **시크릿**: 랩=환경변수 / 실무=시크릿 저장소(Semaphore·Vault류 — 축 ⑤와 연결).
- **TLS**: 실무는 사내 CA 인증서로 웹훅 구간 암호화(랩은 HTTP 허용).
- **⚠️ 외부 LLM egress — 실무 미확인, 아키텍처가 흡수**: 랩 VM은 Claude·Slack 도달
  가능 확인(anthropic 401·slack 200, 2026-07-26)이나 이는 **데모 가능성일 뿐 실무
  검증 아님**. 실무 관제망(도곡) egress 가부는 미확인 = A-1 하위 인터뷰 항목(IDC
  관제망은 egress 차단이 정상에 가까움, 실환경 egress 테스트는 정찰 원칙상 불가).
  대응은 코드 변경 0: egress 열림→Claude / 막힘→`OLLAMA_URL` 세팅해 온프레(외부 전송
  0) / 둘 다 실패→열화 모드. LLM 어댑터의 Claude/Ollama 스왑이 이 미확인을 전제한
  설계지 과설계 아님. Ollama 폴백 실용성은 `latency_bench --provider ollama`로 실측해
  로드맵 첨부.

## 11. LLM 어댑터 + 마스킹 (`llm.py` / `masking.py`)

triage 경로의 분석 계층. 전송 규칙의 원본은 **private/docs/llm_data_spec.md**(코드가 추종).

- **체인**: Claude(주 경로, 타임아웃 20s·`max_retries=0` — 실측 근거 llm_latency_20260726.md)
  → Ollama(OLLAMA_URL 설정 시) → **열화 모드**(전멸 시 선판정 문장만 회신 — LLM이 죽어도
  봇은 결정적 판정으로 응답하는 데모 안전망).
- **마스킹 왕복**: `Masker`가 호스트명·IP·그룹명을 `[host-1]` 토큰으로 치환해 전송하고,
  회신의 토큰을 역치환해 Slack엔 실명이 게시됨. 가명 맵은 요청 단위·메모리 한정.
  화이트리스트는 `build_llm_context()` 자체 — 목록에 없는 필드는 구조적으로 전송 불가.
- **환경변수**: `ANTHROPIC_API_KEY` / `LLM_CLAUDE_MODEL`(기본 claude-opus-4-8) /
  `LLM_TIMEOUT_S`(기본 20) / `OLLAMA_URL` / `OLLAMA_MODEL`(기본 qwen3:8b).
- **드라이런**: `python -m gateway.llm` — 외부 호출 없이 전송 전문+가명 맵 출력
  (전송 명세표 §6 시연 절차).
- 시스템 프롬프트에 "만성/신규 재판정 금지"와 "토큰을 그대로 사용" 조항 포함 —
  latency_bench의 프롬프트를 승계·정제한 것.

## 12. Slack 회신 + 오케스트레이터 (`slack.py` / `triage.py`)

- **`triage.py`**: 데모 C 한 줄 연결 — 수집(collector) → LLM(llm, 마스킹·폴백 내장) →
  게시(slack). 각 구간 소요를 timings로 반환(30초 스톱워치의 코드 측정판). 어느 단계가
  실패해도 예외를 위로 안 던짐 → 웹훅은 항상 200(발송측 재시도 방지).
- **`slack.py`**: Block Kit(header+context+section)으로 게시. SEV별 이모지, 폴백 text 병기.
  `SLACK_BOT_TOKEN`/`SLACK_CHANNEL_ID` 없으면 게시 건너뛰고 콘솔 로그(오프라인·CI 안전).
  scope는 `chat:write` 하나면 충분(단방향 게시).
- **비동기 처리**: app.py의 triage 경로는 `BackgroundTasks`로 오케스트레이터를 넘김 —
  웹훅 응답은 즉시 반환하고 봇 처리(최대 ~15s)는 뒤에서 진행. Zabbix 미디어타입이
  20초를 안 기다리게 함.
- **오프라인 리허설**: `python demo_triage.py` — 랩 Zabbix 없이 수집기만 가짜로 대체하고
  마스킹→실 Claude→실 Slack 게시까지 관통. 랩 통합 전 "봇이 실제로 분석·게시하는가 +
  30초 이내인가"를 확인. 검증: 2026-07-26 열화 모드(무 크리덴셜) 관통 확인, 실 크리덴셜
  리허설은 사용자 환경변수 설정 후.

## 13. 랩 end-to-end 배선 (다음 단계 — 랩 Zabbix 기동 후)

1. Zabbix 미디어타입 등록(`zabbix_media_webhook.js`, §5) — `trigger_id`에 `{TRIGGER.ID}`
   파라미터 추가(수집기 조회 키).
2. 게이트웨이 기동(`uvicorn`, §3) — 랩 호스트에서. Zabbix가 도달 가능한 주소로.
3. 조회 전용 계정 토큰을 `ZABBIX_TOKEN`으로, Slack 크리덴셜 설정.
4. 장애 주입(chaos: 디스크 채움/error_burst) → 트리거 발화 → 미디어타입 → 게이트웨이 →
   Slack에 초동 분석 게시까지 실측. 스톱워치로 30초 확인(발표 리허설).

## 14. 인시던트 병합 (`incident.py`)

### 무엇을 푸는가

봇의 기존 한계는 **알림 1건당 트리아지 1회**였다. 복제 지연 사건에서 복제 지연·iowait·CPU
세 알림이 몇십 초 안에 들어오면, 봇은 세 번 따로 분석하고 Slack 스레드도 3개를 만든다 —
"알림 요약기"에 머물고 **사건(incident) 단위 추론**을 못 한다. §14는 같은 호스트·같은
시간창의 알림들을 코드가 하나의 인시던트로 묶고, 창이 닫히면 **통합 트리아지 1회**를
돌린다. 이것이 모니터링 성숙도의 도약(단일 지표 경보 → 시스템 내 상관 → **시스템 간 상관**)
이자 데모 C의 핵심이다. Wazuh 룰은 자기 데이터 안에서만 상관하지만, 이 병합은 Zabbix
메트릭·Loki 로그·Wazuh 경보를 시간축에서 함께 본다.

### 병합 키와 브리지 (`(host, incident_class)`)

- **분류**: `classify(alert_name, item_key)` 가 알림을 `replication` / `cpu_io_pressure` /
  `auth_security` / `disk_space` / `service_down` / `service_latency` / `network` / `other`
  중 하나로 결정적 매핑(키워드 규칙). 값이 없으면 `other`.
- **키**: `incident_key(host, class)` = `(host, bridge_id(class))`. 같은 키의 알림은 한 사건.
- **브리지 룰**: 서로 다른 class라도 `BRIDGE_GROUPS` 조합이면 같은 키로 병합. 현재 조합은
  `{replication, cpu_io_pressure}` — 복제 지연이 자원 경합(iowait/CPU)과 같은 사건일 수 있다는
  인과 후보. `host`만으로 묶지 않고 class를 넣는 이유: 동일 호스트의 **서로 다른 사건**
  (예: 복제 지연 vs 보안 브루트포스)이 한 창에 뭉치는 것을 막는다. `auth_security`는 브리지에
  없어 항상 독립 인시던트 — Wazuh 보안 신호는 별도 사건으로 보는 정직한 분리.

### 디바운스와 창 마감 (`IncidentManager`)

- 첫 알림이 인시던트를 열고, 알림이 올 때마다 디바운스 타이머를 재설정한다. 창 마감 조건은
  **마지막 알림 후 `debounce_s`(기본 90초) 무알림**, 또는 **`max_window_s`(기본 300초) 초과**.
- **우선순위 우회**: dominant SEV1 이면 `priority_debounce_s`(기본 15초)로 짧게 대기 —
  P1 성격 알림이 90초를 기다리지 않게.
- **안전장치**: `max_alerts`(기본 20) 초과분은 버리고 창을 늘리지 않아 알림 폭주에도 마감됨.
  `fingerprint()` = `(host, bridge, classes)` 해시로 재발 비교, `merge_reason()` = "동일
  호스트 · Ns 관측창 · N건 · 유형 [...] · 알려진 인과 조합" 을 Slack·LLM 컨텍스트에 노출.

### KPI 재정의 — "인시던트 확정 후 30초"

병합은 "여러 알림이 도착할 시간"을 기다려야 하므로 "첫 알림 후 30초"와 상충한다. 그래서
스톱워치 기준을 **"인시던트 확정(창 마감) 후 30초 내 통합 초동 분석 회신"** 으로 바꾼다.
측정 대상을 알림에서 사건으로 옮긴 것(KPI 완화가 아니라 대상 교체) — 상관 시스템은 개별
알림 시각이 아니라 그룹핑된 사건 단위로 다룬다.

### 코드가 결정, LLM은 설명

병합 여부·경계는 전부 코드(`incident.py`)가 결정한다. LLM은 이미 묶인 사건을 받아 축 간
인과를 **설명**만 한다 — 만성/신규 선판정과 같은 환각 방지 원칙. 통합 트리아지는
`triage.run_incident(incident)`: `collector.collect_incident_context`(알림별 Zabbix 조각 +
호스트 단위 Loki·Wazuh 1회) → `llm.triage_reply`(인시던트 형태 감지, 병합 프롬프트) →
`slack.post_triage`("N건이 1개 사건" 헤드라인). LLM·Slack 블로킹 호출은 `asyncio.to_thread`
로 감싸 타이머 루프를 막지 않는다.

### 배선 (`app.py`)

triage 경로 알림은 `triage.run`을 직접 부르지 않고 `IncidentManager.submit(Alert)`로
버퍼에 넣는다(모듈 전역 `_incidents`, `on_close=triage.run_incident`). 단건 알림도 N=1
인시던트로 동일하게 흐른다. 튜닝 환경변수: `INCIDENT_DEBOUNCE_S` / `INCIDENT_MAX_WINDOW_S` /
`INCIDENT_PRIORITY_DEBOUNCE_S` / `INCIDENT_MAX_ALERTS`.

### 검증

`python -m gateway.selftest` — 분류·브리지 키·집계·마스킹 누수는 순수 로직으로, 병합/분리/
멀티호스트 동작은 짧은 디바운스(0.05s) 비동기 버퍼로 검증(2026-07-27, 62 checks 통과).
