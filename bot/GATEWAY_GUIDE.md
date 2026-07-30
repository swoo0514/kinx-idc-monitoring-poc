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
  `auth_security` / `memory_pressure` / `disk_space` / `network` / `service_down` /
  `service_latency` / `other` 중 하나로 결정적 매핑(키워드 규칙). 값이 없으면 `other`.
  - 규칙 순서가 곧 우선순위다. `network`가 `service_down`보다 앞에 있어야 "Link down"이
    서비스 장애로 분류되지 않는다.
  - 짧은 ASCII 토큰(5자 이하)은 **단어 경계**로 매칭한다. 부분 일치가 실제 오분류를 만들었다 —
    `fim`이 confirm, `sca`가 scan·escalation, `oom`이 room, `down`이 shutdown 에 걸린다.
  - 키워드는 좁게 잡는다. `ssh` 단독은 "SSH service is down"을 보안 사건으로,
    `사용률` 단독은 메모리·CPU 사용률을 디스크로 끌어갔다(2026-07-29 실행으로 확인).
  - 검증은 selftest의 `CASES_CLASSIFY` — 표준 템플릿 트리거명·랩 실측 알림명·Wazuh 룰 설명
    23케이스. 분류를 손대면 이 표부터 늘린다.
- **키**: `incident_key(host, class)` = `(host, bridge_id(class))`. 같은 키의 알림은 한 사건.
- **브리지 룰**: 서로 다른 class라도 `BRIDGE_GROUPS` 조합이면 같은 키로 병합. 현재 두 그룹이다.
  - `{replication, cpu_io_pressure}` — 복제 지연이 자원 경합(iowait/CPU)과 같은 사건일 수
    있다는 인과 후보(데모 C 시나리오, 랩 실측으로 확인된 조합).
  - `{disk_space, service_down}` — 디스크가 차서 서비스가 멈추는 것은 한 사건(데모 B 시나리오).
  - `host`만으로 묶지 않고 class를 넣는 이유: 동일 호스트의 **서로 다른 사건**(예: 복제 지연 vs
    보안 브루트포스)이 한 창에 뭉치는 것을 막는다. `auth_security`는 브리지에 없어 항상 독립
    인시던트 — Wazuh 보안 신호는 별도 사건으로 보는 정직한 분리.
  - **그룹은 서로 겹칠 수 없다.** `_bridge_id`가 첫 매칭을 반환하므로 겹치는 class가 있으면
    뒤 그룹이 통째로 死코드가 되고, 그것도 조용히 그렇게 된다. `_validate_bridges()`가
    import 시점에 이 규칙을 강제하므로 겹치게 쓰면 프로세스가 즉시 죽는다(조용한 오작동보다 낫다).
  - `memory_pressure`는 **의도적으로 어느 그룹에도 넣지 않았다.** 자원 경합(swap→iowait→load)과
    OOM→서비스 정지 양쪽에 인과 후보가 걸치는데 그룹은 겹칠 수 없어 한쪽을 고르면 다른 쪽 링크를
    영구히 포기하게 된다. 어느 쪽이 실제로 자주 함께 뜨는지에 대한 실측이 아직 없으므로
    독립 키로 두고, 편입 여부는 co-occurrence 관측 자료가 쌓인 뒤 판단한다.

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

### 발동조건 게이트 (`should_triage`)

병합 인시던트라고 무조건 LLM을 부르지 않는다. 데모 C의 가치는 **교차 상관**이라, 엮을 게
없는 단일 축 알림에 LLM을 부르면 (a) 비용·지연 낭비 (b) "상관 없음" 맹탕 회신으로 신뢰도
저하 (c) "AI가 아무 때나 떠든다"는 인상을 준다. `should_triage(incident, context)` 가 수집
직후·LLM 호출 직전에 발동 여부를 결정한다:

- **발동**: dominant SEV1(위중) / 병합 2건 이상(여러 축 엮임) / **교차 소스 조회 실패
  (`unavailable` — 신호 없음이 아니라 미상이므로 보수적 발동, §15)** / 단일 알림이라도 같은 창에
  교차 소스(Loki 로그 또는 Wazuh 보안) 존재.
- **스킵**: 단일 축 + 교차 신호 없음(조회는 정상) → LLM·Slack 카드 생략(`gated_out: True` 반환). 원 알림은
  팀 기존 Zabbix Slack 경로로 그대로 보이므로 사라지는 게 아니다 — 봇의 **AI 분석 카드만**
  안 붙는다. 임계값 `INCIDENT_GATE_MIN_CROSS`(기본 1 = 로그·보안 중 1종이면 발동).

원리는 만성/신규·병합과 동일 — 판정은 코드가, LLM은 정말 필요할 때만. 발표 방어: "봇이 아무
알림에나 반응하냐?" → "교차 신호가 있을 때만 발동하도록 코드가 먼저 거른다".

**걸러진 사건도 Keep에는 남긴다 (G5, 2026-07-29).** LLM을 안 부르는 것이 게이트의 목적이고
저장은 LLM과 무관하므로 비용이 들지 않는다. 이걸 빠뜨리면 Keep에 "분석까지 간 사건"만 쌓이는데,
게이트에 걸리는 것은 정의상 단일 축·교차 신호 없음, 곧 **만성 노이즈의 전형**이다. 즉 만성 반복
랭킹을 하려는 바로 그 대상이 저장소에서 빠진다. `_push_gated()`가 분석 없이 판정·유형·알림 수만
실어 보낸다. 덤으로 "봇이 판단해서 조용히 넘겼다"는 기록이 남아 게이트 자체의 정당성을 사후에
검증할 수 있다.

### 검증

`python -m gateway.selftest` — 분류·브리지 키·집계·게이트·마스킹 누수는 순수 로직으로,
병합/분리/멀티호스트 동작은 짧은 디바운스(0.05s) 비동기 버퍼로 검증(2026-07-29, 77 checks 통과).

## 19. 채널 계층화 — 급한 것과 덜 급한 것을 나눈다 (2026-07-30)

### 무엇이 끊겨 있었나

`router.decide()`는 진작부터 경로를 넷으로 나눴다. `SEV1·2 → triage`, `SEV3 → digest`,
`SEV4 → dashboard_only`, `NONE → drop`. 그런데 `_dispatch`가 `triage`와 `remediate`만
소비해서 **SEV3·SEV4는 계산만 되고 조용히 버려졌다.**

이걸 지금 잇는 이유는 Wazuh 때문이다. 조사 결과 **FIM 룰은 5~7, SCA 룰은 최고가 9**라
팀 컷라인(레벨 10 이상)을 넘지 못한다. 즉 이 경로가 열려 있지 않으면 **Wazuh 모듈을 아무리 잘
튜닝해도 사람에게 아무것도 안 보인다.** 채널 계층화가 Wazuh 고도화의 선행 조건이었다.

### 어디로 보내나

| 경로 | 심각도 | Slack | Keep | LLM |
|---|---|---|---|---|
| `triage` | SEV1·2 | 메인 채널 (분석 카드) | 저장 | 호출 |
| `digest` | SEV3 | **digest 채널** (경량 카드) | 저장 | **호출 안 함** |
| `dashboard_only` | SEV4 | 없음 | 저장 | 호출 안 함 |
| `drop` | NONE | 없음 | 없음 | 호출 안 함 |

**덜 급한 것에 비싼 분석을 붙이지 않는 것**이 이 경로의 목적이다. 수집기도 LLM도 부르지 않고
알림명·호스트·유형만 가지고 게시한다.

### digest 채널이 없으면 게시하지 않는다

`SLACK_CHANNEL_ID_DIGEST`가 비어 있으면 **메인 채널로 흘려보내지 않고 건너뛴다.** 메인으로
보내면 노이즈를 걷어내려던 목적이 정확히 뒤집히기 때문이다(진단 ① Warning 99.5%). 건너뛰어도
Keep 에는 남으므로 기록이 사라지지는 않는다.

### Keep 에는 전부 남긴다

G5와 같은 이유다. 저장소가 "분석까지 간 사건"만 갖고 있으면 반복 빈도 집계의 모집단이 편향된다.
낮은 심각도야말로 반복의 주력이므로 여기서 빠지면 랭킹이 무의미해진다.

`fingerprint`를 (호스트, 유형)으로 고정해 같은 종류가 한 행에 모이게 한다. 선판정은 계산하지
않는다 — 수집기를 부르지 않는 것이 이 경로의 취지이므로, 이 구간의 랭킹은 `verdict`가 아니라
`classes` 기준 집계로 본다.

## 18. 원시 신호 fast-path — 사람이 0초에 보는 것 (P1-A, 2026-07-29)

### 문제

사람이 보는 첫 Slack 카드는 병합 트리아지 결과뿐이었고, 그것은 **디바운스 창이 닫힌 뒤에야**
나온다(기본 90초, SEV1은 15초, 최대 300초). 즉 병합 사건의 첫 사람 알림이 최악 1분 이상
늦었다. 병합은 사건 단위 상관을 위해 기다리는 것이라 창 자체를 없앨 수는 없다.

### 해결 — 신호와 분석을 분리한다

알림이 도착하는 즉시 **원시 신호 카드**를 띄우고(LLM·수집 호출 0), 분석은 그 스레드의
답글로 이어 붙인다. 원리는 "판정=코드, 해석=LLM"과 무충돌이다 — raw는 LLM을 부르지 않고
"무슨 일이 났다"만 전한다.

```
알림 도착 ── 0초 ── 원시 신호 카드(최상위)        ← 사람이 바로 봄
   └ 후속 알림 ──── 같은 스레드 답글             ← 신호는 다 보이되 부모는 하나
        └ 창 마감 후 ── 통합 분석(같은 스레드)     ← LLM 분석
```

### 부모가 하나로 유지되는 이유

`incident_key(host, class) = (host, bridge_id(class))`이므로 브리지 조합·동일 class 알림은
처음부터 같은 키다. `submit`에서 첫 알림만 `inc is None` 분기를 타고, 이후는 `else`로 간다.
따라서 원시 카드는 **인시던트당 한 번**만 최상위로 뜨고 나머지는 답글이다. "여러 부모 중
어디에 붙나" 문제가 구조적으로 생기지 않는다.

**구현 급소**: `self._open[key] = inc`를 Slack 게시(`await`)보다 **먼저** 한다. 게시하는 동안
같은 키의 알림이 도착하면 그것도 신규로 보여 부모 카드가 두 번 뜨고 스레드가 갈라진다.
asyncio는 단일 스레드 협력형이라 `await`가 없는 구간은 끊기지 않는다 — 조회(`_open.get`)와
등록(`_open[key] = inc`) 사이에 `await`가 없다는 사실이 곧 원자성 보장이다.

### 부모 하나가 보장되지 않는 경계 (넷)

1. **창이 닫히면** 키가 버퍼에서 빠지므로(`_fire_after`의 `pop`) 이후 같은 종류 알림은 새
   인시던트 = 새 부모다. 이것은 올바른 동작이다(다른 사건이므로).
2. **키가 다르면** 별개 부모다(아래 "한계").
3. **게이트웨이 재기동** 시 `_open`이 비어 진행 중이던 사건이 새 부모를 갖는다(G8).
4. **워커를 여럿 띄우면 깨진다.** `_open`은 프로세스 메모리이므로 `uvicorn --workers N` 으로
   띄우면 워커마다 버퍼가 따로 생겨 부모가 워커 수만큼 나올 수 있다. **P1-E에서 systemd
   유닛을 만들 때 `--workers`를 붙이지 말 것.** 다중 워커가 필요해지면 버퍼를 공유 저장소
   (Redis 등)로 옮기는 것이 선행 조건이다.

### 열화 동작

`on_signal` 콜백은 주입식이라 없으면 아무 일도 하지 않는다(순수 로직 테스트가 그대로 돈다).
Slack 게시가 실패해 앵커가 없으면 후속 신호는 생략하고(최상위 카드가 늘어나는 것 방지),
분석은 최상위 게시로 자연 열화한다.

### 한계

키가 다른 알림(브리지 아닌 다른 class, 예: 복제 + 디스크)은 별개 인시던트라 각자 부모를
갖는다. "떨어진 두 사건이 실은 하나"의 교차 병합은 우리 결정적 모델 밖이며 Keep 토폴로지
상관·사람 몫이다.

## 17. 심층조사 발동 — 지식이 있는 곳에서 없는 곳으로 (G9, 2026-07-29)

### 제기된 문제

브리지 룰은 사람이 "이 문제들 연관돼 있네" 하고 알아채서 넣는다. 그런데 심층조사(HolmesGPT)의
주 발동 경로가 그 병합이었다. 그러면 **가장 비싼 분석이 이미 아는 문제에만 돌아간다.** 사람이
알아채야 룰이 되고, 룰이 된 조합에서만 병합이 일어나고, 병합된 것에만 조사가 도는 고리다.

(정확히는 브리지 전용이 아니었다. `merged`는 "알림 2건 이상"이라 같은 유형 반복은 룰 없이도
병합된다. 그러나 **서로 다른 유형의 교차 상관**은 손으로 넣은 조합에서만 일어난다.)

### 해결 — 선판정을 양방향으로 쓴다

`prejudge`가 이미 만성/재발/신규를 결정적으로 계산한다. 새 지능을 만들 필요 없이 그 값을
반대 방향으로도 쓰면 된다.

| 판정 | 뜻 | 심층조사 |
|---|---|---|
| 만성 | 아는 문제, 긴급도 낮음 | **억제** — 매번 3분 30초짜리 조사를 돌릴 이유가 없다 |
| 신규 | 처음 보는 문제 | **발동** — 정보 이득이 가장 크다 |
| 재발 | 그 사이 | 종래 규칙(병합 여부) |

**순서에 의미가 있다.** SEV1(위중)과 봇 열화는 지식 여부와 무관하게 조사가 필요하므로 만성
억제보다 앞에 둔다. MSP 테넌트 경계(마스킹 없으면 금지)는 그보다도 앞이다 — 신규여도 원문이
나가면 안 된다.

`dominant_verdict(context)`가 알림별 판정을 하나로 접는다. **모르는 것이 하나라도 있으면
"신규"**(조사 가치 최대), 전부 아는 문제면 "만성", 그 사이는 "재발".

### 남는 한계 (정직하게)

이것은 **분석 자원의 배분**을 고칠 뿐, "사람이 알아챈 조합만 룰이 된다"는 순환 자체를 끊지
않는다. 순환을 끊는 것은 **co-occurrence → 브리지 룰 후보 제안**(데이터가 제안하고 사람이
확정)이고 로드맵 항목이다. 보류한 `memory_pressure` 편입이 그 메커니즘의 첫 실사용처다.

## 16. 조치 후보 경로 — 데모 B 배관 복구 (P0-1, 2026-07-29)

### 무엇이 끊겨 있었나

`router.decide()`는 SEV1·2 알림에 `automate` 태그가 있고 계약이 조치를 막지 않으면
`{route: "remediate", playbook}`을 계산했다. 그런데 `_dispatch`가 `triage`만 처리하고 나머지를
조용히 버려서, **데모 B(자가 치유)의 배관이 코드에서 끊겨 있었다.** 실행 뒷단(Keep 워크플로 →
SSH → `ansible-playbook`)은 이미 e2e로 검증돼 있었으므로 빠진 것은 앞단 한 조각이었다.

### 흐름과 역할 분담

```
Zabbix 트리거(automate 태그)
  → 게이트웨이 _dispatch: route=remediate
  → keep.push_alert(조치 후보, 승인 대기)        ← 봇은 여기까지
  → [사람] Keep UI 에서 Run Workflow = 승인
  → Keep 워크플로 → SSH(core) → ansible-playbook → 조치 후 상태 재검증
```

봇이 판단까지만 하고 실행에 손대지 않는 것이 핵심이다. 계약 게이트(`scope=notify_only`)는
`router` 단에서 이미 걸러지므로, 조치 후보로 등록되는 것은 조치가 허용된 알림뿐이다.

### 태그 규약 (Zabbix 트리거에 부여)

| 태그 | 값 | 뜻 |
|---|---|---|
| `automate` | `service_restart` | 조치 후보로 등록할 플레이북 논리명 |
| `service` | `chronyd` 등 | 조치 대상 서비스 |
| `scope` | `notify_only` | (선택) 계약상 조치 금지 — 있으면 triage 로 흐른다 |

### 파라미터 하드코딩 제거

기존 워크플로는 `-e target_host=... -e service_name=...` 을 고정값으로 갖고 있었다. 봇이 후보를
올려도 워크플로가 그 값을 안 읽으면 "배관은 이었는데 값은 여전히 고정"이라 시연 중 반문이
나온다. 이제 워크플로가 `{{ alert.host }}` · `{{ alert.service }}` · `{{ alert.playbook }}` 로
알림 필드를 참조한다. **근거(공식 문서)**: Keep `workflows/syntax/context` — "You can access
attributes of the alert anywhere in the workflow: `{{ alert.name }}`" 이며 `{{ alert.customer_id }}`
예시처럼 **임의 커스텀 속성**도 참조 가능하다. 트리거 종류는 manual / interval / alert / incident.

워크플로 첫 단계에 `if: "'{{ alert.playbook }}' == 'service_restart'"` 안전 게이트를 두어, 다른
조치 후보 알림에서 실수로 Run 해도 아무 일이 일어나지 않게 했다.

`fingerprint`는 (호스트·플레이북·서비스)로 고정한다. 같은 조치 후보가 반복 발화해도 Keep에서
한 행으로 모여 승인해야 할 것이 한 줄로 유지된다.

### 랩 배선 절차 (사용자 실행)

1. `git pull` 후 `python -m gateway.selftest` → `ALL OK (109 checks)` 확인
2. Zabbix에서 대상 트리거에 `automate=service_restart`, `service=chronyd` 태그 부여
3. Keep에 갱신된 워크플로 반영(프로비저닝 디렉토리 재적용 또는 UI 갱신)
4. `chaos/service_down.sh <대상> chronyd` 로 서비스 정지
5. 게이트웨이 로그에서 `route=remediate` 와 `remediation queued ...` 확인
6. Keep UI에서 조치 후보 알림 확인 → Run Workflow(승인) → Ansible 실행·재검증 결과 확인

### 미확인 항목

**수동 실행(Run Workflow) 시 알림 컨텍스트가 실리는지**는 공식 문서에 명시가 없다. 알림
행에서 실행하면 실릴 가능성이 높지만 확인이 필요하다. 4~6번 절차에서 명령이 실제 호스트·서비스
값으로 치환됐는지 SSH 실행 로그로 확인할 것. 만약 비어 있으면 대안은 트리거를 `type: alert` +
CEL 필터로 바꾸고 승인 단계를 워크플로 안에 두는 것이다.

## 15. 교차 소스 조회 상태 — "신호 없음"과 "조회 실패"의 구분 (G1, 2026-07-29)

### 무엇이 문제였나

수집기의 Loki·Wazuh 조회는 실패를 예외 삼킴으로 처리하고 빈 리스트를 돌려줬다. 그래서 **"신호가
없다"와 "조회에 실패했다"가 코드상 같은 값**이었고, 그 빈 값을 두 곳이 소비하면서 파급이 번졌다.

1. **LLM 프롬프트가 빈 값을 긍정으로 해석하라고 지시**했다 — "security가 비어 있으면 침해·비인가
   변경 흔적 없음으로 해석하라". 즉 Wazuh 인덱서가 죽으면 봇이 **침해를 배제했다고 단언**한다.
   데모 C의 핵심 장면이 "Wazuh 정상 → 침해 배제"라 정확히 그 장면이 거짓이 된다.
2. **발동조건 게이트도 같은 빈 값으로 판단**했다. 관측 백엔드가 죽으면 교차 신호가 0으로 보여
   **봇이 조용해진다** — 가장 필요한 순간에 침묵한다.

봇이 틀리는 것보다 **틀린 줄 모르고 자신 있게 틀리는 것**이 도입 심사에서 치명적이다.

### 상태 계약 (`collector.SOURCE_*`)

| 상태 | 의미 | 빈 목록의 해석 |
|---|---|---|
| `ok` | 조회 성공 | "없음"이 **사실** — 침해 배제 근거로 사용 가능 |
| `unavailable` | 조회를 시도했으나 실패(예외·HTTP 오류·호스트 라벨 미해석) | **미상** — 근거로 사용 금지 |
| `disabled` | 미배선(URL 미설정) | 애초에 근거 없음 |

`unavailable`과 `disabled`를 나눈 이유는 게이트 동작이 달라야 하기 때문이다. 조회 실패는 "알 수
없다"이므로 보수적으로 LLM을 발동시키지만, 미배선은 의도된 구성이라 발동 사유가 아니다. 둘을
합치면 Loki를 안 붙인 환경에서 게이트가 항상 발동해 게이트의 존재 이유가 사라진다.

### 변경 지점 (자료형은 그대로 — 가산 변경)

`logs`/`security`를 `{status, items}` 형태로 바꾸면 마스킹·게이트·열화 모드·selftest가 연쇄로
깨진다. 검증된 e2e를 흔들지 않으려고 **리스트는 그대로 두고 `sources` 필드를 옆에 붙이는** 방식을
택했다.

- `collector.py` — 조회 함수가 `(목록, 상태)` 튜플 반환. `collect_context`·
  `collect_incident_context` 결과에 `"sources": {"logs": ..., "security": ...}` 추가.
- `masking.py` — `_sources()`가 **알려진 키·값만** 통과시키고 그 밖은 `unknown`으로 강등.
  상태 문자열에는 식별자가 없어 마스킹 대상이 아니다(전송 명세표에 편입).
- `llm.py` — 프롬프트 규칙을 상태 기반으로 개정. `ok`일 때만 "흔적 없음"으로 해석하고,
  그 외에는 "보안 축 조회 불가 — 침해 여부 미상"이라고 쓰게 했다.
- `incident.py` — `should_triage`가 `unavailable`이면 보수적 발동.
- `slack.py` — `_source_note()`가 카드에 "⚠️ 조회 실패: 보안(Wazuh) — 이 축은 '이상 없음'이
  아니라 '미상'"을 표기. 사람 눈에도 드러낸다.
- `triage.py` — 수집이 통째로 실패한 폴백 컨텍스트도 상태를 `unavailable`로 채운다.

### 검증

selftest 11건 추가(외부 호출 0 — 미배선·라벨 미해석 경로만). 미배선/실패 상태 반환, 게이트 3분기
(정상·실패·미배선), 마스킹 화이트리스트(미지 키 차단·미지 값 강등), Slack 문구, **프롬프트와 코드의
동기**(`sources.security`를 안 보는 프롬프트로 되돌아가면 실패)까지 잠갔다.
