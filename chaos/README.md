# chaos/ — 장애 주입 스크립트

데모에서 "장애를 일으켜 관제 화면이 반응하는 것"을 재현하기 위한 스크립트 모음입니다. 모두 **랩 전용**이며, 실환경에서는 실행하지 않습니다.

라이브 데모가 실패할 경우를 대비한 사전 녹화, 리허설, 그리고 "누구나 재현"이라는 산출물 가치를 위해 장애 주입을 코드로 관리합니다.

> **시연 전체를 순서대로 돌리려면 [`docs/04-demo/runbook.md`](../docs/04-demo/runbook.md)를 봅니다.** 이 문서는 스크립트
> 하나하나가 무엇을 하는지를 설명하고, 런북은 관측 코어 기동부터 게이트웨이·Keep 준비, 확인
> 화면, 되돌리기까지를 시나리오 단위로 이어 놓은 것입니다.

## 실행 위치

장애의 성격에 따라 실행 위치가 다릅니다. 실제 IP·대상은 인자로 전달하며 스크립트에 하드코딩하지 않습니다(랩 IP 커밋 방지).

- **`ssh_bruteforce.sh`** — 노드의 22번 포트로 접근하는 외부 공격 시뮬이므로, **노드와 같은 사설망 안의 호스트**(예: 관측 코어 VM)에서 대상 IP를 인자로 실행합니다.
- **`repl_lag.sh`** — slave DB 복제를 다루므로, **관측 코어 VM의 `lab/` 디렉토리**(docker compose 접근)에서 실행합니다.
- **`repl_lag_contention.sh`** — 슬레이브 VM(vm-target-002)의 디스크 I/O를 포화시키므로, **그 슬레이브 VM에서 직접** 실행합니다.
- **`error_burst.sh`** — 노드 로그에 직접 쓰므로, **감시 노드에서 직접** 실행합니다.
- **`service_down.sh`** — 대상 노드의 서비스를 정지시키므로, **작업자 PC에서 SSH 별칭으로** 실행합니다(`service_down.sh vm-target-002 chronyd`). 관측 코어 VM에는 SSH 별칭이 없어 이름을 못 찾습니다. 이 대상은 **이름이 셋이라 헷갈리기 쉽습니다** — 대응표는 [`docs/01-build/hosts.md`](../docs/01-build/hosts.md).

## 스크립트

### `ssh_bruteforce.sh` — 보안 이벤트(브루트포스) 주입

SSH 무차별 대입을 시뮬레이션하여 Wazuh 레벨 10(룰 5712) 보안 이벤트를 발생시킵니다.

- 사용: `./ssh_bruteforce.sh <대상_IP> [횟수=12] [계정=badguy]`
- 원리: 없는 계정으로 반복 로그인 실패 → 룰 5710(level 5) 누적 → 120초 내 8회 초과 시 5712(level 10)로 격상 (Wazuh 상관 분석)
- 확인: Wazuh 대시보드 → Threat Hunting → `rule.id:5712`
- 용도: 데모 A 보안 축, 데모 C(AI 트리아지) 입력 소재

### `service_down.sh` — 서비스 정지 (데모 B 입력)

대상 노드의 서비스를 정지시켜 자가 치유 흐름을 처음부터 끝까지 돌립니다.

- 사용: `./service_down.sh <ssh_대상> [서비스=chronyd]`
- 흐름: 정지 → Zabbix 서비스 트리거 발화 → 게이트웨이가 `automate` 태그를 보고 조치 후보를
  Keep 승인 큐에 등록 → 사람이 Run Workflow(승인) → Ansible 이 재기동하고 상태를 재검증
- 전제: 그 트리거에 `automate=service_restart` 태그와 `service=<서비스명>` 태그가 붙어 있어야
  조치 경로를 탑니다(태그가 없으면 일반 트리아지로 흐릅니다). 계약상 조치 금지 대상이면
  `scope=notify_only` 태그가 조치를 차단합니다.
- 기본값을 `chronyd`로 둔 이유: 랩에 항상 있고 정지해도 서비스 영향이 없어 반복 시연이 안전합니다.

### `repl_lag.sh` — 복제 지연(메트릭 깊이) 유발

master에 대량 쓰기를 걸어 slave 복제 지연을 만듭니다.

- 사용: `./repl_lag.sh [배가횟수=14]`
- 원리: master 대량 쓰기 → slave 단일 SQL 스레드가 재생을 못 따라감 → `Slave_SQL_Running=Yes`를 유지한 채 `Seconds_Behind_Master`만 급등
- 확인: Grafana `KINX 복제 품질` 대시보드 — 상태 Up(1) 유지, 지연(초) 급등
- 용도: 메트릭 깊이 1축(상태만 보면 정상, 지연을 봐야 밀림이 보임)

### `repl_lag_contention.sh` — 복제 지연(자원 경합, 데모 C)

슬레이브 VM의 디스크 I/O를 백업성 부하로 포화시켜 복제가 밀리게 합니다. `repl_lag.sh`(master 대량 쓰기)와 달리 **원인이 자원 경합**이라, 데모 C의 "복제 고장인가 자원 경합인가" 재프레이밍의 소재입니다.

- 사용: `DURATION=180 MASTER_HOST=<master 사설 IP> DEMO_WRITER_USER=... DEMO_WRITER_PASSWORD=... ./repl_lag_contention.sh`
- 실행 위치: 슬레이브 VM(vm-target-002). 사전 구축은 `lab/mariadb/REPL_VM_GUIDE.md`
- 원리: syslog 백업 마커(Loki 교차신호) + 디스크 I/O 포화(대용량 쓰기·로컬 덤프) + master 가벼운 쓰기(복제 스트림) → iowait↑ + `Seconds_Behind_Master`↑ 가 같은 호스트·시간창에
- 확인: Zabbix(지연·iowait 급등) + Loki(백업 로그) + Wazuh(경보 없음=침해 배제) → 봇이 1개 인시던트로 병합
- 용도: 데모 C(AI 트리아지·인시던트 병합) 핵심 시나리오

### `error_burst.sh` — 오류율(로그 기반) 급등

`logger`로 감시 노드 로그에 ERROR를 주입해 Loki 오류율을 급등시킵니다.

- 사용: `./error_burst.sh [건수=300] [태그=payment-api]`
- 원리: `user.err` 로그 → rsyslog가 `/var/log/messages` 기록 → Alloy(`job=varlogs`) → Loki. `rate`로 오류율 지표화
- 확인: Grafana Loki 패널 `sum(rate({job="varlogs"} |= "ERROR" [1m]))` 급등
- 용도: 메트릭 깊이 2축(로그는 수집하는데 오류율을 지표로 안 봄)

### `snmp_iface_error.sh` — 인터페이스 에러 노이즈 폭주 (알림 다이어트 Before)

snmpsim 에러 데이터를 켰다 껐다 반복해 델타 트리거를 반복 발화시킵니다.

- 사용: `./snmp_iface_error.sh [사이클=6] [체류초=70]`
- 실행 위치: 관측 코어 VM의 `lab/`(docker compose 접근)
- 원리: `switch1.error.snmprec`(`rate=3`)와 `switch1.clean.snmprec`(`rate=0`)를 번갈아 물리고 snmpsim 재기동 → `ifInErrors`가 증가/고정을 반복 → `change()>2` 트리거가 PROBLEM/OK 반복
- 확인: Monitoring → Problems 에 반복 발화 누적
- 용도: 알림 다이어트 Before(노이즈 폭주). After 4종 정비(recovery expression·의존성·이벤트 상관·maintenance)로 1건 수렴 대비

### `seed_security.sh` — 보안 이벤트 시드

파일 무결성(FIM) 승격 룰이 걸린 경로에 마커를 심어 보안 이벤트를 만듭니다. 대시보드·리포트의
보안 절이 비어 있지 않게 하는 용도입니다.

- 확인: Wazuh 대시보드 → Threat Hunting → `rule.id:100201`(승격 룰) / `rule.groups:syscheck`
- 인증 실패 축은 별도입니다 — `ssh_bruteforce.sh`를 함께 돌립니다.
- **설정 파일을 건드리므로 반드시 되돌립니다.** 절차는 스크립트 출력과 런북 §4-B-4.

## 추가 예정

| 스크립트 | 주입 내용 | 관제 반응 |
| --- | --- | --- |
| `disk_fill.sh` | 디스크 사용률 상승 (fallocate) | 디스크 임계치 트리거 |
| `service_kill.sh` | 서비스 프로세스 종료 | proc.num 트리거 |

각 스크립트는 대상·강도를 인자로 받아 재현 가능하게 작성하며, 어떤 관제 화면이 어떻게 반응하는지를 본 README에 명시합니다.
