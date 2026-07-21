# chaos/ — 장애 주입 스크립트

데모에서 "장애를 일으켜 관제 화면이 반응하는 것"을 재현하기 위한 스크립트 모음입니다. 모두 **랩 전용**이며, 실환경에서는 실행하지 않습니다.

라이브 데모가 실패할 경우를 대비한 사전 녹화, 리허설, 그리고 "누구나 재현"이라는 산출물 가치를 위해 장애 주입을 코드로 관리합니다.

## 실행 위치

장애의 성격에 따라 실행 위치가 다릅니다. 실제 IP·대상은 인자로 전달하며 스크립트에 하드코딩하지 않습니다(랩 IP 커밋 방지).

- **`ssh_bruteforce.sh`** — 노드의 22번 포트로 접근하는 외부 공격 시뮬이므로, **노드와 같은 사설망 안의 호스트**(예: 관측 코어 VM)에서 대상 IP를 인자로 실행합니다.
- **`cpu_stress.sh`** — 노드 자신의 CPU를 태우는 것이므로, **SSH로 그 노드에 로그인해 실행**합니다. 작업자 PC에서 SSH 별칭으로 원격 실행하거나(`cpu_stress.sh node1`), 노드에서 직접 실행합니다.
- **`repl_lag.sh`** — slave DB 복제를 다루므로, **관측 코어 VM의 `lab/` 디렉토리**(docker compose 접근)에서 실행합니다.
- **`error_burst.sh`** — 노드 로그에 직접 쓰므로, **감시 노드에서 직접** 실행합니다.

## 스크립트

### `ssh_bruteforce.sh` — 보안 이벤트(브루트포스) 주입

SSH 무차별 대입을 시뮬레이션하여 Wazuh 레벨 10(룰 5712) 보안 이벤트를 발생시킵니다.

- 사용: `./ssh_bruteforce.sh <대상_IP> [횟수=12] [계정=badguy]`
- 원리: 없는 계정으로 반복 로그인 실패 → 룰 5710(level 5) 누적 → 120초 내 8회 초과 시 5712(level 10)로 격상 (Wazuh 상관 분석)
- 확인: Wazuh 대시보드 → Threat Hunting → `rule.id:5712`
- 용도: 데모 A 보안 축, 데모 C(AI 트리아지) 입력 소재

### `cpu_stress.sh` — 자원 메트릭(CPU) 급등

노드의 전 코어에 busy-loop을 걸어 CPU utilization을 100%로 올립니다(의존성 없이 순수 bash).

- 사용: `./cpu_stress.sh <ssh_대상> [지속초=60]`
- 원리: 대상의 `nproc` 개수만큼 `while :; do :; done` 워커를 `timeout`으로 실행 → 지정 시간 후 자동 종료
- 확인: Grafana 메트릭 패널(Zabbix `CPU utilization`) 급등
- 용도: 데모 A 메트릭 축. 브루트포스와 함께 주입하면 메트릭·로그·보안 세 축이 같은 순간에 반응

### `repl_lag.sh` — 복제 지연(메트릭 깊이) 유발

master에 대량 쓰기를 걸어 slave 복제 지연을 만듭니다.

- 사용: `./repl_lag.sh [배가횟수=14]`
- 원리: master 대량 쓰기 → slave 단일 SQL 스레드가 재생을 못 따라감 → `Slave_SQL_Running=Yes`를 유지한 채 `Seconds_Behind_Master`만 급등
- 확인: Grafana `KINX 복제 품질` 대시보드 — 상태 Up(1) 유지, 지연(초) 급등
- 용도: 메트릭 깊이 1축(상태만 보면 정상, 지연을 봐야 밀림이 보임)

### `error_burst.sh` — 오류율(로그 기반) 급등

`logger`로 감시 노드 로그에 ERROR를 주입해 Loki 오류율을 급등시킵니다.

- 사용: `./error_burst.sh [건수=300] [태그=payment-api]`
- 원리: `user.err` 로그 → rsyslog가 `/var/log/messages` 기록 → Alloy(`job=varlogs`) → Loki. `rate`로 오류율 지표화
- 확인: Grafana Loki 패널 `sum(rate({job="varlogs"} |= "ERROR" [1m]))` 급등
- 용도: 메트릭 깊이 2축(로그는 수집하는데 오류율을 지표로 안 봄)

## 추가 예정

| 스크립트 | 주입 내용 | 관제 반응 |
| --- | --- | --- |
| `disk_fill.sh` | 디스크 사용률 상승 (fallocate) | 디스크 임계치 트리거 |
| `service_kill.sh` | 서비스 프로세스 종료 | proc.num 트리거 |
| `snmp_iface_error` | snmpsim 인터페이스 에러 카운터 증가 | 알림 다이어트 데모(노이즈 재현) |

각 스크립트는 대상·강도를 인자로 받아 재현 가능하게 작성하며, 어떤 관제 화면이 어떻게 반응하는지를 본 README에 명시합니다.
