# 데모 실행 런북 — 시나리오별 시연 실행 가이드

본 문서는 리허설 및 라이브 시연을 위한 시나리오별 실행 명령어, 검증 관측 경로 및 트러블슈팅 절차를 명시한 가이드입니다.

* **장애 주입 스크립트 세부 동작 원리:** [`chaos/README.md`](../../chaos/README.md)
* **게이트웨이 및 관제 플랫폼 연동 메커니즘:** [`bot/GATEWAY_GUIDE.md`](../../bot/GATEWAY_GUIDE.md), [`keep/KEEP_GUIDE.md`](../../keep/KEEP_GUIDE.md)
* **호스트 식별자, IP 주소 및 저장소 위치 매핑:** [`docs/01-build/hosts.md`](../01-build/hosts.md) (*본 문서의 IP 주소는 예시용 플레이스홀더이므로 실행 전 해당 문서를 참조합니다.*)

---

## 1. 공통 사전 준비 절차 (전체 시나리오 공통 선행 과제)

### 1-1. 관측 코어 컨테이너 기동

```bash
ssh core
cd ~/kinx-idc-monitoring-poc/lab
docker compose up -d
docker compose ps
```

`mariadb` 서비스 상태가 `healthy`로 전환된 후 `zabbix-server` ➔ `zabbix-web` 순서로 기동됩니다. 정상 기동 여부는 아래 로그 명령어로 확인합니다.

```bash
docker compose logs --tail=20 zabbix-server | grep "server #0 started"
```

### 1-2. 게이트웨이(분석 봇) 프로세스 기동

게이트웨이 데몬이 미실행 상태일 경우 알림 수집, Slack 통보 및 Keep 연동이 수행되지 않습니다.

**기존 프로세스 점검 및 완전 종료:**  
환경변수(`.env`) 변경 사항을 적용하고 포트 중복을 방지하기 위해 기존 실행 중인 프로세스를 종료합니다.

```bash
ssh core
ps -ef | grep uvicorn | grep -v grep
kill <식별된_PID>
sleep 1; ps -ef | grep uvicorn | grep -v grep      # 조회 결과가 없어야 정상
```

**파이썬 가상환경 활성화 및 게이트웨이 데몬 기동:**

```bash
ssh core
source ~/bot-venv/bin/activate
cd ~/kinx-idc-monitoring-poc/bot
set -a; source .env; set +a
nohup python -m uvicorn gateway.app:app --host 0.0.0.0 --port 8800 > /tmp/gw.log 2>&1 &
sleep 5 && cat /tmp/gw.log
```

로그 출력에서 `Application startup complete` 및 `Uvicorn running on http://0.0.0.0:8800` 구문을 확인합니다.

> **운영 유의사항:**
> * `address already in use` 에러 발생 시 기존 PID 종료 상태를 재점검합니다.
> * 로그에 `nohup: ignoring input` 구문만 존재하고 데몬이 기동되지 않을 경우, 백그라운드(`&`) 옵션을 제외하고 대화형으로 실행하여 에러 로그를 직접 확인합니다.
> * uvicorn 실행 시 `--workers` 옵션을 사용하지 않습니다. 워커별로 인메모리 인시던트 버퍼가 따로 생성되어 동일 사건에 대해 중복 알림 카드가 발송됩니다.

**동작 상태 검증:**

```bash
curl http://localhost:8800/healthz
```

*(상세 환경변수 명세: [`bot/.env.example`](../../bot/.env.example))*

### 1-3. Keep 관제 플랫폼 상태 재검증 (데모 B 시나리오 전용)

Keep 워크플로 파일은 **Keep 서비스 재시작 시점에만 재로드**됩니다. 워크플로 정의 수정 후 반드시 재시작을 수행합니다.

```bash
ssh keep
cd ~/kinx-idc-monitoring-poc
git pull
docker compose restart keep-backend
```

브라우저 접속(`http://<KEEP_IP>:3000`) ➔ Workflows 메뉴에서 `Remediate service via Ansible` 항목 노출 여부를 확인합니다.

### 1-4. 시연 당일 인프라 최종 점검

```bash
ssh core
cd ~/kinx-idc-monitoring-poc/bot && python -m gateway.selftest
```

*추가 점검:* **Anthropic API 크레딧 잔액을 사전 확인**합니다. 크레딧 소진 시 LLM 인과 분석이 실패하고 코드 기반 선판정 결과만 회신되는 열화(Degraded) 모드로 동작합니다.

---

## 2. 시나리오 A — DB 복제 지연 및 자원 경합 (데모 C, AI 초동 분석)

**시연 목적:**  
서로 다른 트리거에서 분산 수신된 알림 2건을 봇이 **단일 인시던트로 자동 병합**하고, "단순 복제 장애가 아닌 백업 부하로 인한 I/O 경합"으로 근본 원인을 재프레이밍(Reframing)하는 과정을 검증합니다.

*실행 대상 호스트:* `node2` (DB 복제 슬레이브 VM)

### 2-1. 장애 주입 절차

`node2` VM은 복제 전용 노드로 소스 코드 저장소가 존재하지 않으므로, **작업자 PC에서 스크립트를 수시 전송**하여 실행합니다.

```bash
# 1. 작업자 PC에서 스크립트 전송
scp chaos/repl_lag_contention.sh node2:~/

# 2. node2 VM 접속 및 부하 주입 실행
ssh node2
export MASTER_HOST=192.0.2.26          # core 노드 사설 IP (hosts.local.md 참조)
export DEMO_REPL_DB=demo_repl
export DEMO_WRITER_USER=demowriter
read -rs -p "writer pw: " DEMO_WRITER_PASSWORD && export DEMO_WRITER_PASSWORD
DURATION=420 bash ~/repl_lag_contention.sh
```

* 자격 증명 보안 관리를 위해 비밀번호는 `read -rs` 명령을 통해 대화형으로 입력받습니다.
* **`DURATION` 설정:** 최소 **420초(7분) 이상**으로 지정합니다. Zabbix 복제 지연 트리거 조건이 `min(lag, 5m) > 임계치`로 설정되어 있어, 지연 상태가 5분 이상 지속되어야 알림이 발화합니다.

*(해당 스크립트는 디스크 I/O 포화, 로컬 DB 덤프 연산, Master 노드 대량 Write, Syslog 백업 마커 기록을 동시에 수행하여 교차 신호를 생성합니다.)*

### 2-2. 관측 및 검증 경로

| 순번 | 관측 시스템 및 경로 | 검증 항목 |
|---|---|---|
| 1 | Grafana (`core:3000`) | DB 복제 지연 지표 상승, CPU/Load Average 지표 동시 수직 상승 확인 |
| 2 | Zabbix (`core:8080`) ➔ Problems | 동일 호스트 대상 `High` 심각도 알림 2건 발화 (복제 지연 / Load Average) |
| 3 | Slack 채널 | **"2건 알림 ➔ 1개 사건 병합"** 카드 생성 및 LLM 인과관계 분석 회신 확인 |
| 4 | Keep (`keep:3000`) | 병합된 사건이 단일 인시던트 행으로 수집/저장되었는지 확인 |

*알림 카드 회신 소요 시간 지표는 첫 알림 수신 시점이 아닌 **인시던트 디바운스 창 마감(사건 확정) 시점부터 30초 이내**를 기준으로 측정합니다.*

### 2-3. 복구 및 상태 원복

스크립트 내부 `trap` 핸들러에 의해 시뮬레이션 종료 시 임시 파일 삭제 및 백그라운드 프로세스가 자동 정리되며, 지연 지표가 0으로 수렴합니다. (중도 중단 시 `Ctrl+C` 실행)

슬레이브 노드 복제 상태 정밀 확인:

```bash
ssh node2 "sudo mariadb -e 'SHOW SLAVE STATUS\G'" | grep -E "Seconds_Behind|Running"
```

`Slave_IO_Running` 및 `Slave_SQL_Running` 항목이 모두 `Yes` 상태여야 합니다.

*(상세 세부 가이드: [`scenario-c-replication.md`](scenario-c-replication.md))*

---

## 3. 시나리오 B — SSH 무차별 대입 공격 (데모 A, 보안 관측 축)

**시연 목적:**  
동일 시점/동일 호스트 기준 메트릭·로그·보안 3개 관측 축 데이터가 동시 수집되고, Wazuh가 무차별 대입 공격을 감지하여 **레벨 10 경보로 격상** 처리하는 과정을 검증합니다.

*실행 위치:* `core` 노드 (사설망 내부에서 `node1` 대상을 향해 공격 시뮬레이션 실행)

### 3-1. 장애 주입 절차

```bash
ssh core
cd ~/kinx-idc-monitoring-poc/chaos
./ssh_bruteforce.sh 192.0.2.10 12 badguy      # 인자: <대상 IP> [시도횟수=12] [계정명=badguy]
```

Wazuh 룰 엔진이 120초 이내 8회 이상 실패 패턴을 상관하여 룰 5710(레벨 5)을 **룰 5712(레벨 10)**로 승격시키므로, 시도 횟수를 12회 이상으로 설정합니다. (`BatchMode=yes` 옵션이 적용되어 실제 인증은 실패 처리됨)

### 3-2. 관측 및 검증 경로

| 순번 | 관측 시스템 및 경로 | 검증 항목 |
|---|---|---|
| 1 | Wazuh (`dashboard`) ➔ Threat Hunting | `rule.id:5712` 조회 ➔ 레벨 10 보안 경보 이벤트 확인 |
| 2 | Grafana (`core:3000`) 통합 관제 | 보안 패널 스파이크 발생 및 Loki 로그 내 `invalid user badguy` 동일 타임라인 표출 |
| 3 | Grafana 보안 패널 행 클릭 | `agent.name` 값이 `$host` 변수로 전달되어 **Loki 로그가 해당 호스트 조건으로 자동 필터링되는 드릴다운** 동작 확인 |

### 3-3. 복구 및 상태 원복

단순 인증 실패 테스트이므로 대상 서버의 시스템 상태 변경이 발생하지 않아 별도 원복 절차가 필요하지 않습니다. (리허설 반복 실행 시 Wazuh 대시보드 조회 시간 범위를 `Last 15 minutes`로 설정하여 관측)

---

## 4. 시나리오 C — 자가 치유 (데모 B, HITL 승인 기반 조치)

**시연 목적:**  
서비스 중단 알림 발생 시 봇이 해당 알림을 자동 조치 후보로 분류하여 승인 큐에 등록하고, **관제 담당자의 승인(Run 버튼 클릭)을 통해 Ansible 기반 자동 재기동 및 재검증**이 실행되는 전체 제어 흐름을 검증합니다.

*실행 위치:* **작업자 PC** (SSH 별칭 기반 실행을 위해 작업자 PC 환경의 Git Bash에서 실행)

### 4-1. 장애 주입 절차

```bash
# 작업자 PC Git Bash 환경에서 실행
cd <저장소_경로>/chaos
./service_down.sh vm-target-002 chronyd
```

*(대상 인자: `<SSH_별칭> [서비스명=chronyd]`)*

### 4-2. 관측 및 검증 경로

| 순번 | 관측 시스템 및 경로 | 검증 항목 |
|---|---|---|
| 1 | Zabbix (`core:8080`) ➔ Problems | 서비스 중단 트리거 발화 확인 |
| 2 | Keep (`keep:3000`) | 해당 알림이 **조치 후보(Action Candidate)**로 분류되어 승인 큐에 등록됨 확인 |
| 3 | Keep 알림 상세 ➔ **Run Workflow** | `Remediate service via Ansible` 선택 ➔ **명시적 승인 실행** |
| 4 | 워크플로 실행 로그 | `run-ansible-remediation ran successfully`, PLAY RECAP 내 `changed=1` 확인 |
| 5 | 워크플로 실행 결과 | `before: inactive -> after: active` 재검증 출력 확인 |

**HITL 승인 및 안전 게이트 메커니즘:**
* 해당 워크플로는 `manual` 트리거 방식으로 구동되므로 사용자 승인 전에는 자동 실행되지 않습니다.
* 워크플로 첫 단계에서 `alert.playbook == 'service_restart'` 조건을 검증하여, 불일치 시 실행을 차단하는 안전 게이트가 적용되어 있습니다.
* MSP 위탁 계약 조건상 자동 조치가 금지된 자산은 `scope=notify_only` 태그에 의해 조치 라우팅 경로 진입이 차단됩니다.

### 4-3. 필수 전제 조건 (Zabbix 태그 설정)

해당 트리거에 **`automate=service_restart`** 및 **`service=chronyd`** 태그가 설정되어 있어야 자동 조치 후보로 라우팅됩니다. 태그 미설정 시 일반 초동 분석(Triage) 경로로 전환되어 Slack 알림만 발송됩니다. (Zabbix ➔ Trigger ➔ Tags 탭 확인)

### 4-4. 복구 및 재시연 안내

Ansible 플레이북에 의해 서비스가 자동 재기동 및 검증 완료되므로 별도 수동 원복이 필요하지 않습니다. 리허설 재실행 시 스크립트를 재호출합니다.

수동 서비스 상태 점검:

```bash
ssh vm-target-002 systemctl is-active chronyd
```

---

## 5. 시나리오 D — 무차별 대입 공격 + 보안 설정 변경 (복합 보안 시나리오)

**시연 목적:**  
단순 무차별 대입 공격에 이어 '로그인 성공' 및 '`/etc/ssh/sshd_config` 파일 변조' 이벤트가 연속 발생할 때, 봇이 3가지 이벤트를 **단일 사건으로 병합**하고 심층 조사를 통해 "2단계 공격(침투 후 지속성 확보)"임을 명확히 규명하는 과정을 검증합니다.

### 5-1. 장애 주입 절차

독립된 이벤트들이 단일 인시던트로 병합되도록 **두 명령을 연달아 실행**합니다. (이벤트 간격이 디바운스 창인 90초를 초과하지 않도록 유의)

```bash
# 1. SSH 무차별 대입 공격 주입 (core 노드에서 실행)
ssh core
~/kinx-idc-monitoring-poc/chaos/ssh_bruteforce.sh 192.0.2.16 15 hacker3

# 2. 정상 로그인 및 보안 설정 파일 변조 (직후 실행)
ssh node2 "echo '# demo marker' | sudo tee -a /etc/ssh/sshd_config"
```

*(두 번째 명령을 통해 '실패 후 로그인 성공' 및 'FIM 핵심 보안 파일 변경' 경보가 동시에 생성됩니다.)*

### 5-2. 관측 및 검증 경로

| 순번 | 관측 시스템 및 경로 | 검증 항목 |
|---|---|---|
| 1 | Slack 스레드 | 원시 신호 3건(브루트포스 / 실패 후 성공 / sshd_config 변조)이 **단일 스레드로 수집**됨 확인 |
| 2 | Slack 알림 카드 | **"3건 알림 ➔ 1개 사건 병합"** 카드 및 코드 기반 선판정 회신 확인 |
| 3 | Slack 스레드 | **HolmesGPT 심층 조사 결과 회신** (공격 타임라인 및 2단계 연쇄 공격 규명) |
| 4 | Keep (`keep:3000`) | 동일 인시던트 단일 행 수집 및 심층 조사 결과가 Note 항목으로 첨부됨 확인 |

### 5-3. 심층 조사(HolmesGPT) 발동 메커니즘 분석

Wazuh 보안 알림은 전용 트리거 ID가 없어 과거 이력 기반의 선판정이 **`미상(Unknown)`**으로 산출됩니다. 이에 따라 만성 억제 로직을 타지 않고 **`merged` (다중 알림 병합 사건) 조건에 부합하여 심층 조사가 자동 발동**됩니다.

게이트웨이 로그를 통한 발동 사유 확인:

```bash
grep "holmes deep-dive" /tmp/gw.log
```

로그 상에 `reason=merged-incident`, `novel`, `sev1` 중 하나가 출력되어야 정상입니다.

### 5-4. 환경 원복 절차

보안 설정 파일이 수정되었으므로 시연 후 **반드시 아래 원복 명령을 실행**합니다.

```bash
ssh node2 "sudo sed -i '/# demo marker/d' /etc/ssh/sshd_config && sudo sshd -t && echo OK"
```

`sshd -t` 문법 검사를 통해 `OK` 출력을 확인한 후 절차를 마칩니다.

> **시연 설명 지침:**  
> 심층 조사 결과에서 시뮬레이션 공격 주체 IP로 관측 코어(`core`) 노드가 지목됩니다. 이는 테스트 환경 특성에 따른 정황이므로, 시연 시 *"공격 주체로 탐지된 IP는 장애 주입을 실행한 관측 코어 VM 주소입니다"*라는 부연 설명을 진행합니다.

---

## 6. 전체 라이브 시연 추천 실행 순서

시나리오 전체를 연달아 시연할 경우, execution time 효율성을 위해 아래 순서로 진행하는 것을 권장합니다:

1. **시나리오 C (자가 치유):** 결과 확인까지 소요 시간이 가장 짧음 (약 40초)
2. **시나리오 B (SSH 브루트포스):** 주입 후 대시보드 즉시 반영
3. **시나리오 A (DB 복제 지연):** **알림 발화까지 7분 소요** ➔ 전체 시연 시작 직후 백그라운드 주입을 실행해 두고 타 시나리오 시연을 먼저 진행한 후 최종 결과를 확인합니다.

**추천 실행 워크플로:**
```text
① node2 노드에서 repl_lag_contention.sh 스크립트를 DURATION=420 설정으로 백그라운드 실행
② (복제 지연 수집 대기 시간 동안) 시나리오 C (자가 치유) 시연 진행
③ (대기 시간 동안) 시나리오 B (SSH 브루트포스) 시연 진행
④ 시나리오 A 복제 지연 지표 상승 및 Slack 병합 카드 최종 확인
```

---

## 7. 주요 장애 현상별 트러블슈팅 가이드

| 장애 현상 (Symptom) | 추정 원인 (Root Cause) | 점검 및 조치 사항 |
|---|---|---|
| **Slack 채널에 알림 미수신** | 게이트웨이 프로세스 미기동 | `ps -ef \| grep uvicorn` 점검 및 재기동 |
| **`.env` 수정 사항 미반영** | 기존 구 프로세스가 메모리에 점유 중임 | PID 확인 후 `kill` 처리 및 재기동 (§1-2 참조) |
| **중복 알림 카드가 다수 생성됨** | Uvicorn 실행 시 `--workers` 옵션 부여됨 | 단일 Worker 프로세스로 변경하여 재기동 |
| **Keep UI 상에 워크플로 미노출** | Keep 서비스 재시작 미수행 | `docker compose restart keep-backend` 실행 |
| **복제 지연 지표는 오르나 알림 미발화** | 부하 주입 지속 시간이 5분 미만임 | `DURATION` 파라미터를 420초 이상으로 상향 설정 |
| **`Could not resolve hostname` 에러** | `core` 노드에서 SSH 별칭 사용 시도 | 작업자 PC에서 실행하거나 사설 IP 직접 지정 |
| **대시보드 전체 패널에 No data 표기** | Zabbix 조회 계정에 호스트 그룹 권한 누락 | Zabbix ➔ User groups ➔ Host permissions 권한 설정 점검 |
| **시계열 메트릭 패널 데이터 정지** | Grafana 데이터소스 조회 캐시 지연 | 데이터소스 `cacheTTL` 설정값 점검 (1분 단축 설정) |
| **LLM 분석 결과에 수치만 표기됨** | Anthropic API 크레딧 소진 | API 잔액 점검 (크레딧 소진 시 열화 모드 동작) |
| **심층 조사(HolmesGPT) 미발동** | 선판정 결과가 **만성(Chronic)**으로 산출됨 | 만성 장애에 대한 의도적 조사 억제 로직 동작 (정상) |
| **심층 조사 전면 미동작** | `HOLMES_ENABLED` 환경변수 미활성화 | `.env` 설정 확인 후 게이트웨이 재기동 |
| **개별 알림이 병합되지 않고 분리 표출** | 장애 주입 간격이 디바운스 창(90초)을 초과함 | 시뮬레이션 명령을 연속하여 연달아 실행 |

*(기타 인프라 구축 단계별 상세 함정 모음: [`docs/03-pitfalls/build-traps.md`](../03-pitfalls/build-traps.md))*

---

## 8. 실환경 실행 엄금 경고

`chaos/` 디렉토리 내 모든 시뮬레이션 스크립트는 **실험(랩) 인프라 전용**으로 작성되었습니다. 스크립트 실행 전 입력한 대상 주소가 **랩 사설 IP 대역(`192.0.2.0/24`)에 해당하는지 반드시 사전 검증**한 후 실행합니다.