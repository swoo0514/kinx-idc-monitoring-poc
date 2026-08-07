# 데모 C DB 복제 슬레이브(vm-target-002) 구축 및 장애 주입(Chaos) 가이드

## 개요 및 아키텍처 배경

데모 C 시나리오는 **"DB 복제 지연: DB 엔진 결함인가, 자원 경합인가"**라는 핵심 질문을 검증합니다. 이를 실측하기 위해 별도 가상 머신(`vm-target-002`)에 **실제 MariaDB Slave**를 구축하고, 해당 노드의 디스크 I/O를 백업성 부하로 포화시켜 복제 지연(`Seconds_Behind_Master` 수치 상승)을 유발합니다.

복제 커넥션을 의도적으로 단락시키는 것이 아니라 **I/O 자원을 고갈시켜 적체를 유도하는 방식**을 적용함으로써, 분석 봇이 "복제 엔진 장애가 아닌 동일 노드 내 디스크 I/O 자원 경합"으로 정밀 재프레이밍(Reframing)하는 분석 성능을 입증합니다.

* **Master 노드:** Docker Core 환경 내 `kinx-mariadb` 컨테이너 (`server-id=1`, Binlog/GTID 활성화, 사설 IP: `192.0.2.10`)
* **Slave 노드:** `vm-target-002` 노드 (`node2`, 사설 IP: `192.0.2.16`, MariaDB 10.11 버전으로 Master와 일치)
* **복제 대상 대상 DB:** `demo_repl` 전용 경량 DB (전체 Zabbix DB 복제 시 발생하는 슬레이브 디스크 비대화 및 히스토리 부담 방지)

---

## 1. 네트워크 및 방화벽/보안 그룹 사양

본 실험 인프라의 `internal` 보안 그룹은 **사설 서브넷 대역(`/24`) 전체 포트 허용** 정책이 적용되어 있습니다. 주요 통신 구간이 동일 서브넷 내부에서 이루어지므로 보안 그룹 상에 별도 통신 규칙을 추가할 필요가 없으며, `vm-target-002` 노드를 해당 `internal` 보안 그룹에 배치하여 통신을 확보합니다.

### 서브넷 내부 방향별 통신 사양

| 통신 방향 | 포트 | 통신 목적 및 수신 대상 |
|---|---|---|
| **`vm-target-002` 인바운드** | `10050` | Zabbix Server ➔ Agent2 Passive 메트릭 폴링 |
| **`core` 인바운드** | `3306` | Slave Node ➔ Master DB 복제 연결 |
| **`vm-target-002` 아웃바운드** | `10051` / `3100` / `1514·1515` / `3306` | Zabbix Active 통신 / Loki Log Push / Wazuh Manager / Master DB 연결 |

> **[필수 선행 작업: Master DB 3306 포트 호스트 바인딩]**  
> 보안 그룹이 전체 허용 상태이더라도, `mariadb` 컨테이너의 3306 포트는 기본적으로 Docker 내부 네트워크(`lab_net`)에만 바인딩되어 있습니다. 외부 Slave 노드의 접근을 허용하기 위해 Master 노드의 사설 IP(`MASTER_BIND_IP`) 인터페이스로 3306 포트를 바인딩해야 합니다. (공인 IP 바인딩 금지)

---

## 2. Master 노드 바인딩 및 덤프 생성 (`core` 노드)

Master 노드의 `lab/.env` 환경변수에 사설 IP 바인딩 설정을 추가하고 컨테이너를 재기동합니다.

```ini
# lab/.env 파일 설정
MASTER_BIND_IP=192.0.2.10        # Master 노드 사설 IP 지정 (공인 IP 설정 금지)
DEMO_REPL_DB=demo_repl
DEMO_WRITER_USER=demowriter
DEMO_WRITER_PASSWORD=<랩_임의_비밀번호>
```

```bash
# core 노드의 lab/ 디렉토리 이동 및 Master DB 적용
cd ~/kinx-idc-monitoring-poc/lab
docker compose up -d mariadb
```

### Master 사전 환경 구성 및 스냅샷 생성

```bash
# Master 사전 구성 및 GTID 스냅샷 덤프 스크립트 실행
./mariadb/prep-master-for-vm-slave.sh
```

해당 스크립트는 `demo_repl` DB, `load_gen` 테이블, 복제 계정(`repl`), 쓰기 계정(`demowriter`)을 멱등하게 생성하고, GTID 스냅샷 덤프 파일(`/tmp/kinx_demo_dump.sql`)을 생성합니다.

**생성된 덤프 파일의 Slave 노드 전송 (아래 방법 중 선택):**

```bash
# [방법 A] 작업자 PC에서 2-Hop 전송 실행
scp core:/tmp/kinx_demo_dump.sql ./kinx_demo_dump.sql
scp ./kinx_demo_dump.sql node2:/tmp/

# [방법 B] core 노드에서 SSH Agent Forwarding 기반 direct 전송
# 작업자 PC: ssh -A core 실행 후
scp /tmp/kinx_demo_dump.sql rocky@192.0.2.16:/tmp/
```

---

## 3. Slave 노드 구축 (`vm-target-002`)

Ansible 3종 에이전트 배포(`ansible/deploy_agents.yml`)를 완료한 후 Slave 노드 구축을 진행합니다.

```bash
# vm-target-002 (node2) 접속 및 환경변수 설정
ssh node2
export MASTER_HOST=192.0.2.10
export REPLICATION_USER=repl
export REPLICATION_PASSWORD=<lab_.env_비밀번호>
export DEMO_REPL_DB=demo_repl

# Slave 구축 스크립트 실행
bash setup-slave-vm.sh
```

본 스크립트는 MariaDB 10.11 패키지 설치(Master 버전 일치), `server-id=10` 및 GTID 설정, 스냅샷 적재, `CHANGE MASTER TO` 및 `START SLAVE` 구문 실행을 자동 수행합니다. 실행 완료 후 `Slave_IO_Running: Yes`, `Slave_SQL_Running: Yes` 상태를 확인합니다.

---

### 3-1. DB 복제 지연 감시 배선 (Zabbix & Agent2)

`mysql.seconds_behind_master` 지표를 Zabbix에서 관측할 수 있도록 에이전트 측 모니터링 계정 및 세션 배선을 자동화합니다.

```bash
# Control 노드(core)에서 모니터링 계정 및 세션 설정 플레이북 실행
ansible-galaxy collection install community.mysql
ansible-playbook -i inventory.local.ini -e @lab_vars.yml setup_mysql_monitoring.yml
```

* **수행 작업:** `zbx_monitor`@'%' 계정 생성 및 MariaDB 10.5.9+ 전용 권한(`REPLICATION CLIENT`, `SLAVE MONITOR`, `PROCESS`, `SHOW DATABASES`, `SHOW VIEW`) 부여 ➔ Agent2 MySQL 세션(`repl`) 할당 ➔ Agent2 데몬 재기동

**Zabbix UI 템플릿 연동:**
1. 대상 호스트에 **"MySQL by Zabbix agent 2"** 템플릿 연결
2. 매크로 설정: `{$MYSQL.DSN}=repl`, `{$MYSQL.REPL_LAG.MAX.WARN}=60` (기본값 30m에서 데모용 60초로 하향 조정)
3. 템플릿 연결 후 Replication LLD가 Slave 노드를 탐지하여 `Seconds Behind Master` 아이템 및 "Replication lag is too high" 트리거 자동 생성 확인

---

## 4. 자원 경합 장애 주입 (repl_lag_contention.sh)

`vm-target-002` 노드 상에서 디스크 I/O 포화 및 백업 부하를 생성하여 복제 지연을 시뮬레이션합니다.

```bash
# vm-target-002 노드에서 부하 주입 실행
ssh node2
export MASTER_HOST=192.0.2.10
export DEMO_REPL_DB=demo_repl
export DEMO_WRITER_USER=demowriter
export DEMO_WRITER_PASSWORD=<설정_비밀번호>

DURATION=420 bash repl_lag_contention.sh
```

### 스크립트 세부 동작 및 부하 유발 메커니즘
1. **Syslog 백업 마커 기록:** `/var/log/messages` 내 "backup job started" 로그 주입 (Alloy ➔ Loki 교차 관측 신호 생성)
2. **디스크 I/O 포화:** 대용량 쓰기 작업 및 로컬 DB 덤프 연산 반복 실행
3. **Master 쓰기 스트림 유지:** Master 노드로 지속적인 가벼운 Write 연산 전송

### 통합 관측 및 검증 경로
- **Zabbix:** 동일 호스트 대상 `mysql.seconds_behind_master` 수치 및 `system.cpu.util[,iowait]` 지표 동시 급증 확인
- **Loki:** `{host="vm-target-002.novalocal"}` 조건 검색 시 `kinx-chaos backup job started` 로그 수집 확인
- **Wazuh:** 보안 경보 미발생 ➔ "보안 침해 없음" 상태 정황 근거 제공
- **분석 봇:** 3개 관측 신호를 단일 인시던트로 병합 ➔ *"복제 모듈 결함 아님, 디스크 I/O 자원 경합, 복제 스레드 리셋 금지"* 초동 분석 카드 회신 확인

---

## 5. 트러블슈팅 및 장애 조치 가이드

| 장애 현상 (Symptom) | 추정 원인 (Root Cause) | 조치 및 해결 방법 |
|---|---|---|
| **Slave `IO_Running: No` / Connect 실패** | Master DB 3306 포트 접근 불가 또는 Master가 `127.0.0.1`로 바인딩됨 | `lab/.env` 내 `MASTER_BIND_IP` 설정 확인 및 `mysql -h 192.0.2.10 -u repl -p` 도달성 검증 |
| **Duplicate entry / GTID 동기화 오류** | 스냅샷 DB의 GTID 위치 정보 누락 | `prep-master-for-vm-slave.sh` 실행 시 `--gtid --master-data=2` 옵션 포함 여부 점검 |
| **MariaDB 패키지 버전 불일치** | Rocky 9 기본 패키지(10.5)와 Master(10.11) 간 버전 스큐 | `setup-slave-vm.sh` 내 mariadb.org 공식 10.11 레포지토리 지정 설치 확인 |
| **`liburing.so.2` 라이브러리 미설치 에러** | MariaDB 10.11 버전의 `io_uring` 의존성 패키지 누락 | `sudo dnf install -y liburing` (필요시 `--releasever=9` 옵션 추가) 실행 |
| **복제 지연 수치(`Lag`) 미상승** | I/O 부하 부족 또는 슬레이브 디스크 성능 과다 | `repl_lag_contention.sh` 실행 시 `IO_WORKERS` 수치 및 `DURATION` 시간 상향 조정 |
| **`Access denied for user 'repl'` 발생** | 기존 생성된 `repl` 계정의 비밀번호 불일치 | Master DB에서 `ALTER USER 'repl'@'%' IDENTIFIED BY '<비밀번호>'; FLUSH PRIVILEGES;` 실행 후 Slave에서 `CHANGE MASTER TO` 재설정 |
| **Rocky 9.0 저장소 의존성 패키지 낡음** | `liburing 0.7` 및 구버전 `selinux-policy` 충돌 | Rocky 9 AppStream/BaseOS 최신 레포지토리 경로를 직접 지정하여 패키지 업데이트 수용 (`dnf install --repofrompath=...`) |
| **`Table 'zabbix.history' doesn't exist` (Errno 1146)** | Master의 전체 Binlog 수신 중 Zabbix DB 쓰기 이벤트 수용 충돌 | Slave 노드 `/etc/my.cnf.d/zz-slave.cnf` 내 `replicate-wild-do-table=demo_repl.%` 지침 추가 후 MariaDB 재기동 (`demo_repl` 전용 복제 제한) |
| **분석 봇 상에 로그 미수집 (`logs:0`)** | 에이전트 호스트명 불일치 | `deploy_agents.yml` 배포를 통한 FQDN 정규화 재적용 (`hostname -f` = Zabbix Hostname = Loki host = Wazuh agent.name) |