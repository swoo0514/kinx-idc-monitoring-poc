# 데모 C 복제 슬레이브(vm-target-002) — 구축·chaos 가이드

## 무엇을 만드나 / 왜 이 구조인가

데모 C 시나리오는 **"복제 지연: DB 고장인가 자원 경합인가"**다. 이를 실측하려면 별도 VM
(vm-target-002)에 **실제 MariaDB 슬레이브**를 세우고, 그 슬레이브의 디스크 I/O를 백업성
부하로 포화시켜 **복제가 밀리는(Seconds_Behind_Master↑) 장면**을 만든다. 복제를 끊는 게
아니라 **자원을 굶겨** 밀리게 하는 것이 핵심 — 그래야 봇이 "복제 고장 아님, 자원 경합"이라고
재프레이밍하는 시연이 성립한다.

기존 `setup-slave.sh`/`repl_lag.sh`는 **docker 랩 컨테이너(mariadb/mariadb-slave) 전용**이고
지연 원인도 "master 대량 쓰기"라 이 시나리오와 다르다. 이 문서의 스크립트 3종은 **별도 VM +
자원 경합** 버전이다.

- master = docker-core 의 `kinx-mariadb`(server-id=1, log-bin, GTID). 사설 IP 192.0.2.10.
- slave = vm-target-002(192.0.2.16, node2). MariaDB 10.11(master 와 버전 일치).
- 복제 대상 = 작은 전용 DB `demo_repl`(zabbix DB 전체 복제 금지 — 슬레이브 비대·history 부담).

## 포트 / 보안그룹 (질문 답)

이 랩의 internal 보안그룹은 **사설 서브넷(/24)에 전 포트 허용**이다. 필요한 통신(10050 폴링,
3306 복제, 10051·3100·1514/1515 아웃바운드)이 전부 /24 안이므로 — **보안그룹에는 추가할
규칙이 없다.** vm-target-002 를 그 internal 보안그룹에 배치하기만 하면 된다(core 는 이미 소속).

참고로 방향별 통신은 다음과 같다(모두 /24 내부라 허용됨):

| 방향 | 포트 | 통신 |
|---|---|---|
| vm-target-002 인바운드 | 10050 | Zabbix 서버 → agent passive 폴링 |
| core 인바운드 | 3306 | 슬레이브 → master 복제 연결 |
| vm-target-002 아웃바운드 | 10051 / 3100 / 1514·1515 / 3306 | →Zabbix active·자동등록 / →Loki / →Wazuh manager / →master |

**보안그룹과 별개로 반드시 필요한 것 — master 3306 도커 publish.** SG 가 /24 전부 허용이어도,
`mariadb` 컨테이너 3306 은 기본적으로 도커 내부망(lab_net)에만 있고 **호스트 인터페이스에는
안 올라와 있다.** 즉 슬레이브가 도달할 대상 자체가 없다. §1 에서 `MASTER_BIND_IP`(core 사설
IP)로 3306 을 호스트에 노출한다. core 는 공인 IP 도 가지므로 반드시 **사설 IP 에만** 바인딩.

## 1. master 노출 (core 호스트, 안전 바인딩)

`lab/.env` 에 사설 IP 만 노출하도록 설정하고 master 를 재적용한다.

```
MASTER_BIND_IP=<master 사설 IP>   # 사설 IP 만. core 호스트의 공인 IP 절대 금지
DEMO_REPL_DB=demo_repl
DEMO_WRITER_USER=demowriter
DEMO_WRITER_PASSWORD=<랩 임의 비번>
```
```bash
# core 호스트의 리포 lab/ 디렉토리에서 (이미 lab/ 이면 cd 생략)
docker compose up -d mariadb    # 3306 이 MASTER_BIND_IP 인터페이스에만 바인딩됨
```
compose 기본값은 `127.0.0.1:3306`(비노출)이라, MASTER_BIND_IP 를 안 채우면 외부에서 못 붙는다.

## 2. master 준비 + 스냅샷 (core 호스트)

```bash
# core 호스트의 리포 lab/ 에서 (스크립트가 알아서 lab/ 로 이동하므로 어디서 실행해도 됨)
./mariadb/prep-master-for-vm-slave.sh
```
`demo_repl` DB·`load_gen` 테이블·복제 계정(`repl`)·쓰기 계정(`demowriter`)을 멱등 생성하고,
GTID 스냅샷을 core 의 `/tmp/kinx_demo_dump.sql` 로 덤프한다.

그 덤프를 슬레이브 VM 으로 전송한다. `node2` 는 **작업자 PC 의 ~/.ssh/config 별칭**이라 core
에서는 못 쓴다 — 다음 중 하나로:

```bash
# (A) 작업자 PC 에서 2-hop (별칭 둘 다 아는 곳)
scp core:/tmp/kinx_demo_dump.sql ./kinx_demo_dump.sql
scp ./kinx_demo_dump.sql node2:/tmp/

# (B) core 에서 슬레이브 사설 IP 로 직접 (같은 /24, 에이전트 포워딩으로 키 전달)
#   작업자 PC: ssh -A core   → core: scp /tmp/kinx_demo_dump.sql rocky@<슬레이브 사설 IP>:/tmp/
```

## 3. 슬레이브 구축 (vm-target-002)

먼저 3종 에이전트를 배포(`ansible/deploy_agents.yml`, DEPLOY_GUIDE)한 뒤:

```bash
ssh node2
export MASTER_HOST=192.0.2.10
export REPLICATION_USER=repl REPLICATION_PASSWORD=<lab .env 값>
export DEMO_REPL_DB=demo_repl
# lab/mariadb/setup-slave-vm.sh 를 VM 으로 복사해 실행
bash setup-slave-vm.sh
```
MariaDB 10.11 설치(master 버전 일치), server-id=10·GTID 설정, 스냅샷 적재, `CHANGE MASTER`
→ `START SLAVE`. 마지막에 IO=Yes/SQL=Yes 확인. 표준 MySQL 템플릿이 붙으면
`mysql.seconds_behind_master`(초) 아이템으로 지연이 자동 감시된다(공식 템플릿 기본).

## 4. chaos — 자원 경합 주입 (vm-target-002)

```bash
ssh node2
export MASTER_HOST=192.0.2.10
export DEMO_REPL_DB=demo_repl DEMO_WRITER_USER=demowriter DEMO_WRITER_PASSWORD=<값>
DURATION=180 bash repl_lag_contention.sh
```
동작: ① syslog 에 "backup job started" 마커(Alloy→Loki 교차신호) ② 디스크 I/O 포화(대용량
쓰기 + 로컬 덤프 반복) ③ master 에 가벼운 연속 쓰기(복제 스트림 유지). 결과: iowait↑ +
Seconds_Behind_Master↑ 가 같은 호스트·같은 시간창에 = 봇 인시던트 병합의 입력.

관측 확인:
- Zabbix: `mysql.seconds_behind_master` 급등 + `system.cpu.util[,iowait]` 급등(같은 호스트).
- Loki: `{host="vm-target-002.novalocal"}` 에 `kinx-chaos backup job started` 로그.
- Wazuh: 관련 경보 없음 = 침해 배제(정직한 조연).
- 봇: 세 신호를 1개 인시던트로 병합 → "복제 고장 아님, 자원 경합, 복제 리셋 금지" 회신.

## 5. 트러블슈팅

- **슬레이브 IO=No / connect 실패**: core SG 인바운드 3306(소스 192.0.2.16) 누락, 또는
  master 가 `127.0.0.1` 바인딩(§1 MASTER_BIND_IP 미설정). `mysql -h 192.0.2.10 -urepl -p`
  로 도달 확인.
- **Duplicate entry / GTID 오류**: 스냅샷 GTID 미설정. setup-slave-vm.sh 가 덤프의
  `gtid_slave_pos` 를 추출해 `SET GLOBAL` 하므로, 덤프가 `--gtid --master-data=2` 로 떠졌는지
  확인(prep 스크립트가 처리).
- **버전 스큐**: Rocky 9 기본 MariaDB 는 10.5 라 10.11 master 와 복제 시 문제 소지. 스크립트가
  mariadb.org 저장소로 10.11 을 설치해 일치시킨다.
- **`nothing provides liburing.so.2`**: MariaDB 10.11 이 io_uring 라이브러리를 요구하는데 최소
  이미지에 없음. `sudo dnf install -y liburing`(안 되면 `--releasever=9`) 후 재시도. 스크립트가
  선설치하도록 반영됨(구 버전 스크립트면 이 명령을 수동 실행).
- **lag 가 안 오름**: I/O 워커 수(`IO_WORKERS`)·지속(`DURATION`) 상향, 또는 master 쓰기가
  실제로 도달하는지(demowriter 계정·3306) 확인. 슬레이브 디스크가 너무 빠르면 경합이 약함.
- **`Access denied for user 'repl'`**: master 에 repl 계정이 예전(docker HA `setup-slave.sh`)에
  이미 있으면 `CREATE USER IF NOT EXISTS` 가 비번을 안 바꿔 .env 값과 어긋난다. prep 스크립트가
  `ALTER USER` 로 항상 맞추도록 반영됨 — 구 버전이면 master 에서
  `ALTER USER 'repl'@'%' IDENTIFIED BY '<.env REPLICATION_PASSWORD>'; FLUSH PRIVILEGES;` 후
  슬레이브에서 `STOP SLAVE; CHANGE MASTER TO MASTER_PASSWORD='...'; START SLAVE;`.
- **`nothing provides liburing.so.2` / `mysql-selinux >= 1.0.14`**: Rocky 9.0 고정 저장소가 너무
  낡음(liburing 0.7·구 selinux-policy). 현재 Rocky 9 저장소에서 당긴다:
  `sudo dnf install -y --nogpgcheck --repofrompath=r9app,https://dl.rockylinux.org/pub/rocky/9/AppStream/x86_64/os/ --repofrompath=r9base,https://dl.rockylinux.org/pub/rocky/9/BaseOS/x86_64/os/ MariaDB-server MariaDB-client`
  (selinux-policy 가 el9 최신으로 한 단계 오를 수 있음 — 랩 허용). 이 버전 갭 자체가 실환경
  도입 리스크 실측 산출물.
- **`Table 'zabbix.history' doesn't exist` (SQL_Errno 1146)**: 마스터엔 Zabbix 라이브 `zabbix`
  DB 도 돌고 binlog 은 전체라, 슬레이브가 `zabbix.%` 쓰기까지 받아 막힌다. 슬레이브 설정에
  `replicate-wild-do-table=demo_repl.%` 를 넣어 **demo_repl 만 복제**(스크립트 반영). 이미 막혔으면
  `/etc/my.cnf.d/zz-slave.cnf` 에 그 줄 추가 → `systemctl restart mariadb` → `START SLAVE`
  (relay log 의 zabbix 이벤트도 적용 시점에 걸러져 넘어감). 복제 스트림은 chaos 의 demo_repl
  쓰기만 흐르게 되어 오히려 통제됨.
- **에이전트 이름 불일치로 봇 logs:0**: 이 VM 은 deploy_agents.yml 로 FQDN 정규화되어 매핑
  불필요(node1 과 다름). `hostname -f` = Zabbix Hostname = Loki host 라벨 = Wazuh agent.name.
