# 장애 주입 스크립트 가이드 (chaos/)

## 1. 개요 및 작성 목적

본 디렉토리는 시연(Demo) 및 검증 환경에서 인프라 장애 상황을 시뮬레이션하고 관제 파이프라인의 탐지, 초동 분석 및 자동 조치 동작을 검증하기 위한 **장애 주입(Chaos Injection) 스크립트 모음**입니다.

* **주의:** 본 스크립트군은 **실험 인프라(랩) 전용**으로 구현되었으며, 실제 운영(Production) 환경에서의 실행을 엄격히 금지합니다.
* **코드 기반 장애 관리 (Chaos as Code):** 라이브 시연 실패 리스크 최소화, 리허설 수행, 시스템 동작 재현성(Reproducibility) 확보를 목적으로 장애 주입 절차를 스크립트로 관리합니다.

*(전체 시연 실행 워크플로는 [`docs/04-demo/runbook.md`](../docs/04-demo/runbook.md) 가이드를 참조합니다.)*

---

## 2. 스크립트별 실행 위치 매핑

장애 유형에 따라 실행 대상 및 위치가 상이합니다. 하드코딩에 의한 잘못된 인프라 수정을 방지하기 위해 대상 IP 및 파라미터는 CLI 인자(Argument)로 수신합니다.

| 스크립트명 | 권장 실행 위치 | 실행 방식 및 목적 |
|---|---|---|
| **`ssh_bruteforce.sh`** | 동일 사설망 내 노드 (예: 관측 코어 VM) | 대상 노드 22번 포트 접근 외부 공격 시뮬레이션 |
| **`repl_lag.sh`** | 관측 코어 VM (`lab/` 디렉토리) | Docker Compose 제어를 통한 Master DB 대량 Write 생성 |
| **`repl_lag_contention.sh`** | 슬레이브 VM (`vm-target-002`) | 슬레이브 로컬 디스크 I/O 포화를 통한 자원 경합 유발 |
| **`error_burst.sh`** | 감시 대상 VM 직접 실행 | 로컬 저널/로그 파일 직접 쓰기를 통한 오류율 급증 시뮬레이션 |
| **`service_down.sh`** | 작업자 PC (SSH 별칭 이용) | SSH 별칭 기반 대상 서비스 정지 (`service_down.sh vm-target-002 chronyd`) |
| **`snmp_iface_error.sh`** | 관측 코어 VM (`lab/` 디렉토리) | `snmpsim` 컨테이너 제어를 통한 네트워크 에러 카운터 변동 유발 |
| **`seed_security.sh`** | 감시 대상 VM 직접 실행 | 주요 보안 경로 파일 변조를 통한 FIM 경보 시드 생성 |
| **`cert_expiry_chain.sh`** | 웹 서비스 역할 VM (`vm-target-001`) | 만료 인증서로 HTTPS 를 제공해 "포트는 열려 있는데 사용자는 못 붙는" 사건 생성 |

*(참고: 호스트명, 사설 IP 및 SSH 별칭 매핑 정보는 [`docs/01-build/hosts.md`](../docs/01-build/hosts.md) 문서를 참조합니다.)*

---

## 3. 스크립트별 세부 동작 명세

### 3-1. `ssh_bruteforce.sh` — SSH 무차별 대입 공격 (보안 축)

SSH 로그인 실패 패턴을 시뮬레이션하여 Wazuh 레벨 10 보안 경보를 발생시킵니다.

- **실행 명령:** `./ssh_bruteforce.sh <대상_IP> [시도횟수=12] [계정명=badguy]`
- **동작 원리:** 미존재 계정 대상 반복 로그인 시도 ➔ Wazuh 룰 5710(Level 5) 발화 ➔ 120초 이내 8회 이상 누적 시 Wazuh 상관 분석 엔진에 의해 룰 5712(Level 10) 경보로 격상
- **검증 경로:** Wazuh Dashboard ➔ Threat Hunting ➔ `rule.id:5712`
- **적용 시나리오:** 데모 A 보안 통합 관제, 데모 C 복합 보안 시나리오

### 3-2. `service_down.sh` — 서비스 중단 (자가 치유)

대상 노드의 시스템 데몬을 정지하여 승인 기반 자가 치유(HITL) 파이프라인 전체 흐름을 테스트합니다.

- **실행 명령:** `./service_down.sh <SSH_별칭> [서비스명=chronyd]`
- **제어 흐름:** 서비스 정지 ➔ Zabbix 서비스 중단 트리거 발화 ➔ 게이트웨이가 `automate` 태그 확인 후 Keep 승인 큐에 조치 후보 등록 ➔ 관제 담당자 승인(Run Workflow) ➔ Ansible 자동 재기동 및 재검증
- **전제 조건:** Zabbix 트리거에 `automate=service_restart` 및 `service=<서비스명>` 태그가 부여되어 있어야 라우팅됩니다. (`scope=notify_only` 태그 존재 시 조치 라우팅 차단)
- **기본 서비스 (`chronyd`):** 인프라 영향도가 적고 복구가 용이하여 안전한 반복 시연이 가능합니다.

### 3-3. `repl_lag.sh` — DB 복제 지연 (메트릭 축)

Master DB 노드에 대량 쓰기 연산을 발생시켜 Slave 복제 지연을 유발합니다.

- **실행 명령:** `./repl_lag.sh [배가횟수=14]`
- **동작 원리:** Master 대량 쓰기 발생 ➔ Slave 단일 SQL 스레드의 처리 지연 ➔ `Slave_SQL_Running=Yes` 상태를 유지하면서 `Seconds_Behind_Master` 수치 급증
- **검증 경로:** Grafana `KINX 복제 품질` 대시보드 (Status=Up(1) 유지, 지연 시간 급증 확인)
- **적용 시나리오:** 단순 상태 플래그(1/0) 관측과 수치 지표 관측의 깊이 차이 입증

### 3-4. `repl_lag_contention.sh` — 자원 경합 기반 DB 복제 지연 (데모 C 핵심)

슬레이브 VM의 디스크 I/O를 백업성 부하로 포화시켜 복제 지연을 발생시킵니다.

- **실행 명령:** `DURATION=420 MASTER_HOST=<MASTER_IP> DEMO_WRITER_USER=... DEMO_WRITER_PASSWORD=... ./repl_lag_contention.sh`
- **실행 위치:** 슬레이브 VM (`vm-target-002`)
- **동작 원리:** Syslog 백업 마커 생성(Loki 연관 신호) + 로컬 DB 덤프/쓰기 연산으로 디스크 I/O 포화 + Master 가벼운 Write 스트림 전송 ➔ 동일 호스트/동일 타임라인 상에서 `iowait` 상승 및 `Seconds_Behind_Master` 지연 동시 발생
- **검증 경로:** Zabbix (지연/iowait 상승) + Loki (백업 로그) + Wazuh (침해 흔적 없음) ➔ 게이트웨이 단일 인시던트 자동 병합 및 인과관계 분석
- **적용 시나리오:** 데모 C (AI 초동 분석 및 인시던트 병합) 핵심 시나리오

### 3-5. `error_burst.sh` — 애플리케이션/시스템 로그 에러율 급증

`logger` 유틸리티를 통해 시스템 로그에 ERROR 레벨 메시지를 다량 주입합니다.

- **실행 명령:** `./error_burst.sh [건수=300] [태그=payment-api]`
- **동작 원리:** `user.err` 로그 주입 ➔ rsyslog가 `/var/log/messages` 기록 ➔ Alloy 에이전트 수집 ➔ Loki Push ➔ Log Rate 지표 변동
- **검증 경로:** Grafana Loki 패널 (`sum(rate({job="varlogs"} |= "ERROR" [1m]))` 지표 스파이크 확인)
- **적용 시나리오:** 로그 데이터의 지표화(Metricization) 수용성 검증

### 3-6. `snmp_iface_error.sh` — 네트워크 인터페이스 에러 폭주 (알림 노이즈)

`snmpsim` 에러 데이터를 주기적으로 토글하여 네트워크 에러 트리거를 반복 발화시킵니다.

- **실행 명령:** `./snmp_iface_error.sh [사이클=6] [체류시간=70]`
- **실행 위치:** 관측 코어 VM (`lab/` 디렉토리)
- **동작 원리:** `switch1.error.snmprec` (Rate=3)과 `switch1.clean.snmprec` (Rate=0) 응답 파일을 주기적 교체 후 `snmpsim` 재기동 ➔ `ifInErrors` 카운터 증감 반복 ➔ Zabbix `change()>2` 트리거의 PROBLEM/OK 반복 발화
- **검증 경로:** Zabbix Monitoring ➔ Problems 내 중복 알림 누적 확인
- **적용 시나리오:** 알림 노이즈 억제 및 필터링 기능 시연 (Before 환경)

### 3-7. `seed_security.sh` — 보안 경보 데이터 시드 생성

FIM 승격 룰이 적용된 감시 경로 내 파일을 수정하여 보안 경보 데이터를 생성합니다.

- **동작 원리:** `/etc/ssh/sshd_config` 등 주요 보안 파일 내 마커 구문 삽입 ➔ Wazuh FIM 실시간 탐지 ➔ Level 12 승격 경보 생성
- **검증 경로:** Wazuh Dashboard ➔ Threat Hunting ➔ `rule.id:100201`
- **주의 사항:** **시스템 설정 파일이 변경되므로 테스트 완료 후 반드시 복원 절차를 수행합니다.** (복원 방법: [`docs/04-demo/runbook.md`](../docs/04-demo/runbook.md) §5-4 환경 원복 절차 참조)

---

## 4. 추가 개발 로드맵

| 스크립트명 | 주입 장애 내용 | 연동 관제 트리거 및 검증 지표 |
|---|---|---|
| **`disk_fill.sh`** | `fallocate` 유틸리티를 활용한 디스크 사용률 포화 | Zabbix 디스크 용량 임계치 트리거 (`vfs.fs.size`) |
| **`service_kill.sh`** | 특정 서비스 프로세스 강제 종료 (`SIGKILL`) | Zabbix 프로세스 수 관측 트리거 (`proc.num`) |

신규 장애 주입 스크립트 추가 시 대상 파라미터 제어 및 복구(Clean-up) 핸들러를 포함하여 작성하며, 본 README 문서의 동작 사양을 업데이트합니다.

---

## 5. 인증서 만료 사슬 (`cert_expiry_chain.sh`)

### 목적

심층 조사 모드의 **처음 보는 사건** 실증(랩 실증 단계 3)에 쓰는 시나리오입니다. 사건 분류기
(`classify()`)에 인증서 관련 낱말이 없어 `other` 로 떨어지고, 원인과 증상이 **서로 다른
호스트**에 있어 병합으로는 한 사건이 되지 않습니다. 두 신호를 잇는 것은 병합이 아니라
조사 중의 질의여야 합니다.

### 사슬의 실제 모양 — 계획서의 서술을 실측으로 정정함

당초 "인증서 만료 → 443 체크 실패 → 웹 접속 실패"로 적었으나 **거꾸로입니다.** Zabbix 의
https 체크는 인증서를 검증하지 않습니다.

> "Uses (and only works with) libcurl, does not verify the authenticity of the certificate,
> does not verify the host name in the SSL certificate, only fetches the response header
> (HEAD request)."
> — [Zabbix 7.0 · Service check details](https://www.zabbix.com/documentation/7.0/en/manual/appendix/items/service_check_details)

따라서 실제 사슬은 이렇습니다.

| 자리 | 신호 | 호스트 |
|---|---|---|
| 원인 | `Certificate: SSL certificate is invalid` (High) | `cert-vm-target-001.novalocal` (가상) |
| 증상 | 저널의 `certificate has expired` 반복 | `vm-target-001.novalocal` (실호스트, Loki) |
| **함정** | `net.tcp.service[https,,8443]` 이 **1(정상)** 로 남음 | `node1` |

포트 점검이 초록으로 남는 것이 이 사건의 핵심입니다. 화면상 서비스는 정상인데 사용자는
붙지 못합니다. 이것이 매니저가 가치를 인정한 갭(B-6)의 실물이며, 고객 도메인 443 체크만으로는
만료를 못 잡는다는 진단의 근거이기도 합니다.

### 실행

```bash
sudo DOMAIN=$(hostname -f) PORT=8443 bash cert_expiry_chain.sh
```

내부 CA 를 만들고 **이미 지난 기간으로 서버 인증서를 발급**합니다. OpenSSL 3.0 의
`openssl req -x509` 에는 `not_before`/`not_after` 옵션이 없어(3.5 에서 추가) `openssl ca` 의
`-startdate`/`-enddate` 를 씁니다. CA 를 신뢰 저장소에 넣는 이유는 실패 사유를 "발급자 불명"이
아니라 **"만료"**로 만들기 위해서입니다. 사유가 다르면 사건의 성격이 달라집니다.

서비스와 접속 확인이 각각 systemd 유닛으로 돌고 출력이 저널로 갑니다. Alloy 가 저널을 읽으므로
로그가 Loki 까지 도달합니다(파일 로그는 권한 문제로 못 읽습니다 — `BUILD_GUIDE` 참고).

### Zabbix 쪽 준비 (한 번만)

```bash
export ZABBIX_API_TOKEN='<관리 권한 토큰>'
ansible-playbook -i ansible/inventory.ini -i ansible/inventory.local.ini   ansible/certificates.yml -e @ansible/certs.local.yml -e @ansible/lab_vars.yml
```

`certs.local.yml` 에 `domain: vm-target-001.novalocal` / `port: 8443` 항목이 있어야 합니다.
포트 점검 아이템(`net.tcp.service[https,,8443]`)은 대상 호스트에 직접 답니다 — 이 아이템이
없으면 "포트는 정상"이라는 결정적 재료가 조사에 안 잡힙니다.

### 되돌리기

```bash
sudo systemctl disable --now lab-webapp.service lab-webapp-client.service
sudo rm -f /etc/systemd/system/lab-webapp*.service            /etc/pki/ca-trust/source/anchors/lab-internal-ca.crt
sudo update-ca-trust extract && sudo systemctl daemon-reload
```
