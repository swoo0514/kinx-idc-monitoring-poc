# 3종 에이전트 배포 (deploy_agents.yml) — 통합 구축 가이드

## 1. 개요 및 고도화 목적

Rocky Linux 9 호스트 환경을 대상으로 `zabbix-agent2`, `Alloy`, `wazuh-agent` 등 **3종 관측 에이전트를 단일 Ansible 플레이북 실행으로 자동 설치 및 설정**합니다. 이는 MaC(Monitoring as Code) 파이프라인 수립을 위한 핵심 프로세스입니다.

본 가이드는 기존 운영팀의 에이전트 배포 파이프라인을 대체하는 것이 아닌, 상위 호환 형태로 확장 적용합니다:

1. **3종 관측 번들 일괄 배포**: 메트릭 수집(`zabbix-agent2`)에 국한되지 않고, 로그 수집(`Alloy` ➔ `Loki`) 및 보안 수집(`wazuh-agent`)을 배포 단계에서 통합 처리하여 3개 소스 연관 관측 기반을 마련합니다.
2. **호스트 식별자(FQDN) 정규화**: 세 에이전트 모두에 동일한 `agent_identity`(FQDN)를 주입합니다 (`zabbix Hostname` = `alloy host` 라벨 = `wazuh 에이전트명`). 수동 설치 호스트에서 발생하던 명칭 불일치를 원천 차단하여 별도 식별자 매핑(`HOST_LABEL_MAP`) 없이도 인시던트 병합이 가용하도록 정규화를 강제합니다.
3. **자동 등록(Autoregistration) 메타데이터 적용**: `HostMetadata=linux-3agent-bundle`을 설정하여 서버 측 액션이 해당 메타데이터를 식별하고 자동 등록 및 템플릿 링크를 수행하도록 구성합니다.
4. **멱등성 기반 구버전 환경 정리**: 기존 `zabbix-agent` (v1)의 포트 10050 점유 충돌 현상을 자동 정리하는 사전 작업을 포함합니다.

---

## 2. 설정 검증 사양 (node1 실측 기준)

플레이북 변수의 실측 설정값은 node1 검증 환경에서 추출되었습니다. 사설 IP 정보 유출 방지를 위해 기본 저장소 커밋본은 RFC 5737 가상 주소를 사용하며, 실제 랩 주소는 Git 관리에서 제외된 `lab_vars.yml`을 통해 동적으로 주입합니다.

| 변수명 | 설정 출처 |
|---|---|
| `zabbix_server` | node1 `zabbix_agent2.conf` 내 `Server` 지침 |
| `loki_push_url` | node1 `config.alloy` 내 `loki.write` 엔드포인트 |
| `wazuh_manager` | node1 `ossec.conf` 내 `server address` 지침 |
| **OS / 패키지 버전** | Rocky Linux 9 / `zabbix-agent2` 7.0.28, `Alloy` 1.17.1, `wazuh-agent` 4.14.6 |

### 배포 대상 주요 설정 템플릿

| Jinja2 템플릿 | 배포 경로 | 포함 주요 설정 |
|---|---|---|
| `zabbix_agent2.conf.j2` | `/etc/zabbix/zabbix_agent2.conf` | 서버 주소, 자동 등록 메타데이터 (`HostMetadata`) |
| `alloy_config.alloy.j2` | `/etc/alloy/config.alloy` | systemd-journald 수집 및 Loki Push 엔드포인트 |
| `ossec.conf.j2` | `/var/ossec/etc/ossec.conf` | Wazuh Manager 주소, FIM 감시/제외 경로, SCA 설정 |

---

## 3. 플레이북 실행 절차

1. **대상 VM 인벤토리 추가** (`inventory.ini` 내 `[targets]` 섹션에 FQDN 명시):
   ```ini
   db-target-001 ansible_host=192.0.2.XX agent_identity=db-target-001.novalocal
   ```

2. **실환경 변수 파일 작성** (`ansible/lab_vars.yml` - Git 관리 제외):
   ```yaml
   zabbix_server: "<ZABBIX_SERVER_IP>"
   loki_push_url: "http://<LOKI_SERVER_IP>:3100/loki/api/v1/push"
   wazuh_manager: "<WAZUH_MANAGER_IP>"
   ```

3. **Ansible 플레이북 실행**:
   ```bash
   cd ansible
   ansible-galaxy collection install ansible.posix community.general
   ansible-playbook -i inventory.ini -e @lab_vars.yml deploy_agents.yml
   ```

4. **서비스 기동 상태 검증**:
   ```bash
   ansible targets -i inventory.ini -b -m shell -a "systemctl is-active zabbix-agent2 alloy wazuh-agent"
   ```

### 배포 후 동작 검증 포인트

- 3개 서비스가 모두 `active` 상태여야 합니다.
- Zabbix 서버에 호스트가 FQDN 식별자로 자동 등록되어야 합니다 (서버 측 Autoregistration Action 연동 필요).
- Loki에 `{host="<FQDN>"}` 구조의 로그 스트림 수집이 확인되어야 합니다 (`probe.py loki <FQDN>` 검증).
- 게이트웨이의 `collect_context` 모듈이 `HOST_LABEL_MAP` 우회 없이 해당 호스트의 메트릭·로그·보안 경보를 수집해야 합니다.

---

## 4. 서버 측 자동 등록 액션 (`autoregister_action.yml`)

에이전트가 송신한 `HostMetadata=linux-3agent-bundle` 항목을 매칭하여 호스트 추가, 그룹 배정, 템플릿 연동을 자동 처리하는 Zabbix API 기반 연동 플레이북입니다.

```bash
cd ansible
export ZABBIX_API_TOKEN='<ZABBIX_API_TOKEN>'
ansible-playbook -i inventory.ini autoregister_action.yml
```

`host_metadata` 조건값은 `deploy_agents.yml`에 정의된 메타데이터와 완전 일치해야 합니다. 실행 완료 후 신규 VM에 에이전트 배포 시 즉시 자동 등록 및 템플릿 링크 프로세스가 가동됩니다.

---

## 5. DB 복제 지연 감시 배선 (`setup_mysql_monitoring.yml`)

데모 C 시나리오 핵심 지표인 `mysql.seconds_behind_master` 항목을 Zabbix에서 수집할 수 있도록 에이전트 측 DB 모니터링 계정 및 `zabbix-agent2` MySQL 세션을 자동 구성합니다.

본 작업은 1회성 구성에 그치지 않고, 동일한 DB 환경 온보딩 시 재사용할 수 있도록 **코드화(As-Code)**되어 제공됩니다.

### 베스트 프랙티스 준수 및 멱등성 검증

수동으로 계정을 생성할 경우 이후 플레이북이 멱등한 no-op 상태가 되어 계정 생성 경로가 검증되지 않는 문제를 방지하고자, **클린 상태의 호스트에 플레이북을 직접 돌려 배선과 검증을 동시에 완주**합니다.

```bash
# control 노드(core)에서 컬렉션 설치
ansible-galaxy collection install community.mysql

# lab_vars.yml 내 mysql_monitor_password 추가 후 실행
ansible-playbook -i inventory.local.ini -e @lab_vars.yml setup_mysql_monitoring.yml
```

### Zabbix 서버 측 템플릿 연동 (`link_mysql_template.yml`)

대상 호스트에 "MySQL by Zabbix agent 2" 템플릿을 연결하고, 필수 매크로(`{$MYSQL.DSN}=repl`, `{$MYSQL.REPL_LAG.MAX.WARN}=60`)를 할당합니다. 기존 "Linux by Zabbix agent" 템플릿이 해제되지 않도록 `link_templates`를 명시하여 실행합니다.

```bash
export ZABBIX_API_TOKEN='<ZABBIX_API_TOKEN>'
ansible-playbook -i inventory.ini -e mysql_target_host=<FQDN> link_mysql_template.yml
```

연동 완료 시 Replication LLD(Low-Level Discovery) 프로세스가 복제 슬레이브 노드를 자동 탐지하여 `Seconds Behind Master` 아이템 및 "Replication lag is too high" 트리거를 생성합니다.

---

## 6. 디렉토리 구조 리팩터링 방향 (향후 확장 로드맵)

현재 `ansible/` 디렉토리는 단일 플레이북 중심으로 구성되어 있습니다. 대상 호스트 수, 인프라 티어, 요구사항 확장에 대응하기 위해 Ansible 권장 모범 구조로의 리팩터링 방향을 정의합니다:

- **`roles/`**: 기능 단위(예: `agents`, `db_monitoring`)로 모듈화하여 로직 재사용성을 확보합니다.
- **`group_vars/` / `host_vars/`**: OS, 고객사, DB 환경 차이를 폴더 분리가 아닌 변수 계층 구조로 흡수합니다.
- **환경별 인벤토리 분리**: `production`과 `staging` 인벤토리를 엄격히 격리합니다.

> **[조직 원칙]** OS/고객사별 별도 디렉토리를 생성하지 않고, 기능 단위 역할(Role) 구성과 변수 매핑(`group_vars`/`host_vars`)을 통해 동적 환경에 상응하도록 디자인합니다.

---

## 7. Wazuh 에이전트 감시 정의 (`ossec.conf.j2`)

### 템플릿화 도입 배경

`wazuh-agent`는 환경변수(`WAZUH_MANAGER`)를 최초 설치 시점에만 단 1회 읽기 때문에, 재배포를 통한 매니저 주소 변경이 반영되지 않는 한계가 존재합니다. Jinja2 템플릿 기반으로 배포함으로써 구성 변경을 즉시 반영할 수 있습니다.

또한, 기본 설정 적용 시 미지정 임시 파일(`/etc/zabbix/zabbix_md5.tmp` 등) 변경 이벤트가 전체 FIM 발생 건수의 85% 이상을 차지하는 노이즈를 유발하므로, 코드 기반의 정밀 감시/제외 범위 설정이 필수적입니다.

### 감시 경로 정의 (기본값 유지 및 핵심 경로 확장)

기본 설정(`/etc`, `/usr/bin`, `/usr/sbin`, `/bin`, `/sbin`, `/boot` 12시간 주기 스캔)을 유지하여 CIS RHEL 9 기준 AIDE 커버리지를 충족하며, 아래의 핵심 경로를 추가 감시 대상으로 지정합니다:

| 추가 감시 경로 | 모드 | 설정 목적 및 이유 |
|---|---|---|
| `/root/.ssh` | `realtime` | 권한 승격 후 백도어 SSH 키 생성 감시 |
| `/etc/cron.d`, `cron.daily`, `cron.hourly` | `realtime` | 지속성(Persistence) 확보 목적의 스케줄러 변조 감시 |
| `/etc/systemd/system` | `realtime` | systemd 서비스 유닛 생성을 통한 지속성 확보 감시 |
| `/etc/ssh` | `whodata` + `report_changes` | 변경 주체 Audit 추적 및 상세 diff 차이 기록 |

`realtime` 모드는 inotify watch 예산 한계를 고려하여 변경 빈도가 낮고 위협도가 높은 특정 경로로 국한하여 지정합니다.

### 기본 제외 규칙 및 설정 보존 (Ignore Rules)

`ossec.conf.j2` 템플릿 배포 시 패키지 기본 설정이 덮어씌워지므로, 공식 기본 파일(`wazuh/etc/ossec-agent.conf`) 내 필수 정의 항목을 반드시 보존합니다:

- **기존 `<ignore>` 14개 항목 유지**: `/etc/mtab`, `/etc/adjtime`, `/etc/random-seed` 등 정상 시스템 운영 중 상시 변경되는 파일들의 노이즈 표출 차단
- **`<synchronization>` 블록 보존**: syscheck/syscollector 모듈과 매니저 DB 간 상태 정합성 동기화 유지
- **`<rootcheck>` 모듈 유지**: 루트킷/트로이목마 시그니처 탐지 기능 유지

### Rootcheck 모듈 내 `system_audit` 제거 이유

기본 rootcheck 설정에 포함된 `<system_audit>` 세부 지침 항목 중 `cis_debian_linux_rcl.txt` 등의 타 OS 점검 파일은 제거합니다. 해당 설정 점검 기능은 SCA 모듈(`cis_rocky_linux_9.yml`, 166개 항목)에서 정밀 수행되므로 중복 점검 요소를 배제합니다.

### 실측 기반 노이즈 제외 규칙 추가

| 제외 대상 패턴 | 추가 사유 및 근거 |
|---|---|
| `^/etc/zabbix/.*\.tmp$` | Zabbix 커스텀 스크립트 작업 파일 (FIM 노이즈 발생 원인의 85.7% 점유) |
| `/boot/grub2/grubenv` (`.new` 포함) | `grub-boot-success.timer`에 의해 상시 갱신되는 정상 파일 (Red Hat KB 7099376) |
| 임시/로그 확장자 9종 | `.log$`, `.swp$` 등 가변 파일 감시 제외 확장 |
| `/var/ossec/queue`, `/var/ossec/logs` | 감시 도구 자체 로그 생성에 따른 자기 순환 노이즈 차단 |

자격 증명 보관 파일(`/etc/shadow` 및 주요 키 파일)에는 `<nodiff>` 지침을 적용하여 변경 여부만 기록하고 실제 평문 diff 데이터가 알림 로그에 실리지 않도록 통제합니다.

---

## 8. Wazuh 알림 게이트웨이 연동 (`wazuh_gateway_integration.yml`)

### 조회(Pull)와 배선(Push)의 역할 구분

- **조회 (Pull, 봇 ➔ Indexer)**: 인시던트 발화 후 봇이 추가 보안 맥락 데이터를 수집하는 경로 (기존 구성 완료)
- **배선 (Push, Manager ➔ 봇)**: 레벨 10 이상의 주요 보안 경보 발생 시 매니저가 봇으로 웹훅 알림을 즉시 송신하여 **인시던트를 직접 발화시키는 경로** (본 플레이북을 통해 신설)

### 분류기(Classify) 키워드 매칭 정밀화

보안 경보 웹훅 연동 전, Wazuh 알림 메시지가 `other` 분류로 탈락하여 병합이 무효화되는 현상을 방지하고자 매칭 로직을 수정했습니다:

1. **단어 경계 정규식 개선**: 정규식 단어 경계(`\b`)가 밑줄(`_`)을 단어 문자로 취급하여 `sshd_config` 패턴이 `sshd` 매칭에서 누락되던 문제를 영숫자 경계 매칭으로 변경하여 해결함
2. **보안 축 키워드 추가**: `integrity`, `무결성`, `syscheck`, `파일 변경`, `루트킷` 등 주요 FIM/보안 키워드를 라우팅 테이블에 등록함

### 연동 파이프라인 구성 사양

Wazuh 커스텀 연동 규약(Custom Integration)을 준수합니다:

- **스크립트 경로**: `/var/ossec/integrations/custom-gateway` (권한: `root:wazuh` 750)
- **수신 임계치**: 레벨 10 이상 경보 항목만 게이트웨이로 전송 (팀 내 관제 기준 준수)
- **토큰 보안 관리**: CLI 인자 전달 방식을 지양하고, `/var/ossec/etc/gateway_token` (`root:wazuh` 640) 개별 보안 파일 읽기 방식으로 구현하여 프로세스 트리 내 인증 토큰 노출을 차단함

```bash
# 인벤토리 변수 설정 후 플레이북 실행
ansible-playbook -i inventory.local.ini wazuh_gateway_integration.yml -e @lab_vars.yml
```

### 동작 검증 절차

```bash
# 1. Wazuh Manager 연동 데몬 상태 확인
ssh rocky@<WAZUH_MANAGER_IP> "sudo /var/ossec/bin/wazuh-control status | grep integrator"
# 출력: wazuh-integratord is running

# 2. 매니저 연동 로그 확인
ssh rocky@<WAZUH_MANAGER_IP> "sudo tail -20 /var/ossec/logs/integrations.log"
# 출력: sent rule=100201 level=12 ... -> HTTP 200
```

---

## 9. 레거시(v1) 에이전트 잔재 정리 (`cleanup_legacy_zabbix_agent.yml`)

### 불필요 노이즈 원인 추적 결과

FIM 이벤트 분석 중 지속적으로 발생하던 `/etc/zabbix/zabbix_md5.tmp` 변경 로그를 추적한 결과, 과거 구버전(v1) 에이전트용 재기동 크론 스크립트(`/etc/cron.d/restart_zabbix_agent`)가 4시간마다 주기 실행되어 가짜 변경 이벤트를 생성하고 있음을 확인했습니다.

### 정리 스크립트 적용 내용

`zabbix-agent2` (v2) 환경에서 불필요한 구버전 크론 파일 및 스크립트를 완전히 제거합니다:

```yaml
- name: 구버전 zabbix-agent(v1) 스크립트 및 크론 제거
  ansible.builtin.file:
    path: "{{ item }}"
    state: absent
  loop:
    - /etc/cron.d/restart_zabbix_agent
    - /etc/zabbix/scripts/restart_agent.sh
    - /etc/zabbix/zabbix_md5.cur
    - /etc/zabbix/zabbix_md5.tmp
```

`zabbix_agent2.conf` 배포 플레이북 내 `notify: restart zabbix-agent2` 핸들러가 구성 변경 시 즉시 재기동을 처리하므로, 주기적인 외부 크론 재기동 스크립트는 불필요합니다.

---

## 10. Wazuh 매니저 커스텀 룰 (`wazuh_manager_rules.yml`)

### 주요 승격 룰 정의

| 룰 ID | 감시 대상 이벤트 | 승격 레벨 | 승격 사유 |
|---|---|---|---|
| **100201** | `/root/.ssh/`, `/etc/ssh/sshd_config`, `/etc/passwd`, `/etc/shadow`, `/etc/sudoers` 변경 | Level 3~7 ➔ **Level 12** | 핵심 보안 파일 변조 발생 시 팀 컷오프(10) 이상으로 승격하여 즉시 알림 발화 |
| **100210** | SCA 하드닝 검사 통과 ➔ 실패 회귀 (Rule 19011) | Level 9 ➔ **Level 12** | 보안 하드닝 설정이 풀리는 시점에 한해 예외적으로 알림 승격 처리 |

정규식 구문 작성 시 `type="pcre2"` 속성을 명시하여 OS_Regex 구문 해석 오류로 인한 매칭 누락을 방지합니다.

---

## 11. MSP 멀티테넌트 고객 환경 에이전트 배포

`deploy_agents.yml` 실행 시 `customer` 인벤토리 변수를 지정하여 MSP 테넌트별 자동 등록 그룹을 동적으로 격리합니다:

| 테넌트 구분 | 인벤토리 변수 설정 | HostMetadata 설정값 | Zabbix 자동 등록 그룹 |
|---|---|---|---|
| **사내 인프라** | (기본값) | `linux-3agent-bundle:internal` | `Discovered hosts` |
| **MSP 고객사 B** | `customer=customer-b` | `linux-3agent-bundle:customer-b` | `Customers/Customer-B` |

`HostMetadata` 조건값 뒤에 테넌트 접미사(`:customer-b`)를 명시적 부여함으로써, 사내 자동 등록 액션과의 부분 매칭(`like`) 충돌 및 그에 따른 타 테넌트 그룹 중복 등록 문제를 차단합니다.

---

## 12. 인증서 만료 감시 자동화 (`certificates.yml`)

### 구축 개요

Zabbix 7.0 내장 템플릿인 **"Website certificate by Zabbix agent 2"**를 활용하여 도메인별 TLS/SSL 인증서 만료 주기를 모니터링합니다.

- **아이템 키**: `web.certificate.get[{$CERT.WEBSITE.HOSTNAME},{$CERT.WEBSITE.PORT},{$CERT.WEBSITE.IP}]`
- **수집 지표**: 만료 예정일, 발급자, SAN, SHA-1 Fingerprint, 검증 결과 등
- **기본 임계치**: 만료 30일 전 Warning 알림 발화 (`{$CERT.EXPIRY.WARN}=30`)

### 이원화 트리거 구성 (만료 임박 vs 점검 불가)

상용 환경에서 TLS 핸드셰이크 실패 시 아이템이 `unsupported` 상태로 전환되어 기존 만료 임박 트리거가 발화하지 않는 문제를 보완하기 위해 이원화 트리거를 구축합니다:

| 트리거 명칭 | 검증 목적 및 조건식 | 부여 심각도 |
|---|---|---|
| **인증서 만료 임박** | 인증서 만료 잔여일 임계치 미달 시 발화 | `Warning` |
| **인증서 점검 불가** | `nodata(12h)` 조건 성립 시 발화 (네트워크 단락, 도메인 장애, 에이전트 중단 감지) | `Average` |

`nodata()` 검증 대상 아이템 지정 시 마스터 아이템이 아닌 **종속 아이템(`cert.not_after`)**을 지정하여, History 설정 미비(`history=0`)에 의한 계산 오류를 방지합니다. `nodata()` 창 크기는 전처리 하트비트 주기(6h)의 2배수인 **12시간**으로 지정하여 정상 하트비트 간격에 의한 오탐 발화를 방지합니다.

```bash
# 인증서 감시 호스트 생성 및 템플릿 연동 실행
export ZABBIX_API_TOKEN='<ZABBIX_ADMIN_TOKEN>'
ansible-playbook -i ansible/inventory.ini ansible/certificates.yml -e @ansible/certs.local.yml
```

---

## 13. MSP 월간 리포트 파이프라인 (`msp_report.yml` + `bot/msp_report.py`)

### 시스템 아키텍처 및 데이터 흐름

기존 Zabbix Scheduled Report 기능을 수용하면서, Zabbix 단독으로 산출이 불가능한 인시던트 병합 통계, 만성/신규 선판정 비율, 자동 조치 후보 등록 수, LLM 종합 분석 서사 데이터를 외부에서 Trapper 아이템으로 주입하는 파이프라인을 구축합니다.

```text
Keep /alerts (인시던트 이력) ──▶ bot/msp_report.py (통계 집계 및 LLM 서사 생성)
                                        │
                                (Zabbix Sender)
                                        │
                                        ▼
Grafana 대시보드 (kinx-msp-report) ──▶ Grafana Image Renderer ──▶ PDF / Email 발송
```

### 미산출 지표 표기 규약 (`NOT_MEASURED`)

집계 실패 또는 미측정 지표에 대해 `0`이나 누락 처리 대신 **`-1` (`NOT_MEASURED`)** 값을 명시적으로 전송하여, 대시보드 상에 "미산출" 상태로 정확히 표현되도록 강제합니다. (과거 집계 데이터 이월 표시 및 0% 오인 오독 방지)

### 서사 생성 승인 게이트 (Human-in-the-Loop)

LLM이 생성한 월간 종합 분석 서사(`report.summary`)는 명시적 사용자 승인 전까지 `"검토 대기 — 승인 후 게시됩니다"` 상태로 고정되어 승인되지 않은 분석 문장이 메일 리포트에 실리는 것을 차단합니다.

```bash
# 1. 고객별 리포트 Trapper 호스트 및 아이템 자동 생성
export ZABBIX_API_TOKEN='<ZABBIX_ADMIN_TOKEN>'
ansible-playbook -i inventory.ini -i inventory.local.ini msp_report.yml

# 2. 통계 집계 및 요약 초안 Keep 승인 큐 전송
python bot/msp_report.py --host-filter customer-a --target report-Customer-A --draft-to-keep

# 3. 승인 완료 후 Zabbix 주입 및 메일 리포트 발송
python bot/msp_report.py --host-filter customer-a --target report-Customer-A --send --approve
```

---

## 14. 요약 및 검증 상태

본 문서에 명시된 모든 Ansible 플레이북, Wazuh 연동 스크립트, Zabbix 템플릿 배선 및 리포트 집계 모듈은 랩 환경에서 실측 및 검증이 완료된 상태입니다.

실환경 적용 시 `lab_vars.yml` 및 `certs.local.yml` 변수 파일 내 대상 IP와 도메인 항목을 목적지에 맞게 수정하여 실행합니다.