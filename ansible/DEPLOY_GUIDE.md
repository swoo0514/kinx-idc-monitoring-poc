# 3종 에이전트 배포 (deploy_agents.yml) — 가이드

## 무엇인가 / 왜 고도화인가

새 Rocky 9 호스트 하나에 **zabbix-agent2 + Alloy + wazuh-agent를 플레이북 한 번으로** 설치·
설정한다. MaC(Monitoring as Code)의 "배포 절반"이다.

**팀 기존 Ansible 대체가 아니라 위에 얹는 것**(인터뷰 B-4: 팀은 이미 Ansible로 에이전트
배포·등록 중). 기존 단일 분기 스크립트가 지금 안 하는 것을 추가분으로 얹는다:

1. **3종 번들** — 메트릭(zabbix)만이 아니라 로그(Alloy→Loki)·보안(wazuh)까지 배포 단계에서
   함께. 데모 C의 3소스가 여기서 시작된다.
2. **호스트 식별자 FQDN 정규화** — 세 에이전트 모두에 같은 `agent_identity`(FQDN)를 심는다
   (zabbix Hostname = alloy host 라벨 = wazuh 에이전트명). 손설치한 node1은 이름이 셋 다
   달라(Zabbix node1 / Loki·Wazuh FQDN) 봇이 `HOST_LABEL_MAP` 없이는 상관을 못 했다. 이
   플레이북으로 온보딩한 호스트는 **처음부터 정규화되어 매핑이 불필요**하다 — 로드맵의 "FQDN
   정규화"를 온보딩에서 강제하는 구현.
3. **autoregistration 준비** — `HostMetadata=linux-3agent-bundle`을 심어, 서버측 액션이 이
   메타데이터를 보고 자동 등록·템플릿 링크(실측 Discovered hosts 0 = 자동등록 미사용을 메움).
4. **구버전 정리(멱등)** — 랩에서 겪은 구버전 zabbix-agent(v1) 포트 10050 선점 충돌을 제거.

## config 정답지 (node1 실측, 2026-07-27)

플레이북 변수의 **실 값은 node1의 검증된 설정에서** 왔다(문서 추측 아님). 단 랩 사설 IP는
커밋하지 않으므로, 커밋본 기본값은 문서용 placeholder(RFC5737)이고 실 값은 gitignored
`lab_vars.yml`로 주입한다. 실 값 출처:

| 변수 | 출처 |
|---|---|
| `zabbix_server` | node1 `zabbix_agent2.conf` 의 Server |
| `loki_push_url` | node1 `config.alloy` 의 loki.write endpoint |
| `wazuh_manager` | node1 `ossec.conf` 의 server address |
| OS/버전 | Rocky 9 / agent2 7.0.28 · alloy 1.17.1 · wazuh 4.14.6 (node1 rpm -q) |

배포되는 설정 파일은 셋이다.

| 템플릿 | 배포 위치 | 담는 것 |
|---|---|---|
| `zabbix_agent2.conf.j2` | `/etc/zabbix/zabbix_agent2.conf` | 서버 주소, 자동등록 메타데이터 |
| `alloy_config.alloy.j2` | `/etc/alloy/config.alloy` | 저널 수집 → Loki push |
| `ossec.conf.j2` | `/var/ossec/etc/ossec.conf` | 매니저 주소, FIM 감시 경로·제외, SCA |

## 실행

1. 대상 VM을 `inventory.ini`의 `[targets]`에 추가 (agent_identity = 그 VM의 FQDN):
   ```
   db-target-001 ansible_host=192.0.2.XX agent_identity=db-target-001.novalocal
   ```
2. 실 랩 값을 gitignored `ansible/lab_vars.yml`에 작성 (커밋 안 됨):
   ```yaml
   zabbix_server: "<node1 실측 IP>"
   loki_push_url: "http://<동일 IP>:3100/loki/api/v1/push"
   wazuh_manager: "<node1 ossec.conf server 주소>"
   ```
3. 배포 (SSH·sudo 필요, 상태 변경이므로 사용자가 실행):
   ```bash
   cd ansible
   ansible-galaxy collection install ansible.posix community.general   # yum_repository 등
   ansible-playbook -i inventory.ini -e @lab_vars.yml deploy_agents.yml
   ```
4. 검증:
   ```bash
   ansible targets -i inventory.ini -b -m shell -a "systemctl is-active zabbix-agent2 alloy wazuh-agent"
   ```

## 검증 포인트 (배포 후)

- 세 서비스 active. Zabbix에 그 FQDN 호스트가 autoregistration으로 등록(서버측 액션 필요 — 아래).
- Loki에 `{host="<FQDN>"}` 로그 유입 (probe.py loki <FQDN> 로 확인).
- 봇 `collect_context`가 그 호스트 이벤트로 logs/security를 **HOST_LABEL_MAP 없이** 수집 —
  정규화가 됐으므로.

## 서버측 autoregistration 액션 (autoregister_action.yml)

agent가 보낸 `HostMetadata=linux-3agent-bundle`을 매칭해 호스트 추가·그룹 배정·템플릿 링크를
자동화하는 액션. deploy_agents.yml(agent 측)과 짝이며, 이게 있어야 "손등록 0"이 완성된다.
onboard.yml 과 같은 Zabbix API 방식이라 별도 실행:

```bash
cd ansible
ansible-playbook -i inventory.ini autoregister_action.yml   # ZABBIX_API_TOKEN env 필요
```

`host_metadata` 값은 deploy_agents.yml의 것과 반드시 일치. 이후 새 VM에 deploy_agents.yml을
돌리면 접속 즉시 자동 등록·템플릿 링크된다. (액션 조건/오퍼레이션 파라미터는 community.zabbix
zabbix_action 공식 문서 확인.)

## DB 복제 지연 감시 배선 (setup_mysql_monitoring.yml)

데모 C 지표(`mysql.seconds_behind_master`)를 Zabbix 가 보게 하는 agent 측 배선(모니터링 계정 +
agent2 mysql 세션). 사내 동질 DB 군(서비스 slave 12대) 온보딩의 **첫 인스턴스**이므로 코드화한다
(1회성이 아니라 반복 패턴의 시작 + "누구나 30분 재현" 산출물 요구).

**핵심 — 손으로 먼저 만들지 않는다:** 손으로 계정을 만들면 이후 플레이북은 idempotent no-op 이
되어 "계정 생성" 경로가 영영 검증되지 않는다(미검증 산출물). 따라서 **깨끗한 호스트에 플레이북을
실행하는 그 행위가 곧 셋업이자 검증**이다.

베스트 프랙티스 준수: raw command 대신 idempotent 전용 모듈 `community.mysql.mysql_user`,
비밀은 랩=gitignored lab_vars.yml / 프로덕션=Ansible Vault.

```bash
# control 노드(core). 컬렉션 1회 설치
ansible-galaxy collection install community.mysql
# lab_vars.yml 에 mysql_monitor_password 추가
ansible-playbook -i inventory.local.ini -e @lab_vars.yml setup_mysql_monitoring.yml
```
모듈이 PyMySQL·priv 이름(`SLAVE MONITOR` 등 MariaDB 전용)을 실행 시 검증한다 — 실패하면 그게
검증이 일하는 것, 고쳐서 재실행.

**Zabbix 측(서버 API) — link_mysql_template.yml**: 호스트에 "MySQL by Zabbix agent 2" 템플릿
링크 + 매크로 `{$MYSQL.DSN}=repl`·`{$MYSQL.REPL_LAG.MAX.WARN}=60`. UI 로 먼저 링크하면 이 경로가
검증 안 되므로 플레이북 실행이 곧 링크+검증. `link_templates` 는 기존 "Linux by Zabbix agent" 도
함께 나열해 언링크를 막는다. 호스트명은 agent_identity(FQDN)와 동일.
```bash
export ZABBIX_API_TOKEN='<랩 토큰>'
ansible-playbook -i inventory.ini -e mysql_target_host=<FQDN> link_mysql_template.yml
```
링크 후 Replication LLD 가 slave 를 발견해 `Seconds Behind Master` 아이템 + "Replication lag is
too high" 트리거 생성. (community.zabbix + 낮은 ansible-core 궁합 이슈 시 zabbix_action 처럼
파라미터 보정.)

MSP 이질 고객 DB 는 매니저 프록시 Q3 판정과 같은 이유(환경 제각각=자동화 저효용)로 이 플레이북을
그대로 밀지 말고 파라미터화 출발점으로.

## 확장 시 디렉토리 리팩터링 방향 (현재 스코프 밖 — 기록용)

현재 `ansible/` 는 flat 플레이북 모음이다(데모 대상 1대·플레이북 4개 규모엔 적절 — 지금
roles 로 갈아엎는 건 over-engineering). 호스트·티어·재사용이 늘면 **Ansible 공식 권장
레이아웃**으로 refactor:

- `roles/` — 기능별(예: `agents`, `db_monitoring`). 재사용 로직은 flat 플레이북이 아니라 role.
- `group_vars/` · `host_vars/` — **OS·고객사·DB 차이는 폴더가 아니라 변수로 흡수.**
- 환경별 인벤토리(production/staging) 분리.

핵심 — **OS/고객사/DB별 폴더로 나누지 않는다.** 공식 조직 원리는 "기능(role)별 조직 + 변종은
`group_vars`/`host_vars`/인벤토리 그룹으로 흡수"다. 예: Rocky vs Ubuntu 는 role 안
`ansible_os_family` 분기 또는 OS 그룹 `group_vars`, 고객사별은 `host_vars`+인벤토리 그룹.
근거: docs.ansible.com/ansible/latest/tips_tricks/sample_setup.html

## Wazuh 에이전트 감시 정의 (`ossec.conf.j2`, 2026-07-30)

### 왜 템플릿으로 뺐나

wazuh-agent 는 `WAZUH_MANAGER` 환경변수를 **최초 설치 때 한 번만** 읽는다. 재배포로 매니저
주소를 바꿔도 반영되지 않았다. 템플릿을 배포하면 그 한계가 없어진다.

더 큰 이유는 따로 있다. 랩 인덱서를 조회해 보니 **FIM 이벤트 107건 중 상위 5건 가운데 4건이
`/etc/zabbix/zabbix_md5.tmp`** 였다. 아무도 켠 적 없는데 기본값이 활성이라 계속 쌓이고 있었다.
무엇을 감시하고 무엇을 빼는지가 코드에 없으면 이런 상태를 알아챌 방법도, 고칠 방법도 없다.

### 감시 경로 — 기본값을 유지하고 소수만 더했다

기본값은 `/etc`, `/usr/bin`, `/usr/sbin`, `/bin`, `/sbin`, `/boot` 를 12시간 주기로 본다. 이
범위는 CIS RHEL 9 의 6.1.x 가 전제하는 AIDE 커버리지와 대체로 겹치므로 그대로 둔다. 실제 갭은
커버리지가 아니라 빠진 소수였다.

| 추가 경로 | 모드 | 이유 |
|---|---|---|
| `/root/.ssh` | realtime | 권한 상승 후 백도어 키를 심는 자리인데 기본 감시 밖 |
| `/etc/cron.d`, `cron.daily`, `cron.hourly` | realtime | 지속성 확보의 고전적 경로 |
| `/etc/systemd/system` | realtime | 위와 같음. systemd 유닛으로 심는 쪽이 더 흔하다 |
| `/etc/ssh` | whodata + report_changes | "누가 바꿨나"와 "무엇이 바뀌었나"까지 남긴다 |

**realtime 을 큰 트리에 걸지 않는다.** inotify watch 예산이 유한해서, 넓게 걸면 rule 560(실시간
큐 포화)이 난다. 작고 값이 높으며 평소 안 바뀌는 곳에만 쓴다.

whodata 는 Rocky 9 커널(5.14 대)에서 eBPF provider 요건(5.8+)을 만족한다. 안 되면 audit 모드로
자동 폴백하므로 실패하지는 않는다.

`frequency` 12시간은 PCI DSS 11.5.2 의 "최소 주간" 요구를 넉넉히 넘는다.

### 제외 규칙 — 공식 기본값 14건을 먼저 보존한다

**템플릿은 패키지 기본 `ossec.conf` 를 통째로 덮어쓴다.** 그래서 기본 파일에 있던 것을
빠뜨리면 조용히 사라진다. 처음 작성했을 때 실제로 두 가지를 떨어뜨렸다가 공식 기본 파일
(`wazuh/etc/ossec-agent.conf`)과 대조해서 되살렸다.

- **기본 `<ignore>` 14건** — `/etc/mtab`(마운트할 때마다 변경), `/etc/adjtime`(시각 동기화),
  `/etc/random-seed`(부팅) 등. 전부 "정상 동작으로 계속 바뀌는 파일"이라 Wazuh가 처음부터
  빼 둔 것들이다. 이걸 놓쳤으면 우리가 노이즈를 줄이러 가서 **새 노이즈를 만들** 뻔했다
- **`<synchronization>` 블록** — syscheck·syscollector가 매니저와 DB를 맞추는 설정.
  없으면 내장 기본값으로 돌지만, 명시가 사라지면 무엇이 적용 중인지 코드에서 안 보인다
- **`<rootcheck>` 통째로** — 배포 후 에이전트 로그에 `rootcheck: INFO: Rootcheck disabled.`
  가 찍혀서 발견했다. 루트킷·트로이목마 시그니처 탐지라 FIM·SCA 어느 쪽도 대체하지 않는다.
  룰 510이 레벨 7이라 컷라인(10) 아래여서 알림 폭증 위험도 없다

**교훈: 기본 파일을 덮어쓰는 템플릿은 "무엇을 더했나"보다 "무엇을 뺐나"를 먼저 대조해야
한다.** 원본은 공식 저장소 `etc/ossec-agent.conf` 다.

### 되살리되 그대로는 아닌 것 — rootcheck의 `<system_audit>`

기본 rootcheck에는 `<system_audit>` 세 줄이 딸려 있는데 **이건 일부러 뺐다.**

```
system_audit_rcl.txt / system_audit_ssh.txt / cis_debian_linux_rcl.txt
```

세 번째가 **Debian용 CIS 파일**이다. Rocky 9 호스트에서 돌릴 물건이 아니다. 그리고 이 설정
점검 기능은 SCA가 하는 일과 겹치는데, SCA는 OS에 맞는 `cis_rocky_linux_9.yml`(166체크)을
쓴다. **같은 일을 틀린 기준으로 한 번 더 할 이유가 없다.**

루트킷·트로이목마 탐지(`rootkit_files`·`rootkit_trojans`)만 남겼다. 이건 다른 모듈이
대신해 주지 않는 기능이다.

**"뺐다"와 "빠뜨렸다"는 다르다.** 위 두 건은 빠뜨린 것이라 되살렸고, 이건 근거를 두고 뺀 것이다.

### 우리가 추가한 제외 규칙 — 랩 실측에서 나온 것

| 제외 대상 | 근거 |
|---|---|
| `^/etc/zabbix/.*\.tmp$` | **7일 FIM 이벤트 56건 중 48건(85.7%)이 이 파일 하나.** Zabbix 커스텀 스크립트의 작업 파일 |
| `/boot/grub2/grubenv`(+`.new`) | 같은 기간 4건(7.1%). `grub-boot-success.timer` 가 세션마다 다시 쓴다 (Red Hat KB 7099376, Bugzilla 1971356 — 의도된 동작) |
| 변경 잦은 확장자 9종 | 기본 ignore 의 `.log$\|.swp$` 를 확장 |
| `/var/ossec/queue`, `/var/ossec/logs` | 감시 도구가 자기 로그를 쓰고 그게 이벤트가 되는 루프 (공식 경고) |

위 둘로 **56건 중 52건(92.9%)이 걸러진다.** 남는 4건은 전부 우리가 Ansible로 배포하며
실제로 바꾼 파일이다(`config.alloy` 2, `ld.so.cache` 1, `mysql.conf` 1) — 즉 FIM은
제대로 동작하고 있었고, **의미 있는 4건이 무의미한 52건에 묻혀 있었을 뿐**이다.

앞의 둘은 **둘 다 임시 조치다.** 근본 해결은 각각 스크립트가 `/etc` 대신 `/var/lib/zabbix` 에
쓰게 고치는 것과 타이머를 마스킹하는 것이다. 표준 설치하면 누구에게나 생기는 노이즈라 제외
규칙으로 덮되, 근본 해결책을 로드맵에 남긴다.

`<nodiff>` 는 `/etc/shadow` 와 키 파일에 건다. **변경 사실은 남기되 내용은 남기지 않는다** —
report_changes 가 켜진 상태에서 자격증명 파일의 diff 가 알림에 실리면 그 자체가 유출이다.

### SCA·syscollector 를 명시적으로 적은 이유

둘 다 기본값 그대로다. 그럼에도 적는 것은 **우리가 무엇을 켜뒀는지가 코드에 보여야 하기**
때문이다. 이번 작업의 발단이 "기본값으로 돌고 있는데 아무도 몰랐다"였다.

SCA 는 에이전트가 OS 에 맞는 정책만 자동 설치하므로 Rocky 9 에는 `cis_rocky_linux_9.yml`
(166 체크) 하나만 돈다. syscollector 는 취약점 탐지의 입력원이라 `os`·`packages` 가 필수다 —
매니저가 이 인벤토리를 CVE 피드와 대조한다.

전체 조사 결과와 매니저 측 설정은 `private/docs/wazuh_enhancement_plan.md`.

## Wazuh 알림을 봇으로 (`wazuh_gateway_integration.yml`, 2026-07-30)

### 조회는 이미 되고 있었다 — 배선은 다른 문제를 푼다

혼동하기 쉬운 지점이라 먼저 정리한다.

| | 방향 | 이전 상태 | 무엇을 위한 것 |
|---|---|---|---|
| **조회 (pull)** | 봇 → 인덱서 | **동작 중** | 봇이 발동한 뒤 **맥락을 채운다** |
| **배선 (push)** | 매니저 → 봇 | **없음** | 보안 이벤트가 **봇을 발동시킨다** |

배선을 깔아도 조회는 계속 필요하다. 웹훅이 "발동 신호"를, 조회가 "주변 맥락"을 준다.

### 무엇이 안 되고 있었나

봇이 Zabbix 알림에만 발동했다. 그래서 둘이 안 됐다.

- **보안 단독 사건에 봇이 침묵한다.** 승격 룰이 인증 파일 변경을 레벨 12로 올렸는데, Zabbix 쪽에 아무 일이 없으면 봇은 그 사건을 모른다. 컷라인 위로 올린 의미가 반쪽이다
- **인시던트 병합이 3소스가 아니다.** 병합은 호스트와 사건 분류로 알림을 묶는데 들어오는 알림이 Zabbix뿐이었다. 즉 "3소스"는 **수집 3소스이지 병합 3소스가 아니었다**

### 게이트웨이 쪽은 이미 완성돼 있었다

`/webhook/wazuh` 엔드포인트가 토큰 검증·멱등·심각도 정규화·라우팅을 다 하고, triage 경로면 인시던트 버퍼에 넣는다. **웹훅만 오면 병합이 자동으로 3소스가 된다.** 매니저 쪽 배선 하나가 없었다.

기대 페이로드는 여섯 필드다.

| 필드 | 출처 (Wazuh 알림 JSON) |
|---|---|
| `alert_id` | `id` (없으면 룰ID-타임스탬프로 폴백) |
| `rule_id` / `rule_level` / `rule_description` | `rule.*` |
| `agent_name` | `agent.name` |
| `timestamp` | `timestamp` |

헤더 `X-Gateway-Token` 필수.

### 먼저 고친 것 — 분류기가 보안 축을 못 알아봤다

배선 전에 확인하니 **우리 룰 설명이 `other` 로 분류됐다.**

| 알림명 | 수정 전 | 원인 |
|---|---|---|
| 인증·권한 핵심 파일 변경(우리 승격 룰) | `other` | 한글 키워드 없음 + 아래 밑줄 문제 |
| `Integrity checksum changed`(기본 FIM 룰) | `other` | `integrity` 키워드 없음 |

`other` 로 떨어지면 **브루트포스와 병합되지 않는다.** 교차 신호 시나리오가 성립하지 않는다.

두 가지를 고쳤다.

**① 단어 경계를 영숫자로 바꿨다.** 기존에는 정규식 단어 문자로 경계를 잡았는데, 그 정의는 **밑줄을 단어 문자로 본다.** 그래서 `sshd` 가 `sshd_config` 에 안 걸렸다. 영숫자 경계로 바꾸면 걸리고, 오분류 방지 목적은 유지된다 — `scan`·`escalation` 의 `sca`, `room` 의 `oom`, `shutdown` 의 `down` 은 앞뒤가 영문자라 여전히 차단된다.

**② 보안 축 키워드를 추가했다** — `integrity`, `무결성`, `syscheck`, `파일 변경`, `루트킷`.

**일부러 안 고친 것**: 기본 FIM 룰의 파일 삭제·추가 설명(`File deleted.`, `File added to the system.`)은 여전히 `other` 다. 레벨 7/5로 컷라인 아래여서 웹훅까지 오지 않고, 우리 승격 룰이 그 세 룰을 한국어 설명으로 덮으므로 실제 경로에서는 문제가 없다. **추측으로 키워드를 늘리지 않는다.**

### 배선 구조

공식 커스텀 연동 계약을 따른다.

| 항목 | 값 |
|---|---|
| 스크립트 경로 | `/var/ossec/integrations/custom-gateway` |
| 소유·권한 | `root:wazuh`, 750 |
| 이름 규칙 | **`custom-` 접두 필수** |
| 인자 | argv[1]=알림 JSON 파일, argv[2]=api_key, argv[3]=hook_url |
| 포맷 | `alert_format json` → 전체 알림 JSON |

**레벨 필터를 10으로 둔다.** 팀 현행 컷라인이다. 이 아래를 보내면 봇이 폭주한다 — FIM(5~7)과 SCA(7~9)는 화면과 digest 몫이고, 컷라인 위로 올린 둘(인증 파일 변경, SCA 회귀)과 취약점 High/Critical, 브루트포스만 봇으로 간다.

### 토큰을 `api_key` 로 넘기지 않았다

공식 방식은 `api_key` 를 설정에 적고 스크립트가 argv[2]로 받는 것이다. **두 가지 이유로 쓰지 않았다.**

- 명령줄 인자는 실행 중 프로세스 목록에 보인다. 오늘 curl 에서 겪은 것과 같은 노출 경로다
- 우리는 크리덴셜을 코드·커밋·문서에 남기지 않는다. `api_key` 를 쓰면 공개하는 설정 스니펫에 토큰이 들어간다

그래서 스크립트가 `/var/ossec/etc/gateway_token`(`root:wazuh` 640)에서 읽는다. 플레이북이 그 파일을 `no_log` 로 배포하므로 실행 로그에도 남지 않는다.

### 안전장치는 룰 배포와 같은 순서다

```
토큰·URL 주입 확인 → 토큰 파일 → 스크립트 → ossec.conf 백업
  → integration 블록 삽입 → 설정 검증 → (실패 시 복구 + 실행 실패)
  → 재기동 → 기동 확인 → integratord 기동 확인
```

`integratord` 기동 확인을 마지막에 넣은 이유가 있다. **설정이 문법적으로 통과해도 연동 블록이 실제로 파싱되지 않으면 그 데몬이 안 뜬다.** 매니저는 `active` 인데 알림이 안 가는 상태가 되므로, 그걸 실행 실패로 잡는다.

블록 삽입은 `blockinfile` 로 마커를 남긴다. 재실행 시 같은 블록을 중복 삽입하지 않고, 나중에 사람이 열어봐도 어디가 자동 관리 구간인지 보인다.

### 실행

`ansible/lab_vars.yml`(gitignored)에 두 값을 넣는다.

```yaml
gateway_token: "<GATEWAY_TOKEN 과 같은 값>"
gateway_hook_url: "http://<게이트웨이 호스트>:8800/webhook/wazuh"
```

```bash
ansible-playbook -i inventory.local.ini wazuh_gateway_integration.yml -e @lab_vars.yml
```

사전 검증이 placeholder 주소를 거부하므로, 실 주소를 안 넣으면 첫 task에서 멈춘다.

### 확인

**① 데몬**

```bash
ssh -i ~/.ssh/deploy_key.pem rocky@<매니저> 'sudo /var/ossec/bin/wazuh-control status | grep integrator'
```

`wazuh-integratord is running` 이어야 한다.

**② 시나리오** — 승격 룰 시나리오를 그대로 다시 돌린다(SSH 설정 파일 한 줄 변경 후 원복).

```bash
ssh -i ~/.ssh/deploy_key.pem rocky@<대상> 'sudo cp -a /etc/ssh/sshd_config /tmp/sshd_config.bak'
ssh -i ~/.ssh/deploy_key.pem rocky@<대상> 'echo "# gateway wiring test" | sudo tee -a /etc/ssh/sshd_config'
```

**③ 매니저 측 전송 로그**

```bash
ssh -i ~/.ssh/deploy_key.pem rocky@<매니저> 'sudo tail -20 /var/ossec/logs/integrations.log'
```

스크립트가 출력한 `sent rule=100201 level=12 agent=... -> HTTP 200` 이 보여야 한다. 실패면 사유가 같은 로그에 남는다(토큰 파일 없음 / 게이트웨이 도달 실패 / 거부).

**④ 게이트웨이 로그** — `event=... source=wazuh host=... sev=SEV2 class=auth_security route=triage`

**⑤ Slack** — 원시 신호 카드가 먼저 오고, 디바운스 창이 닫히면 병합 트리아지가 스레드에 붙는다.

**⑥ 3소스 병합** — 브루트포스를 같은 호스트에 함께 주입하면 두 알림이 **하나의 인시던트**로 묶여야 한다. 둘 다 `auth_security` 라 같은 병합 키를 갖는다. 되돌린 것도 파일 변경이므로 알림이 한 번 더 오는 것이 정상이다.

되돌릴 때 SSH 설정 문법 검사를 반드시 거친다.

```bash
ssh -i ~/.ssh/deploy_key.pem rocky@<대상> 'sudo cp -a /tmp/sshd_config.bak /etc/ssh/sshd_config && sudo sshd -t && echo SSHD_CONFIG_OK'
```

### 확인해야 할 볼륨 리스크

취약점 탐지를 켠 뒤 High/Critical 알림이 얼마나 나오는지 아직 모른다. 배선 전 실측에서 해당 그룹 이벤트는 7일에 1건이었지만, 커넥터를 켠 뒤 값이 달라질 수 있다. **배선 후 하루 동안 게이트웨이 로그의 `source=wazuh` 건수를 세어 본다.** 과하면 연동 블록에 룰 ID 또는 그룹 조건을 추가해 좁힌다.

## v1 잔재 정리 — FIM 노이즈를 추적해서 찾은 것 (2026-07-30)

### 어떻게 발견했나

FIM 이벤트 56건 중 **48건(85.7%)이 `/etc/zabbix/zabbix_md5.tmp`** 하나였다. 그 파일이 뭔지
추적하니 v1 시절 자동화가 나왔다.

```bash
/etc/cron.d/restart_zabbix_agent          # 0 */4 * * * → 4시간마다
  └─ /etc/zabbix/scripts/restart_agent.sh
       md5sum /etc/zabbix/zabbix_agentd.d/*  > zabbix_md5.tmp   # agent v1 디렉터리
       diff zabbix_md5.cur zabbix_md5.tmp
       → 다르면  service zabbix-agent restart                    # agent v1 서비스
```

**설정이 바뀌면 에이전트를 재기동하는 구조**다. 그런데 감시 대상과 재기동 대상이 둘 다 v1이다.

```
$ rpm -q zabbix-agent zabbix-agent2
package zabbix-agent is not installed
zabbix-agent2-7.0.28-release1.el9.x86_64

$ systemctl status zabbix-agent
Unit zabbix-agent.service could not be found.
```

**v1은 없다.** 즉 이 자동화는 4시간마다 돌면서 아무 일도 하지 않고 `/etc` 에 파일만 쓴다.

### 왜 순수 노이즈인가

`.tmp` 는 `else` 분기 첫 줄에서 **diff 결과와 무관하게 매 실행 생성**된다. 설정이 안 바뀌니
`md5sum` 결과는 매번 같고, **내용은 동일한데 `mtime` 만 갱신**된다. FIM 은 `check_all` 에 mtime 이
포함되므로 **아무것도 안 바뀌었는데 변경으로 기록**한다.

산수도 맞는다 — 6회/일 × 7일 = 42회, 실측 48건(에이전트 재기동 시 `scan_on_start` 로 추가 감지).

반대로 `.cur` 는 변경이 있을 때만 갱신되므로 FIM 상위 경로에 안 나타났다. **스크립트 로직이
실측 분포를 설명한다** — 교차검증이 됐다.

### 두 번째 피해 — UserParameter 4개가 고아가 됐다

같은 전환 잔재로 `/etc/zabbix/zabbix_agentd.d/` 에 UserParameter 4개가 남아 있다.

```
UserParameter=discovery.local.ip   curl http://169.254.169.254/.../local-ipv4
UserParameter=discovery.public.ip  curl http://169.254.169.254/.../public-ipv4
UserParameter=discovery.proc       /etc/zabbix/scripts/discovery.proc.sh
UserParameter=update.agent         sudo /etc/zabbix/scripts/update_agent.sh
```

**agent2 는 `/etc/zabbix/zabbix_agent2.d/` 를 읽는다**(우리 템플릿의 `Include`). 그 디렉터리에는
우리 Ansible 이 넣은 `mysql.conf` 하나뿐이다. **네 개 전부 로드되지 않는다.**

`169.254.169.254` 는 클라우드 인스턴스 메타데이터 서비스이므로, 이 세트는 **클라우드 VM 플릿
관리를 전제로 설계된 일관된 묶음**(IP 자동발견 · 프로세스 발견 · 자기 업데이트 · 설정변경
자동재기동)이다. 7개 파일과 cron 이 모두 `Jun 29 14:01` 동일 타임스탬프여서 **일괄 배포된
것**이다. **다만 출처는 미확인이다** — "사내 표준"이라고 단정하지 않는다.

### 플레이북에 무엇을 넣었나

```yaml
- name: 구버전 zabbix-agent(v1) 잔재 정리
  ansible.builtin.file: { path: "{{ item }}", state: absent }
  loop:
    - /etc/cron.d/restart_zabbix_agent
    - /etc/zabbix/scripts/restart_agent.sh
    - /etc/zabbix/zabbix_md5.cur
    - /etc/zabbix/zabbix_md5.tmp
```

**죽은 것만 지운다.** `zabbix_agentd.d/*.conf` 와 나머지 스크립트(`set_kinx.sh`,
`update_agent.sh`, `discovery.proc.sh`, `get_metadata.py`)는 **건드리지 않는다** — 용도가
확인되지 않았고, 고아 UserParameter 는 `zabbix_agent2.d/` 로 옮기면 기능이 살아날 수 있어
삭제가 아니라 판단 대상이다.

**옮길지는 사용자 판단이다.** 특히 `update.agent` 는 `sudo` 로 자기 업데이트를 실행하므로
우리가 조용히 켤 항목이 아니다.

### 왜 이게 중요한가

**우리 플레이북의 "구버전 정리 멱등"이 패키지 제거까지였다.** 포트 10050 선점 충돌은 막았지만
파일 잔재는 보지 않았다. 실환경에서 팀이 agent v1 → v2 전환을 하면 같은 일이 난다.

그리고 이 스크립트의 목적(설정 변경 시 재기동)은 **우리 MaC 가 이미 더 정확하게 한다** —
`notify: restart zabbix-agent2` handler 가 배포 시점에 처리하므로 4시간 폴링이 필요 없다.

> **MaC 의 구체적 이득**: cron 폴링으로 설정 변경을 감지하던 것을 배포 도구의 handler 가
> 대체한다. 폴링은 최대 4시간 지연 + `/etc` 오염을 낳고, handler 는 즉시 + 부작용 없음.

### 일반화 — 실환경 도입 체크리스트

출처가 무엇이든 성립하는 교훈이다.

> **FIM 을 켜기 전에 `/etc` 에 주기적으로 쓰는 cron·스크립트를 먼저 찾는다.**
> 랩은 그게 하나였고 그것만으로 노이즈의 85.7% 였다.

찾는 방법:

```bash
sudo grep -rl '/etc/' /etc/cron.d/ /etc/cron.*/ /var/spool/cron/ 2>/dev/null
sudo find /etc -newermt '-1 day' -type f 2>/dev/null | head -30
```

**노이즈를 끝까지 추적하면 정보가 된다** — 이번엔 죽은 자동화 하나와 고아 UserParameter 4개를
찾았다. 좀비 트리거 39%·죽은 Pushover 미디어와 같은 유형이고, **FIM 을 켠 덕분에 발견됐다.**

## Wazuh 매니저 룰 (`wazuh_manager_rules.yml`, 2026-07-30)

### 무엇을 승격하나 — 둘만

| 룰 | 대상 | 레벨 | 이유 |
|---|---|---|---|
| 100201 | `/root/.ssh/`, `/etc/ssh/sshd_config`, `/etc/passwd`, `/etc/shadow`, `/etc/sudoers` 변경 | 3~7 → **12** | 바뀌면 안 되는 것 소수만. 기본 FIM 룰(550/553/554)은 7/7/5 로 팀 컷라인(10) 아래라 알림이 안 간다 |
| 100210 | SCA 체크가 통과 → 실패로 회귀 (19011) | 9 → **12** | 현재 0건이라 켜도 조용하고, 하드닝이 풀리는 순간에만 울린다 |

**19007(신규 실패)은 승격하지 않는다.** 이미 312건이 실패 상태라 컷라인 위로 올리면 그대로
폭탄이 된다. 준수율은 대시보드에서 본다.

**에이전트 disconnect(504)도 승격하지 않는다.** 실환경 321대에서 재부팅마다 뜨면 새 노이즈다.
대시보드 패널과 digest 채널로 보낸다 — "수집은 넓게, 알림은 좁게".

### 필드명 — 공식 매핑을 따른다

룰에서 쓰는 이름과 알림 JSON 필드 이름이 다르다.

| 룰 필드 | 알림 JSON |
|---|---|
| `file` | `syscheck.path` |
| `process_name` | `audit.process.name` |
| `user_name` | `audit.user.name` |
| `changed_fields` | `changed_attributes` |

근거: [Creating custom FIM rules](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/creating-custom-fim-rules.html)

### 정규식 — `type="pcre2"` 를 반드시 붙인다

Wazuh 기본 정규식(OS_Regex)은 **PCRE와 점 의미가 반대**다.

> osregex: `.` 는 **문자 그대로의 점**, `\.` 가 **아무 문자**를 매칭한다

즉 PCRE 습관으로 `\.ssh` 라고 쓰면 osregex 에서는 `/root/Xssh` 같은 것도 걸린다. 반대로
osregex 로 쓰려면 `.` 를 그냥 써야 한다. **틀려도 에러가 안 나고 룰이 조용히 안 맞을 뿐**이라
가장 위험한 종류의 실수다.

그래서 `100201` 은 `<field name="file" type="pcre2">` 로 명시했다. **이 속성을 지우면
정규식 의미가 바뀐다** — 지울 경우 `\.` 를 `.` 로 함께 고쳐야 한다.

근거: [Regular expression syntax](https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/regex.html)

### 버린 룰 — 패키지 매니저 강등

`dnf`/`yum`/`rpm` 이 바꾼 파일을 레벨 2로 내리는 룰을 계획했다가 **버렸다.**

`process_name` 은 **whodata 가 켜진 경로에서만 채워진다.** 우리는 whodata 를 `/etc/ssh` 한
곳에만 걸었고(inotify watch 예산 때문), 패키지 업데이트가 건드리는 `/usr/bin`·`/etc` 는 12시간
예약 스캔이라 audit 정보가 아예 없다. **룰이 적용될 표면이 없다.**

패키지 업데이트 노이즈는 빈도 기반 `<auto_ignore>` 가 담당한다.

**교훈**: whodata 범위를 좁게 잡는 결정이 **쓸 수 있는 룰의 범위도 함께 좁힌다.** 두 설정은
독립이 아니다.

### 안전장치 — 룰 문법이 틀리면 매니저가 안 뜬다

플레이북 순서가 그래서 이렇다.

```
백업 → 배포 → wazuh-logtest -t 검증 → (실패 시 백업 복구 + 실행 실패) → 재기동 → is-active 확인
```

`ansible.builtin.copy` 의 `validate` 파라미터를 쓰지 않은 이유는, `wazuh-logtest -t` 가
임의 파일이 아니라 **`/var/ossec/etc` 전체 룰셋**을 검사하기 때문이다. 파일을 놓은 뒤에
검사해야 하고, 그래서 되돌리는 경로가 별도로 필요하다.

### 실행

```bash
ansible-playbook -i inventory.local.ini wazuh_manager_rules.yml
```

`[wazuh_managers]` 그룹에 master·worker 둘 다 넣는다. 룰은 양쪽에 같아야 한다.

### 확인 — 시나리오 한 번

```bash
ssh vm-target-002 "sudo cp /etc/ssh/sshd_config /tmp/sshd_config.bak"
ssh vm-target-002 "echo '# fim test' | sudo tee -a /etc/ssh/sshd_config"
```

`/etc/ssh` 는 whodata + realtime 이라 **몇 초 안에** 레벨 12 알림이 떠야 한다. 확인 순서:

1. 대시보드 `보안 이벤트 (Wazuh) — 레벨 10+` 표에 나타나는지
2. `파일 변경 이력 (Wazuh FIM)` 표에 경로가 보이는지
3. Slack 도달 (컷라인 10 위)
4. 게이트웨이가 붙어 있으면 봇 카드까지

되돌린다. **`sshd -t` 문법 검사를 꼭 한다** — 설정이 깨진 채 재기동되면 SSH 가 막힌다.

```bash
ssh vm-target-002 "sudo mv /tmp/sshd_config.bak /etc/ssh/sshd_config && sudo sshd -t && echo OK"
```

## MSP 고객 호스트에 3종 번들 적용 (2026-07-30)

### 배제할 이유가 없다

`deploy_agents.yml` 은 `hosts: targets` 이므로 인벤토리에 고객 호스트를 추가하면 그대로 돈다.
MSP를 막는 코드는 없었다. **막혀 있던 건 배포가 아니라 자동등록 그룹이었다.**

```yaml
autoreg_group: "Discovered hosts"   # 하드코딩 — 고객 호스트도 전부 여기로
```

이러면 Day7에 만든 중첩 그룹 권한 상속(`Customers/<고객>`)이 적용되지 않아 **고객 격리
계정이 자기 호스트를 못 본다.** 자동등록을 고객별로 분기해야 한다.

### HostMetadata 접미사로 가른다

| 대상 | 인벤토리 변수 | HostMetadata | 자동등록 그룹 |
|---|---|---|---|
| 사내 | (없음 → 기본값) | `linux-3agent-bundle:internal` | `Discovered hosts` |
| MSP 고객 B | `customer=customer-b` | `linux-3agent-bundle:customer-b` | `Customers/Customer-B` |

`autoregister_action.yml` 이 `customers.yml` 을 읽어 고객마다 액션을 하나씩 만든다.
액션 이름은 `Autoregister 3-agent bundle - Customer-B` 형태이고, 조건은
`host_metadata like "linux-3agent-bundle:customer-b"` 다.

**접미사를 사내에도 붙인 이유**: 자동등록 조건은 **부분 일치(`like`)** 다. 사내 조건을
`linux-3agent-bundle` 로 두면 `...:customer-b` 도 그 문자열을 포함하므로 **MSP 호스트가
사내 액션에도 걸려 `Discovered hosts` 에 중복 등록된다.** 처음 만들 때 이 버그를 냈고,
양쪽에 접미사를 붙여 해소했다.

인벤토리 예:
```
custb-web-01.example.net ansible_host=192.0.2.51 agent_identity=custb-web-01.example.net customer=customer-b
```

`customer` 값은 `customers.yml` 의 `host_group` 마지막 조각을 소문자로 쓴 것이다
(`Customers/Customer-B` → `customer-b`).

### 소관 판단 — 왜 MSP에도 Wazuh를 넣나

Wazuh가 보는 것을 층으로 나누면 답이 나온다.

| 대상 | 층 |
|---|---|
| 로그인 실패·sudo | OS 인증 = **인프라** |
| 파일 무결성 (`/etc`, SSH 키, cron) | OS 설정 = **인프라** |
| 패키지 CVE | OS 패키지 = **인프라** |
| 앱 내부 취약점 | 고객 |

앞의 셋은 우리가 정한 경계(호스트·리소스=MSP 관측 / 앱 내부=고객)에서 MSP 쪽이다.
**다만 에이전트 추가 설치 자체는 고객 협의 사안**이다(인터뷰 A-6 "임의로 진행 못 함").
기술 제약이 아니라 계약 확인 항목으로 둔다.

**에이전트를 못 깔는 고객**에는 대안이 있다 — 고객사 프록시에 Wazuh syslog 수신
(`<remote><connection>syslog</connection>`, 514, `allowed-ips` 필수)을 얹으면 에이전트 없이
장비 로그를 받는다. 단 그 구간이 **PSK/TLS 없는 일반 인터넷**이므로 보안 로그를 평문으로
태우게 된다. 암호화 적용 권고와 반드시 묶어서 제안한다.

## 인증서 만료 감시 (`certificates.yml`, 2026-07-30)

### 왜 하나

MSP 고객 도메인 28개에 **인증서 만료 감시가 한 건도 없다**(정찰 실측). 있는 것은 443 포트
체크뿐인데, **포트 체크는 만료된 인증서도 통과시킨다** — 포트는 열려 있으니까. 만료되는 날
브라우저가 경고를 띄우고 나서야 알게 되는 구조다. 매니저가 인터뷰(B-6)에서 가치를 인정한
항목이기도 하다.

### 표준 템플릿을 그대로 쓴다

Zabbix 7.0 이 **"Website certificate by Zabbix agent 2"** 템플릿을 기본 제공한다. 커스텀
아이템을 만들지 않는다. 우리 진단이 "표준 템플릿이 공짜로 주는 것을 안 쓰고 자작한다"였으므로
여기서 자작하면 같은 실수다.

템플릿이 주는 것(7.0 기준, 공식 저장소 README 확인):

| 항목 | 내용 |
|---|---|
| 수집 | `web.certificate.get[{$CERT.WEBSITE.HOSTNAME},{$CERT.WEBSITE.PORT},{$CERT.WEBSITE.IP}]` |
| 파생 아이템 | 만료일·발급자·주체·SAN·지문·검증결과 등 12종 (JSONPath 종속 아이템) |
| 트리거 | 유효하지 않음(High) / 만료 임박(Warning) / 지문 변경(Info) |
| 만료 임박 식 | `(last(cert.not_after) - now()) / 86400 < {$CERT.EXPIRY.WARN}` |

WebCertificate 플러그인은 **agent 2 에 기본 내장**이라 따로 설치·활성화할 것이 없다. 우리
MaC 번들이 agent2 를 깔고 있으므로 추가 배포도 필요 없다.

### 구조 — 도메인 1개 = 호스트 1개

7.0 템플릿에는 **LLD 가 없다.** 공식 가이드도 "여러 사이트를 보려면 호스트를 따로 만들거나
복제해서 매크로만 바꾸라"고 안내한다. 즉 도메인 28개면 **호스트 28개를 손으로 복제**하는 것이
공식 절차다.

이게 바로 우리가 MSP 진단에서 짚은 복붙 온보딩 부채와 같은 모양이라, 손으로 하지 않고
`certs.yml` 목록 → `certificates.yml` 플레이북으로 만든다. 도메인 추가 = 목록에 한 줄.

```
certs.yml (도메인 목록)  →  certificates.yml  →  호스트 N개 + 템플릿 링크 + 매크로 3종
```

`host_group` 을 `Customers/Customer-X` 로 주면 **그 고객 계정에만 자기 인증서가 보인다** —
중첩 그룹 권한 상속이 그대로 적용되므로 별도 권한 작업이 없다.

**8.0 계열에는 LLD 가 들어갔다**(`cert.website.discovery`, 호스트 하나에 도메인 목록). 버전을
올리면 호스트 N개 구조가 사라진다 — 업그레이드 편익으로 로드맵에 남긴다.

### 점검 주체는 에이전트다

`web.certificate.get` 은 **에이전트가 실행하는 패시브 아이템**이다. 감시 호스트는 도메인마다
따로 만들되, 그 호스트들의 에이전트 인터페이스는 전부 **실제로 점검을 수행할 에이전트 한 대**를
가리킨다(`cert_checker_dns`). 공식 가이드도 같은 구조다(인터페이스를 127.0.0.1 로 두는 예).

따라서 점검 에이전트는 **대상 도메인 443 으로 아웃바운드가 되는 곳**에 있어야 한다. 실환경
MSP 라면 고객망 안이 아니라 인터넷이 나가는 쪽이다.

### 임계값을 7일이 아니라 30일로 둔 이유

템플릿 기본 `{$CERT.EXPIRY.WARN}` 은 **7일**이다. 갱신이 자동인 환경을 전제한 값이라 우리에겐
너무 늦다. 상용 인증서는 발급사 검증에 며칠이 걸리고, 고객사 승인이 끼면 더 걸린다. 7일 남았을
때 알면 이미 늦을 수 있다.

기본값을 **30일**(`cert_expiry_warn_default`)로 두고 도메인별로 `expiry_warn` 으로 덮는다.
Let's Encrypt 계열처럼 30일 전에 자동 갱신되는 대상은 오히려 짧게(예: 10일) 주는 편이 낫다 —
30일로 두면 자동 갱신 직전마다 매번 울린다.

**알려진 한계**: 7.0 템플릿의 만료 트리거는 하나(Warning)뿐이라 "30일 = 경고 / 7일 = 심각"
2단 에스컬레이션이 안 된다. 커스텀 트리거를 하나 더 다는 방법이 있지만, 그러면 호스트 28개에
커스텀 트리거 28개가 생겨 우리가 지적한 복붙 부채를 재생산한다. 2단 구분이 필요해지면
**LLD 가 있는 상위 버전에서 트리거 프로토타입으로 푸는 것이 맞다.**

> **버전 정정 (2026-07-31)**: LLD(`cert.website.discovery`) 도입은 **7.2**다(앞서 "8.0 계열"로
> 적었던 것을 정정). 매크로에 콤마 목록(`{$CERT.WEBSITE.HOSTNAME}` = `a.com,b.com,c.com`)을
> 넣으면 호스트 하나에서 다중 도메인이 발견된다. 다만 **결론은 같다** — 7.0.27 에는 없고,
> 팀이 LTS 를 쓰므로 실질 업그레이드 경로는 7.2(비LTS)가 아니라 **8.0 LTS** 다.

### 트리거가 둘인 이유 — "곧 죽는다"와 "보지 못하고 있다"는 다른 사건이다

이 절이 이 문서에서 가장 중요하다. **왜 트리거를 하나 더 달았는지**가 우리 설계 원칙의
두 번째 적용 사례이기 때문이다.

**계기.** 사용자가 인증서 감시를 실환경으로 확장할 때 무엇이 달라지는지 조사해 왔고
(2026-07-31), 그 안에 이런 지적이 있었다 — *"`web.certificate.get` 은 인증서 오류를 제외한
TLS 핸드셰이크 실패 시 아이템이 unsupported 가 된다"*. 공식 근거로 확인했다.

> "The `web.certificate.get` item turns unsupported if TLS handshake fails with **any error
> except an invalid certificate**."
> — https://support.zabbix.com/browse/ZBX-20206 ,
>   https://www.zabbix.com/forum/zabbix-help/451665-unsupported-item-key-website-certificate-by-zabbix-agent-2

**무엇이 문제인가.** 만료 임박 트리거는 `last(cert.not_after)` 를 본다. 아이템이 unsupported
가 되면 **값이 갱신되지 않고, 트리거는 발화하지 않고, 화면은 조용하다.** 즉:

| 실제 상황 | 화면 |
|---|---|
| 인증서가 멀쩡하다 | 조용함 |
| **서비스가 죽어서 인증서를 아예 못 봤다** | **조용함 (같음)** |

두 상태가 구분되지 않는다. 그리고 하필 **가장 조용해야 할 때가 아니라 가장 시끄러워야 할 때**
조용하다 — 서비스가 죽었는데 인증서 감시는 아무 말이 없다.

**이것은 게이트웨이 G1 과 같은 결함이다.** 거기서도 Wazuh 인덱서 조회 실패와 "보안 이벤트
없음"이 같은 빈 값으로 처리돼, 봇이 **인덱서가 죽은 상태에서 "침해 흔적 없음"을 단언**했다.
그때 상태 3종(`ok` / `unavailable` / `disabled`)을 도입해 고쳤다. 게이트웨이에서는 고쳐 놓고
인증서에서 같은 실수를 하면 **원리를 가진 것이 아니라 그 자리를 우연히 고친 것**이 된다.

**그래서 트리거를 짝으로 둔다.**

| 트리거 | 묻는 것 | 심각도 |
|---|---|---|
| 만료 임박 (템플릿 기본) | **인증서가 곧 죽는가** | Warning |
| **점검 불가 (신규)** | **인증서를 보고 있기는 한가** | Average |

식은 `nodata()` 를 쓴다 — 아이템이 unsupported 든 에이전트가 죽었든 **데이터가 안 들어오는
모든 경우**를 한 번에 잡는다. 원인 구분은 사람이 하고, 트리거는 "못 보고 있다"만 말한다.

**부수 효과**: 점검 에이전트 자체가 죽은 경우도 이 트리거가 잡는다. 감시 대상 28개가 통째로
안 보이는 상황인데 종래 구조로는 완전한 침묵이었다. 이는 §3-7 "감시자를 감시한다" 의 확장이다.

**호스트마다 트리거 1개가 부채 아닌가.** 위 "알려진 한계"에서 커스텀 트리거 28개를 부채라
불렀으므로 스스로 모순인지 짚어 둔다. 우리가 진단에서 부채라 부른 것은 **사람이 손으로 복붙해
정의가 28군데로 흩어진 것**이다. 여기서는 정의가 `certificates.yml` **한 곳**에 있고 28개는
그 산출물이다 — 도메인 추가는 목록 한 줄, 트리거 수정은 파일 한 곳 고치고 재실행(멱등)이다.
호스트 28개를 이미 그렇게 만들고 있으므로 일관된 처리다. 8.0 LTS 로 올리면 **호스트 1개 +
트리거 프로토타입 1개**로 접히며 이 구조 자체가 사라진다.

### Grafana 배치 — 전용 대시보드로 두는 이유 (2026-07-31)

| 층 | 무엇 | 왜 |
|---|---|---|
| 통합 관제 `kinx-overview` | **stat 1개** ("30일 내 만료 N건") + 전용 대시보드 링크 | 숫자는 통합 화면에, 분석은 전용 화면에 (§4-5 무마찰 확장) |
| 전용 `kinx-certificates` | 재고 테이블 · 점검 불가 · 발급자 분포 · 와일드카드 공유 | 아래 3가지 이유 |
| 고객사 `kinx-msp`·`kinx-msp-os` | **넣지 않는다** | 전용 대시보드가 `$group` 변수 + 권한 상속으로 이미 커버 |

**① 시간축이 다르다.** 다른 패널은 "지금 상태"(5분~6시간)를 보고 인증서는 **미래의 날짜**
(30~90일)를 본다. 같은 대시보드에 두면 상단 시간 범위가 서로 싸운다. Wazuh 패널에서 이미
`timeFrom` 을 패널마다 고정해 우회했는데(SCA 30d / 취약점 90d), 우회는 되지만 지저분해진다.

**② 사용 주기가 다르다.** 인증서는 상시 감시가 아니라 **월 1회 점검** 성격이다. 장애 대응
화면에 섞으면 평소엔 자리만 차지하고 필요할 때 못 찾는다.

**③ 발표에 한 장이 필요하다.** "28개 도메인, 잔여일 오름차순, 이번 달에 N개 만료" 가 한
화면이어야 한다. 다른 패널 사이에 끼면 안 보인다.

**고객사 대시보드에 따로 안 만드는 이유**: 전용 대시보드에 `$group` 변수를 두면 KINX 운영자는
All 을, 고객 계정은 중첩 그룹 권한 상속으로 자기 것만 본다(§4-6 에서 검증된 메커니즘).
고객용 패널을 따로 만들면 같은 것을 두 벌 유지하게 된다.

### cert 호스트를 두 그룹에 넣는 이유 (부작용 회피)

`Customers/Customer-X` 하나만 주면 **`kinx-msp` 의 `$host` 드롭다운에
`cert-www.example.com` 이 섞인다.** 그것을 고르면 DB·OS 패널이 전부 no data 가 되어
"왜 이 호스트는 다 비어 있나"가 된다.

| 그룹 | 용도 |
|---|---|
| `Customers/Customer-X` (또는 `Certificates`) | **권한 상속** — 고객이 자기 인증서를 본다 |
| `Certificates` (공통, 항상 추가) | **전용 대시보드 필터** |

Zabbix 호스트는 다중 그룹 소속이 되므로 충돌이 없다. 더불어 `kinx-msp` 의 `$host` 변수는
정규식으로 `cert-` 를 제외한다.

### 실행

```bash
export ZABBIX_API_TOKEN='<조회·쓰기 토큰>'
ansible-playbook -i inventory.local.ini ansible/certificates.yml -e @ansible/certs.local.yml
```

실 도메인 목록은 **커밋하지 않는다.** `ansible/certs.local.yml`(gitignored)에 두고 `-e` 로
주입한다. 리포의 `certs.yml` 은 형식을 보여주는 예시(RFC 2606 예약 도메인)다.

멱등이므로 도메인을 추가하고 다시 돌리면 된다. 목록에서 뺀 도메인의 호스트는 **자동으로
지워지지 않는다** — Ansible 이 없는 항목을 삭제하지는 않기 때문이다. 정리는 수동이다.

### 확인

1. Zabbix → Latest data → `Expires on` 아이템에 만료일이 들어왔는지
2. `{$CERT.EXPIRY.WARN}` 을 일부러 크게(예: 3650) 줘서 트리거가 발화하고 Slack 까지 오는지
3. Grafana `kinx-overview` 맨 아래 "인증서 만료 재고" 패널에 도메인별 만료 시점이 뜨는지

3번 패널은 Zabbix 가 초 단위 유닉스 타임스탬프를 주는데 Grafana 는 밀리초로 읽으므로
플러그인 함수 `scale(1000)` 을 걸어 뒀다. 값이 1970년으로 보이면 그 함수가 빠진 것이다.

## 아직 남은 것 (다음)
- **MariaDB 복제**: 데모 C(복제 지연) 대상이 되려면 이 VM에 slave를 얹어야 함(별도 단계).
