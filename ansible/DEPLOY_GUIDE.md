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
