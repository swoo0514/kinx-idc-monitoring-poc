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

## DB 타깃 복제 지연 감시 (setup_mysql_monitoring.yml)

데모 C 의 핵심 지표(`mysql.seconds_behind_master`)를 Zabbix 가 보게 하는 배선. 손으로 SSH 들어가
설정하지 않고 플레이북으로 코드화한다(agent 측). 두 작업:

1. **모니터링 계정** — 타깃 로컬 MariaDB 에 `zbx_monitor`@'%' 생성 + 공식 템플릿 요구 권한
   (`REPLICATION CLIENT, SLAVE MONITOR, PROCESS, SHOW DATABASES, SHOW VIEW`. `SLAVE MONITOR` 는
   MariaDB 10.5.9+ 의 `SHOW SLAVE STATUS` 권한).
2. **agent2 MySQL 플러그인 세션** — `/etc/zabbix/zabbix_agent2.d/mysql.conf` 에 명명 세션
   (`Plugins.Mysql.Sessions.repl.Uri/User/Password`). 자격증명을 Zabbix DB 가 아닌 에이전트
   설정에만 둔다.

실행 (control 노드에서, 비번은 gitignored lab_vars.yml):
```bash
# lab_vars.yml 에 추가: mysql_monitor_password: "<랩 비번>"
ansible-playbook -i inventory.local.ini -e @lab_vars.yml setup_mysql_monitoring.yml
```

**Zabbix 측 (서버 API — 현재 수동 1회 or 코드화 선택)**: 호스트에 "MySQL by Zabbix agent 2"
템플릿 링크 + 매크로 `{$MYSQL.DSN}=repl`(세션명 일치) + 데모용 `{$MYSQL.REPL_LAG.MAX.WARN}=60`
(기본 30m 은 높음). `community.zabbix.zabbix_host` 로 자동화 가능하나 컬렉션 버전 이슈 여지가
있어, 데모에선 UI 1회가 확실. 링크 후 Replication LLD 가 slave 를 발견해 지연 아이템·트리거 생성.

## 아직 남은 것 (다음)
- **wazuh 재실행 멱등 한계**: 매니저 주소는 최초 설치 시에만 주입됨. 재배포로 매니저를 바꾸려면
  ossec.conf 템플릿화 필요(현재는 최초 설치 정상 동작 우선).
- **MariaDB 복제**: 데모 C(복제 지연) 대상이 되려면 이 VM에 slave를 얹어야 함(별도 단계).
