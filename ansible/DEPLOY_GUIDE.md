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

## 아직 남은 것 (다음)
- **wazuh 재실행 멱등 한계**: 매니저 주소는 최초 설치 시에만 주입됨. 재배포로 매니저를 바꾸려면
  ossec.conf 템플릿화 필요(현재는 최초 설치 정상 동작 우선).
- **MariaDB 복제**: 데모 C(복제 지연) 대상이 되려면 이 VM에 slave를 얹어야 함(별도 단계).
