# 랩 호스트 — 이름·주소 규약

랩에서 **가장 많이 틀리는 지점**은 명령이 아니라 이름이다. 같은 서버를 부르는 이름이 셋이라,
맞는 명령을 틀린 이름으로 쳐서 안 되는 경우가 반복됐다. 이 문서가 그 대응표의 owner다.

문서에 적힌 IP는 전부 **문서용 예시 주소**(RFC 5737 `192.0.2.0/24`)다. 실제 값은
`docs/01-build/hosts.local.md`에 두고 커밋하지 않는다(§3).

---

## 1. 호스트 하나에 이름이 셋이다

| 실제 장비 | SSH 별칭 (작업자 PC) | 사설 IP (예시) | 감시 시스템에 찍히는 이름 |
|---|---|---|---|
| 관측 코어 | `core` | `192.0.2.26` | (Zabbix 서버 자신) |
| 감시 노드 1 | `node1` | `192.0.2.10` | `vm-target-001.novalocal` |
| 복제 슬레이브 · 3종 에이전트 | `node2` 또는 `vm-target-002` | `192.0.2.16` | `vm-p3-target-002.novalocal` |
| Keep | `keep` 또는 `vm-p3-keep` | `192.0.2.35` | — |
| Wazuh 대시보드 (점프 호스트) | `dashboard` | `<PUBLIC_IP>` | — |
| Wazuh Indexer 3노드 | `indexer1` `indexer2` `indexer3` | `192.0.2.5` `192.0.2.8` `192.0.2.33` | `node-1` `node-2` `node-3` |
| Wazuh Server 2노드 | `wazuh1` `wazuh2` | `192.0.2.13` `192.0.2.18` | `wazuh-1`(master) `wazuh-2`(worker) |

**SSH 별칭은 작업자 PC의 `~/.ssh/config`에만 있다.** `core`에 들어가서 `ssh vm-target-002`를
치면 이름을 못 찾는다(`Could not resolve hostname`). 거기서는 사설 IP를 쓴다.

세 이름이 갈리는 지점은 도구마다 다르다.

- **SSH 별칭** — 작업자 PC에서 치는 명령(`chaos/service_down.sh`, `scp`)
- **인벤토리 FQDN** — Zabbix 호스트명 · Loki `host` 라벨 · Wazuh `agent.name` · Ansible 인벤토리.
  세 시스템이 같은 이름을 쓰도록 맞춘 것이 **FQDN 정규화**이며, 이게 없으면 봇이 세 축을
  같은 호스트로 인식하지 못한다 → `docs/02-design/` 및 `ansible/DEPLOY_GUIDE.md`
- **사설 IP** — VM 안에서 다른 VM을 부를 때, chaos 스크립트 인자

> 손으로 설치한 `node1`만 이름이 어긋나 있어 게이트웨이의 `HOST_LABEL_MAP`으로 번역한다.
> Ansible로 배포한 호스트(`node2`)는 세 에이전트에 같은 `agent_identity`를 심으므로 매핑이
> 필요 없다. 이 차이가 "손 설치 1회 → 코드 배포"의 실측 근거다.

---

## 2. 리포가 있는 곳과 없는 곳

**모든 VM에 리포가 있는 게 아니다.** 없는 곳에서 `cd ~/kinx-idc-monitoring-poc`를 치면
`No such file or directory`가 난다.

| 호스트 | 리포 | 경로 |
|---|---|---|
| `core` | 있음 (Ansible control node 겸용) | `~/kinx-idc-monitoring-poc` |
| `keep` | 있음 (워크플로 프로비저닝용) | `~/kinx-idc-monitoring-poc` |
| `node2` | **없음** — 스크립트를 그때그때 `scp`로 올린다 | — |
| `node1` | **없음** | — |

## 화면 주소

| 화면 | 주소 | 용도 |
|---|---|---|
| Grafana | `core:3000` | 통합 관제 · MSP · 리포트 |
| Zabbix | `core:8080` | Problems · 트리거 · 미디어타입 |
| Keep | `keep:3000` | 승인(Run Workflow) |
| Wazuh | `dashboard` | Threat Hunting |
| mailpit | `core:8025` | 리포트 메일 수신함 |

---

## 3. placeholder 규약 — 왜 실 IP를 문서에 안 쓰는가

리포는 이미 두 가지 관례를 쓰고 있고, 문서도 같은 규약을 따른다.

| 관례 | 이미 쓰는 곳 |
|---|---|
| 문서용 IP 대역 `192.0.2.0/24` (RFC 5737) | `lab/.env.example`, `bot/gateway/selftest.py`, `ansible/inventory.ini` |
| 실값은 `*.local.*` 파일에 두고 gitignore | `ansible/lab_vars.yml`, `ansible/inventory.local.ini`, `ansible/certs.local.yml` |

이유는 셋이다.

1. **문서만 실 IP를 쓰면 규약이 둘로 갈린다.** 코드는 예시 주소인데 문서는 실주소면
   따라 하는 사람이 어느 쪽을 믿을지 알 수 없다.
2. **랩이 재구축되면 IP가 바뀐다.** 그 순간 문서 전체가 조용히 거짓이 된다.
3. **placeholder는 "여기를 네 환경 값으로 채워라"라는 재현 지시**가 되지만, 실 IP는 그냥
   노이즈다. 이 문서의 독자는 이 랩을 그대로 쓰는 사람이 아니라 **다시 세우는 사람**이다.

### 실값을 두는 곳

```
docs/01-build/hosts.local.md      # gitignore 대상. 팀 내 별도 전달
```

`.gitignore`에 `docs/**/*.local.md`가 있다. 이 파일에 §1 표를 그대로 복사하고 IP 열만
실값으로 채워 쓴다.

### 크리덴셜은 어디에도 적지 않는다

랩 비밀번호(복제 계정, Grafana admin, Wazuh 기본 계정)는 **문서에 쓰지 않는다.**
`.env` / `lab_vars.yml` / `certs.local.yml`이 정해진 자리다. 명령에 비밀번호가 필요하면
문서에는 값을 적지 말고 입력받는 형태로 적는다.

```bash
read -rs -p "writer pw: " DEMO_WRITER_PASSWORD && export DEMO_WRITER_PASSWORD
```

> 예외: Wazuh 설치 직후의 **벤더 기본 계정**(`admin`/`admin` 등)은 공식 설치 절차의
> 일부이고 첫 로그인에서 바꾸는 값이라 구축 가이드에 남긴다.

---

## 4. 대상을 틀리지 않기 위한 확인

`chaos/`의 스크립트는 전부 **대상을 인자로 받는다.** 하드코딩해 두면 실수로 실환경을 때릴 수
있기 때문이다. 실행 전에 인자로 넣은 주소가 랩 사설 대역인지 눈으로 한 번 확인한다.

관련 문서 — `chaos/README.md`(스크립트별 실행 위치), `docs/04-demo/runbook.md`(시나리오 순서)
