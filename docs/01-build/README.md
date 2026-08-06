# 랩 구축 — 무엇을 어떤 순서로 세우는가

**`docker compose up` 하나로 다 뜨지 않는다.** 관측 코어만 compose이고 나머지는 별도 VM이거나
Ansible이다. 이 표가 그 전체 그림이고, 각 단계의 명령은 오른쪽 가이드에 있다.

시작하기 전에 [`hosts.md`](hosts.md)를 먼저 읽는다 — 같은 서버를 부르는 이름이 셋이라
**여기서 가장 많이 틀린다.**

## 구축 7단계

| # | 무엇 | 구축 방식 | 전제 | 가이드 |
|---|---|---|---|---|
| 1 | **관측 코어** Zabbix 7.0.27 · MariaDB · Grafana · Loki | `lab/docker-compose.yml` (VM 1대) | Rocky 9 VM, Docker | [`01-observability-core.md`](01-observability-core.md) |
| 2 | **Wazuh 6노드 클러스터** Indexer 3 · Server 2 · Dashboard 1 | **별도 VM 6대 · 패키지 설치** | VM 6대, 시간 동기화 | [`02-wazuh-cluster.md`](02-wazuh-cluster.md) |
| 3 | **감시 대상 노드 + 3종 에이전트** zabbix-agent2 · Alloy · wazuh-agent | **Ansible** (control node = 관측 코어 VM) | 1·2 완료, SSH 키 | [`ansible/DEPLOY_GUIDE.md`](../../ansible/DEPLOY_GUIDE.md) |
| 4 | **복제 슬레이브** MariaDB slave + 복제 지연 감시 | 별도 VM + Ansible 2종 | 1·3 완료 | [`lab/mariadb/REPL_VM_GUIDE.md`](../../lab/mariadb/REPL_VM_GUIDE.md) |
| 5 | **게이트웨이(봇)** FastAPI 웹훅 · 트리아지 | 관측 코어 VM에서 프로세스 기동 | 1 완료, `.env` | [`bot/GATEWAY_GUIDE.md`](../../bot/GATEWAY_GUIDE.md) · [`bot/.env.example`](../../bot/.env.example) |
| 6 | **Keep** 알림 저장 · HITL 승인 UI | **별도 VM · Keep 공식 compose** | 5 완료 | [`keep/KEEP_GUIDE.md`](../../keep/KEEP_GUIDE.md) |
| 7 | **마스킹 프록시 · HolmesGPT** (선택) | `masking/docker-compose.yml` + `docker run` | 5 완료 | [`masking/MASKING_GUIDE.md`](../../masking/MASKING_GUIDE.md) |

**1·2는 서로 독립이므로 병행 가능하다.** 3부터는 앞 단계가 있어야 한다.

**데모만 돌려 보려면 1·3·5까지면 된다.** 데모 B는 6, 데모 C의 복제 시나리오는 4가 추가로 필요하다.

## 각 단계가 끝났다는 것을 어떻게 아는가

| # | 이게 되면 성공 |
|---|---|
| 1 | `docker compose logs zabbix-server`에 `server #0 started`, Grafana 데이터소스 3종이 초록 |
| 2 | Indexer 클러스터 상태 `green`, Dashboard에서 Manager `Online` |
| 3 | Zabbix에 호스트가 **자동 등록**되고, Loki `host` 라벨과 Wazuh `agent.name`이 **같은 FQDN** |
| 4 | Grafana 복제 패널에 `Seconds Behind Master`가 그려짐 (상태 1/0이 아니라 초) |
| 5 | `curl localhost:8800/healthz` → ok, `python -m gateway.selftest` 전건 통과 |
| 6 | Keep Workflows에 `Remediate service via Ansible`이 보임 |
| 7 | `masking/MASKING_GUIDE.md`의 왕복 검증 — 전송 본문에 호스트명·IP가 없고 회신은 역치환됨 |

3번의 **FQDN 일치**가 가장 중요하고 가장 자주 깨진다. 세 시스템이 같은 호스트를 다른 이름으로
부르면 봇이 세 축을 합치지 못한다 — 손으로 설치한 호스트에서 실제로 겪은 일이고, 그래서
Ansible 배포가 세 에이전트에 같은 `agent_identity`를 심는다. 자세한 것은 [`hosts.md`](hosts.md).

## 구축 중에 밟게 되는 함정

단계마다 걸리는 곳이 정해져 있다. 증상과 원인은 [`../03-pitfalls/build-traps.md`](../03-pitfalls/build-traps.md)에
모아 두었다. 대표적인 것만:

- **2단계** — VM 간 시계가 어긋나면 TLS 인증서가 거부된다. 분산 배포의 1순위 함정이다.
- **2단계** — 매니저를 설치해도 Filebeat 설정은 빈 파일이다. 별도 설치·수동 추가가 필요하다.
- **3단계** — 구버전 zabbix-agent가 남아 있으면 포트를 선점해 새 에이전트가 안 뜬다.
- **3단계** — 자동 등록된 호스트는 `Discovered hosts` 그룹에 들어간다. **Grafana 조회 계정에
  그 그룹 권한이 없으면 대시보드 전 패널이 no data**가 된다.
- **1·5단계** — Grafana 데이터소스 `cacheTTL` 기본값이 1시간이라 값이 멈춰 보인다.

## 다음

구축이 끝나면 [`../04-demo/runbook.md`](../04-demo/runbook.md)로 간다.
