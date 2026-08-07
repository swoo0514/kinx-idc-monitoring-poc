# 랩 구축 — 단계별 구축 순서 및 실행 가이드

전체 랩 환경은 **단일 `docker compose up` 명령만으로 구성되지 않습니다.** 관측 코어 영역만 Docker Compose 기반으로 실행되며, 타 컴포넌트는 별도 VM 인스턴스 또는 Ansible 기반으로 구축됩니다. 본 문서는 전체 구축 로드맵을 제공하며, 각 단계별 세부 실행 명령어는 표에 연결된 가이드 문서를 참조합니다.

구축 시작 전 [`hosts.md`](hosts.md) 가이드를 먼저 숙지하시기 바랍니다. (동일 호스트에 대한 다중 식별자 정의로 인해 설정 오류가 가장 빈번히 발생하는 구간입니다.)

---

## 1. 단계별 구축 로드맵

| # | 컴포넌트 | 구축 방식 | 전제 조건 | 상세 가이드 |
|---|---|---|---|---|
| 1 | **관측 코어** (Zabbix 7.0.27 · MariaDB · Grafana · Loki) | `lab/docker-compose.yml` (VM 1대) | Rocky Linux 9 VM, Docker | [`01-observability-core.md`](01-observability-core.md) |
| 2 | **Wazuh 6노드 클러스터** (Indexer 3 · Server 2 · Dashboard 1) | 별도 VM 6대 (패키지 기반 직접 설치) | VM 6대, 시간 동기화(NTP) | [`02-wazuh-cluster.md`](02-wazuh-cluster.md) |
| 3 | **감시 대상 노드 + 에이전트 3종** (zabbix-agent2 · Alloy · wazuh-agent) | **Ansible** (Control Node = 관측 코어 VM) | 1·2단계 완료, SSH 키 설정 | [`ansible/DEPLOY_GUIDE.md`](../../ansible/DEPLOY_GUIDE.md) |
| 4 | **DB 복제 슬레이브** (MariaDB Slave + 복제 지연 관측) | 별도 VM + Ansible 플레이북 2종 | 1·3단계 완료 | [`lab/mariadb/REPL_VM_GUIDE.md`](../../lab/mariadb/REPL_VM_GUIDE.md) |
| 5 | **게이트웨이 (봇 엔진)** (FastAPI 웹훅 · 트리아지 판단) | 관측 코어 VM 내 프로세스 기동 | 1단계 완료, `.env` 설정 | [`bot/GATEWAY_GUIDE.md`](../../bot/GATEWAY_GUIDE.md) · [`bot/.env.example`](../../bot/.env.example) |
| 6 | **Keep 관제 시스템** (알림 저장 · HITL 승인 UI) | 별도 VM (Keep 공식 Compose) | 5단계 완료 | [`keep/KEEP_GUIDE.md`](../../keep/KEEP_GUIDE.md) |
| 7 | **마스킹 프록시 · HolmesGPT** (선택 사항) | `masking/docker-compose.yml` + `docker run` | 5단계 완료 | [`masking/MASKING_GUIDE.md`](../../masking/MASKING_GUIDE.md) |

* **병렬 구축 가능 구역:** 1단계와 2단계는 상호 의존성이 없어 병행 구축이 가능합니다. 3단계부터는 이전 단계 구축 완료가 필수 전제 조건입니다.
* **데모 시나리오별 최소 구성 조건:**
  * **통합 관제 (Demo A):** 1·2·3단계. 보안 축(Wazuh)이 화면의 3축 중 하나이므로 **2단계가 필수**이며, 게이트웨이는 필요하지 않습니다.
  * **자가 치유 (Demo B):** 위에 더해 5·6단계 (게이트웨이가 조치 후보를 올리고 Keep에서 승인)
  * **AI 초동 분석 (Demo C):** 위에 더해 5단계. 복제 지연 시나리오를 재현하려면 4단계도 필요합니다.

---

## 2. 단계별 완료 검증 기준

| # | 구축 단계 | 완료 검증 기준 (Success Criteria) |
|---|---|---|
| 1 | **관측 코어** | `docker compose logs zabbix-server` 조회 시 `server #0 started` 로그 확인 및 Grafana 데이터소스 3종 정상 연결(Green) |
| 2 | **Wazuh 클러스터** | Indexer 클러스터 상태 `green` 및 Dashboard 내 Manager 상태 `Online` 표시 |
| 3 | **에이전트 배포** | Zabbix에 호스트 **자동 등록** 확인, Loki `host` 라벨과 Wazuh `agent.name`이 **동일 FQDN으로 일치** |
| 4 | **DB 복제 슬레이브** | Grafana DB 복제 관측 패널에 `Seconds Behind Master` 지표가 시계열 그래프(초 단위)로 정상 렌더링 |
| 5 | **게이트웨이** | `curl localhost:8800/healthz` 실행 시 `ok` 반환 및 `python -m gateway.selftest` 테스트 항목 전건 통과 |
| 6 | **Keep 관제 UI** | Keep Workflows 항목에 `Remediate service via Ansible` 워크플로 노출 확인 |
| 7 | **마스킹 프록시** | [`masking/MASKING_GUIDE.md`](../../masking/MASKING_GUIDE.md) 기준 왕복 검증 통과 (전송 데이터 내 호스트명/IP 마스킹 처리 및 회신 수신 시 역치환 정상 동작) |

> **FQDN 정규화의 중요성:** 3단계의 **FQDN 명칭 일치**는 관측 데이터 통합의 가장 핵심적인 전제 조건입니다. 3개 관측 시스템에서 동일 감시 대상을 서로 다른 명칭으로 수집할 경우 AI 분석 엔진이 단일 인시던트로 통합하지 못합니다. (Ansible 배포 스크립트를 통해 3종 에이전트에 동일한 `agent_identity`를 자동 적용함으로써 해당 문제를 방지합니다.)

---

## 3. 구축 과정 주요 유의사항 및 트러블슈팅

각 단계별로 발생하기 쉬운 주요 장애 패턴 및 원인은 [`../03-pitfalls/build-traps.md`](../03-pitfalls/build-traps.md) 문서에 집대성되어 있습니다. 대표적인 점검 항목은 다음과 같습니다:

* **2단계 (Wazuh 클러스터):** VM 간 시간 동기화(NTP) 오차 발생 시 TLS 인증서 검증 실패로 클러스터 결성에 실패합니다. (분산 환경 구축 시 1순위 점검 항목)
* **2단계 (Filebeat 연동):** Wazuh Manager 설치 후에도 Filebeat 설정 파일이 기본 빈 상태로 생성되므로, 별도 설치 및 템플릿/SSL 수동 추가 설정이 필요합니다.
* **3단계 (에이전트 포트 충돌):** 구버전 `zabbix-agent` 데몬이 실행 중일 경우 포트(10050) 선점으로 인해 신규 `zabbix-agent2` 기동에 실패합니다.
* **3단계 (Grafana 권한 문제):** 자동 등록된 호스트는 `Discovered hosts` 그룹에 할당됩니다. **Grafana 조회 계정에 해당 호스트 그룹 읽기 권한이 없으면 대시보드 전체 패널에 No Data가 발생**합니다.
* **1·5단계 (조회 캐시 지연):** Grafana 데이터소스의 `cacheTTL` 기본값이 1시간으로 설정되어 있어, 조정하지 않을 경우 패널 데이터가 반영되지 않고 정지된 것처럼 보입니다.

---

## 4. 후속 절차

구축 단계가 완료되면 [`../04-demo/runbook.md`](../04-demo/runbook.md) 가이드로 이동하여 시연 및 시나리오 검증을 진행합니다.