# 랩 호스트 — 식별자 및 주소 표기 규약

본 문서는 **실험 환경(랩) 내 호스트 식별자(호스트명, IP, SSH 별칭) 매핑 기준**을 정의하는 Single Source of Truth (Owner) 문서입니다. 동일 인프라 자원에 대해 사용 목적 및 관측 도구별로 할당된 식별자가 상이함에 따른 작업 오류를 방지하기 위해 작성되었습니다.

문서 내 명시된 IP 주소는 **문서용 예시 대역 (RFC 5737 `192.0.2.0/24`)**을 사용하며, 실제 환경 설정 정보는 버전 관리 커밋 대상에서 제외되는 `docs/01-build/hosts.local.md` 파일에서 별도 관리합니다 (§3 참조).

---

## 1. 호스트 식별자 매핑 구조

| 실제 장비 역할 | SSH 별칭 (작업자 PC) | 사설 IP (예시) | 감시 시스템 수집 명칭 (FQDN) |
|---|---|---|---|
| 관측 코어 | `core` | `192.0.2.26` | (Zabbix Server 자체) |
| 감시 대상 노드 1 | `node1` | `192.0.2.10` | `vm-target-001.novalocal` |
| 복제 슬레이브 · 에이전트 3종 | `node2` 또는 `vm-target-002` | `192.0.2.16` | `vm-p3-target-002.novalocal` |
| Keep 관제 승인 | `keep` 또는 `vm-p3-keep` | `192.0.2.35` | — |
| Wazuh 대시보드 (점프호스트) | `dashboard` | `<PUBLIC_IP>` | — |
| Wazuh Indexer 3노드 | `indexer1` `indexer2` `indexer3` | `192.0.2.5` `192.0.2.8` `192.0.2.33` | `node-1` `node-2` `node-3` |
| Wazuh Server 2노드 | `wazuh1` `wazuh2` | `192.0.2.13` `192.0.2.18` | `wazuh-1` (Master) `wazuh-2` (Worker) |

**SSH 별칭 사용 규칙:** SSH 별칭은 **작업자 PC 환경의 `~/.ssh/config` 설정 내에서만 유효**합니다. `core` VM 내부에서 별칭(`ssh vm-target-002`)으로 접근을 시도할 경우 호스트 해석 실패(`Could not resolve hostname`) 에러가 발생하므로, VM 내부 간 통신 시에는 사설 IP 주소를 사용합니다.

**도구별 식별자 분류:**
* **SSH 별칭:** 작업자 PC 환경에서의 대화형 명령어 실행 및 스크립트 전달용 (`chaos/service_down.sh`, `scp` 등)
* **인벤토리 FQDN:** Zabbix 호스트명, Loki `host` 라벨, Wazuh `agent.name`, Ansible 인벤토리 명칭. 3개 관측 시스템 간 호스트 식별자를 일치시키는 절차를 **FQDN 정규화**라 하며, 미적용 시 AI 분석 엔진이 동일 호스트로 인지하지 못합니다 (참조: `docs/02-design/`, `ansible/DEPLOY_GUIDE.md`).
* **사설 IP:** VM 간 내부 통신 및 Chaos 스크립트 실행 인자 전달용

> *참고: 수동으로 구축된 `node1`의 경우 식별자 불일치로 인해 게이트웨이의 `HOST_LABEL_MAP`을 통한 변환을 수행합니다. 반면 Ansible로 자동 배포된 호스트(`node2`)는 3종 에이전트에 동일한 `agent_identity`가 설정되어 별도 매핑이 필요 없습니다. 이는 수동 설치 대비 코드 기반 배포의 데이터 정합성 이점을 보여주는 실증 사례입니다.*

---

## 2. 저장소(Repository) 배치 및 웹 접속 경로

**모든 VM 인스턴스에 소스 코드 저장소가 존재하는 것은 아닙니다.** 저장소가 존재하지 않는 VM에서 `cd ~/kinx-idc-monitoring-poc` 명령 실행 시 경로 찾기 오류가 발생합니다.

### 2-1. 소스 코드 저장소 배치 현황

| 호스트 | 저장소 존재 여부 | 저장소 경로 |
|---|---|---|
| `core` | **존재** (Ansible Control Node 겸용) | `~/kinx-idc-monitoring-poc` |
| `keep` | **존재** (워크플로 프로비저닝용) | `~/kinx-idc-monitoring-poc` |
| `node2` | **미존재** (필요 스크립트는 `scp`로 수시 전송) | — |
| `node1` | **미존재** | — |

### 2-2. 대시보드 및 웹 UI 접속 주소

| 대시보드 / 서비스 | 접속 URL | 주요 용도 |
|---|---|---|
| **Grafana** | `core:3000` | 통합 관제 · MSP · 리포트 대시보드 |
| **Zabbix** | `core:8080` | 장애(Problems) 관리 · 트리거 · 미디어 타입 설정 |
| **Keep** | `keep:3000` | 관제 조치 승인 관리 (`Run Workflow`) |
| **Wazuh** | `dashboard` | 보안 위협 탐지 및 세부 분석 (Threat Hunting) |
| **Mailpit** | `core:8025` | 리포트 이메일 발송 수신함 테스트 |

---

## 3. 플레이스홀더(Placeholder) 표기 규약

본 프로젝트 및 기술 문서는 실환경 주소 정보의 외부 유출 방지 및 환경 재현성 확보를 위해 아래의 표기 규약을 준수합니다.

| 표기 규약 | 적용 대상 및 위치 |
|---|---|
| **문서용 예시 IP 대역 (`192.0.2.0/24`, RFC 5737)** | `lab/.env.example`, `bot/gateway/selftest.py`, `ansible/inventory.ini` |
| **실제 환경 설정 파일 (`*.local.*`, gitignore 적용)** | `ansible/lab_vars.yml`, `ansible/inventory.local.ini`, `ansible/certs.local.yml` |

**플레이스홀더 채택 사유:**
1. **문서와 코드 간 일관성 유지:** 코드는 예시 주소를 사용하고 문서는 실제 주소를 사용할 경우, 구축 작업 시 혼선을 야기합니다.
2. **환경 재구축 시 신뢰성 보장:** 랩 환경 재구축으로 IP가 변경되더라도 문서의 유효성이 유지됩니다.
3. **재현 지침의 명확화:** 플레이스홀더 표기는 "해당 항목을 작업자 환경 정보로 치환"해야 함을 명확히 전달합니다.

### 실제 주소 관리 파일 (`hosts.local.md`)

```text
docs/01-build/hosts.local.md      # .gitignore 등록 대상 (팀 내부 채널을 통해 공유)
```

`.gitignore` 설정에 따라 `docs/**/*.local.md` 경로 파일은 커밋에서 제외됩니다. 해당 파일에 §1의 표를 복사한 후 IP 열을 실제 환경 주소로 채워 관리합니다.

### 자격 증명(Credential) 보안 관리 수칙

랩 환경 비밀번호(DB 복제 계정, Grafana Admin, Wazuh 기본 계정 등)는 **문서 내 직접 기재를 금지**하며, `.env`, `lab_vars.yml`, `certs.local.yml` 파일에서 관리합니다. 대화형 명령어 실행 시 직접 기재 대신 아래와 같이 대화형 입력 형태를 사용합니다:

```bash
read -rs -p "writer pw: " DEMO_WRITER_PASSWORD && export DEMO_WRITER_PASSWORD
```

*(예외 사항: Wazuh 설치 직후 제공되는 벤더 기본 계정 `admin`/`admin` 등은 공식 설치 절차상 변경 대상이므로 구축 가이드에 한하여 기재를 허용합니다.)*

---

## 4. 장애 주입 실행 시 안전 수칙

`chaos/` 디렉토리 내 시뮬레이션 스크립트는 **대상 호스트 주소를 매개변수(Argument)로 전달받도록 구현**되어 있습니다. 하드코딩으로 인한 타 환경 오발동을 방지하기 위함이며, 스크립트 실행 전 입력한 주소가 랩 사설 IP 대역에 해당하는지 반드시 확인합니다.

*관련 참조 문서:* [`chaos/README.md`](../../chaos/README.md) (스크립트별 실행 위치), [`docs/04-demo/runbook.md`](../04-demo/runbook.md) (시나리오 실행 절차)