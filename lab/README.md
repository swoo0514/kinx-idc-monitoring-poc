# lab/ — KINX IDC 관측 코어 (Docker 기반 인프라)

본 디렉토리는 KINX IDC 모니터링 랩의 핵심 관측 계층을 Docker Compose로 구축하기 위한 구성 환경을 정의합니다. `docker-compose.yml` 단일 매니페스트를 통해 메트릭 수집(`Zabbix 7.0.27`), 데이터베이스(`MariaDB`), 시각화(`Grafana`), 로그 수집(`Loki`) 컴포넌트를 통합 기동합니다.

보안 관측 계층(`Wazuh`)은 별도의 6개 노드 분산 클러스터로 가동되며, 동일한 사설 네트워크 대역에 배치되어 Grafana 대시보드와 상호 연동됩니다.

---

## 1. 전제 조건 및 시스템 사양

### 1-1. VM 권장 사양 (관측 코어 4종 기본 세트)

| 구분 | 최소 사양 | 권장 사양 | 비고 |
| --- | --- | --- | --- |
| **CPU** | 2 vCPU | 4 vCPU | - |
| **Memory** | 4 GB | 8 GB | 프로필 확장 시 메모리 추가 할당 필요 |
| **Disk** | 40 GB | 40 GB 이상 | NVMe/SSD 권장 |
| **OS** | Rocky Linux 9 | Rocky Linux 9 | 운영 환경과의 정합성 준수 |
| **Network** | Dual NIC (사설 IP + 공인 IP) | Dual NIC (사설 IP + 공인 IP) | Wazuh 클러스터 연동 및 관제 접근용 |

> **[프로필 확장 시 메모리 할당 안내]**  
> 기본 4종 컴포넌트 외에 추가 프로필을 활성화하는 경우, 서비스 스택에 따라 **+2 GB ~ +4 GB** 범위의 RAM 추가 증설이 요구됩니다.
> - `--profile ha`: DB 복제 슬레이브 노드
> - `--profile chaos`: `snmpsim` 기반 장애 주입 시뮬레이터
> - `--profile msp`: 멀티테넌트 고객사 가상 컨테이너 세트

> **[네트워크 구성 규약]**  
> 본 관측 코어 VM은 사설 IP와 공인 IP를 동시에 활용합니다. 사설 IP는 사설망 내 배치된 Wazuh Indexer 클러스터와의 데이터 연동에 사용되며, 공인 IP는 Zabbix Web UI 및 Grafana 대시보드 접근에 사용됩니다. 공인 IP 접근 포트는 인프라 보안을 위해 작업자 사설 대역(`/32`)으로 엄격히 제한합니다.

### 1-2. 소프트웨어 의존성

- Docker Engine 및 Docker Compose 플러그인 (v2 이상)
- Git

---

## 2. 구축 절차

### 2-1. 소스 코드 저장소 클론

본 저장소는 비공개(Private) 저장소이므로, 권한이 부여된 계정의 인증 정보를 사용하여 클론을 수행합니다 (HTTPS는 Personal Access Token, SSH는 SSH Key 사용).

```bash
# Git 패키지 미설치 시 사전 설치
sudo dnf -y install git

# HTTPS 방식 (패스워드 입력란에 Personal Access Token 입력)
git clone https://github.com/swoo0514/kinx-idc-monitoring-poc.git

# SSH 방식 (SSH Key 등록 완료 시)
# git clone git@github.com:swoo0514/kinx-idc-monitoring-poc.git

cd kinx-idc-monitoring-poc/lab
```

### 2-2. Docker 런타임 설치 (Rocky Linux 9 기준)

```bash
sudo dnf -y install dnf-plugins-core
sudo dnf config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo

# Rocky Linux 9 환경에서 $releasever가 '9.0'으로 확장되는 현상 방지 (Major 버전 '9'로 고정)
sudo sed -i 's/\$releasever/9/g' /etc/yum.repos.d/docker-ce.repo

sudo dnf -y install docker-ce docker-ce-cli containerd.io docker-compose-plugin
sudo systemctl enable --now docker
sudo usermod -aG docker $USER

# 세션 재접속 후 Docker 버전 및 권한 검증
docker compose version
```

### 2-3. 환경변수 및 크리덴셜 설정

```bash
cp .env.example .env
# .env 파일을 편집하여 4개 주요 서비스 비밀번호를 랩 전용 임의값으로 수정합니다. (운영 환경 비밀번호 사용 금지)
```

### 2-4. 관측 코어 컨테이너 기동

```bash
docker compose pull
docker compose up -d

# 서비스 컨테이너 기동 상태 및 헬스체크 확인
docker compose ps

# Zabbix Server 기동 로그 모니터링 ("server #0 started" 구문 확인 시 기동 완료)
docker compose logs -f zabbix-server
```

*최초 기동 시 MariaDB 데이터베이스 스키마 및 초기 데이터 자동 생성 프로세스로 인해 약 1~2분의 대기 시간이 소요됩니다.*

---

## 3. 서비스 접속 정보 및 방화벽 설정

| 서비스 명칭 | 접속 포트 및 URL | 초기 계정 / 비밀번호 |
| --- | --- | --- |
| **Zabbix Web** | `http://<공인_IP>:8080` | `Admin` / `zabbix` *(초기 로그인 후 즉시 변경)* |
| **Grafana** | `http://<공인_IP>:3000` | `admin` / `.env` 내 `GRAFANA_ADMIN_PASSWORD` |

> **[인바운드 접근 제어 정책 (보안 그룹)]**  
> 공인 IP 접근 인바운드 규칙은 `22(SSH)`, `8080(Zabbix Web)`, `3000(Grafana)` 포트에 한해 **작업자 IP (`<IP>/32`)로 한정하여 개방**합니다.  
> `10051(Zabbix Trapper)` 및 `3100(Loki)` 포트는 사설 네트워크(Internal Subnet) 전용 통신 포트이므로 공인망으로 개방하지 않습니다.

---

## 4. 디렉토리 구조 명세

```text
lab/
├── docker-compose.yml                    # 관측 코어 4종 서비스 정의 매니페스트
├── .env.example                          # 자격 증명 템플릿 (.env 파일 버전 관리 제외)
├── loki/loki-config.yml                  # Loki 수집 및 보존 정책 설정 파일
└── grafana/provisioning/datasources/     # Grafana 데이터소스 자동 프로비저닝 정의
```

---

## 5. 핵심 아키텍처 및 구성 특징

- **단일 MariaDB 기반 가동:** 단일 DB 인스턴스로 초기 기동하며, Master-Slave 복제 모니터링 시연 시 `--profile ha` 옵션을 통해 슬레이브 노드를 동적으로 추가합니다.
- **Zabbix Server 단일 구성:** 기존 운영 인프라에 이미 구현되어 있는 Keepalived VIP 기반 이중화 계층의 재현을 지양하고, 본 랩 환경에서는 관측 데이터 연동 및 AI 분석 기능 검증에 집중합니다.
- **보안 자격 증명 분리:** 서비스 계정 및 DB 암호 등 모든 보안 자격 증명은 `.env` 파일로 통합 관리하며 Git 버전 관리에서 제외합니다.

---

## 6. 관련 참조 문서

- 상세 설정 기술 근거, 공식 출처, 데이터소스 연동 및 트러블슈팅: [`docs/01-build/01-observability-core.md`](../docs/01-build/01-observability-core.md)
- 전체 인프라 구축 순서 및 수립 가이드: [`docs/01-build/README.md`](../docs/01-build/README.md)
- 호스트 식별자 및 네트워크 IP 주소 할당 규약: [`docs/01-build/hosts.md`](../docs/01-build/hosts.md)