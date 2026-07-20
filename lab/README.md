# lab/ — KINX IDC 모니터링 랩 (Docker 관측 코어)

실환경 미러 랩의 관측 계층을 Docker Compose로 구축합니다. `docker-compose.yml` 하나로 Zabbix 7.0.27(메트릭) + MariaDB(DB) + Grafana(시각화) + Loki(로그)를 기동합니다. 보안 계층(Wazuh)은 별도 6노드 클러스터로 운영되며, 본 관측 코어와 동일 사설망에 위치시켜 Grafana에서 연동합니다.

---

## 전제 조건

### VM 사양 (권장 — 관측 코어 4종 기준)

| 구분 | 사양 |
| --- | --- |
| CPU | 4 vCPU (최소 2 vCPU) |
| Memory | 8 GB (최소 4 GB) |
| Disk | 40 GB 이상 |
| OS | Rocky Linux 9 (실환경 정합) |
| 네트워크 | 사설 IP(Wazuh 클러스터와 동일 사설망 — 연동 필수) + 공인 IP 1개(대시보드 접근용) |

> 위 사양은 관측 코어 4종 기준 추정치입니다. Profile 확장 시 증설이 필요합니다 — 특히 `--profile chaos`(에이전트 노드·snmpsim)는 +2~4 GB, `--profile ai`(Ollama)는 모델 크기에 따라 별도의 사양·GPU 검토가 필요합니다.

> **네트워크 구성:** 본 VM은 사설 IP와 공인 IP를 함께 사용합니다. 사설 IP는 Grafana가 Wazuh Indexer(사설망 내)에 연동하기 위해 필수이며, 공인 IP는 Zabbix Web·Grafana 대시보드에 브라우저로 접근하기 위한 용도입니다. 공인 IP의 노출 포트(아래 방화벽 항목)는 반드시 작업자 IP로 제한합니다.

### 소프트웨어

- Docker Engine + Docker Compose 플러그인 (v2)
- Git

---

## 구축 절차

### 1. 저장소 클론

비공개(private) 저장소이므로 접근 권한이 있는 계정으로 인증이 필요합니다. HTTPS는 Personal Access Token을, SSH는 등록된 공개키를 사용합니다.

```bash
# git 미설치 시 먼저 설치
sudo dnf -y install git

# HTTPS (인증 시 비밀번호 대신 Personal Access Token 입력)
git clone https://github.com/swoo0514/kinx-idc-monitoring-poc.git

# 또는 SSH (계정에 공개키 등록 시)
# git clone git@github.com:swoo0514/kinx-idc-monitoring-poc.git

cd kinx-idc-monitoring-poc/lab
```

### 2. Docker 설치 (미설치 시, Rocky Linux 9 기준)

```bash
sudo dnf -y install dnf-plugins-core
sudo dnf config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
# Rocky 9는 $releasever가 "9.0"으로 확장되나 Docker repo는 major(9)만 제공 → 404 방지 위해 9로 고정
sudo sed -i 's/\$releasever/9/g' /etc/yum.repos.d/docker-ce.repo
sudo dnf -y install docker-ce docker-ce-cli containerd.io docker-compose-plugin
sudo systemctl enable --now docker
sudo usermod -aG docker $USER   # 로그아웃 후 재접속하여 권한 적용
docker compose version
```

### 3. 크리덴셜 설정

```bash
cp .env.example .env
# .env 파일을 열어 비밀번호 4개를 랩 전용 임의 값으로 설정합니다. 실환경 비밀번호 금지.
```

### 4. 기동

```bash
docker compose pull
docker compose up -d
docker compose ps                    # mariadb(healthy) → zabbix-server → web → grafana 순
docker compose logs -f zabbix-server # "server #0 started" 출력 시 정상
```

최초 기동은 MariaDB 스키마 자동 생성으로 약 1~2분이 소요됩니다.

---

## 접속 정보

| 서비스 | 접속 URL | 초기 계정 |
| --- | --- | --- |
| Zabbix Web | `http://<공인_IP>:8080` | `Admin` / `zabbix` (로그인 후 즉시 변경) |
| Grafana | `http://<공인_IP>:3000` | `admin` / `.env`의 `GRAFANA_ADMIN_PASSWORD` |

> **방화벽(보안 그룹):** 공인 IP 측은 22(SSH)·8080(Zabbix)·3000(Grafana)만, 그리고 반드시 **작업자 IP(Source /32)로 제한**하여 개방합니다. 나머지 공인 포트는 전부 차단합니다. 10051(Zabbix Trapper)·3100(Loki)은 사설망 내 통신 전용이므로 공인으로 열지 않습니다.

---

## 디렉토리 구성

```
lab/
├── docker-compose.yml                    # 관측 코어 4종 정의
├── .env.example                          # 크리덴셜 템플릿 (.env는 커밋 금지)
├── loki/loki-config.yml                  # Loki 설정
└── grafana/provisioning/datasources/     # Grafana 데이터소스 (코드 관리)
```

---

## 구성 요약

- **단일 MariaDB로 시작**합니다. 복제(slave)는 `--profile ha`에서 추가합니다 — "DB 편측 감시" 진단 시연을 위한 Master-Slave 미러 구성입니다.
- **Zabbix 서버는 단일 구성**입니다. keepalived VIP 이중화는 이미 운영 중인 가용성 계층이므로 재현하지 않습니다(관측 계층에 집중).
- **크리덴셜은 전부 `.env`**로 분리하며 커밋하지 않습니다.

## 상세 문서

설정별 기술 근거·공식 출처·데이터소스 연동·트러블슈팅·Profile 확장 구조는 내부 구축 가이드에서 관리합니다(내부 인프라 연동 정보 포함으로 비공개).
