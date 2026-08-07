# Wazuh 6노드 분산 배포 가이드 (패키지 기반)

운영 환경 구성(Indexer 3대 / Server 2대 / Dashboard 1대)을 동일하게 미러링하는 6대 VM 분산 배포 가이드입니다.

본 문서에 명시된 IP 주소는 예시용 플레이스홀더이며, 실제 사양은 `hosts.local.md` ([`hosts.md`](hosts.md))를 참조합니다.
*설치 직후 제공되는 벤더 기본 계정 정보는 공식 설치 절차의 일부로 기재되었으며, 최초 로그인 직후 변경을 권장합니다.*

---

## 0. 패키지 기반 분산 배포 채택 사유 (Docker 미채택 이유)

6대의 독립 VM 환경에서는 `wazuh-docker` (Multi-node) 방식을 사용하지 않습니다.

* `wazuh-docker` Multi-node 방식은 **단일 호스트 상의 6개 컨테이너 전용 배포 스펙**입니다 (공식 사양). 다중 VM 분산 환경은 공식 지원하지 않습니다.
* 다중 VM 환경의 표준 구축 방식은 **패키지 기반 분산 배포(Distributed Deployment)**이며, 해당 구조가 운영 환경의 실제 아키텍처를 정확히 반영합니다.
* 단일 호스트 컨테이너 구성 시 발생하는 불필요한 장애(힙 OOM 등)를 방지하며, 6대 분산 환경에서 발생하는 인증서, NTP, 방화벽 관련 이슈는 **운영 환경 도입 시 사전에 검증해야 할 주요 리스크 관리 항목**에 해당합니다.

---

## 1. VM 인프라 배치 및 네트워크 설계

| 역할 | 노드명 | 사설 IP (예시) | 리소스 사양 | SSH 별칭 |
|---|---|---|---|---|
| Indexer | `node-1` | `192.0.2.5` | 8C / 16GB | `indexer1` |
| Indexer | `node-2` | `192.0.2.8` | 8C / 16GB | `indexer2` |
| Indexer | `node-3` | `192.0.2.33` | 8C / 16GB | `indexer3` |
| Server (Master) | `wazuh-1` | `192.0.2.13` | 4C / 8GB | `server1` |
| Server (Worker) | `wazuh-2` | `192.0.2.18` | 4C / 8GB | `server2` |
| Dashboard | `dashboard` | `192.0.2.17` + **공인 IP 1개** | 2C / 4GB | `dashboard` |

### 네트워크 정책 — 공인 IP 최소화 (1개 할당)

* **Indexer 3대 + Server 2대:** 사설 IP 전용 구성 (외부 직접 노출 원천 차단)
* **Dashboard 1대:** 공인 IP 1개 할당 (사설망 직접 접근 불가 환경 대응을 위한 단일 진입점 역할)
* 대시보드 노드를 배스천/점프호스트 역할로 활용하여 내부 5개 노드를 외부로부터 격리합니다.
* **보안 필수 사항:** 대시보드 공인 IP의 22 및 443 포트는 작업자 IP(Source /32) 범위로 한정 허용하고, 9200 등 기타 포트는 공인 영역에서 전면 차단합니다.

### 방화벽 허용 포트 정책

| 통신 구간 | 포트 / 프로토콜 | 용도 및 비고 |
|---|---|---|
| Indexer 간 | 9200 (REST) / 9300 (Transport) | 클러스터 내부 통신 |
| Server → Indexer | 9200 | 인덱싱 데이터 전송 |
| Server 간 | 1516 (Cluster) | 마스터-워커 클러스터 통신 |
| Agent → Server | 1514 (Event) / 1515 (Registration) | 에이전트 이벤트 수신 및 등록 |
| Server API | 55000 | 대시보드 및 게이트웨이 연동 |
| Dashboard → Indexer/Server | 443 / 9200 / 55000 | 대시보드 백엔드 통신 |
| 외부 작업자 접근 | 22 / 443 | **대시보드 공인 IP 한정 (작업자 IP 허용)** |

*주의: 구축 작업 중 통신 장애 방지를 위해 관련 포트는 초기 인프라 설정 단계에서 일괄 개방하는 것을 권장합니다.*

### 스토리지 볼륨 구성

**Indexer 3대 노드에는 별도 데이터 볼륨을 마운트하여 `/var/lib/wazuh-indexer` 경로에 할당합니다.**

Indexer는 알림 데이터 저장소 역할을 수행하므로, 루트 디스크 할당만으로는 용량 초과 현상이 발생하여 워터마크 도달 시 인덱싱이 중단될 수 있습니다. Server 2대의 경우 루트 디스크 용량이 충분할 경우 추가 볼륨 마운트를 생략할 수 있습니다.

```bash
lsblk                                     # 마운트할 디스크 명칭 확인
sudo mkfs.xfs /dev/vdb
sudo mkdir -p /var/lib/wazuh-indexer
sudo mount /dev/vdb /var/lib/wazuh-indexer
echo '/dev/vdb /var/lib/wazuh-indexer xfs defaults 0 0' | sudo tee -a /etc/fstab
```

*패키지 설치 전 볼륨 마운트 작업이 선행되어야 데이터가 해당 저장소에 정상 누적됩니다.*

---

## 2. 6개 노드 공통 사전 설정

```bash
# 시간 동기화 (분산 환경에서 시계 오차 발생 시 TLS 인증서 검증 실패 원인이 됨)
sudo dnf -y install chrony
sudo systemctl enable --now chronyd
chronyc tracking          # 6개 노드 모두 동기화 상태 확인

# (Indexer VM 전용) 커널 파라미터 설정 (미설정 시 Indexer 기동 실패)
sudo sysctl -w vm.max_map_count=262144
echo 'vm.max_map_count=262144' | sudo tee /etc/sysctl.d/99-wazuh.conf
```

노드 간 호스트명 해석을 위해 6개 노드 전체의 `/etc/hosts` 파일에 호스트명 및 IP 매핑 정보를 추가합니다.

---

## 3. TLS 인증서 생성 및 배포 (indexer1 기준 실행)

```bash
curl -sO https://packages.wazuh.com/4.14/wazuh-certs-tool.sh
curl -sO https://packages.wazuh.com/4.14/config.yml
```

`config.yml` 파일에 6개 노드의 호스트명 및 IP 정보(Indexer 3, Server 2, Dashboard 1)를 작성합니다.

```bash
bash ./wazuh-certs-tool.sh -A
tar -cvf ./wazuh-certificates.tar -C ./wazuh-certificates/ .
```

VM 간 직접 SSH 키가 없는 환경을 고려하여 작업자 PC를 경유하여 인증서를 배포합니다.

```bash
# 작업자 PC에서 실행 (~/.ssh/config 별칭 기반 전달)
scp indexer1:~/wazuh-certificates.tar ./
scp ./wazuh-certificates.tar indexer2:~/
scp ./wazuh-certificates.tar indexer3:~/
scp ./wazuh-certificates.tar server1:~/
scp ./wazuh-certificates.tar server2:~/
scp ./wazuh-certificates.tar dashboard:~/
```

> **주의 사항 (SAN IP 일치):** `config.yml` 내 IP 설정은 실제 VM IP(SAN)와 정확히 일치해야 합니다. 불일치 시 노드 간 상호 인증 거부로 클러스터 형성에 실패합니다. 또한 인증서 tar 파일은 Git 저장소 외부에 보관합니다.

---

## 4. Indexer 클러스터 구축 (node-1 ~ node-3)

각 Indexer VM에서 저장소를 등록하고 패키지를 설치합니다.

```bash
sudo rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH
cat << 'EOF' | sudo tee /etc/yum.repos.d/wazuh.repo
[wazuh]
gpgcheck=1
gpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH
enabled=1
name=EL-$releasever - Wazuh
baseurl=https://packages.wazuh.com/4.x/yum/
protect=1
EOF

sudo dnf -y install wazuh-indexer
```

`/etc/wazuh-indexer/opensearch.yml` 파일에서 **`network.host` 및 `node.name`은 노드별로 개별 지정**하며, 아래 클러스터 설정은 3개 노드 모두 동일하게 작성합니다.

```yaml
cluster.initial_master_nodes:
  - "node-1"
  - "node-2"
  - "node-3"
discovery.seed_hosts:
  - "192.0.2.5"
  - "192.0.2.8"
  - "192.0.2.33"
```

각 노드별로 인증서를 배치합니다.

```bash
NODE_NAME=node-1      # 노드별 해당 노드명 지정
sudo mkdir -p /etc/wazuh-indexer/certs
sudo tar -xf ~/wazuh-certificates.tar -C /etc/wazuh-indexer/certs/ \
  ./$NODE_NAME.pem ./$NODE_NAME-key.pem ./admin.pem ./admin-key.pem ./root-ca.pem
sudo mv -n /etc/wazuh-indexer/certs/$NODE_NAME.pem     /etc/wazuh-indexer/certs/indexer.pem
sudo mv -n /etc/wazuh-indexer/certs/$NODE_NAME-key.pem /etc/wazuh-indexer/certs/indexer-key.pem
sudo chmod 500 /etc/wazuh-indexer/certs
sudo chmod 400 /etc/wazuh-indexer/certs/*
sudo chown -R wazuh-indexer:wazuh-indexer /etc/wazuh-indexer/certs

sudo systemctl daemon-reload
sudo systemctl enable --now wazuh-indexer
```

**보안 초기화 스크립트는 indexer1 노드에서 1회만** 실행합니다.

```bash
sudo /usr/share/wazuh-indexer/bin/indexer-security-init.sh

# 클러스터 노드 기동 검증 (node-1/2/3 3개 항목 확인)
curl -k -u admin:admin https://192.0.2.5:9200/_cat/nodes?v
```

> **트러블슈팅 유의사항:** 패키지 설치 시 노드별 `opensearch.yml` 자동 생성 결과가 다를 수 있습니다. `discovery.seed_hosts` 및 `cluster.initial_master_nodes` 설정 항목이 주석 처리되어 있지 않은지 3개 노드 전체에서 점검합니다. `vm.max_map_count` 미설정 시에도 기동 실패 로그(`max_map_count [65530] is too low`)가 발생하므로 사전 설정을 확인합니다.

---

## 5. Server 클러스터 구축 (Master / Worker)

저장소 등록 후 `sudo dnf -y install wazuh-manager`를 실행합니다.

`/var/ossec/etc/ossec.conf` 내 `<cluster>` 섹션을 설정합니다. **두 노드의 차이는 `node_name` 및 `node_type` 두 항목**입니다.

* `<node_name>`: `wazuh-1` (Master) / `wazuh-2` (Worker)
* `<node_type>`: `master` / `worker`
* `<key>`: **두 노드 동일하게 설정** (`openssl rand -hex 16` 명령으로 생성하여 양쪽 동일 적용)
* `<nodes><node>`: 양쪽 노드 모두 **Master 노드 IP** 지정
* **`<disabled>`:** 기본값이 `yes`로 되어 있으므로 **반드시 `no`로 변경**

```bash
sudo systemctl restart wazuh-manager
sudo /var/ossec/bin/cluster_control -l    # 두 노드 정상 인식 여부 확인
```

### Filebeat 추가 설치 및 설정

**`wazuh-manager` 설치와 별개로 Filebeat 추가 설치가 필요합니다.**

```bash
sudo dnf -y install filebeat
sudo curl -so /etc/filebeat/filebeat.yml \
  https://raw.githubusercontent.com/wazuh/wazuh/v4.14.6/extensions/filebeat/7.x/filebeat.yml
sudo curl -so /etc/filebeat/wazuh-template.json \
  https://raw.githubusercontent.com/wazuh/wazuh/v4.14.6/extensions/elasticsearch/7.x/wazuh-template.json
sudo chmod go+r /etc/filebeat/wazuh-template.json
sudo curl -s https://packages.wazuh.com/4.x/filebeat/wazuh-filebeat-0.4.tar.gz \
  | sudo tar -xvz -C /usr/share/filebeat/module

# Indexer 접속 자격 증명 설정
sudo /var/ossec/bin/wazuh-keystore -f indexer -k username -v admin
sudo /var/ossec/bin/wazuh-keystore -f indexer -k password -v admin
```

기본 템플릿에 SSL 관련 설정이 누락되어 있으므로 직접 추가합니다. Indexer가 TLS 기반이므로 `https` 설정이 필수적입니다.

```yaml
output.elasticsearch.hosts: ['https://192.0.2.5:9200','https://192.0.2.8:9200','https://192.0.2.33:9200']
output.elasticsearch.username: admin
output.elasticsearch.password: admin
output.elasticsearch.ssl.certificate_authorities: ['/etc/filebeat/certs/root-ca.pem']
output.elasticsearch.ssl.certificate: '/etc/filebeat/certs/filebeat.pem'
output.elasticsearch.ssl.key: '/etc/filebeat/certs/filebeat-key.pem'
```

인증서를 각 서버별 명칭으로 배치한 후 데몬을 기동합니다.

```bash
sudo systemctl enable --now filebeat
sudo filebeat test output       # 'talk to server... OK' 출력 확인
```

---

## 6. Dashboard 구축

저장소 등록 후 `sudo dnf -y install wazuh-dashboard` 명령으로 설치하고 인증서를 배치합니다.

> **설정 파일 역할 구별:**
>
> | 설정 파일 | 연동 대상 및 역할 |
> |---|---|
> | `opensearch_dashboards.yml` | **Indexer (저장소)** 연동 설정 (`opensearch.hosts`, `kibanaserver` 계정 사용) |
> | `wazuh.yml` | **Server API (Manager)** 연동 설정 (`url`에 Master 서버 지정, 55000 포트) |
>
> 대시보드 화면은 정상 표시되나 Manager 상태가 Offline으로 출력될 경우 `wazuh.yml` 내 URL 설정이 `localhost`로 남아있는지 확인합니다.

```bash
sudo systemctl enable --now wazuh-dashboard
```

접속: `https://<DASHBOARD_PUBLIC_IP>` 접속 후 자체 서명 인증서 경고를 승인합니다. Manager 상태가 Online으로 표시되면 구축이 완료됩니다. ("Error checking updates" 메시지는 사설망 환경 특성상 정상입니다.)

---

## 7. 구축 검증 체크리스트

- [ ] 6개 노드 시간 동기화 정상 여부 (`chronyc tracking`)
- [ ] 6개 노드 인증서 배치 완료
- [ ] Indexer `_cat/nodes` 조회 시 3개 노드 출력 확인
- [ ] `cluster_control -l` 조회 시 Server 2개 노드 (Master + Worker) 출력 확인
- [ ] `filebeat test output` 실행 시 Server 2대 모두 OK 확인
- [ ] 대시보드 로그인 및 **Manager Online** 상태 확인
- [ ] **초기 기본 비밀번호 변경 완료**
- [ ] 에이전트 1대 등록 후 무차별 대입 공격 시뮬레이션을통한 레벨 10 알림 수집 검증
- [ ] **레플리카 설정을 1로 상향 조정한 후** 단일 노드 다운 시 클러스터 Green 상태 유지 검증 (레플리카 설정이 0일 경우 Red 상태로 전환됨)

---

## 8. 운영 환경 도입 리스크 및 검증 로그

단일 호스트 또는 컨테이너 환경에서는 발생하지 않으나, 6대 분산 VM 구축 시 발생하는 실증 리스크 항목입니다.

* **방화벽 설정 이슈:** SSH 보안그룹 CIDR 범위 설정 오류, Server 간 1516 포트 미개방으로 인한 Worker 노드 미합류, Dashboard → Server API 55000 포트 미개방으로 인한 Manager Offline 현상 발생 ➔ 초기 방화벽 허용 정책 일괄 적용 권장
* **주요 기본 설정 누락:** `ossec.conf` 내 `<disabled>` 기본값(`yes`), 클러스터 키(`key`) 불일치, `vm.max_map_count` 미설정으로 인한 서비스 기동 실패
* **설정 자동 생성 결과 검증:** 노드별 설정 파일 내 주석 처리 여부 육안 점검 필요
* **Filebeat 추가 설치 및 SSL 설정:** 기본 템플릿 내 SSL 설정 미포함 항목 직접 추가 필요
* **대시보드 연동 설정 구별:** `opensearch_dashboards.yml` 및 `wazuh.yml` 역할 구별
* **인증서 배포 변수 관리:** `NODE_NAME` 변수 누락으로 인한 빈 파일 생성 방지

---

## 참고 공식 문서

* [Wazuh Distributed Deployment Guide](https://documentation.wazuh.com/current/installation-guide/index.html)
* [Wazuh Indexer Step-by-Step Installation](https://documentation.wazuh.com/current/installation-guide/wazuh-indexer/step-by-step.html)
* [Wazuh Server Cluster Installation](https://documentation.wazuh.com/current/installation-guide/wazuh-server/)
* 인증서 도구 스크립트: `packages.wazuh.com/4.14/wazuh-certs-tool.sh`, `config.yml`