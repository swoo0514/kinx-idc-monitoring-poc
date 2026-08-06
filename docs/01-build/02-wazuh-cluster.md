# Wazuh 6노드 분산 배포 (패키지 기반)

실환경 구성(Indexer 3 / Server 2 / Dashboard 1)을 그대로 미러하는 6대 VM 분산 배포 가이드입니다.

문서의 IP는 예시 주소이고 실값은 `hosts.local.md`에 둡니다 — [`hosts.md`](hosts.md).
**설치 직후의 벤더 기본 계정은 공식 절차의 일부라 그대로 적었습니다.** 첫 로그인에서 바꿉니다.

---

## 0. 왜 Docker가 아니라 패키지인가

6대 실제 VM에는 `wazuh-docker`(multi-node)를 쓰지 않습니다.

- `wazuh-docker`의 multi-node는 **"1대 호스트에 6컨테이너" 전용**입니다(공식). 여러 VM 분산을
  지원하지 않습니다.
- 6대 실제 VM의 정석은 **패키지 기반 distributed deployment**이고, 이것이 실환경의 진짜
  미러입니다.
- "Docker로 가자"는 판단은 **단일 호스트 재현성** 때문이었는데, 6대 실 VM으로 가면서 그
  전제가 사라졌습니다.

> **1대 컨테이너로 만들면 실환경에 없는 가짜 문제(힙 OOM 등)를 만듭니다.** 반대로 6대 분산에서
> 겪는 인증서·NTP·방화벽 문제는 **실환경 도입에서 그대로 재현될 리스크**라 그것 자체가
> 산출물입니다.

## 1. VM 배치

| 역할 | 노드명 | 사설 IP (예시) | 사양 | SSH 별칭 |
|---|---|---|---|---|
| indexer | `node-1` | `192.0.2.5` | 8C/16GB | `indexer1` |
| indexer | `node-2` | `192.0.2.8` | 8C/16GB | `indexer2` |
| indexer | `node-3` | `192.0.2.33` | 8C/16GB | `indexer3` |
| server (master) | `wazuh-1` | `192.0.2.13` | 4C/8GB | `server1` |
| server (worker) | `wazuh-2` | `192.0.2.18` | 4C/8GB | `server2` |
| dashboard | `dashboard` | `192.0.2.17` + **공인 IP 1개** | 2C/4GB | `dashboard` |

### 네트워크 결정 — 공인 IP는 하나만

- **Indexer 3 + Server 2 = 사설 IP만.** 외부 노출 0.
- **Dashboard 1 = 공인 IP 1개.** 작업자 VPN이 없어 사설 접속이 불가능하므로 대시보드만
  외부 문으로 씁니다.

서버마다 공인 IP를 박는 것은 비용·보안상 실무에서 하지 않습니다. **대시보드가 외부에서
들어오는 유일한 문 = 배스천/점프호스트 패턴**이고, 나머지 5대는 공인 IP가 없어 원천 격리됩니다.

**보안 필수** — 대시보드 공인 IP의 22·443만 작업자 IP에 열고, 9200 등 나머지 포트는 공인
쪽에서 전부 차단합니다.

### 방화벽 오픈 포트

| 구간 | 포트 |
|---|---|
| indexer 간 | 9200(REST) / 9300(transport) |
| server → indexer | 9200 |
| server 간 | 1516(cluster) |
| agent → server | 1514(이벤트) / 1515(등록) |
| server API | 55000 |
| dashboard → indexer/server | 443 / 9200 / 55000 |
| 작업자 접속 | 22 · 443 — **대시보드(공인)에만, 작업자 IP로 한정** |

> **포트를 단계마다 만나는 대로 열지 말고 처음에 전부 열어 둡니다.** 이 랩에서 가장 반복적으로
> 막힌 지점입니다(§8).

### 볼륨

**Indexer 3대에 데이터 볼륨을 별도 부착해 `/var/lib/wazuh-indexer`에 마운트합니다.**

Indexer가 알림 데이터 저장소라 루트 디스크만으로는 며칠 만에 차고, **워터마크에 도달하면
인덱싱이 중단됩니다.** 볼륨 크기와 디스크 종류(HDD/SSD) 선택 자체가 리스크 실측 항목입니다.
Server 2대는 상대적으로 가벼워 루트가 넉넉하면 생략 가능합니다.

```bash
lsblk                                     # 붙인 디스크 이름 확인
sudo mkfs.xfs /dev/vdb
sudo mkdir -p /var/lib/wazuh-indexer
sudo mount /dev/vdb /var/lib/wazuh-indexer
echo '/dev/vdb /var/lib/wazuh-indexer xfs defaults 0 0' | sudo tee -a /etc/fstab
```

**마운트가 패키지 설치보다 먼저여야** 데이터가 볼륨에 쌓입니다.

## 2. 6대 공통 사전 준비

```bash
# 시간 동기화 — 분산 배포의 1순위 함정 (시계가 어긋나면 TLS 인증서가 거부된다)
sudo dnf -y install chrony
sudo systemctl enable --now chronyd
chronyc tracking          # 6대 모두 확인

# (인덱서 VM만) 커널 파라미터 — 없으면 인덱서가 기동 실패한다
sudo sysctl -w vm.max_map_count=262144
echo 'vm.max_map_count=262144' | sudo tee /etc/sysctl.d/99-wazuh.conf
```

노드명 해석을 위해 6대 모두의 `/etc/hosts`에 6줄을 추가합니다(노드명 ↔ IP).

## 3. 인증서 생성 (indexer1에서 한 번 → 나머지에 배포)

```bash
curl -sO https://packages.wazuh.com/4.14/wazuh-certs-tool.sh
curl -sO https://packages.wazuh.com/4.14/config.yml
```

`config.yml`에 6대의 이름과 IP를 채웁니다 — indexer 3, server 2(master/worker), dashboard 1.

```bash
bash ./wazuh-certs-tool.sh -A
tar -cvf ./wazuh-certificates.tar -C ./wazuh-certificates/ .
```

**배포는 작업자 PC를 경유합니다.** VM끼리는 SSH 키가 없어 서로 scp가 안 됩니다.

```bash
# 작업자 PC에서 — ~/.ssh/config 별칭으로 점프·키가 자동 적용된다
scp indexer1:~/wazuh-certificates.tar ./
scp ./wazuh-certificates.tar indexer2:~/
scp ./wazuh-certificates.tar indexer3:~/
scp ./wazuh-certificates.tar server1:~/
scp ./wazuh-certificates.tar server2:~/
scp ./wazuh-certificates.tar dashboard:~/
```

> **⚠️ `config.yml`의 IP가 실제 VM IP와 정확히 일치해야 합니다(SAN).** 틀리면 노드가 서로
> 인증을 거부해 **클러스터가 형성되지 않습니다.** 6대 분산의 최대 함정입니다.
>
> **인증서 tar는 리포 안에 두지 않습니다.** scp 목적지를 리포 디렉토리로 잡으면 그대로
> 커밋 위험이 됩니다(`.gitignore`가 이중으로 막고 있지만, 애초에 리포 밖으로 받습니다).

## 4. 인덱서 클러스터 (VM 1~3)

각 인덱서 VM에서 저장소를 등록하고 설치합니다.

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

`/etc/wazuh-indexer/opensearch.yml`에서 **`network.host`와 `node.name`만 노드마다 다르고**,
아래 두 목록은 3대 모두 같습니다.

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

인증서를 배치합니다(각 노드에서 `NODE_NAME`만 바꿔서).

```bash
NODE_NAME=node-1      # 노드마다 다름. 변수를 비운 채 tar를 돌리면 조용히 실패한다
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

**보안 초기화는 indexer1에서만 1회** 실행합니다.

```bash
sudo /usr/share/wazuh-indexer/bin/indexer-security-init.sh

# 확인 — node-1/2/3 세 줄이 나오면 성공
curl -k -u admin:admin https://192.0.2.5:9200/_cat/nodes?v
```

> **⚠️ 실제로 겪은 것 — 인덱서마다 `opensearch.yml` 자동 생성 결과가 달랐습니다.**
> 한 노드는 멀쩡했는데 다른 노드는 `discovery.seed_hosts`와 `cluster.initial_master_nodes`의
> 일부 줄이 **주석 처리**돼 있어 기동·합류에 실패했습니다.
> **3대 전부 `sudo cat`으로 육안 확인**하고 주석을 제거합니다.
> `vm.max_map_count` 미설정 노드도 기동에 실패합니다(로그: `max_map_count [65530] is too low`).

## 5. 서버 클러스터 (master + worker)

저장소 등록 후 `sudo dnf -y install wazuh-manager`.

`/var/ossec/etc/ossec.conf`의 `<cluster>` 섹션을 채웁니다. **두 노드의 차이는
`node_name`과 `node_type` 두 곳뿐**입니다.

- `<node_name>` — `wazuh-1` / `wazuh-2`
- `<node_type>` — `master` / `worker`
- `<key>` — **두 노드 동일**. `openssl rand -hex 16`으로 만들어 양쪽에 넣습니다. 다르면 미합류
- `<nodes><node>` — 양쪽 다 **master의 IP**
- **`<disabled>` — 기본값이 `yes`입니다. 반드시 `no`로 바꿉니다**

```bash
sudo systemctl restart wazuh-manager
sudo /var/ossec/bin/cluster_control -l    # 두 노드가 다 보이면 성공
```

### Filebeat — 별도 설치가 필요합니다

**`wazuh-manager`를 설치해도 Filebeat는 따로 설치해야 합니다.** 안 하면
`/etc/filebeat/filebeat.yml`이 빈 파일입니다.

```bash
sudo dnf -y install filebeat
sudo curl -so /etc/filebeat/filebeat.yml \
  https://raw.githubusercontent.com/wazuh/wazuh/v4.14.6/extensions/filebeat/7.x/filebeat.yml
sudo curl -so /etc/filebeat/wazuh-template.json \
  https://raw.githubusercontent.com/wazuh/wazuh/v4.14.6/extensions/elasticsearch/7.x/wazuh-template.json
sudo chmod go+r /etc/filebeat/wazuh-template.json
sudo curl -s https://packages.wazuh.com/4.x/filebeat/wazuh-filebeat-0.4.tar.gz \
  | sudo tar -xvz -C /usr/share/filebeat/module

# 인덱서 접속 크리덴셜은 keystore에
sudo /var/ossec/bin/wazuh-keystore -f indexer -k username -v admin
sudo /var/ossec/bin/wazuh-keystore -f indexer -k password -v admin
```

**템플릿에 SSL·인증 줄이 없으므로 직접 추가합니다.** 인덱서가 TLS라 `https`가 필수입니다.

```yaml
output.elasticsearch.hosts: ['https://192.0.2.5:9200','https://192.0.2.8:9200','https://192.0.2.33:9200']
output.elasticsearch.username: admin
output.elasticsearch.password: admin
output.elasticsearch.ssl.certificate_authorities: ['/etc/filebeat/certs/root-ca.pem']
output.elasticsearch.ssl.certificate: '/etc/filebeat/certs/filebeat.pem'
output.elasticsearch.ssl.key: '/etc/filebeat/certs/filebeat-key.pem'
```

인증서를 배치하고(각 서버의 자기 이름으로) 기동합니다.

```bash
sudo systemctl enable --now filebeat
sudo filebeat test output       # 'talk to server... OK' 가 나오면 성공
```

## 6. 대시보드

저장소 등록 후 `sudo dnf -y install wazuh-dashboard`, 인증서 배치.

> **⚠️ 설정 파일이 두 개입니다. 가장 헷갈리는 지점입니다.**
>
> | 파일 | 무엇을 연결 |
> |---|---|
> | `opensearch_dashboards.yml` | **인덱서**(저장소) — `opensearch.hosts`, 계정은 `kibanaserver`(admin 아님) |
> | `wazuh.yml` | **서버 API**(Manager) — `url`을 master 서버로, port 55000 |
>
> **화면은 떴는데 Manager가 Offline이면** `wazuh.yml`의 url이 `localhost`로 남아 있는 것입니다.

```bash
sudo systemctl enable --now wazuh-dashboard
```

접속: `https://<DASHBOARD_PUBLIC_IP>` — 자체 서명 경고는 무시합니다. Manager가 Online이면
완성입니다. "Error checking updates"는 사설망이라 정상입니다.

## 7. 검증 체크리스트

- [ ] 6대 시계 동기화 (전부 Normal)
- [ ] 인증서 6대 배포
- [ ] 인덱서 `_cat/nodes`에 3노드
- [ ] `cluster_control -l`에 서버 2노드 (master + worker)
- [ ] `filebeat test output` — 서버 2대 모두 OK
- [ ] 대시보드 로그인 + **Manager Online**
- [ ] **기본 비밀번호 전부 변경**
- [ ] 에이전트 1대 등록 → 브루트포스로 레벨 10 알림 재현
- [ ] **레플리카를 1로 올린 뒤** 노드 1대 다운 → 클러스터 green 유지 검증
      (레플리카 0이면 yellow가 아니라 **red**가 됩니다)

## 8. 도입 리스크 실측 로그

**단일 호스트나 컨테이너로는 안 나오고 "6대 실 VM이라서" 겪는 것들**이라, 실환경 도입 시
그대로 재현될 리스크입니다.

**방화벽 — 가장 반복적으로 막혔습니다.**
SSH 보안그룹 소스를 좁게 잡아 일부 노드가 범위 밖이었습니다(VM IP가 연속 배정되지 않으므로
CIDR은 서브넷 전체로). 인덱서 포트는 열었는데 **server 간 1516을 놓쳐** worker가 master에
미합류했고, **dashboard → 서버 API 55000**을 안 열어 Manager가 Offline이었습니다.
→ **처음에 필요한 포트를 한 번에 열어 둡니다.** OS 방화벽도 별도로 확인합니다.

**놓치기 쉬운 기본값.**
`ossec.conf`의 `<disabled>` 기본값이 `yes`라 안 바꾸면 서버 클러스터 자체가 안 켜집니다.
클러스터 `<key>`가 다르면 미합류합니다. `vm.max_map_count` 미설정 노드는 인덱서가 기동 실패합니다.

**설정 자동 생성이 노드마다 다릅니다.** 육안 확인이 필요합니다(§4).

**Filebeat는 별도 설치이고 템플릿에 SSL 줄이 없습니다**(§5).

**대시보드 설정 파일이 두 개입니다**(§6).

**VM 간 인증서 배포는 작업자 PC를 경유해야 합니다**(§3). `NODE_NAME` 변수가 세션이 끊기면
날아가는데, **빈 변수로 tar를 돌리면 조용히 실패합니다.**

## 출처 (공식)

- [Distributed deployment](https://documentation.wazuh.com/current/installation-guide/index.html)
- [Indexer step-by-step](https://documentation.wazuh.com/current/installation-guide/wazuh-indexer/step-by-step.html)
- [Server cluster](https://documentation.wazuh.com/current/installation-guide/wazuh-server/)
- 인증서 도구: `packages.wazuh.com/4.14/wazuh-certs-tool.sh`, `config.yml`
