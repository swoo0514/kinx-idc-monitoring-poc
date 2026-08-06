# 관측 코어 구축 — Zabbix + MariaDB + Grafana + Loki

실환경 미러 랩의 관측 계층 코어를 Docker Compose로 구축하는 가이드입니다. `docker-compose.yml`
각 설정 항목의 기술적 근거, 실행 절차 및 검증 방법을 명시합니다.

문서에 나오는 IP는 예시 주소입니다 — [`hosts.md`](hosts.md) 참조. 코드는 `lab/`에 있습니다.

---

## 0. 환경 및 구축 목적

* **구성 요소:** Zabbix 7.0 (메트릭) + MariaDB 10.11 (DB) + Grafana 11.6.16 (시각화) + Loki 3.4.0 (로그)
* **배포 환경:** IXcloud 단일 VM 인스턴스 (Docker 컨테이너 방식)
* **네트워크 구성:** 사설 IP + 공인 IP 1개를 함께 할당합니다.
  * **사설 IP:** Wazuh 6노드 클러스터와 동일 사설망에 위치시켜, Grafana가 Wazuh
    Indexer(node-1 `192.0.2.5:9200`)에 직접 연동하기 위한 필수 경로입니다.
  * **공인 IP:** Zabbix Web(8080)·Grafana(3000) 대시보드에 브라우저로 접근하기 위한 용도입니다.
    Wazuh 랩의 "대시보드만 공인 노출" 원칙과 동일하게, 보안 그룹에서 22·8080·3000을
    작업자 IP(Source /32)로 한정 개방하고 나머지 공인 포트는 차단합니다.
* **사설망 연동 사유:** 로컬 PC 환경은 사설망 접근이 불가능하여 Wazuh 연동이 성립하지 않으므로,
  관측 코어를 사설망 내 VM에 배치합니다.
* **Docker 채택 사유:** 관측 레이어 재현성 확보 및 환경 격리를 단일 호스트 인프라로 손쉽게
  검증하기 위함입니다.

---

## 1. 사전 인프라 준비

### 1-1. Docker 및 Compose 플러그인 설치 (Rocky Linux 9 기준)

```bash
sudo dnf -y install git dnf-plugins-core
sudo dnf config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
# [트러블슈팅] Rocky 9는 $releasever가 "9.0"으로 확장되나 Docker repo는 major(9)만 제공하여 404 발생.
# repo 파일의 $releasever를 9로 고정한다.
sudo sed -i 's/\$releasever/9/g' /etc/yum.repos.d/docker-ce.repo
sudo dnf -y install docker-ce docker-ce-cli containerd.io docker-compose-plugin
sudo systemctl enable --now docker
sudo usermod -aG docker $USER
# 로그아웃 후 재접속하여 권한 적용 확인
docker compose version
```

### 1-2. 네트워크 보안 그룹 설정

* **`8080/TCP` (Zabbix Web) / `3000/TCP` (Grafana):** 작업자 IP(Source /32) 한정 허용.
* **`10051/TCP` (Zabbix Trapper):** 사설망 대역 내 에이전트 통신용 허용.
* **`3100/TCP` (Loki):** 내부 컨테이너 간 통신 전용 (외부 노출 불필요).

---

## 2. 컴포넌트별 설정 상세 및 기술 근거

### 2-1. MariaDB (`mariadb:10.11`)

* **버전 선정:** Zabbix 7.0 공식 지원 사양은 MariaDB 10.5.00 ~ 12.3.X입니다. 지원 범주 내
  안정적인 LTS 버전인 10.11을 채택했습니다.
* **Command 주요 파라미터:**
  * `--character-set-server=utf8mb4` / `--collation-server=utf8mb4_bin`: Zabbix 7.0 필수
    문자셋 및 콜레이션 사양입니다.
  * `--log_bin_trust_function_creators=1`: 최초 DB 스키마 임포트 시 저장 함수(Stored Function)
    생성 권한 오류를 방지합니다.
  * *(MySQL 전용 옵션인 `--skip-mysqlx`는 MariaDB 호환성을 위해 제외)*
* **단일 구성 사유:** 1차 코어 기동 검증을 위해 단일 노드로 시작하며, HA 주/부 복제
  옵션(`--log-bin`, `--server-id`)은 DB 이중화 및 편측 감시 진단 단계에서 추가 적용합니다(§9).
* **Healthcheck:** MariaDB 공식 헬스체크 유틸리티 (`healthcheck.sh --connect
  --innodb_initialized`)를 적용하여 Zabbix Server 기동 순서를 제어합니다.

### 2-2. Zabbix Server 및 Web (`alpine-7.0.27`)

* **이미지 태그:** 실환경 버전과 정합성을 맞추기 위해 `alpine-7.0.27` 태그로 고정합니다.
* **주요 환경 변수:**
  * **Server:** `DB_SERVER_HOST`, `MYSQL_DATABASE`, `MYSQL_USER`, `MYSQL_PASSWORD`,
    `MYSQL_ROOT_PASSWORD` (최초 스키마 생성 권한 확보용)
  * **Web:** `ZBX_SERVER_HOST`, `DB_SERVER_HOST`, `MYSQL_DATABASE`, `MYSQL_USER`,
    `MYSQL_PASSWORD`, `PHP_TZ` (보안을 위해 root 계정 미부여)
* **의존성 정의 (`depends_on`):** `mariadb` 컨테이너의 `service_healthy` 상태 확인 후 Server
  데몬이 기동하도록 제어하여 DB 연결 실패 반복 현상을 차단합니다.

### 2-3. Grafana (`grafana:11.6.16`)

* **플러그인 프로비저닝:** `GF_INSTALL_PLUGINS=alexanderzobnin-zabbix-app` 환경변수를 전달하여
  Zabbix 공식 연동 모듈을 자동 설치합니다(버전 미지정 시 최신 v6.x 설치).
* **버전 호환성(중요):** 자동 설치되는 Zabbix 플러그인 최신(v6.x)은 **Grafana 11.6.0 이상**을
  요구합니다(플러그인 v6.0.0 changelog 기준). 초기에 Grafana 11.2.0으로 구성했을 때
  데이터소스 추가 화면에서 React error #130(컴포넌트 렌더 실패)이 발생하여, 안정 버전
  11.6.16으로 상향했습니다. 참고로 플러그인 v5.x는 Grafana 10.4.8 이상을 요구합니다.
* **IaC 구성:** 데이터소스 매핑을 GUI 수동 작업 대신
  `grafana/provisioning/datasources/datasources.yml` 코드로 관리하여 재현성을 보장합니다.

### 2-4. Loki (`loki:3.4.0`)

* **아키텍처:** 단일 프로세스(Monolithic), 파일시스템 스토리지 및 최신 스키마(`tsdb`, `v13`)를
  적용합니다.
* **공식 기본값 대비 커스텀 변경 사항:**
  1. `path_prefix`: Docker 볼륨 영속성 처리를 위해 `/tmp/loki`에서 `/loki`로 변경.
  2. `reject_old_samples: false`: 장애 시뮬레이션 및 과거 타임스탬프 로그 재현 시 데이터 수용 목적.
* **보존 정책:** Deprecated 처리된 `table_manager`를 배제하고 최신 retention 스펙을 준수합니다.

---

## 3. 서비스 실행

```bash
cd lab
cp .env.example .env
# .env 파일을 열어 랩 전용 임의 비밀번호 설정

# 이미지 다운로드 및 컨테이너 백그라운드 기동
docker compose pull
docker compose up -d

# 기동 상태 및 로그 확인
docker compose ps
docker compose logs -f zabbix-server
```

*(최초 기동 시 MariaDB 스키마 자동 생성 작업으로 약 1~2분의 소요 시간이 발생합니다. 로그 상에
`server #0 started` 출력을 확인합니다.)*

---

## 4. 접속 정보 및 데이터소스 연동

| 서비스 | 접속 URL | 초기 계정 정보 |
| --- | --- | --- |
| **Zabbix Web** | `http://<VM_IP>:8080` | `Admin` / `zabbix` (로그인 후 즉시 변경) |
| **Grafana** | `http://<VM_IP>:3000` | `admin` / `.env` 내 `GRAFANA_ADMIN_PASSWORD` |

### 4-1. 데이터소스 provisioning (코드 관리)

데이터소스는 `grafana/provisioning/datasources/datasources.yml`로 자동 등록됩니다. 크리덴셜은
파일에 넣지 않고 **환경변수로 치환**합니다 — Grafana provisioning은 `$VAR` / `${VAR}` 문법으로
컨테이너 환경변수를 읽습니다(공식 문서). 각 변수는 compose의 grafana 서비스가 `.env`에서
주입합니다.

| 데이터소스 | type | 필요 환경변수 | 비고 |
| --- | --- | --- | --- |
| Loki | `loki` | 없음 | 인증 없는 랩. 바로 동작. |
| Zabbix | `alexanderzobnin-zabbix-datasource` | `ZBX_GRAFANA_USER`, `ZBX_GRAFANA_PASSWORD` | Zabbix UI에서 읽기 전용 계정 생성 선행. url은 `api_jsonrpc.php`로 고정. |
| Wazuh | `grafana-opensearch-datasource` | `WAZUH_INDEXER_URL`, `WAZUH_INDEXER_USER`, `WAZUH_INDEXER_PASSWORD` | 사설망에 붙는 VM에서만 값 유효. 자체서명 인증서라 `tlsSkipVerify: true`. |
| Wazuh-States | `grafana-opensearch-datasource` | 위와 동일 | 취약점 재고 전용(스냅샷 인덱스). 근거는 [`../02-design/README.md`](../02-design/README.md) |

절차:

1. Zabbix Web(`:8080`) 접속 → 읽기 전용 계정(예: `grafana-ro`) 생성.
2. `.env`에 위 환경변수 기입(`.env.example` 참고). Wazuh 값은 로컬에서 비워두면 데이터소스는
   등록되나 연결만 실패(무해).
3. Grafana 재생성(환경변수는 볼륨 재사용 시 스킵될 수 있음):
   ```bash
   docker compose up -d --force-recreate grafana
   ```
4. 검증: Grafana → Connections → Data sources에서 등록 확인, 각 "Test" 통과.

> 주의: 비밀번호에 `$`를 쓰면 provisioning이 변수로 오인합니다. 랩 비밀번호에는 `$`를
> 피하거나 `$$`로 이스케이프합니다(공식 문서).

> **`cacheTTL` 주의:** Zabbix 데이터소스의 조회 캐시 기본값은 1시간입니다. 그대로 두면
> 값이 갱신되지 않아 **패널이 멈춘 것처럼 보입니다.** 랩에서 두 번 같은 사고를 겪어
> 1분으로 낮춰 두었습니다.

### 4-2. 대시보드 provisioning

`grafana/provisioning/dashboards/dashboards.yml`(provider)가 `.../dashboards/json/` 폴더의
모든 `*.json`을 Grafana 폴더 `KINX`에 자동 로드합니다. `allowUiUpdates: true`라 UI에서
수정도 가능합니다.

작업 흐름(권장): UI에서 패널을 구성 → Dashboard settings → JSON Model 또는 Export로
JSON 확보 → `json/` 폴더에 커밋. 데이터소스는 파일명이 아닌 **uid**(`loki`/`zabbix`/`wazuh`)로
참조해야 이식 시 깨지지 않습니다.

현재 제공되는 대시보드:

| 대시보드 | 데이터소스 | 용도 |
| --- | --- | --- |
| `kinx-overview` | Zabbix + Loki + Wazuh | 메트릭·로그·보안 동일 타임라인 (데모 A) |
| `kinx-msp` / `kinx-msp-os` | Zabbix | MSP 고객사별 뷰 (DB형 / OS형) |
| `kinx-msp-report` | Zabbix + Wazuh + Loki | MSP 월간 리포트 (렌더 대상) |
| `kinx-replication` | Zabbix | 복제 품질 — 상태(1/0)가 아닌 지연(초) |
| `kinx-certificates` | Zabbix | 인증서 만료 재고 |
| `kinx-noise` | Zabbix | 알림 노이즈 (다이어트 Before) |

---

## 5. 최종 검증 체크리스트

* [ ] `docker compose ps` 실행 시 `mariadb` 상태가 `healthy`이고 타 서비스가 `running` 상태인가?
* [ ] `docker compose logs zabbix-server` 로그에 `server #0 started` 구문이 존재하는가?
* [ ] Zabbix Web (`:8080`) 접속 및 System information 정보가 정상 출력되는가?
* [ ] Grafana (`:3000`) Connections → Data sources에 Loki·Zabbix·Wazuh가 등록되어 있는가?
* [ ] Grafana 대시보드 폴더 `KINX`에 대시보드가 로드되어 있는가?
* [ ] (에이전트 배포 후) Zabbix 수집 데이터가 시계열 그래프로 렌더링되는가?

---

## 6. 주요 장애 패턴 및 트러블슈팅

* **Zabbix Server 컨테이너 재시작 반복 (`CrashLoopBackOff`):**
  * DB 미준비 또는 인증 실패 현상임. `docker compose logs mariadb`로 DB 헬스 상태를 점검하고,
    `.env` 파일의 `MYSQL_USER/PASSWORD` 일치 여부를 확인합니다.
* **Zabbix Web "Database error" 출력:**
  * DB 최초 스키마 임포트 미완료 상태임. `zabbix-server` 컨테이너 로그를 확인하여 스키마
    생성이 완료될 때까지 대기합니다.
* **Grafana Zabbix 플러그인 인식 불가:**
  * 기존 볼륨 재사용 시 환경변수가 스킵될 수 있습니다.
    `docker compose up -d --force-recreate grafana` 명령으로 컨테이너를 재생성합니다.
* **Zabbix 데이터소스 API 연결 실패:**
  * URL 끝의 `/api_jsonrpc.php` 경로 누락 여부 및 Grafana 컨테이너 내부에서의 `zabbix-web`
    DNS 해석 상태를 점검합니다.
* **Zabbix 데이터소스 추가 화면에서 React error #130 (컴포넌트 렌더 실패):**
  * 자동 설치되는 Zabbix 플러그인 최신(v6.x)이 Grafana 11.6.0 이상을 요구하는데 Grafana
    버전이 낮을 때 발생합니다. Grafana 이미지를 11.6.16(안정)으로 상향하고
    `docker compose up -d grafana`로 재생성합니다.
* **대시보드 전 패널 no data:**
  * 자동 등록된 호스트는 `Discovered hosts` 그룹에 들어갑니다. **Grafana 조회 계정에 그 그룹
    읽기 권한이 없으면 전 패널이 no data**가 됩니다. Zabbix → User groups → Host permissions.
* **git / docker repo 관련(사전 준비):**
  * `git: command not found` → `sudo dnf -y install git`. Docker repo 404 → 위 §1-1의
    `sed`로 `$releasever`를 9로 고정.

---

## 7. Profile 확장 구조

기본 관측 코어 기동 후, 필요에 따라 Profile 옵션을 부여하여 세부 기능을 추가 기동합니다.

| Profile | 추가되는 것 |
| --- | --- |
| (기본) | mariadb, zabbix-server, zabbix-web, zabbix-web-service, grafana, grafana-image-renderer, mailpit, loki |
| `ha` | `mariadb-slave`(`server-id=2`, Master-Slave 복제), zabbix-agent2 |
| `chaos` | `snmpsim` (인터페이스 에러 카운터 조작) |
| `msp` | 고객사 컨테이너 세트 (web + DB master/slave + 에이전트) |

```bash
# 예시: Chaos 프로파일을 포함한 선택적 기동
docker compose --profile chaos up -d
```

> 에이전트(zabbix-agent2·Alloy·wazuh-agent)를 실제 VM에 배포하는 것은 compose가 아니라
> **Ansible**입니다 — [`ansible/DEPLOY_GUIDE.md`](../../ansible/DEPLOY_GUIDE.md).
> n8n·Ollama 프로파일은 검토했으나 채택하지 않았습니다(승인은 Keep, LLM은 API 경로).

---

## 9. MariaDB Master-Slave 복제 (`--profile ha`)

### 9-1. 목적과 방식

실환경 Zabbix DB는 MariaDB master-slave 구성입니다. 랩에서 이를 미러하여 **"DB 이중화
짝 중 한쪽만 감시되는" 진단을 시연**하기 위한 복제 계층입니다.
복제 방식은 MariaDB 공식 권장인 **GTID(`MASTER_USE_GTID=slave_pos`)** 를 사용합니다.
바이너리 로그 파일명·위치를 수동 추적하지 않아 재현성이 높습니다.

### 9-2. 마스터 설정 (compose 상시 적용)

기존 코어의 `mariadb` 서비스 command에 복제 마스터 옵션 4종을 상시 적용했습니다. 슬레이브가
없어도 무해하며, 실환경(복제 상시 가동)과 정합합니다. (근거: MariaDB 복제 공식 문서)

| 옵션 | 근거 |
| --- | --- |
| `--server-id=1` | 복제 토폴로지 내 고유 ID(마스터). 슬레이브는 2. |
| `--log-bin` | 바이너리 로그 활성화 — 복제의 전제. |
| `--log-basename=mariadb-master` | 바이너리 로그 파일명을 호스트명과 분리(컨테이너 재생성 시 이름 변화 방지). |
| `--binlog-format=mixed` | 공식 기본 권장 포맷. |

> 주의: 코어를 이미 복제 옵션 없이 기동했다면, `docker compose up -d` 시 command 변경으로
> `mariadb` 컨테이너가 **재생성**됩니다. 데이터 볼륨(`mariadb_data`)은 유지되므로 데이터
> 손실은 없습니다.

### 9-3. 슬레이브 서비스 (`mariadb-slave`, profile: ha)

`--server-id=2`, `--log-basename=mariadb-slave`, `--read-only=1`(슬레이브 역할 고정).
별도 데이터 볼륨(`mariadb_slave_data`)을 사용합니다. **복제 부트스트랩은 자동 init이 아니라
`setup-slave.sh`를 사용자가 실행**합니다 — 부트스트랩 각 단계(계정 생성·스냅샷·CHANGE
MASTER)를 이해하고 방어하기 위함입니다(자동화 시 은닉되는 지식).

### 9-4. 실행 절차

```bash
cd lab
# .env 에 REPLICATION_USER / REPLICATION_PASSWORD 채웠는지 확인 (.env.example 참고)

# 마스터+슬레이브 기동 (코어가 이미 떠 있으면 마스터는 재생성됨 — 9-2 주의 참고)
docker compose --profile ha up -d

# 둘 다 healthy 확인
docker compose ps

# 복제 부트스트랩 (계정 생성 → 스냅샷 덤프 → 슬레이브 적재 → CHANGE MASTER → START SLAVE → 검증)
./mariadb/setup-slave.sh
```

스크립트 5단계와 GTID 방식 근거는 스크립트 상단 주석 및 MariaDB 공식 문서 참조. 정상 시
`[OK] 복제 정상 (IO=Yes, SQL=Yes)` 출력. `setup-slave.sh`는 멱등(재실행 시 `RESET SLAVE`
후 재구성)합니다.

> 별도 VM에 슬레이브를 세우는 경우(데모 C)는
> [`lab/mariadb/REPL_VM_GUIDE.md`](../../lab/mariadb/REPL_VM_GUIDE.md).

### 9-5. 검증

* `Slave_IO_Running: Yes` 그리고 `Slave_SQL_Running: Yes` (둘 다 Yes여야 정상 — 공식 기준)
* `Seconds_Behind_Master: 0`(또는 소수) — 복제 지연
* 마스터에서 값 변경 후 슬레이브에서 반영 확인:
  ```bash
  docker compose exec -T -e MYSQL_PWD=<root암호> mariadb \
    mariadb -uroot -e "CREATE TABLE zabbix.repl_test(id int); INSERT INTO zabbix.repl_test VALUES(1);"
  docker compose exec -T -e MYSQL_PWD=<root암호> mariadb-slave \
    mariadb -uroot -e "SELECT * FROM zabbix.repl_test;"   # 1 이 보이면 복제 정상
  ```

### 9-6. 트러블슈팅

* **`Slave_IO_Running: Connecting`**: 마스터 접속 실패. 복제 계정(`REPLICATION_USER`) 존재·
  권한(`REPLICATION SLAVE`)·비밀번호(.env 일치), `lab_net` 내 `mariadb` DNS 해석,
  마스터 `--log-bin` 활성 여부를 확인합니다.
* **`Slave_SQL_Running: No` + 에러**: 스냅샷 시점과 GTID 불일치. `setup-slave.sh`를 다시
  실행하면 `RESET SLAVE` 후 스냅샷부터 재구성합니다.
* **마스터 재생성이 두려운 경우**: `mariadb_data` 볼륨은 유지되므로 안전합니다. 확신이
  필요하면 사전에 `docker compose exec mariadb mariadb-dump ...`로 백업 후 진행합니다.
* **`--read-only`인데 복제가 되나?**: `read_only`는 일반 계정의 쓰기만 막고 복제 SQL
  스레드에는 적용되지 않습니다(정상 동작).

---

## 10. Grafana correlation·대시보드 드릴다운 프로비저닝

Wazuh 보안 이벤트에서 같은 호스트의 Loki 로그로 건너뛰는 드릴다운을 두 경로로 구성했습니다.
역할이 겹치지 않으므로 둘 다 유지합니다.

### 10-1. Correlation (Explore 전용) — `datasources.yml` 프로비저닝

* **역할**: Explore에서 Wazuh 쿼리 결과의 `agent.name` 값을 클릭하면 오른쪽에 Loki 분할 뷰가
  열리며 그 호스트 로그 쿼리가 자동 실행됩니다. 자유 탐색(수사) 도구이며 대시보드 패널에서는
  동작하지 않습니다.
* **⚠️ Grafana 11.6.16 correlation provisioning 버그 (도입 리스크 — 실환경도 이 버전이면 동일)**:
  두 가지 검증이 동시에 걸려 형식을 정확히 맞추지 않으면 **데이터소스 프로비저닝 전체가 중단**되고
  Grafana가 기동하지 못합니다. 소스(`pkg/services/provisioning/datasources/datasources.go`
  의 `makeCreateCorrelationCommand`)로 확인한 조건은 다음과 같습니다.
  * **root 레벨 `type`을 명시하면 패닉**: `correlation["type"]`(YAML의 string)을
    `corrType.(correlations.CorrelationType)`로 직접 타입 단언 → `interface conversion:
    string is not correlations.CorrelationType` 패닉. → **root `type`은 반드시 생략**
    (생략 시 내부에서 `CorrelationType("query")`로 기본값 처리).
  * **`config.type`을 생략하면 에러**: `if config.Type != correlations.CorrelationType("query")`
    검증에서 생략 시 `config.Type == ""` → `"" != "query"` → `ErrInvalidConfigType`
    (`"correlation contains non default value in config.type"`). → **`config.type: query`를
    명시적으로 넣어야 합니다.**
* **유일하게 통과하는 형식** (`datasources.yml`, Wazuh 데이터소스 블록 하위):
  ```yaml
  correlations:
    - targetUID: loki
      label: "보안 이벤트 → 해당 호스트 로그"
      description: ""
      config:
        type: query            # 필수: 생략 시 ErrInvalidConfigType
        field: agent.name
        target:
          editorMode: code
          expr: '{host="$${__value.raw}"}'   # $$ 로 provisioning 환경변수 치환 회피
          queryType: range
  ```
  root 레벨에 `type`을 넣지 않는 것이 핵심입니다. `$${__value.raw}`의 `$$`는 Grafana
  provisioning이 `${...}`를 환경변수로 치환하는 것을 막아 런타임에 `${__value.raw}`로
  복원되게 합니다.
* **검증**: `docker compose restart grafana` 후 로그에 `panic`·`Failed to provision data
  sources`·`config.type`가 없고 `HTTP Server Listen`이 있으면 성공(성공은 별도 info 로그를
  남기지 않음). UI는 `/correlations`에서 provisioned 항목 확인.
* correlation은 UI export를 지원하지 않으므로 provisioning YAML을 손으로 작성합니다.

### 10-2. Data Link (대시보드) — `kinx-overview.json`

* **역할**: 대시보드 패널에서 미리 짜둔 드릴다운. Explore 전용인 correlation과 무대가 다릅니다.
* **구성 3요소**:
  1. **대시보드 변수 `$host`**: `Query` 타입, Loki 데이터소스, `Label values` → `host`,
     Include All(`allValue: .+`).
  2. **Wazuh Table 패널**: 쿼리 `rule.level:>=10`, Metric을 `Count`가 아닌 **`Raw Data`**
     로 설정해야 개별 이벤트 문서가 행으로 표시됩니다(`agent.name` 컬럼 포함).
  3. **`agent.name` 필드 override → Data links**: URL `/d/kinx-overview?var-host=${__value.raw}`
     (같은 대시보드를 그 호스트로 재오픈). Open in new tab 끄기. Loki 로그 패널 쿼리를
     `{host=~"$host"}`로 연결하면 클릭 시 그 호스트 로그로 필터됩니다.
* **전제 = 호스트 아이덴티티 정규화**: Wazuh `agent.name`(= `vm-target-001.novalocal`)과 Loki
  `host` 라벨이 일치해야 매칭됩니다. Alloy 설정의 `host`를 FQDN(`hostname -f`)으로 맞춰
  정규화했습니다(OpenTelemetry `host.name` 규약: FQDN 선호). → [`hosts.md`](hosts.md)

> **`allValue`에 주의:** 고객사 리포트처럼 테넌트가 갈리는 대시보드에서 `allValue: ".+"`는
> "전체"를 **"다른 고객까지"**로 만듭니다. 계정 권한과 별개로 대시보드가 새면 안 됩니다.

### 10-3. 알아둘 점

* **`$host` 드롭다운에 옛 이름이 남음**: Alloy `host` 라벨을 짧은 이름 → FQDN으로 바꾸기
  이전에 쌓인 Loki 스트림이 옛 라벨로 남아 있어 `label_values(host)`가 둘 다 반환합니다.
  Loki 보존기간이 지나면 사라지며, Wazuh `agent.name`은 FQDN이라 드릴다운은 항상 정규화된
  이름으로 동작합니다(과거 잔재일 뿐).
* **드릴다운이 눈에 띄려면 로그를 보내는 호스트가 2대 이상**이어야 합니다. 1대뿐이면
  "All"과 "그 호스트" 결과가 같아 시각적 변화가 없습니다.

---

## 11. 참고 공식 문서

* [Zabbix 7.0 Database Requirements](https://www.zabbix.com/documentation/7.0/en/manual/installation/requirements)
* [Zabbix Official Container Installation Guide](https://www.zabbix.com/documentation/7.0/en/manual/installation/containers)
* [Zabbix Official Docker Repository (7.0 Branch)](https://github.com/zabbix/zabbix-docker)
* [Grafana Zabbix Plugin Documentation](https://grafana.com/grafana/plugins/alexanderzobnin-zabbix-app/)
* [Grafana Loki Docker Setup Guide](https://grafana.com/docs/loki/latest/setup/install/docker/)
* [MariaDB Setting up Replication (GTID)](https://mariadb.com/kb/en/setting-up-replication/)

---

> **이관 시 갱신한 것.** 이 문서는 구축 중에 쓰인 내부 가이드를 옮긴 것이며, 옮기면서 IP를
> 예시 주소로 치환했습니다. 그 외에 **구축 당시 시점 기준이라 지금은 사실이 아닌 서술 세 곳을
> 갱신**했습니다 — 대시보드 목록(당시 "골격 1종" → 현재 7종), Profile 목록(검토했으나 채택하지
> 않은 `auto`·`ai` 제거), 그리고 이후 겪은 함정 3건 추가(`cacheTTL`, `Discovered hosts` 권한,
> `allValue` 유출). 나머지 본문은 손대지 않았습니다.
