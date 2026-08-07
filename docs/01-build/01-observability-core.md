# 관측 코어 구축 — Zabbix + MariaDB + Grafana + Loki

운영 환경 미러링 랩의 관측 계층 코어를 Docker Compose 기반으로 구축하는 가이드입니다. `docker-compose.yml` 내 각 설정 항목의 기술적 근거, 실행 절차 및 검증 항목을 명시합니다.

본 문서에 명시된 IP 주소는 예시용 플레이스홀더이며, 상세 사양은 [`hosts.md`](hosts.md)를 참조합니다. 관련 코드는 `lab/` 디렉토리에 위치합니다.

---

## 0. 환경 및 구축 목적

* **구성 요소:** Zabbix 7.0 (메트릭) + MariaDB 10.11 (DB) + Grafana 11.6.16 (시각화) + Loki 3.4.0 (로그)
* **배포 환경:** IXcloud 단일 VM 인스턴스 (Docker 컨테이너 방식)
* **네트워크 구성:** 사설 IP 및 공인 IP 1개를 함께 할당
  * **사설 IP:** Wazuh 6노드 클러스터와 동일 사설망에 배치하여, Grafana가 Wazuh Indexer(node-1 `192.0.2.5:9200`)에 직접 연동하기 위한 경로를 확보합니다.
  * **공인 IP:** Zabbix Web(8080) 및 Grafana(3000) 대시보드 브라우저 접근 용도로 사용합니다. Wazuh 랩의 "대시보드 한정 공인 노출" 원칙에 따라, 보안 그룹에서 22·8080·3000 포트를 작업자 IP(Source /32)로 제한 개방하고 나머지 공인 포트는 차단합니다.
* **사설망 연동 이유:** 로컬 PC 환경은 사설망 직접 접근이 불가하여 Wazuh 연동이 구성되지 않으므로, 관측 코어를 사설망 내 VM에 배치합니다.
* **Docker 채택 이유:** 단일 호스트 인프라 환경에서 관측 레이어 재현성 확보 및 환경 격리를 용이하게 검증하기 위함입니다.

---

## 1. 사전 인프라 준비

### 1-1. Docker 및 Compose 플러그인 설치 (Rocky Linux 9 기준)

```bash
sudo dnf -y install git dnf-plugins-core
sudo dnf config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
# [트러블슈팅] Rocky 9 환경에서 $releasever가 "9.0"으로 확장되어 Docker repo 404가 발생하는 현상 방지
# repo 파일의 $releasever를 major 버전(9)으로 고정
sudo sed -i 's/\$releasever/9/g' /etc/yum.repos.d/docker-ce.repo
sudo dnf -y install docker-ce docker-ce-cli containerd.io docker-compose-plugin
sudo systemctl enable --now docker
sudo usermod -aG docker $USER
# 로그아웃 후 재접속하여 권한 적용 확인
docker compose version
```

### 1-2. 네트워크 보안 그룹 설정

* **`8080/TCP` (Zabbix Web) / `3000/TCP` (Grafana):** 작업자 IP(Source /32) 한정 허용
* **`10051/TCP` (Zabbix Trapper):** 사설망 대역 내 에이전트 통신 허용
* **`3100/TCP` (Loki):** 내부 컨테이너 간 통신 전용 (외부 노출 차단)

---

## 2. 컴포넌트별 설정 상세 및 기술 근거

### 2-1. MariaDB (`mariadb:10.11`)

* **버전 선정:** Zabbix 7.0 공식 지원 사양인 MariaDB 10.5.00 ~ 12.3.X 범주 내에서 검증된 LTS 버전인 10.11을 채택했습니다.
* **주요 Command 파라미터:**
  * `--character-set-server=utf8mb4` / `--collation-server=utf8mb4_bin`: Zabbix 7.0의 필수 문자셋 및 콜레이션 사양 준수
  * `--log_bin_trust_function_creators=1`: 초기 DB 스키마 임포트 시 저장 함수(Stored Function) 생성 권한 오류 방지
  * *(MySQL 전용 옵션인 `--skip-mysqlx`는 MariaDB 호환성을 고려하여 제외)*
* **단일 노드 구성 사유:** 초기 코어 기동 검증을 위해 단일 노드로 시작하며, HA 주/부 복제 옵션(`--log-bin`, `--server-id`)은 DB 이중화 및 장애 진단 단계에서 추가 적용합니다 (§9 참조).
* **Healthcheck:** MariaDB 공식 헬스체크 유틸리티(`healthcheck.sh --connect --innodb_initialized`)를 적용하여 Zabbix Server의 기동 순서를 제어합니다.

### 2-2. Zabbix Server 및 Web (`alpine-7.0.27`)

* **이미지 태그:** 운영 환경 버전과의 정합성을 위해 `alpine-7.0.27` 태그로 고정합니다.
* **주요 환경 변수:**
  * **Server:** `DB_SERVER_HOST`, `MYSQL_DATABASE`, `MYSQL_USER`, `MYSQL_PASSWORD`, `MYSQL_ROOT_PASSWORD` (초기 스키마 생성 권한 확보용)
  * **Web:** `ZBX_SERVER_HOST`, `DB_SERVER_HOST`, `MYSQL_DATABASE`, `MYSQL_USER`, `MYSQL_PASSWORD`, `PHP_TZ` (보안을 위해 root 계정 미부여)
* **의존성 정의 (`depends_on`):** `mariadb` 컨테이너의 `service_healthy` 상태 확인 후 Server 데몬이 기동되도록 설정하여 DB 연결 실패 반복 현상을 차단합니다.

### 2-3. Grafana (`grafana:11.6.16`)

* **플러그인 프로비저닝:** `GF_INSTALL_PLUGINS=alexanderzobnin-zabbix-app` 환경변수를 전달하여 Zabbix 공식 연동 모듈을 자동 설치합니다.
* **버전 호환성 요구사항:** 자동 설치되는 Zabbix 플러그인 최신 버전(v6.x)은 **Grafana 11.6.0 이상**을 요구합니다 (플러그인 v6.0.0 Changelog 기준). Grafana 11.2.0 구성 시 데이터소스 추가 화면에서 React error #130(컴포넌트 렌더 실패)이 발생함에 따라 안정 버전인 11.6.16으로 상향 조정했습니다.
* **IaC 구성:** 데이터소스 매핑을 GUI 수동 작업 대신 `grafana/provisioning/datasources/datasources.yml` 코드로 관리하여 재현성을 보장합니다.

### 2-4. Loki (`loki:3.4.0`)

* **아키텍처:** 단일 프로세스(Monolithic) 방식, 파일시스템 스토리지 및 최신 스키마(`tsdb`, `v13`)를 적용합니다.
* **커스텀 설정 변경 사항:**
  1. `path_prefix`: Docker 볼륨 영속성 처리를 위해 `/tmp/loki`에서 `/loki`로 변경
  2. `reject_old_samples: false`: 장애 시뮬레이션 및 과거 타임스탬프 로그 재현 시 데이터 수용 목적
* **보존 정책:** Deprecated된 `table_manager`를 배제하고 최신 Retention 스펙을 적용합니다.

---

## 3. 서비스 실행

```bash
cd lab
cp .env.example .env
# .env 파일을 편집하여 랩 전용 임의 비밀번호 설정

# 이미지 다운로드 및 컨테이너 백그라운드 기동
docker compose pull
docker compose up -d

# 기동 상태 및 로그 확인
docker compose ps
docker compose logs -f zabbix-server
```

*(최초 기동 시 MariaDB 스키마 자동 생성 작업으로 약 1~2분이 소요됩니다. 로그상에서 `server #0 started` 문구를 확인합니다.)*

---

## 4. 접속 정보 및 데이터소스 연동

| 서비스 | 접속 URL | 초기 계정 정보 |
| --- | --- | --- |
| **Zabbix Web** | `http://<VM_IP>:8080` | `Admin` / `zabbix` (로그인 후 즉시 변경) |
| **Grafana** | `http://<VM_IP>:3000` | `admin` / `.env` 내 `GRAFANA_ADMIN_PASSWORD` |

### 4-1. 데이터소스 프로비저닝 (코드 관리)

데이터소스는 `grafana/provisioning/datasources/datasources.yml`을 통해 자동 등록됩니다. 크리덴셜 정보는 파일 내에 직접 명시하지 않고 **환경변수 치환 방식**을 사용합니다. Grafana 프로비저닝은 `$VAR` / `${VAR}` 문법으로 컨테이너 환경변수를 읽어오며, 각 변수는 Compose의 Grafana 서비스가 `.env` 파일에서 주입받습니다.

| 데이터소스 | type | 필요 환경변수 | 비고 |
| --- | --- | --- | --- |
| Loki | `loki` | 없음 | 별도 인증 없이 동작 |
| Zabbix | `alexanderzobnin-zabbix-datasource` | `ZBX_GRAFANA_USER`, `ZBX_GRAFANA_PASSWORD` | Zabbix UI 내 읽기 전용 계정 생성 선행 필요. URL은 `api_jsonrpc.php`로 고정 |
| Wazuh | `grafana-opensearch-datasource` | `WAZUH_INDEXER_URL`, `WAZUH_INDEXER_USER`, `WAZUH_INDEXER_PASSWORD` | 사설망 바인딩 VM에서만 유효. 자체서명 인증서 사용으로 `tlsSkipVerify: true` 설정 |
| Wazuh-States | `grafana-opensearch-datasource` | 상동 | 취약점 재고 관리 전용 (스냅샷 인덱스, [`../02-design/README.md`](../02-design/README.md) 참조) |

**절차:**

1. Zabbix Web(`:8080`) 접속 → 읽기 전용 계정(예: `grafana-ro`) 생성
2. `.env` 파일에 관련 환경변수 기입 (`.env.example` 참조)
3. Grafana 컨테이너 재생성 (볼륨을 재사용하면 환경변수 갱신이 스킵되므로 강제 재생성):
   ```bash
   docker compose up -d --force-recreate grafana
   ```
4. 검증: Grafana → Connections → Data sources 항목에서 등록 확인 및 각 데이터소스 "Test" 통과 여부 확인

> **주의 사항 (특수문자 이스케이프):** 비밀번호에 `$` 문자가 포함될 경우 프로비저닝 과정에서 변수로 오인될 수 있습니다. 비밀번호 내 `$` 사용을 지양하거나 `$$`로 이스케이프 처리합니다.

> **`cacheTTL` 설정 주의:** Zabbix 데이터소스의 조회 캐시 기본값은 1시간입니다. 기본값을 유지할 경우 데이터 갱신이 반영되지 않아 **패널이 정지된 것처럼 보일 수 있습니다.** 랩 환경에서는 1분으로 단축 설정하여 운영합니다.

### 4-2. 대시보드 프로비저닝

`grafana/provisioning/dashboards/dashboards.yml` 프로비저닝 설정에 따라 `.../dashboards/json/` 폴더 내의 모든 `*.json` 파일이 Grafana의 `KINX` 폴더로 자동 로드됩니다. `allowUiUpdates: true` 옵션이 적용되어 UI상에서의 수정도 허용됩니다.

**권장 작업 워크플로:** UI에서 패널 구성 → Dashboard settings → JSON Model 또는 Export를 통해 JSON 데이터 확보 → `json/` 폴더에 커밋 및 관리. 데이터소스 참조 시 파일명이 아닌 **UID**(`loki`/`zabbix`/`wazuh`) 기준을 사용해야 환경 이관 시 깨짐 현상을 방지할 수 있습니다.

**제공 대시보드 목록:**

| 대시보드 | 데이터소스 | 용도 |
| --- | --- | --- |
| `kinx-overview` | Zabbix + Loki + Wazuh | 메트릭·로그·보안 통합 타임라인 (데모 A) |
| `kinx-msp` / `kinx-msp-os` | Zabbix | MSP 고객사별 통합 뷰 (DB형 / OS형) |
| `kinx-msp-report` | Zabbix + Wazuh + Loki | MSP 월간 리포트 (출력 렌더링 대상) |
| `kinx-replication` | Zabbix | DB 복제 품질 관측 — 단순 상태(1/0)가 아닌 지연 시간(초) 기준 |
| `kinx-certificates` | Zabbix | SSL/TLS 인증서 만료 예정 현황 관리 |
| `kinx-noise` | Zabbix | 알림 노이즈 현황 (최적화 전/후 비교) |

---

## 5. 최종 검증 체크리스트

* [ ] `docker compose ps` 실행 시 `mariadb` 상태가 `healthy`이고 타 서비스가 `running` 상태인가?
* [ ] `docker compose logs zabbix-server` 로그에 `server #0 started` 구문이 정상 출력되는가?
* [ ] Zabbix Web (`:8080`) 접속 및 System information 페이지가 정상 표시되는가?
* [ ] Grafana (`:3000`) Connections → Data sources 메뉴에 Loki·Zabbix·Wazuh가 등록되어 있는가?
* [ ] Grafana 대시보드 폴더 `KINX`에 정의된 대시보드가 정상 로드되어 있는가?
* [ ] (에이전트 배포 완료 후) Zabbix 수집 데이터가 시계열 그래프로 정상 렌더링되는가?

---

## 6. 주요 장애 패턴 및 트러블슈팅

* **Zabbix Server 컨테이너 재시작 반복 (`CrashLoopBackOff`):**
  * DB 미준비 또는 인증 실패가 원인일 수 있습니다. `docker compose logs mariadb`로 DB 헬스 상태를 점검하고, `.env` 파일 내 `MYSQL_USER/PASSWORD` 설정의 일치 여부를 확인합니다.
* **Zabbix Web에 "Database error" 메시지 출력:**
  * DB 초기 스키마 임포트가 진행 중인 상태입니다. `zabbix-server` 컨테이너 로그를 확인하여 스키마 생성이 완료될 때까지 대기합니다.
* **Grafana Zabbix 플러그인 인식 불가:**
  * 기존 볼륨 재사용 시 환경변수 적용이 스킵될 수 있습니다. `docker compose up -d --force-recreate grafana` 명령을 실행하여 컨테이너를 재생성합니다.
* **Zabbix 데이터소스 API 연결 실패:**
  * URL 끝의 `/api_jsonrpc.php` 경로 누락 여부 및 Grafana 컨테이너 내부에서의 `zabbix-web` DNS 해석 상태를 점검합니다.
* **Zabbix 데이터소스 추가 시 React error #130 (컴포넌트 렌더 실패) 발생:**
  * 자동 설치되는 Zabbix 플러그인 최신 버전(v6.x)이 요구하는 Grafana 최소 버전(11.6.0)보다 설치된 버전이 낮을 때 발생합니다. Grafana 이미지를 11.6.16으로 상향 조정한 후 재생성합니다.
* **대시보드 전체 패널에 "No data" 표기:**
  * 자동 등록된 호스트는 `Discovered hosts` 그룹에 할당됩니다. **Grafana 조회 계정에 해당 호스트 그룹의 읽기 권한이 없으면 전 패널에 No data가 발생**합니다. (Zabbix → User groups → Host permissions 권한 설정 점검)
* **사전 환경 준비 중 패키지 오류:**
  * `git: command not found` 발생 시 `sudo dnf -y install git` 실행. Docker repo 404 발생 시 §1-1 절차에 따라 `sed` 명령으로 `$releasever`를 9로 고정합니다.

---

## 7. 프로파일(Profile) 확장 구조

기본 관측 코어 기동 후, 필요에 따라 Profile 옵션을 부여하여 세부 기능을 선택적으로 추가 기동합니다.

| Profile | 구성 컴포넌트 |
| --- | --- |
| **(기본)** | mariadb, zabbix-server, zabbix-web, zabbix-web-service, grafana, grafana-image-renderer, mailpit, loki |
| **`ha`** | `mariadb-slave` (`server-id=2`, Master-Slave 복제 구성), zabbix-agent2 |
| **`chaos`** | `snmpsim` (인터페이스 에러 카운터 시뮬레이션) |
| **`msp`** | 고객사 멀티테넌트 컨테이너 세트 (Web + DB Master/Slave + Agent) |

```bash
# 예시: Chaos 프로파일을 포함한 선택적 기동
docker compose --profile chaos up -d
```

*참고: 실제 감시 대상 VM에 에이전트(zabbix-agent2·Alloy·wazuh-agent)를 배포하는 작업은 Compose가 아닌 **Ansible 플레이북**으로 수행합니다 ([`ansible/DEPLOY_GUIDE.md`](../../ansible/DEPLOY_GUIDE.md) 참조).*

---

## 8. MariaDB Master-Slave 복제 구성 (`--profile ha`)

### 8-1. 구성 목적 및 방식

운영 환경 Zabbix DB의 Master-Slave 구성을 미러링하여 **"DB 이중화 페어 중 단일 노드만 감시되는" 장애 상황을 진단/시연**하기 위한 복제 계층입니다. 복제 방식은 MariaDB 공식 권장 사항인 **GTID (`MASTER_USE_GTID=slave_pos`)** 방식을 채택하여 바이너리 로그 위치 수동 추적에 따른 오류를 방지합니다.

### 8-2. 마스터 설정 (Compose 상시 적용)

기존 관측 코어의 `mariadb` 서비스 Command에 복제 마스터 옵션 4종을 적용했습니다.

| 적용 옵션 | 설정 이유 및 근거 |
| --- | --- |
| `--server-id=1` | 복제 토폴로지 내 마스터 노드 고유 ID 지정 (Slave는 2 지정) |
| `--log-bin` | 바이너리 로그 활성화 (복제 구성 필수 전제조건) |
| `--log-basename=mariadb-master` | 바이너리 로그 파일명을 호스트명과 분리하여 컨테이너 재생성 시 명칭 변경 방지 |
| `--binlog-format=mixed` | MariaDB 공식 권장 기본 로그 포맷 적용 |

*주의: 기존에 복제 옵션 없이 코어를 기동한 상태에서 `docker compose up -d` 실행 시 Command 변경으로 인해 `mariadb` 컨테이너가 재생성됩니다. 데이터 볼륨(`mariadb_data`)은 유지되므로 데이터 손실은 발생하지 않습니다.*

### 8-3. 슬레이브 서비스 (`mariadb-slave`, profile: ha)

`--server-id=2`, `--log-basename=mariadb-slave`, `--read-only=1` (슬레이브 읽기 전용 고정) 옵션을 적용하며 별도 데이터 볼륨(`mariadb_slave_data`)을 참조합니다. 복제 부트스트랩은 자동 초기화 대신 **`setup-slave.sh` 스크립트를 직접 실행**하는 방식을 사용합니다.

### 8-4. 실행 절차

```bash
cd lab
# .env 파일 내 REPLICATION_USER / REPLICATION_PASSWORD 설정 확인 (.env.example 참조)

# 마스터 및 슬레이브 컨테이너 기동
docker compose --profile ha up -d

# 컨테이너 헬스 상태 확인
docker compose ps

# 복제 부트스트랩 실행 (계정 생성 → 덤프 스냅샷 생성 → 슬레이브 복원 → CHANGE MASTER → START SLAVE → 검증)
./mariadb/setup-slave.sh
```

정상 처리 시 `[OK] 복제 정상 (IO=Yes, SQL=Yes)` 문구가 출력됩니다. `setup-slave.sh` 스크립트는 멱등성을 보장하도록 작성되어 있습니다.

*(별도 VM 인스턴스에 슬레이브를 세우는 구성은 [`lab/mariadb/REPL_VM_GUIDE.md`](../../lab/mariadb/REPL_VM_GUIDE.md) 참조)*

### 8-5. 정상 동작 검증

* `Slave_IO_Running: Yes` 및 `Slave_SQL_Running: Yes` 상태 확인 (두 항목 모두 Yes여야 정상)
* `Seconds_Behind_Master: 0` (복제 지연 시간 확인)
* 마스터 노드 데이터 변경 후 슬레이브 노드 동기화 확인:
  ```bash
  docker compose exec -T -e MYSQL_PWD=<root암호> mariadb \
    mariadb -uroot -e "CREATE TABLE zabbix.repl_test(id int); INSERT INTO zabbix.repl_test VALUES(1);"
  docker compose exec -T -e MYSQL_PWD=<root암호> mariadb-slave \
    mariadb -uroot -e "SELECT * FROM zabbix.repl_test;"   # 1 값이 정상 조회되면 복제 완료
  ```

### 8-6. 트러블슈팅

* **`Slave_IO_Running: Connecting` 상태 지속:**
  * 마스터 노드 접속 실패 상태입니다. 복제 계정(`REPLICATION_USER`) 존재 여부, 권한(`REPLICATION SLAVE`), `.env` 비밀번호 일치 여부, `lab_net` 네트워크 내 `mariadb` DNS 해석 상태 및 마스터 노드의 `--log-bin` 활성화 여부를 점검합니다.
* **`Slave_SQL_Running: No` 오류 발생:**
  * 스냅샷 시점과 GTID 불일치가 원인입니다. `setup-slave.sh`를 재실행하면 `RESET SLAVE` 처리 후 스냅샷 단계를 재구성합니다.
* **`--read-only` 설정 상태에서의 복제 동작 여부:**
  * `read_only` 옵션은 일반 사용자 계정의 Write 작업만 제한하며, 복제 SQL 스레드의 데이터 동기화 동작에는 영향을 주지 않습니다.

---

## 9. Grafana Correlation 및 대시보드 드릴다운 구성

Wazuh 보안 이벤트에서 동일 호스트의 Loki 로그로 이동하는 드릴다운을 두 가지 경로로 구성했습니다.

### 9-1. Correlation (Explore 전용) — `datasources.yml` 프로비저닝

* **역할:** Explore 메뉴에서 Wazuh 쿼리 결과의 `agent.name` 필드를 클릭하면 우측에 Loki 분할 뷰가 생성되며 해당 호스트의 로그 쿼리가 자동 실행됩니다. (대시보드 패널이 아닌 Explore 자유 탐색용 기능)
* **Grafana 11.6.16 Correlation 프로비저닝 제약 사항:**
  검증 로직 특성상 형식을 정확히 맞추지 않을 경우 **데이터소스 프로비저닝 전체가 중단**되고 Grafana 기동에 실패합니다. 소스 코드(`pkg/services/provisioning/datasources/datasources.go`) 기준 검증 조건은 다음과 같습니다:
  * **Root 레벨 `type` 명시 시 패닉 발생:** `correlation["type"]`을 `CorrelationType`으로 타입 단언하는 과정에서 패닉이 발생하므로 **Root 레벨의 `type` 필드는 반드시 생략**해야 합니다 (생략 시 기본값 `query`로 동작).
  * **`config.type` 생략 시 검증 에러:** `config.Type` 검증 단계에서 에러(`ErrInvalidConfigType`)가 발생하므로 **`config.type: query`를 명시적으로 기재**해야 합니다.
* **정상 적용 예시 (`datasources.yml` Wazuh 데이터소스 하위 블록):**
  ```yaml
  correlations:
    - targetUID: loki
      label: "보안 이벤트 → 해당 호스트 로그"
      description: ""
      config:
        type: query            # 필수: 생략 시 ErrInvalidConfigType 발생
        field: agent.name
        target:
          editorMode: code
          expr: '{host="$${__value.raw}"}'   # $$ 처리를 통해 프로비저닝 환경변수 치환 회피
          queryType: range
  ```
* **검증:** `docker compose restart grafana` 실행 후 로그에 `panic` 또는 `Failed to provision data sources` 에러가 없고 정상 기동되면 완료됩니다. (UI의 `/correlations` 경로에서 프로비저닝 항목 확인 가능)

### 9-2. Data Link (대시보드 전용) — `kinx-overview.json`

* **역할:** 대시보드 패널 간 정의된 경로로 이동하는 드릴다운 기능입니다.
* **구성요소 3가지:**
  1. **대시보드 변수 `$host`:** `Query` 타입, Loki 데이터소스, `Label values` → `host`, Include All (`allValue: .+`) 설정
  2. **Wazuh Table 패널:** 쿼리 `rule.level:>=10`, Metric 항목을 **`Raw Data`**로 설정하여 개별 이벤트 문서가 행 단위로 표기되도록 설정 (`agent.name` 컬럼 포함)
  3. **`agent.name` 필드 Override → Data links:** URL 경로 `/d/kinx-overview?var-host=${__value.raw}` 설정 (동일 대시보드를 해당 호스트 조건으로 재호출). Loki 로그 패널 쿼리를 `{host=~"$host"}`로 연결하여 클릭 시 해당 호스트 로그로 필터링되도록 구성
* **전제 조건 (호스트 식별자 정규화):** Wazuh의 `agent.name`(= `vm-target-001.novalocal`)과 Loki의 `host` 라벨 값이 동일해야 정상 매칭됩니다. Alloy 설정의 `host` 라벨을 FQDN(`hostname -f`) 사양으로 표준화하여 정규화를 적용했습니다 ([`hosts.md`](hosts.md) 참조).

> **`allValue` 설정 주의:** 테넌트가 분리된 대시보드에서 `allValue: ".+"` 설정 사용 시 "전체" 조건 선택 시 **타 고객사 데이터까지 조회 범위에 포함**될 수 있으므로 권한 분리 설계 시 주의가 필요합니다.

### 9-3. 운영 시 유의 사항

* **`$host` 드롭다운의 기존 라벨 잔재:** Alloy `host` 라벨을 FQDN 표준화로 변경하기 이전에 수집된 Loki 스트림 정보가 남아있어 `label_values(host)` 조회 시 기존 명칭과 FQDN이 함께 반환될 수 있습니다. 해당 현상은 Loki 데이터 보존 기간이 지나면 자동 소멸되며, Wazuh `agent.name`은 FQDN 기준이므로 드릴다운은 정상 동작합니다.
* **드릴다운 시각적 검증:** 드릴다운 동작을 명확히 확인하려면 로그를 전송하는 감시 대상 호스트가 2대 이상 구성되어 있어야 합니다.

---

## 10. 참고 공식 문서

* [Zabbix 7.0 Database Requirements](https://www.zabbix.com/documentation/7.0/en/manual/installation/requirements)
* [Zabbix Official Container Installation Guide](https://www.zabbix.com/documentation/7.0/en/manual/installation/containers)
* [Zabbix Official Docker Repository (7.0 Branch)](https://github.com/zabbix/zabbix-docker)
* [Grafana Zabbix Plugin Documentation](https://grafana.com/grafana/plugins/alexanderzobnin-zabbix-app/)
* [Grafana Loki Docker Setup Guide](https://grafana.com/docs/loki/latest/setup/install/docker/)
* [MariaDB Setting up Replication (GTID)](https://mariadb.com/kb/en/setting-up-replication/)

---

*문서 개정 이력: 본 문서는 초기 구축 가이드를 기반으로 IP 플레이스홀더 적용 및 최신 시스템 상태(대시보드 7종 확장, Profile 구성 최적화, `cacheTTL` / 권한 / `allValue` 등 운영 트러블슈팅 사례 반영)를 업데이트하여 정제한 문서입니다.*