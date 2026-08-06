# 데모 실행 런북 — 어디서 무엇을 치는가

리허설과 라이브 시연용. **네 시나리오(복제 지연 · SSH 브루트포스 · 자가 치유 · 브루트포스+설정
변경)를 처음부터 끝까지 돌리는 데 필요한 명령만** 순서대로 적었다. 각 스크립트가 무엇을 왜
하는지는 `chaos/README.md`, 배선 원리는 `bot/GATEWAY_GUIDE.md`·`keep/KEEP_GUIDE.md`.

호스트 이름·주소·리포 위치는 **[`docs/01-build/hosts.md`](../01-build/hosts.md)** 에 있다.
이 문서의 IP는 전부 예시 주소이므로 실행 전에 그 문서를 먼저 본다.

---

## 1. 공통 사전 준비 — 모든 시나리오가 이걸 먼저 한다

### 1-1. 관측 코어 기동

```bash
ssh core
cd ~/kinx-idc-monitoring-poc/lab
docker compose up -d
docker compose ps
```

`mariadb`가 `healthy`가 된 뒤 `zabbix-server` → `zabbix-web` 순으로 올라온다. 서버가 떴는지는
로그로 확인한다.

```bash
docker compose logs --tail=20 zabbix-server | grep "server #0 started"
```

### 1-2. 게이트웨이(봇) 기동

**봇이 안 떠 있으면 알림이 Slack에도 Keep에도 안 간다.** 모든 시나리오가 이게 전제다.

먼저 **떠 있는 것부터 죽인다.** 옛 프로세스가 살아 있으면 `.env`를 고쳐도 안 먹고, `healthz`는
멀쩡히 `ok`를 돌려주기 때문에 속기 쉽다.

```bash
ssh core
ps -ef | grep uvicorn | grep -v grep
kill <위에서 나온 PID>
sleep 1; ps -ef | grep uvicorn | grep -v grep      # 아무것도 안 나와야 한다
```

새로 띄운다.

```bash
cd ~/kinx-idc-monitoring-poc/bot
set -a; source .env; set +a
nohup python -m uvicorn gateway.app:app --host 0.0.0.0 --port 8800 > /tmp/gw.log 2>&1 &
sleep 5 && cat /tmp/gw.log
```

`Application startup complete`와 `Uvicorn running on http://0.0.0.0:8800`이 보여야 한다.
`address already in use`가 나오면 앞의 kill이 안 된 것이다.

로그에 `nohup: ignoring input` 한 줄만 있으면 **아직 기동 중이거나 죽은 것**이다. 프로세스가
살아 있는지부터 본다 — `ps -ef | grep uvicorn | grep -v grep`. 프로세스가 없으면 백그라운드를
빼고 앞에서 띄워 에러를 직접 본다.

venv를 먼저 활성화해야 한다(`source ~/bot-venv/bin/activate`). 안 하면 `uvicorn` 모듈을
못 찾고 죽는데, 그 에러가 로그에만 남아서 눈에 안 띈다.

**`--workers`를 붙이지 않는다.** 워커마다 인시던트 버퍼가 따로 생겨서 부모 카드가 여러 개 뜬다.

동작 확인:

```bash
curl http://localhost:8800/healthz
```

환경변수 전체 목록과 각 변수가 없을 때 무엇이 열화되는지는 [`bot/.env.example`](../../bot/.env.example).

### 1-3. Keep 확인 (자가 치유 시나리오에서만 필요)

워크플로 파일은 **Keep을 재시작할 때만** 읽는다. 리포에서 워크플로를 고쳤으면 반드시 재시작한다.

```bash
ssh keep
cd ~/kinx-idc-monitoring-poc
git pull
docker compose restart keep-backend
```

브라우저에서 `keep:3000` → Workflows에 `Remediate service via Ansible`이 보이면 된다.

### 1-4. 시연 당일 추가 점검

```bash
ssh core
cd ~/kinx-idc-monitoring-poc/bot && python -m gateway.selftest
```

그리고 **Anthropic 크레딧 잔액을 확인한다.** 소진된 상태로 시연에 들어가 월간 분석이 실패한
적이 있다. 크레딧이 없으면 봇은 규칙 판정만 회신하는 열화 모드로 돌고, 하이라이트 데모가 죽는다.

---

## 2. 시나리오 A — 복제 지연 (데모 C, 하이라이트)

**보여 주려는 것.** 알림 2건이 서로 다른 트리거에서 따로 올라오는데, 봇이 그것을 **한 사건으로
묶고** "복제가 고장 난 게 아니라 백업 부하가 I/O를 먹어서 밀린 것"이라고 재프레이밍하는 것.

**실행 위치는 슬레이브 VM이다.** 부하를 그 디스크에 걸어야 하기 때문이다.

### 2-1. 주입

**node2에는 리포가 없다.** 이 VM은 복제 슬레이브로만 세웠고 클론한 적이 없다. 스크립트를
먼저 올린다 — **작업자 PC에서**:

```bash
scp chaos/repl_lag_contention.sh node2:~/
```

그리고 node2에서 실행한다.

```bash
ssh node2
export MASTER_HOST=192.0.2.26          # core 사설 IP (hosts.local.md 참조)
export DEMO_REPL_DB=demo_repl
export DEMO_WRITER_USER=demowriter
read -rs -p "writer pw: " DEMO_WRITER_PASSWORD && export DEMO_WRITER_PASSWORD
DURATION=420 bash ~/repl_lag_contention.sh
```

**비밀번호를 문서에도, 명령 이력에도 남기지 않는다.** 위처럼 `read -s`로 받는다.

`DURATION`은 초. **420초(7분) 이상으로 준다.** MySQL 복제 트리거가 `min(lag,5m)>임계`라
**5분을 버텨야 발화한다.** 180초로 주면 지연은 오르는데 알림이 안 뜬다.

스크립트는 세 가지를 동시에 한다 — 디스크 I/O 포화(백업성 대용량 쓰기), 로컬 덤프 반복,
master 쪽 쓰기. 그리고 `logger`로 syslog에 백업 마커를 남겨 Loki 쪽 교차 신호를 만든다.

### 2-2. 확인 순서

| 순서 | 어디서 | 무엇을 |
|---|---|---|
| 1 | Grafana `core:3000` | 복제 지연 패널이 0에서 단조 증가. CPU·Load도 같이 오른다 |
| 2 | Zabbix `core:8080` → Monitoring → Problems | 같은 호스트에 High 2건 — 복제 지연 / Load average |
| 3 | Slack | 봇 카드에 **"2건이 1개 사건"** 판정과 인과 설명 |
| 4 | Keep `keep:3000` | 같은 사건이 한 행으로 쌓인 것 |

**3번이 나오기까지 걸리는 시간이 재는 값이다.** 다만 재는 기준은 첫 알림이 아니라
**사건 확정(병합 창 마감) 이후 30초**다. 병합 창은 마지막 알림 뒤 90초 무알림이거나 최대
300초에서 닫힌다.

### 2-3. 되돌리기

스크립트가 `trap`으로 자기 정리를 한다(임시 파일 삭제, 백그라운드 작업 종료). 끝나면 지연이
자동으로 0으로 수렴한다. 중간에 끊고 싶으면 `Ctrl+C` — 그래도 정리는 돈다.

지연이 안 내려가면 슬레이브에서 확인한다.

```bash
ssh node2 "sudo mariadb -e 'SHOW SLAVE STATUS\G'" | grep -E "Seconds_Behind|Running"
```

`Slave_IO_Running`·`Slave_SQL_Running`이 둘 다 `Yes`여야 한다. 하나라도 `No`면 복제가 실제로
끊긴 것이라 시나리오가 달라진다(그건 데모 C의 소재가 아니다).

시나리오의 설계 의도·심사 반문 대비는 [`scenario-c-replication.md`](scenario-c-replication.md).

---

## 3. 시나리오 B — SSH 브루트포스 (데모 A 보안 축)

**보여 주려는 것.** 같은 시각·같은 호스트에서 지표·로그·보안 세 축이 동시에 반응하는 것.
Wazuh가 연속 실패를 상관해 **레벨 10으로 격상**하는 지점이 핵심이다.

**실행 위치는 대상과 같은 사설망 안**이어야 한다. 외부에서 들어오는 접근을 흉내 내는 것이라
core에서 node1을 때리는 형태로 돈다.

### 3-1. 주입

```bash
ssh core
cd ~/kinx-idc-monitoring-poc/chaos
./ssh_bruteforce.sh 192.0.2.10 12 badguy      # 대상 = node1 사설 IP
```

인자는 `<대상 IP> [횟수=12] [계정=badguy]`. **횟수를 12로 두는 이유**는 Wazuh가 120초 안에
8회를 넘겨야 룰 5710(레벨 5)을 5712(레벨 10)로 올리기 때문이다. 8회 아래로 줄이면 레벨 10이
안 뜬다.

없는 계정으로 붙기 때문에 실제로 뚫리지 않는다. `BatchMode=yes`라 비밀번호를 묻지 않고 바로
실패한다.

### 3-2. 확인 순서

| 순서 | 어디서 | 무엇을 |
|---|---|---|
| 1 | Wazuh `dashboard` → Threat Hunting | `rule.id:5712` 검색 → 레벨 10 이벤트 |
| 2 | Grafana `core:3000` 통합 관제 | 보안 패널 스파이크 + Loki에 `invalid user badguy` 같은 시간축 |
| 3 | Grafana 보안 패널 행 클릭 | `agent.name`이 `$host`로 넘어가 Loki 로그가 그 호스트로 좁혀지는 드릴다운 |

**2번이 데모 A의 핵심 장면이다.** 세 축이 같은 타임라인·같은 호스트에 찍힌다.

### 3-3. 되돌리기

**되돌릴 것이 없다.** 로그인에 실패했을 뿐이라 대상 서버 상태가 변하지 않는다. 이벤트는
Wazuh에 남는데, 그건 남아 있어야 정상이다.

리허설을 여러 번 돌리면 이벤트가 겹쳐 화면이 지저분해진다. Wazuh 대시보드의 시간 범위를
`Last 15 minutes`로 좁히면 방금 것만 보인다.

---

## 4. 시나리오 C — 자가 치유 (데모 B)

**보여 주려는 것.** 서비스가 죽고 → 봇이 조치 후보로 분류해 승인 큐에 올리고 → **사람이 버튼을
한 번 누르면** → Ansible이 재기동하고 스스로 재검증하는 것. 사람 개입은 Run 버튼 1회다.

**실행 위치는 작업자 PC다.** 스크립트가 SSH 별칭으로 대상에 붙는데, 그 별칭은 작업자 PC에만
있다. core에서 돌리면 `Could not resolve hostname`이 난다.

### 4-1. 주입

작업자 PC의 리포 디렉토리에서, **Git Bash**로:

```bash
cd <리포>/chaos
./service_down.sh vm-target-002 chronyd
```

인자는 `<ssh 대상> [서비스=chronyd]`. `chronyd`를 기본값으로 둔 이유는 랩에 항상 있고
정지해도 서비스 영향이 없어 반복 시연이 안전하기 때문이다.

스크립트가 먼저 SSH 연결을 확인하고, 안 붙으면 이름과 실행 위치를 안내하고 멈춘다.

### 4-2. 확인 순서

| 순서 | 어디서 | 무엇을 |
|---|---|---|
| 1 | Zabbix `core:8080` → Problems | 서비스 트리거 발화 (폴링 주기만큼 기다린다) |
| 2 | Keep `keep:3000` | 알림에 **조치 후보** 표시 — Severity와 `Service=chronyd` 태그 |
| 3 | Keep 알림 상세 → **Run Workflow** | `Remediate service via Ansible` 선택 = **승인** |
| 4 | 워크플로 실행 결과 | `run-ansible-remediation ran successfully`, PLAY RECAP에 `changed=1` |
| 5 | 같은 출력 | `before: inactive -> after: active` |

**3번이 HITL 승인이다.** 워크플로가 `manual` 트리거라 알림이 떠도 자동으로 실행되지 않는다.
사람이 누를 때까지 아무 일도 안 일어난다.

**안전 게이트가 걸려 있다.** 워크플로 첫 줄이 `alert.playbook == 'service_restart'`를
확인하므로, 다른 알림에서 실수로 Run을 눌러도 아무 일도 일어나지 않는다. 계약상 조치가 금지된
대상이면 `scope=notify_only` 태그가 조치 경로 자체를 막는다.

### 4-3. 전제 — 태그가 없으면 조치 경로를 안 탄다

트리거에 **`automate=service_restart`**와 **`service=chronyd`** 태그가 붙어 있어야 조치 후보가
된다. 태그가 없으면 그냥 일반 트리아지로 흘러 Slack 분석만 나가고 Keep 승인 큐에는 안 올라온다.

Zabbix에서 트리거 → Tags 탭에서 확인한다.

### 4-4. 되돌리기 · 다시 하기

승인까지 돌렸으면 **Ansible이 이미 살려 놨다.** 따로 할 게 없다.

리허설을 다시 하려면 다시 죽이면 된다. 승인 없이 수동으로 복구하려면:

```bash
ssh vm-target-002 sudo systemctl start chronyd
```

독립적으로 확인하고 싶으면(워크플로 출력을 안 믿고):

```bash
ssh vm-target-002 systemctl is-active chronyd
```

---

## 4-B. 시나리오 D — 브루트포스 + 설정 변경 (보안 축이 주연이 되는 케이스)

**보여 주려는 것.** 브루트포스 하나만으로는 흔한 잡음이다. 그런데 **거기에 로그인 성공과
`/etc/ssh/sshd_config` 변경이 이어지면 성격이 달라진다.** 봇이 그 셋을 한 사건으로 묶고,
심층 조사가 "2단계 공격(침투 → 지속성 확보)"으로 규명한다.

시나리오 B(브루트포스 단독)와 대비해서 보여 주면 **"축이 겹칠 때만 진짜 사건"**이라는
설계가 화면으로 드러난다.

### 4-B-1. 주입

세 동작을 **연달아** 친다. 사이가 벌어지면 병합 창(마지막 알림 뒤 90초) 밖으로 나가 따로
논다.

```bash
# ① 브루트포스 — core 에서
ssh core
~/kinx-idc-monitoring-poc/chaos/ssh_bruteforce.sh 192.0.2.16 15 hacker3

# ② 정상 로그인 + 설정 변경 — 곧바로
ssh node2 "echo '# demo marker' | sudo tee -a /etc/ssh/sshd_config"
```

②가 `Multiple authentication failures followed by a success`(실패 뒤 성공)와
`인증·권한 핵심 파일 변경`(FIM 승격 룰) 두 개를 동시에 만든다. 뒤엣것은 Wazuh 고도화에서
넣은 `local_rules.xml` 승격 룰이 있어야 컷라인 위로 올라온다.

### 4-B-2. 확인 순서

| 순서 | 어디서 | 무엇을 |
|---|---|---|
| 1 | Slack | 원시 신호 3건이 **한 스레드**에 — 브루트포스 / 실패 뒤 성공 / sshd_config 변경 |
| 2 | 같은 스레드 | **"3건이 1개 사건"** 병합 카드 + 봇 초동 분석 |
| 3 | 같은 스레드 | **심층 조사 회신** — 타임라인 표와 2단계 공격 규명 |
| 4 | Keep | 같은 사건이 한 행, 심층 조사가 Note 로 붙음 |

### 4-B-3. 이 시나리오가 심층 조사를 타는 이유

카드의 판정이 **`3건 병합 · 미상`**으로 찍힌다. "미상"인 이유는 **Wazuh 알림에는 만성/신규
판정이 안 붙기 때문**이다 — 선판정은 Zabbix 트리거의 90일 발생 이력을 세는데, Wazuh 알림에는
트리거 ID가 없다(`bot/gateway/collector.py`). 그래서 만성 억제도 신규 발동도 타지 않고
**`merged` 조건으로 발동**한다.

**시나리오 A(복제 지연)와 갈리는 지점이 여기다.** A는 Zabbix 알림이라 판정이 붙고, 랩에서
반복 주입했으니 **만성**이 되어 심층 조사가 **억제**된다. 설계대로다 — 반복 확인된 문제에
가장 비싼 분석을 또 돌리지 않는다.

발동 여부가 이상하면 게이트웨이 로그에서 사유를 본다.

```bash
grep "holmes deep-dive" /tmp/gw.log
```

`reason=merged-incident` / `novel` / `sev1` 중 하나가 찍힌다. **억제된 경우는 로그가 안
남으므로**, 안 붙은 이유는 Slack 카드의 판정 표시(만성인지 미상인지)로 읽는다.

### 4-B-4. 되돌리기

**설정 파일을 건드렸으므로 반드시 되돌린다.**

```bash
ssh node2 "sudo sed -i '/# demo marker/d' /etc/ssh/sshd_config && sudo sshd -t && echo OK"
```

`sshd -t`가 문법 검사다. `OK`가 안 나오면 `sshd`를 재시작하지 말고 파일을 먼저 확인한다.

### 4-B-5. 시연 때 주의

심층 조사가 **공격자 IP로 관측 코어(주입을 실행한 호스트) 자신을 지목한다.** 시뮬레이션이라
사실 그대로지만, 화면에 사설 IP가 뜨고 "coordinated attack"이라는 단어가 나오므로 **한 줄로
먼저 설명하고 넘어가는 편이 안전하다** — "공격자로 지목된 주소는 방금 주입한 관측 코어입니다."

---

## 5. 리허설 전체를 한 번에 돌릴 때 권장 순서

세 시나리오를 이어서 보여 준다면 이 순서가 낫다.

1. **자가 치유(C)** — 가장 짧고 결과가 확실하다. 승인 버튼까지 40초면 끝난다.
2. **SSH 브루트포스(B)** — 주입이 몇 초라 화면 전환 부담이 없다.
3. **복제 지연(A)** — **7분이 필요하다.** 이걸 마지막에 두지 말고, **1번을 시작하기 전에 미리
   주입을 걸어 두고** 다른 시나리오를 도는 동안 익게 하는 편이 낫다.

즉 실제로는 이렇게 친다.

```
① node2 에서 repl_lag_contention.sh 를 DURATION=420 으로 백그라운드 주입
② (기다리는 동안) 자가 치유 시연
③ (기다리는 동안) SSH 브루트포스 시연
④ 돌아와서 복제 지연 병합 카드 확인
```

---

## 6. 안 될 때 먼저 볼 것

| 증상 | 원인 | 확인 |
|---|---|---|
| Slack에 아무것도 안 온다 | 게이트웨이가 안 떠 있다 | `ps -ef \| grep uvicorn` |
| `.env`를 고쳤는데 안 먹는다 | 옛 프로세스가 살아 있다 | kill 후 재기동 (1-2) |
| 봇 카드가 여러 개 뜬다 | `--workers`를 붙였다 | 워커 없이 단일 프로세스로 |
| Keep에 워크플로가 안 보인다 | Keep을 재시작 안 했다 | `docker compose restart keep-backend` |
| 지연은 오르는데 알림이 없다 | 5분을 못 버텼다 | `DURATION`을 420 이상으로 |
| `Could not resolve hostname` | core에서 SSH 별칭을 썼다 | 작업자 PC에서 실행하거나 사설 IP 사용 |
| 대시보드 전 패널 no data | 조회 계정에 호스트그룹 권한이 없다 | Zabbix → User groups → Host permissions |
| 메트릭 패널이 멈춰 보인다 | Grafana 조회 캐시(`cacheTTL`) | 데이터소스 cacheTTL 확인 (1m로 낮춰 둠) |
| LLM 분석이 수치만 나온다 | Anthropic 크레딧 소진 | 잔액 확인 — 열화 모드로 돈 것 |
| 심층 조사가 안 붙는다 | 판정이 **만성**이면 설계상 억제 | 카드의 판정 표시. 만성이면 정상 |
| 심층 조사가 아예 한 번도 안 붙는다 | `HOLMES_ENABLED`가 안 켜졌다 | `.env` 확인 후 게이트웨이 재기동 |
| 알림이 따로따로 뜬다 | 주입 간격이 병합 창(90초)을 넘겼다 | 연달아 친다 |

구축 단계에서 밟는 함정은 `docs/03-pitfalls/build-traps.md`.

---

## 7. 실환경에서는 절대 돌리지 않는다

`chaos/`의 모든 스크립트는 **랩 전용**이다. 대상 IP를 인자로 받게 만든 이유가 여기 있다 —
하드코딩해 두면 실수로 실환경을 때릴 수 있다. 실행 전에 **인자로 넣은 IP가 랩 사설 대역인지**
눈으로 한 번 확인한다.
