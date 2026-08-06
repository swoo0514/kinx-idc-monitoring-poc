# docs/ — 인수인계·재현 문서

이 디렉토리는 **랩을 다시 세우고 이어받기 위한 문서**다. 목차를 읽고 고르는 것이 아니라,
**하려는 일**로 바로 들어간다.

## 어디부터 읽나

| 하려는 일 | 첫 문서 |
|---|---|
| 랩을 처음부터 다시 세운다 | [`01-build/README.md`](01-build/README.md) |
| 데모를 돌린다 · 리허설한다 | [`04-demo/runbook.md`](04-demo/runbook.md) |
| 안 돌아간다, 원인을 찾는다 | [`03-pitfalls/build-traps.md`](03-pitfalls/build-traps.md) → [`04-demo/runbook.md §6`](04-demo/runbook.md#6-안-될-때-먼저-볼-것) |
| 왜 이렇게 만들었는지 알아야 한다 | [`02-design/README.md`](02-design/README.md) |
| 이 PoC의 약점·미완을 알아야 한다 | [`03-pitfalls/README.md`](03-pitfalls/README.md), [`05-handover/status.md`](05-handover/status.md) |
| 이어서 개발한다 | [`05-handover/next-steps.md`](05-handover/next-steps.md) |
| 코드를 고친다 | [`00-architecture.md`](00-architecture.md) → 해당 디렉토리의 `*_GUIDE.md` |

## 문서 지도

```
docs/
├── 00-architecture.md      계층 구조 · 알림 1건의 생애 · 용어집
├── 01-build/               랩 재현 — 무엇을 어떤 순서로 세우는가
├── 02-design/              설계 근거 · 판정 — 왜 이렇게 만들었는가
├── 03-pitfalls/            구조 함정 · 한계 — 무엇이 조용히 틀리는가
├── 04-demo/                데모 시나리오 · 실행 런북
└── 05-handover/            현황 · 다음 할 일 · PoC 과정 서사
```

---

## 문서 규약

이 규약은 **6주 뒤 문서가 코드와 갈라지는 것을 막기 위한 것**이다. 문서를 추가·수정할 때 지킨다.

### 1. 한 사실의 owner는 그것을 바꾸는 사람이 가장 먼저 여는 파일이다

- **구축·운영 절차는 그 코드가 있는 디렉토리의 가이드가 owner다.**
  `ansible/DEPLOY_GUIDE.md`, `bot/GATEWAY_GUIDE.md`, `keep/KEEP_GUIDE.md`,
  `masking/MASKING_GUIDE.md`, `lab/README.md`, `lab/mariadb/REPL_VM_GUIDE.md`,
  `lab/grafana/USE_RED_GUIDE.md`, `chaos/README.md`, `tools/RECON_GUIDE.md`,
  `bot/BENCH_GUIDE.md`, `bot/BRIDGE_MINER_GUIDE.md`.
  **`docs/`로 옮기거나 요약본을 만들지 않는다.** 플레이북을 고치는 사람이 같은 변경에서
  문서를 보지 않게 되는 순간부터 문서는 늙기 시작하고, **갈라진 것을 아무도 눈치채지 못한다.**

- **`docs/`가 소유하는 것은 "어느 코드 옆에도 못 두는 사실"뿐이다.**

  | owner 문서 | 왜 코드 옆이 아닌가 |
  |---|---|
  | `02-design/severity-normalization.md` | Zabbix·Wazuh·Grafana·`severity.py` 넷이 같은 표를 참조 |
  | `02-design/llm-data-contract.md` | `masking.py`·`llm.py`·`holmes.py`·마스킹 프록시가 참조 |
  | `01-build/hosts.md` | 이름 3중 대응이 chaos·ansible·런북·Zabbix 라벨에 걸침 |
  | `04-demo/runbook.md` | 여섯 디렉토리를 순서대로 꿰는 유일한 문서 |
  | `03-pitfalls/structural-gaps.md` | 구조 갭이 코드·문서·운영에 흩어짐 |

- **`docs/`의 나머지 문서는 링크 허브다.** 가질 수 있는 것은 넷뿐 —
  이 단계의 **전제** / **산출물**(무엇이 생기면 성공인가) / 밟기 쉬운 **함정** 1~3줄 /
  **원본 가이드 링크**. **명령어 블록을 재게재하지 않는다**(진입 1줄은 예외).

### 2. `private/` 참조를 기계적으로 지우지 않는다

코드·문서에 남아 있는 `private/` 언급 중 **아래는 깨진 링크가 아니라 데이터 취급 정책**이다.
"실환경 조회 결과는 `private/` 아래에만 둔다"는 지시이며, 지우면 규약이 사라진다.

```
tools/zabbix_serverstats.py       tools/zabbix_alert_crosscheck.py
tools/zabbix_replication_check.py tools/zabbix_mediatype_check.py
bot/bridge_miner.py               bot/report_deliver.py
```

증적 스크린샷(`bot/GATEWAY_GUIDE.md`의 검증 이력)도 마찬가지다. 마스킹 비용 때문에 이관하지
않기로 한 **의도된 경계**이지 누락이 아니다.

그 외의 `private/` 참조 — 즉 **읽는 사람이 그 문서를 못 열면 작업이 막히는 것** — 은 전부
`docs/`로 재지정했다. 새로 추가할 때도 같은 기준으로 판단한다.

### 3. 주소는 placeholder, 이름은 유지

문서에 쓰는 IP는 `192.0.2.0/24`(RFC 5737 문서용 대역), 공인 IP는 `<PUBLIC_IP>`.
실값은 `*.local.md`(gitignore)에 둔다. 근거와 대응표는 [`01-build/hosts.md`](01-build/hosts.md).

**크리덴셜은 문서에 쓰지 않는다.** 값이 필요한 명령은 입력받는 형태(`read -s`)로 적는다.
벤더 설치 기본 계정만 예외다(첫 로그인에서 바꾸는 값이고 공식 절차의 일부).

### 4. 실환경 수치는 비율·구조만

실환경 진단에서 나온 **비율·분포·순위**는 쓴다("커스텀 트리거의 39%가 발화 불가",
"상위 2개 트리거가 이벤트의 78.6%"). **모수는 쓰지 않는다** — 호스트 대수, 총 이벤트 건수,
NVPS 실측값, 고객 도메인 개수. 조직을 식별할 수 있는 수치가 되기 때문이다.

랩에서 측정한 값은 자유롭게 쓰되 **"랩 값"임을 밝힌다.**

### 5. 변하는 숫자를 문서에 박제하지 않는다

셀프테스트 통과 건수처럼 커밋마다 변하는 값은 고정 숫자로 적지 않는다. 적어야 하면
**작성 시점에 재산출**하거나 "실행해서 확인"으로 적는다. 박제된 숫자는 다음 커밋에서
바로 거짓이 된다.

### 6. 문서를 옮길 때는 치환만, 개선은 따로

`private/`에서 이관한 문서는 **원문을 다듬지 않았다.** 스크럽과 편집을 한 번에 하면
나중에 "무엇이 마스킹이고 무엇이 편집인가"를 검증할 수 없다.
