# docs/ — 인수인계 및 재현 가이드

이 디렉토리는 **실험 환경(랩) 구축과 프로젝트 인수인계를 위한 문서 모음**입니다. 전체 목차를 순서대로 읽기보다는, **수행하려는 작업**에 따라 필요한 문서로 바로 이동하여 참조합니다.

## 작업별 시작 문서

| 수행하려는 작업 | 우선 참고할 문서 |
|---|---|
| 랩 환경을 처음부터 다시 구축할 때 | [`01-build/README.md`](01-build/README.md) |
| 데모를 실행하거나 시연을 리허설할 때 | [`04-demo/runbook.md`](04-demo/runbook.md) |
| 정상 동작하지 않는 원인을 분석하고 해결할 때 | [`03-pitfalls/build-traps.md`](03-pitfalls/build-traps.md) → [`04-demo/runbook.md`](04-demo/runbook.md) §7 트러블슈팅 |
| 설계 의도와 배경을 파악해야 할 때 | [`02-design/README.md`](02-design/README.md) |
| PoC의 한계점 및 미완성 항목을 확인할 때 | [`03-pitfalls/README.md`](03-pitfalls/README.md), [`05-handover/status.md`](05-handover/status.md) |
| 기존 작업에 이어 후속 개발을 진행할 때 | [`05-handover/next-steps.md`](05-handover/next-steps.md) |
| 소스 코드를 수정·개선할 때 | [`00-architecture.md`](00-architecture.md) → 해당 디렉토리의 `*_GUIDE.md` |

## 문서 지도

```
docs/
├── 00-architecture.md      계층 구조 · 알림 1건의 생애주기 · 용어집
├── 01-build/               랩 환경 재현 — 순서별 구축 가이드
├── 02-design/              설계 의도 및 의사결정 근거 — 주요 설계 판단 이유
├── 03-pitfalls/            구조적 함정 및 한계점 — 은밀하게 발생하는 오류 유발 요인
├── 04-demo/                데모 시나리오 및 실행 런북(Runbook)
└── 05-handover/            프로젝트 현황 · 향후 과제 · PoC 진행 경과
```

---

## 문서 작성 및 관리 규약

이 규약은 **시간이 흐름에 따라 문서와 실제 코드가 불일치(Drift)하는 현상을 방지하기 위한 규칙**입니다. 문서를 추가하거나 수정할 때 반드시 준수합니다.

### 1. 정보의 단일 소스(Owner)는 해당 코드를 수정하는 작업자가 가장 먼저 여는 파일입니다.

- **구축 및 운영 절차의 Owner는 해당 코드가 위치한 디렉토리의 가이드 파일입니다.**
  `ansible/DEPLOY_GUIDE.md`, `bot/GATEWAY_GUIDE.md`, `keep/KEEP_GUIDE.md`,
  `masking/MASKING_GUIDE.md`, `lab/README.md`, `lab/mariadb/REPL_VM_GUIDE.md`,
  `lab/grafana/USE_RED_GUIDE.md`, `chaos/README.md`, `tools/RECON_GUIDE.md`,
  `bot/BENCH_GUIDE.md`, `bot/BRIDGE_MINER_GUIDE.md`.
  **이 내용을 `docs/`로 이관하거나 별도 요약본으로 작성하지 않습니다.** 플레이북을 수정하는 작업자가 코드 변경 시 관련 문서를 동시에 확인하지 않게 되는 순간 문서의 신뢰성은 저하되며, 코드와 문서 간의 불일치를 인지하기 어려워집니다.

- **`docs/` 디렉토리는 "특정 코드 위치에 귀속시킬 수 없는 공통 사실"만 관리합니다.**

  | Owner 문서 | 코드 디렉토리에 두지 않는 이유 |
  |---|---|
  | `02-design/severity-normalization.md` | Zabbix·Wazuh·Grafana·`severity.py` 4개 요소가 동일한 기준표를 참조 |
  | `02-design/llm-data-contract.md` | `masking.py`·`llm.py`·`holmes.py` 및 마스킹 프록시가 공통 참조 |
  | `01-build/hosts.md` | 식별자 대응 관계가 chaos·ansible·런북·Zabbix 라벨 전반에 걸쳐 영향 |
  | `04-demo/runbook.md` | 6개 디렉토리의 실행 순서를 종합하여 연결하는 유일한 문서 |
  | `03-pitfalls/structural-gaps.md` | 구조적 갭이 코드·문서·운영 영역 전반에 분산 존재 |

- **`docs/` 내의 나머지 문서는 링크 허브 역할을 수행합니다.** 다음 4가지 요소만 포함할 수 있습니다:
  해당 단계의 **전제 조건** / **성공 산출물**(완료 기준) / 주의해야 할 **주요 함정**(1~3줄 요약) / **원본 가이드 링크**.
  **실행 명령어 블록을 중복 기재하지 않습니다** (진입점 1줄은 예외).

### 2. `private/` 경로 참조를 임의로 삭제하지 않습니다.

코드와 문서에 남아 있는 `private/` 경로는 단순한 깨진 링크가 아니라 **데이터 보안 및 취급 정책**을 나타냅니다.
"실환경 조회 결과 데이터는 `private/` 하위 경로에만 보관한다"는 지침이므로, 이를 삭제할 경우 관리 규약이 상실됩니다.

```
tools/zabbix_serverstats.py       tools/zabbix_alert_crosscheck.py
tools/zabbix_replication_check.py tools/zabbix_mediatype_check.py
bot/bridge_miner.py               bot/report_deliver.py
```

증적 스크린샷(`bot/GATEWAY_GUIDE.md`의 검증 이력) 역시 마찬가지입니다. 마스킹 처리 비용 문제로 이관하지 않기로 결정한 **의도적 관리 경계**이며 누락 사항이 아닙니다.

그 외 작업 수행에 필수적인 `private/` 참조 항목(미개설 시 작업이 중단되는 문서)은 모두 `docs/` 경로로 재지정되었습니다. 신규 작성 시에도 동일한 기준을 적용합니다.

### 3. IP 주소는 플레이스홀더(Placeholder)로 표기하며, 식별자 명칭은 유지합니다.

문서 내 표기용 IP는 `192.0.2.0/24`(RFC 5737 문서 전용 대역)를 사용하고, 공인 IP는 `<PUBLIC_IP>`로 표기합니다.
실제 연결 정보는 `*.local.md`(gitignore 대상)에서 관리하며, 상세 매핑 기준은 [`01-build/hosts.md`](01-build/hosts.md)를 참조합니다.

**문서 내에 계정 자격 증명(Credential)을 직접 명시하지 않습니다.** 비밀번호 등이 필요한 명령은 `read -s`와 같은 대화형 입력 방식을 사용합니다.
단, 벤더 기본 설정 계정(초기 로그인 후 변경해야 하는 공식 설치 절차상의 계정)은 예외로 합니다.

### 4. 실환경 관련 수치는 비율 및 구조 정보만 기재합니다.

실환경 진단 데이터 중 **비율·분포·순위 정보**는 기재가 가능합니다 (예: "커스텀 트리거의 39%가 발화 불가 상태", "상위 2개 트리거가 전체 이벤트의 78.6% 차지").
단, 특정 조직을 식별할 수 있는 **절대 모수 데이터는 기재를 금지**합니다 (호스트 수, 총 이벤트 수, NVPS 실측값, 고객 도메인 수 등).

실험 환경(랩)에서 측정한 지표는 제약 없이 사용하되, **"랩 실측값"임을 명확히 표기**합니다.

### 5. 가변적인 수치를 문서에 고정값으로 작성하지 않습니다.

셀프 테스트 통과 건수와 같이 커밋 시점마다 변경되는 데이터는 고정된 숫자로 기재하지 않습니다.
기재가 필요한 경우 **작성 시점에 재산출**하거나 "명령 실행을 통한 실시간 확인" 형태로 작성합니다.

### 6. 문서 이관 작업 시에는 내용 개정이 아닌 경로 치환만 진행합니다.

`private/` 디렉토리에서 이관된 문서는 **원문 내용을 임의로 다듬지 않고 이관**합니다. 마스킹(스크럽) 작업과 내용 편집을 동시에 진행할 경우, 추후 변경 내역의 검증이 불가능해지기 때문입니다.