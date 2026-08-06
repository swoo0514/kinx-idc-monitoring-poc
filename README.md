# kinx-idc-monitoring-poc

IDC 파트 모니터링 시스템(Zabbix + Grafana/Alloy + Wazuh) 고도화 **3주 PoC**의 산출물입니다.
실환경을 API로 진단해 문제를 특정하고, **실환경에는 아무 변경도 가하지 않은 채** 별도의 미러
랩에서 통합 관제·AI 초동 분석·자가 치유를 재현 가능한 형태로 검증했습니다.

리포에는 **랩을 다시 세우고 이어받는 데 필요한 것**만 있습니다. 실환경 진단 결과·전략 문서·
크리덴셜은 `private/`에 있고 커밋되지 않습니다. 문서에 실환경 수치를 쓸 때도 **비율·구조만**
쓰고 호스트 대수 같은 모수는 쓰지 않습니다.

## 어디부터 읽나

| 하려는 일 | 첫 문서 |
|---|---|
| 랩을 처음부터 다시 세운다 | [`docs/01-build/README.md`](docs/01-build/README.md) |
| 데모를 돌린다 · 리허설한다 | [`docs/04-demo/runbook.md`](docs/04-demo/runbook.md) |
| 안 돌아간다, 원인을 찾는다 | [`docs/04-demo/runbook.md §6`](docs/04-demo/runbook.md#6-안-될-때-먼저-볼-것) |
| 왜 이렇게 만들었는지 알아야 한다 | [`docs/02-design/README.md`](docs/02-design/README.md) |
| 약점·미완을 알아야 한다 | [`docs/03-pitfalls/README.md`](docs/03-pitfalls/README.md) |
| 이어서 개발한다 | [`docs/05-handover/status.md`](docs/05-handover/status.md) |

전체 문서 지도와 작성 규약은 **[`docs/README.md`](docs/README.md)**.

## 구조

```mermaid
flowchart LR
    subgraph 수집
      A1[zabbix-agent2<br/>메트릭]
      A2[Alloy<br/>로그]
      A3[wazuh-agent<br/>보안]
    end
    subgraph 저장·관측
      B1[(Zabbix<br/>+ MariaDB)]
      B2[(Loki)]
      B3[(Wazuh<br/>Indexer)]
      B4[Grafana]
    end
    subgraph 게이트웨이
      C1[분류 · 심각도 정규화]
      C2[인시던트 병합]
      C3[만성/신규 선판정]
      C4[마스킹]
      C5[LLM 분석]
    end
    subgraph 반출·조치
      D1[Slack]
      D2[Keep<br/>승인 큐]
      D3[Ansible]
    end
    A1 --> B1; A2 --> B2; A3 --> B3
    B1 & B2 & B3 --> B4
    B1 -- 웹훅 --> C1
    B3 -- 웹훅 --> C1
    C1 --> C2 --> C3 --> C4 --> C5
    C5 --> D1
    C5 --> D2
    D2 -- 사람 승인 1회 --> D3
    B1 & B2 & B3 -. 컨텍스트 조회 .-> C2
    E([chaos 주입]) -.-> A1 & A2 & A3
```

세 줄로 요약하면 이렇습니다.

- **세 시스템이 같은 호스트를 같은 이름으로 부르게** 만든 뒤(FQDN 정규화), 한 화면·한 사건으로 본다.
- **판정은 코드가, 설명만 LLM이** 한다 — 병합 규칙과 만성/신규 판정은 결정적이라 환각이 불가능하다.
- **외부로 나가는 경로는 하나**이고, 그 하나가 화이트리스트와 가역 마스킹을 통과한다.

## 저장소 구성

| 디렉토리 | 무엇 | 대표 문서 | 상태 |
|---|---|---|---|
| `lab/` | Docker 관측 코어(Zabbix 7.0.27·MariaDB·Grafana·Loki) + 대시보드 JSON 7종 + 복제 스크립트 | [`lab/README.md`](lab/README.md) · [`lab/grafana/USE_RED_GUIDE.md`](lab/grafana/USE_RED_GUIDE.md) | 랩 실증 |
| `ansible/` | 3종 에이전트 배포, 자동 등록, 복제 감시, Wazuh 감시 정의, 인증서 만료 감시, MSP 온보딩, 조치 플레이북 | [`ansible/DEPLOY_GUIDE.md`](ansible/DEPLOY_GUIDE.md) | 랩 실증 |
| `bot/` | 게이트웨이(웹훅·병합·선판정·마스킹·LLM·Slack·Keep) + MSP 월간 리포트 | [`bot/GATEWAY_GUIDE.md`](bot/GATEWAY_GUIDE.md) · [`bot/.env.example`](bot/.env.example) | 랩 실증 |
| `chaos/` | 장애 주입 스크립트 (브루트포스·서비스 정지·복제 지연·오류율·SNMP 노이즈·보안 시드) | [`chaos/README.md`](chaos/README.md) | 랩 실증 |
| `keep/` | HITL 승인 워크플로 (Keep → SSH → Ansible) | [`keep/KEEP_GUIDE.md`](keep/KEEP_GUIDE.md) | 랩 실증 |
| `tools/` | Zabbix **읽기 전용** 정찰 스크립트 | [`tools/RECON_GUIDE.md`](tools/RECON_GUIDE.md) | 실환경 정찰에 사용 |
| `masking/` | Presidio + LiteLLM 이그레스 마스킹 프록시 | [`masking/MASKING_GUIDE.md`](masking/MASKING_GUIDE.md) | 코드 있음 · 평가 단계 |
| `docs/` | 인수인계·재현 문서 | [`docs/README.md`](docs/README.md) | — |

상태는 세 값만 씁니다 — **랩 실증**(랩에서 처음부터 끝까지 돌려 확인) / **코드 있음·미실증** /
**미구현**. "완료"라는 말은 쓰지 않습니다.

## 데모

| | 데모 A — 통합 관제 | 데모 B — 자가 치유 | 데모 C — AI 초동 분석 |
|---|---|---|---|
| **보여주는 것** | 메트릭·로그·보안이 같은 타임라인·같은 호스트에 찍히고, 클릭하면 그 호스트 로그로 좁혀진다 | 서비스가 죽고 → 승인 버튼 1회 → Ansible이 고치고 스스로 재검증한다 | 따로 올라온 알림 N건을 한 사건으로 병합하고 "복제 고장이 아니라 자원 경합"으로 재프레이밍한다 |
| **주입** | `chaos/ssh_bruteforce.sh` | `chaos/service_down.sh` | `chaos/repl_lag_contention.sh` |
| **확인 화면** | Grafana `kinx-overview` | Keep 승인 큐 → 워크플로 출력 | Slack 스레드 병합 카드 |
| **런북** | [§3](docs/04-demo/runbook.md#3-시나리오-b--ssh-브루트포스-데모-a-보안-축) | [§4](docs/04-demo/runbook.md#4-시나리오-c--자가-치유-데모-b) | [§2](docs/04-demo/runbook.md#2-시나리오-a--복제-지연-데모-c-하이라이트) |

시나리오 설계와 반문 대비는 [`docs/04-demo/`](docs/04-demo/README.md).

## 랩에서 측정한 것

**아래는 전부 랩 측정값이며 실환경 값이 아닙니다.**

- **AI 트리아지 15.77초** (컨텍스트 수집 0.16 + LLM 15.03 + Slack 게시 0.58) — 예산 30초 대비 여유
- **복제 지연 0 → 6분 13초** 단조 증가 (자원 경합 주입), 같은 호스트에 알림 2건 → **1개 사건으로 병합**
- **SCA 준수율 52%** (Wazuh CIS 벤치마크, 인덱서 직접 조회와 리포트 집계가 교차 검증됨)
- **HolmesGPT 3분 31초 / 30콜** — 원인 정확도는 우리 봇보다 깊었으나 실시간 예산·마스킹·온프렘
  요건에서 불통과 → **하이브리드**로 결론
- 게이트웨이 셀프테스트: `cd bot && python -m gateway.selftest` (외부 의존성 없이 순수 로직 검증)

## 경계와 한계

정직하게 적어 둔 약점 목록도 산출물의 일부입니다 — [`docs/03-pitfalls/`](docs/03-pitfalls/README.md).

- **게이트웨이가 새로운 SPOF입니다.** 봇이 안 떠 있으면 알림이 Slack에도 Keep에도 안 갑니다.
- **인시던트 버퍼가 메모리에 있습니다.** 재기동하면 진행 중이던 병합이 사라집니다.
- **병합 규칙과 만성/신규 판정은 사람이 정한 규칙**입니다. AI가 스스로 찾은 것이 아니며,
  그렇게 만든 이유(환각 통제)를 문서에 적어 두었습니다.
- 실환경 적용은 하지 않았습니다. 이 리포의 실증은 전부 랩 범위입니다.

## 빠른 시작

```bash
cd lab
cp .env.example .env      # 랩 전용 임의 비밀번호로 채운다
docker compose up -d
docker compose logs -f zabbix-server   # "server #0 started" 확인
```

전체 구축 순서(에이전트·Wazuh·게이트웨이·Keep)는 [`docs/01-build/README.md`](docs/01-build/README.md).
**`docker compose up` 하나로 다 뜨지 않습니다.**

## 데이터 취급 규약

- **크리덴셜은 `.env`에만.** `.env.example`만 커밋합니다(`lab/`·`bot/` 각각).
- **`private/`는 커밋하지 않습니다.** 실환경 정찰 결과·인터뷰·고객 리포트 산출물·키가 여기 있습니다.
- 문서의 IP는 `192.0.2.0/24`(RFC 5737 문서용 대역) **예시 주소**입니다. 실값은 `*.local.*`
  파일에 두고 gitignore합니다 — [`docs/01-build/hosts.md`](docs/01-build/hosts.md).
- `tools/`의 정찰 스크립트는 **읽기 전용 `.get` API만** 호출합니다. 출력물은 `private/`에만 둡니다.
- 인증서·키(`*.pem` `*.key` `*.p12` `*.crt`)와 생성된 PDF는 위치 불문 커밋 금지입니다.

## 라이선스

사내 전용. 외부 배포·공개를 하지 않습니다.
