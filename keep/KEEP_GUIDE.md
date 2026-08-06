# Keep — HITL 자가치유 워크플로 (Keep → SSH → Ansible)

Keep(keephq)을 알림 저장·UI + 승인 + Ansible 실행 허브로 쓰는 데모 B 배선. 평가 근거·판정은
[`docs/02-design/decisions/adr-001-keep-adopt.md`](../docs/02-design/decisions/adr-001-keep-adopt.md).
아키텍처(봇·HolmesGPT 분석이 Keep에 수렴)는 그 문서 참조.

## 구성 요소

- **SSH provider (Keep UI에서 1회 생성, 이름 `core-ansible`)**: paramiko로 core(ansible control
  node)에 SSH. 필드 — host=core 사설 IP, user=rocky, port=22, pkey=배포키 내용. 크리덴셜은
  Keep에 저장됨(랩 한정, 프로덕션은 시크릿 관리·최소권한 별도).
- **워크플로 (`keep/workflows/*.yml`)**: `type: manual` 트리거(자동 실행 안 됨 = 승인 게이트).
  step에서 SSH provider로 `ansible-playbook remediate_service.yml` 실행. 코드로 버전관리.

## 프로비저닝 (as-code, UI 손질 없이 파일에서 로드)

Keep은 `KEEP_WORKFLOWS_DIRECTORY`가 가리키는 디렉토리의 워크플로 파일을 재시작 시 provision
(추가·갱신·삭제 자동 반영). docker-compose override에서:

```yaml
services:
  keep-backend:
    environment:
      - KEEP_WORKFLOWS_DIRECTORY=/workflows
    volumes:
      - /home/rocky/kinx-idc-monitoring-poc/keep/workflows:/workflows
```

리포를 keep VM에 `git clone` 후 이 디렉토리를 마운트 → `git pull` + 재시작이면 워크플로 갱신.
(근거: docs.keephq.dev `/deployment/provision/workflow`.)

## HITL 승인 = "Run Workflow"

워크플로가 manual 트리거라 알림이 떠도 자동 실행되지 않는다. 운영자가 **Keep 알림 상세 →
"Run Workflow" → 이 워크플로 선택**으로 실행 = 승인. 실행되면 SSH→core→ansible→서비스 재기동,
결과(PLAY RECAP·조치 후 재검증)가 step 출력으로 회귀.

## 실측 확인 (2026-07-28)

Keep 워크플로 → SSH(core `~/ansible-venv`) → `ansible-playbook -i inventory.local.ini
remediate_service.yml -e target_host=vm-p3-target-002 -e service_name=chronyd` end-to-end 성공
(changed=1, before/after active). 상세: keep_evaluation_plan.md §4-1b.

## 두 번째 승인 — 월간 리포트 발송 (`msp_report_approve.yml`, 2026-07-31)

승인 계층을 **새로 만들지 않았다.** 조치 승인(데모 B)과 리포트 발송 승인이 같은 화면,
같은 방식(manual 트리거 + "Run Workflow")이다. n8n 같은 GUI 엔진을 더하지 않는 근거가
여기 있다 — 필요한 승인 UI 는 이미 있었다.

| | 데모 B | 월간 리포트 |
|---|---|---|
| 안전 게이트 | `alert.playbook == 'service_restart'` | `alert.playbook == 'report_approve'` |
| 알림이 실어 오는 값 | `host`, `service` | `host`, `customer`, `host_filter`, `recipient` |
| 하는 일 | Ansible 서비스 재기동 | 초안 게시 → PDF → 메일 |

**`--from-draft` 가 핵심이다.** 승인할 때 집계를 다시 돌리면 LLM 이 새 서사를 만들어
**사람이 읽고 승인한 문장과 다른 글**이 고객에게 간다. 초안을 파일로 굳혀 두고
(`~/.kinx-report-drafts/<호스트>.txt`) 승인은 그 파일을 그대로 게시한다. 숫자는 결정적이라
그때 다시 계산해도 같은 값이 나온다 — 달라질 수 있는 것은 서사뿐이므로 서사만 고정한다.

**실측 (2026-07-31)**: 초안 등록 → 워크플로가 실행할 명령을 그대로 실행 →
`processed: 15; failed: 0` → PDF 373KB → 메일 수신 확인. 그리고 **게시된 서사가 저장된
초안과 문자열까지 일치**하는 것을 Zabbix 아이템 값과 대조해 확인했다(요약·월간 분석 둘 다).

## 세 번째 워크플로 — 자동화 후보 표시 (`mark_automation_candidate.yml`)

반복(만성)으로 판정된 사건에 **표시만** 남긴다. "반복 → 자동화 후보" 폐루프에서 빠져 있던
조각이다.

분업이 이 파일의 요점이다 — **반복 식별의 지능은 우리 층**(90일 빈도로 만성/재발/신규 결정),
**저장·필터·UI 는 Keep**. 상용 AIOps 가 차별화 기능으로 파는 "무엇을 자동화할지 추천"을 얇은
층으로 값싸게 갖는다.

**조치는 하지 않는다.** 표시만 남기고 실행은 사람이 조치 워크플로를 Run 해서 한다.
LLM 분석 텍스트를 자동으로 절차서나 조치로 굳히지 않는다는 원칙과 같은 선이다.

쓰는 법: Keep UI 에서 `automation_candidate = yes` 로 필터하고 `classes` 로 묶어 보면
**"어떤 유형이 반복 최다인가" = 자동화 1순위**가 나온다.

> 이 랭킹은 만성 판정 횟수에 의존하는데, 그 횟수가 조회 상한에서 포화되는 문제가 있다 —
> [`docs/03-pitfalls/structural-gaps.md#g3`](../docs/03-pitfalls/structural-gaps.md).

근거(공식): docs.keephq.dev `/workflows/syntax/enrichment` — `enrich_alert` 로 트리거 알림에
필드를 추가한다.

## 알려진 마찰 (도입 리스크)

- Keep UI "새 워크플로 생성"이 일부 상황에서 `workflow_raw_data: null`로 실패 → 프로비저닝(파일)
  경로가 더 안정적.
- Keep 네이티브 Zabbix provider는 Zabbix 7.0에서 API 파라미터 에러 → 알림 유입은 게이트웨이
  push 권장.
