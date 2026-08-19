# Keep 기반 HITL 자가 치유 워크플로 가이드 (Keep ➔ SSH ➔ Ansible)

본 문서는 Keep(keephq) 솔루션을 인시던트 저장소, 승인 UI 및 Ansible 자동화 연동 허브로 활용하는 자가 치유(HITL, Human-in-the-Loop) 파이프라인 배선 명세서입니다.

*(솔루션 평가 근거 및 아키텍처 설계 문서: [`docs/02-design/decisions/adr-001-keep-adopt.md`](../docs/02-design/decisions/adr-001-keep-adopt.md) 참조)*

---

## 1. 주요 구성 요소 명세

- **SSH Provider (`core-ansible`):** Keep UI에서 생성된 SSH 연결 프로바이더입니다. Paramiko 라이브러리를 통해 Ansible Control Node(`core`)로 원격 접속을 수행합니다.
  - `host`: `core` 노드 사설 IP
  - `user`: `rocky`
  - `port`: `22`
  - `pkey`: 배포용 SSH Private Key (Keep 시크릿 스토리지에 암호화 보관)
- **워크플로 정의 파일 (`keep/workflows/*.yml`):** `type: manual` 트리거 조건이 적용된 IaC(Infrastructure as Code) 기반 정의 파일입니다. 자동 실행이 차단되어 명시적 사용자 승인 게이트 역할을 수행합니다.

---

## 2. 프로비저닝 방식 (Workflow-as-Code)

Keep은 `KEEP_WORKFLOWS_DIRECTORY` 가리키는 디렉토리 내 워크플로 정의 파일을 기동 시점에 자동 재로드(Provisioning)합니다. Docker Compose 환경에서 아래와 같이 볼륨 마운트를 구성합니다:

```yaml
services:
  keep-backend:
    environment:
      - KEEP_WORKFLOWS_DIRECTORY=/workflows
    volumes:
      - /home/rocky/kinx-idc-monitoring-poc/keep/workflows:/workflows
```

*운영 절차:* Keep VM 내 Git 저장소 업데이트(`git pull`) 후 Backend 컨테이너를 재시작(`docker compose restart keep-backend`)하여 워크플로 변경 사항을 동적 적용합니다.

---

## 3. HITL 승인 및 실행 메커니즘 ("Run Workflow")

`manual` 트리거가 설정된 워크플로는 알림이 인입되어도 자동 실행되지 않고 대기 상태를 유지합니다.

```text
알림 인입 ➔ Keep UI 알림 상세 확인 ➔ "Run Workflow" 클릭 ➔ 해당 워크플로 선택 (승인 완료)
   │
   ▼
SSH 프로바이더 호출 (`core-ansible`) ➔ Ansible 플레이북 실행 (`remediate_service.yml`)
   │
   ▼
서비스 재기동 및 상태 재검증 ➔ 실행 결과 (PLAY RECAP / Before-After 상태) Keep UI 회신
```

---

## 4. 실측 검증 이력 (2026-07-28)

Keep 워크플로 ➔ SSH 연동(`core` 노드 `~/ansible-venv`) ➔ Ansible 플레이북 호출 연동 전체 파이프라인의 성공을 검증했습니다:

```bash
ansible-playbook -i inventory.local.ini remediate_service.yml \
  -e target_host=vm-p3-target-002 \
  -e service_name=chronyd
```
*(검증 결과: `changed=1`, 상태 변환 `before: inactive -> after: active` 정상 동작 확인)*

---

## 5. 승인 파이프라인 재사용 사례

기존 조치 승인 파이프라인(데모 B)의 승인 계층을 그대로 재활용하여 신규 승인 워크플로를 확장 구현했습니다.

### 5-1. 월간 리포트 발송 승인 (`msp_report_approve.yml`)

별도의 GUI 승인 엔진(n8n 등)을 추가하지 않고 동일한 승인 메커니즘(`manual` 트리거 + "Run Workflow")을 적용했습니다.

| 구분 | 서비스 자동 조치 (데모 B) | 월간 리포트 발송 승인 |
|---|---|---|
| **안전 게이트 조건** | `alert.playbook == 'service_restart'` | `alert.playbook == 'report_approve'` |
| **전달 파라미터** | `host`, `service` | `host`, `customer`, `host_filter`, `recipient` |
| **실행 작업** | Ansible 서비스 재기동 | 초안 기반 최종 리포트 렌더링 및 메일 발송 |

*서사 데이터 고정 (`--from-draft`):* 승인 시점에 LLM 집계를 재호출할 경우 문장 표현이 변경되는 문제를 방지하기 위해, 초안 텍스트 파일(`~/.kinx-report-drafts/<host>.txt`)을 생성 및 보관한 뒤 승인 실행 시 해당 초안 원문을 변함없이 게시 및 발송합니다.

### 5-2. 연계 규칙 교체 승인 (`rules_promote_approve.yml`)

상관 마이닝 재측정 결과를 게이트웨이에 반영할 때 사람 검토를 거치도록 하는 워크플로입니다. 승인 계층을 신규 구축하지 않고 동일 메커니즘을 적용한 **세 번째 사례**입니다.

**승인을 두는 이유:** 재측정 자동화 자체는 기계적으로 가능하나, 규칙이 무단 변경되면 판정 근거가 달라져도 인지할 수 없습니다. 부실한 측정이 그대로 반영될 위험도 있습니다(실측상 통과 조합의 81%가 단일 사건에서 산출된 사례 존재).

| 구분 | 서비스 자동 조치 (데모 B) | 월간 리포트 발송 | 연계 규칙 교체 |
|---|---|---|---|
| **안전 게이트 조건** | `alert.playbook == 'service_restart'` | `== 'report_approve'` | `== 'rules_approve'` |
| **전달 파라미터** | `host`, `service` | `customer`, `host_filter`, `recipient` | `staged_path`, `active_path`, `staged_hash` |
| **실행 작업** | Ansible 서비스 재기동 | 리포트 렌더링·발송 | 규칙 파일 교체 + 게이트웨이 재기동 |

**검토 대상과 반영 대상의 동일성 보장(`--expect`):** 승인과 반영 사이에 재측정이 실행되면 검토한 내용과 다른 파일이 반영됩니다. 승인 시점 해시를 함께 전달하여 불일치 시 거부합니다. 월간 리포트의 초안 고정(`--from-draft`)과 동일한 원칙입니다.

**부수 설계:** 변경분만 제시(전체 파일 제시 시 검토가 형해화됨), 비율 30% 이상 변동·관측 일수 급감·규칙 전량 소멸 시 주의 표기, 이전 파일 시각 기준 보존, 변경 없으면 승인 요청 미생성(빈 요청 누적 시 실제 변경도 함께 통과됨).

**랩 실증 (2026-08-10):** 변경분 산출(추가 1·변경 1·삭제 1) → 승인 대기 등록 → UI 승인 → 해시 대조 통과 → 파일 교체 및 백업 생성 → 게이트웨이 재기동(`active`) 전 구간 확인.

### 5-3. 자동화 후보 레이블링 (`mark_automation_candidate.yml`)

반복(만성) 발생 인시던트에 대해 자동화 검토 후보 태그를 부착하는 워크플로입니다.

- **역할 분담:** 만성/재발/신규 장애 선판정(90일 발생 이력 연산)은 게이트웨이 파이프라인이 전담하고, Keep은 태그 부여(`enrich_alert`), 필터링 및 시각화 UI 역할을 담당합니다.
- **운영 규칙:** 자동 조치가 직접 실행되지 않으며, `automation_candidate = yes` 태그 부착 후 관제 담당자가 인시던트 모수를 확인하여 자동화 대상으로 등록하도록 지원합니다.

*(참고: 만성 판정 카운트의 API 조회 상한 포화 이슈는 [`docs/03-pitfalls/structural-gaps.md`](../docs/03-pitfalls/structural-gaps.md) G3 항목을 참조합니다.)*

### 5-4. 수동 분석 요청 (`analyze_now.yml`)

게이트웨이 발동 조건에 의해 분석이 생략된 알림에 대해, 관제 담당자가 임의 시점에 분석을 직접 요청하는 워크플로입니다.

- **적용 배경:** 관측 소스가 일부만 배선된 환경에서는 교차 신호 부재로 인한 생략 비율이 높습니다. 요청 경로가 없을 경우 봇의 판정이 최종 결정으로 확정되며, 담당자가 이를 번복할 수단이 존재하지 않습니다.
- **안전 게이트:** `alert.playbook == 'analyze'` — 데모 B(`service_restart`)·리포트 승인(`report_approve`)·규칙 교체(`rules_approve`)와 동일한 형태입니다.
- **사건 복원:** 알림 카드의 `analyze_ref` 속성(`소스,이벤트ID,트리거ID,유형`, 복수 시 `|` 연결)을 `bot/tools/analyze_now.py` 에 전달하여 요청 시점에 Zabbix 를 재조회합니다. 생략 시점의 컨텍스트를 저장하지 않는 이유는 경과 시간 동안의 상태 변화를 분석에 반영하기 위함입니다.
- **발동 조건 미적용:** 봇의 판정을 사람이 번복하는 절차이므로 조건을 재평가하지 않습니다(`run_incident(force=True)`).
- **네 번째 재사용 사례:** 승인·실행 계층을 신규 구성하지 않고 기존 Keep 워크플로 구조를 그대로 적용하였습니다.
- **부수 산출 (2026-08-12):** 담당자가 이 워크플로를 실행한 행위 자체가 **게이트 판정에 대한 음성 라벨**이므로, 실행 시 직전 판정에 자동으로 기록됩니다. 추가 조작을 요구하지 않고 축적되는 유일한 라벨입니다.

### 5-5. 판정 확인·정정 (`judgment_confirm.yml` · `judgment_correct.yml`)

봇의 판정에 대해 관제 담당자가 정오 여부를 표시하는 워크플로입니다. 여기서 수집된 라벨이 판정 정확도 산출의 분자·분모가 되며, 정답으로 확인된 결론만 차기 사건의 과거 결론으로 재사용됩니다(`bot/GATEWAY_GUIDE.md` §25).

- **다섯 번째 재사용 사례:** 조치·리포트 발송·규칙 교체·재분석에 이어 동일 구조를 적용하였습니다.
- **버튼 2종 구성:** 정정 단독 구성 시 분모가 성립하지 않아 정확도를 산출할 수 없으며, 라벨이 오류 방향으로 편향됩니다(수고를 감수하고 조작하는 담당자는 대부분 오판이라 인지한 경우임).
- **안전 게이트 위치 변경:** 본 워크플로는 게이트를 워크플로 `if:` 가 아니라 **SSH 명령 내부**(`test -n '{{ alert.judgment_id }}'`)에 둡니다. `if:` 로 차단할 경우 건너뛴 실행이 성공으로 표시되어, 판정 식별자가 없는 카드에서 실행해도 담당자는 라벨이 기록된 것으로 인지합니다. 명령 내부에 두면 종료코드가 0이 아니므로 실행 이력에 실패로 남습니다.
- **오귀속 방지:** `judgment_id` 와 `fingerprint` 를 함께 전달하여 불일치 시 거부합니다. Keep 이 지문 기준으로 카드를 병합하므로, 카드가 최신 판정으로 갱신된 뒤에도 화면에 옛 식별자가 잔존할 수 있습니다.
- **축 구성:** 초기에는 `overall` 단일 축만 사용합니다. 게이트·병합·원인으로 분리 시 버튼이 6종이 되어 라벨 수집량이 감소합니다. 저장 구조는 축을 보유하므로 이력 손실 없이 분리 가능합니다.

---

---

## 6. 알려진 기술적 제약 사항 (Adoption Risks)

- **Keep UI 상의 워크플로 생성 제약:** Keep UI 내에서 신규 워크플로 직접 생성 시 특정 조건에서 `workflow_raw_data: null` 오류가 발생할 수 있으므로, 파일 기반 프로비저닝(Provisioning) 방식을 기본 표준으로 적용합니다.
- **UI 접속에 포트 3종 필요 (2026-08-10 실측):** 사설망 환경에서 SSH 터널로 접속할 경우 **3000(UI)·8080(API)·6001(WebSocket)** 을 모두 포워딩해야 합니다. 8080 누락 시 화면은 표시되나 데이터가 조회되지 않으며, **6001 누락 시 무한 로딩 상태로 원인이 드러나지 않습니다**(3000·8080이 정상 응답하므로 연결 문제로 인지되지 않음). 프론트엔드가 브라우저에 알리는 주소는 `NEXT_PUBLIC_API_URL`·`PUSHER_HOST` 환경변수로 확인합니다.
- **인증 헤더 파싱 실패:** 과거 세션 데이터가 잔존할 경우 백엔드 로그에 `Failed to parse Authorization header` 가 기록되며 조회가 전량 거부됩니다. 브라우저 저장 데이터 삭제 또는 시크릿 창으로 확인합니다.
- **Keep 내장 Zabbix Provider 버전 호환성:** Keep 네이티브 Zabbix Provider 모듈이 Zabbix 7.0 API 파라미터 규격과 충돌을 일으키므로, 알림 데이터 인입은 게이트웨이 Push 방식을 권장합니다.