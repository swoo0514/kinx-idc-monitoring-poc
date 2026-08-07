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

### 5-2. 자동화 후보 레이블링 (`mark_automation_candidate.yml`)

반복(만성) 발생 인시던트에 대해 자동화 검토 후보 태그를 부착하는 워크플로입니다.

- **역할 분담:** 만성/재발/신규 장애 선판정(90일 발생 이력 연산)은 게이트웨이 파이프라인이 전담하고, Keep은 태그 부여(`enrich_alert`), 필터링 및 시각화 UI 역할을 담당합니다.
- **운영 규칙:** 자동 조치가 직접 실행되지 않으며, `automation_candidate = yes` 태그 부착 후 관제 담당자가 인시던트 모수를 확인하여 자동화 대상으로 등록하도록 지원합니다.

*(참고: 만성 판정 카운트의 API 조회 상한 포화 이슈는 [`docs/03-pitfalls/structural-gaps.md`](../docs/03-pitfalls/structural-gaps.md) G3 항목을 참조합니다.)*

---

## 6. 알려진 기술적 제약 사항 (Adoption Risks)

- **Keep UI 상의 워크플로 생성 제약:** Keep UI 내에서 신규 워크플로 직접 생성 시 특정 조건에서 `workflow_raw_data: null` 오류가 발생할 수 있으므로, 파일 기반 프로비저닝(Provisioning) 방식을 기본 표준으로 적용합니다.
- **Keep 내장 Zabbix Provider 버전 호환성:** Keep 네이티브 Zabbix Provider 모듈이 Zabbix 7.0 API 파라미터 규격과 충돌을 일으키므로, 알림 데이터 인입은 게이트웨이 Push 방식을 권장합니다.