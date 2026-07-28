# Keep — HITL 자가치유 워크플로 (Keep → SSH → Ansible)

Keep(keephq)을 알림 저장·UI + 승인 + Ansible 실행 허브로 쓰는 데모 B 배선. 평가 근거·판정은
`private/docs/keep_evaluation_plan.md`. 아키텍처(봇·HolmesGPT 분석이 Keep에 수렴)는 그 문서 참조.

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

## 알려진 마찰 (도입 리스크)

- Keep UI "새 워크플로 생성"이 일부 상황에서 `workflow_raw_data: null`로 실패 → 프로비저닝(파일)
  경로가 더 안정적.
- Keep 네이티브 Zabbix provider는 Zabbix 7.0에서 API 파라미터 에러 → 알림 유입은 게이트웨이
  push 권장.
