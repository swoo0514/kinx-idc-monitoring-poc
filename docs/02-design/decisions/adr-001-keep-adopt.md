# ADR-001 — Keep(keephq)을 알림 저장·UI·승인 substrate로 채택

**판정: 채택. 단 "게이트웨이가 먹여주는" 방식으로.** Keep이 Zabbix를 직접 당겨오게 하지 않고,
우리 게이트웨이가 Keep의 generic webhook으로 밀어 넣는다.

## 왜 평가했나

"인시던트 저장 + 볼 수 있는 UI + 만성→자동화 후보 + 심층 조사 연동"이 필요했는데, 이것을
**손으로 스키마를 짜서 만들면 Keep의 alerts/incidents/correlation과 그대로 겹칩니다.**
겹치는 것을 나중에 발견하면 만든 것을 버리게 되므로, 만들기 전에 채택 여부를 실측으로
정했습니다. HolmesGPT 평가와 같은 규율 — **하드 요건에 걸어 채점하고, 통과하면 채택합니다.**

## Keep이 주는 것 (공식 문서 확인)

- **자체 스키마** — alerts / incidents / correlation groups 정규화 테이블
- **DB 백엔드** — SQLite·**MySQL/MariaDB**·PostgreSQL·SQL Server (우리 MariaDB 재사용 가능)
- **셀프호스트 Docker Compose 단일 노드** — **쿠버네티스 불필요**. 온프렘 VM에 적합
- **UI 내장**, 디듑(fingerprint), 상관, **워크플로**(YAML 트리거/스텝/액션)
- Zabbix provider (6.0+)

## 채점 결과

| 요건 | 하드 | 판정 |
|---|---|---|
| KR-1 Zabbix 알림 실제 수집 | 필수 | **PASS (단 얕음)** — 문제가 Alerts로 들어오지만 아래 KR-3 참조 |
| KR-2 마스킹 경계(MSP) | **하드** | pull 모드는 저위험 — 저장 JSON에 호스트명·IP가 거의 없음. 단 push로 가면 마스킹 필요 → **게이트웨이 앞단에서 해결** |
| KR-3 상관 역할 중복 | 필수 | **기본값 위험** — fingerprint가 설명 기준이라 **서로 다른 고객의 같은 트리거를 호스트 구분 없이 1건으로 병합**. 상세 화면에 호스트조차 안 뜸 = 멀티테넌트 부적합 |
| KR-4 만성→자동화 후보 | 필수 | Keep 네이티브 아님 → **우리 분석 층이 담당** |
| KR-5 조치·읽기 전용 원칙 | **하드** | Keep의 Zabbix 통합은 **쓰기**를 요구(media type·script·action 생성). 랩은 무방하나 **실환경 읽기 전용 원칙과 충돌** → push-only·전용 계정으로 제한 필요 |
| KR-6 HITL + Ansible | 필수 | **PASS (실증)** — 아래 참조 |
| KR-7 심층 조사 enrichment | 참고 | 가능 (API/워크플로) |
| KR-8 온프렘·규모 | 참고 | Docker Compose 온프렘 OK. 고알림량 DB 연결 이슈 보고가 있으나 우리 규모와 무관 |

### 결정적 발견 — 네이티브 Zabbix provider가 7.0에서 버그

push 웹훅 설치를 실행한 결과: 설치 자체는 200을 반환하지만 **`Keep` 미디어타입이 깨끗하게
생성되지 않았고**, provider가 `Invalid parameter "/": cannot be empty.` /
`the parameter "eventids" is missing.` 오류를 5초마다 반복했습니다. Zabbix 7.0이 provider의
호출을 거부하는 것으로, **초기 pull 몇 건은 통과했으나 다수 호출이 실패**했습니다.

→ **Keep 네이티브 Zabbix 연동은 우리 버전에서 부적합**입니다.

### KR-6 실증 — Keep 워크플로가 Ansible을 실제로 실행한다

경로: Keep SSH provider(paramiko) → 관측 코어(Ansible control node) →
`ansible-playbook remediate_service.yml`. 결과가 Keep step 출력으로 돌아옵니다 —
`PLAY RECAP ok=7 changed=1 failed=0`, `before: inactive -> after: active`.

**의미: Keep은 "알림 저장 + UI + 승인 + Ansible 실행"을 한 도구로 합니다.** 데모 B(HITL
자가 치유)를 Keep으로 구현할 수 있고, 별도 GUI 워크플로 엔진(n8n)을 추가할 이유가 없어집니다.
주 화면이 Grafana와 Keep 둘로 수렴합니다.

도입 마찰도 함께 기록합니다 — ① UI의 "새 워크플로 생성"이 500 에러(생성 버그)라 파일이나
API로 우회해야 함 ② SSH provider에 개인키 원문을 저장해야 함 ③ 워크플로 파일은
**Keep을 재시작할 때만** 읽습니다.

## 최종 판정

**채택 유효. 단 턴키가 아니라 "채택 + 통합"입니다.**

스토어·UI·디듑·워크플로·양방향 액션을 공짜로 주므로 손 스키마보다 낫습니다(도루묵 회피 확인).
그러나 ① 네이티브 provider가 7.0에서 버그 ② 기본 pull은 호스트가 없어 얕음 ③ 마스킹은
앞단이 필요 — 이 셋이 **하나의 아키텍처 결정으로 동시에 해소**됩니다.

```
게이트웨이(마스킹 · 분류 · 만성 판정 · host 포함)
        │  generic webhook push
        ▼
      Keep (저장 · UI · 디듑 · 워크플로 승인)  ←  심층 조사 결과 enrichment
```

역할 분담: **Keep** = 저장·디듑·UI·워크플로 substrate / **우리 봇** = 실시간 30초·마스킹·
**만성 판정**(Keep이 안 해주는 것) / **심층 조사** = 온디맨드 enrichment.

## 결정 규칙 (판단을 재사용할 때)

- 하드 요건(마스킹·읽기 전용)이 **해소 가능**하고 기능 요건이 대체로 통과 → 채택하고 손 스키마 폐기
- 마스킹을 Keep 앞에 못 세우면 → MSP 데이터에는 직접 투입 불가 → 사내 한정 채택 또는 프록시 선행
- 쓰기가 실환경에 부담이면 → push-only·전용 계정으로 제한
- 둘 다 막히면 → 최소 자체 스토어로 후퇴하되 **스키마를 단순·표준적으로 유지**해 나중 이관 비용을 줄임

배선 절차는 [`keep/KEEP_GUIDE.md`](../../../keep/KEEP_GUIDE.md).

## 출처 (공식)

- Keep 정체·기능·DB·배포: <https://github.com/keephq/keep>, <https://docs.keephq.dev>
- Docker 배포(3컨테이너): <https://docs.keephq.dev/deployment/docker>
- Zabbix provider: <https://docs.keephq.dev/providers/documentation/zabbix-provider>
