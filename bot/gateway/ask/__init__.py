"""대화형 질의 — 사람이 관측 화면에서 자연어로 묻는 창구. 설계는 bot/GATEWAY_GUIDE.md §27.

알림 경로는 컨텍스트를 `masking.build_llm_context` 화이트리스트가 지킨다. 질의 경로에는
그 보호가 없다. 사람은 호스트명이든 IP든 계정명이든 아무거나 친다.

**이 파일은 이름을 모아 두는 자리다.** 원래 한 파일(1,289줄)이었고 2026-08-19 에 옮기기만
했다. 밖에서는 예전처럼 `ask.run_ask`·`ask.build_table` 로 쓰면 된다.

    policy    질의가 닿을 수 있는 감시 영역
    table     조회 대상 표 — 표에 없으면 대상을 지정할 방법이 없다
    session   세션 역치환 표와 멈춤
    hygiene   질문 위생과 이력 자르기
    answer    답 조립·시스템 문구·손잡이 정리
    budget    사용자별 사용량
    loop      질의 반복문
    engine    엔진 선택과 LangGraph 경로
    fetch/    축별 조회기 (loki · wazuh · zabbix · judgments · panels)
    config    설정값과 고정 문구

**밖에서 갈아 끼우는 이름은 여기가 기준이다.** `build_table`·`fetch_problems`·
`FACTS_FILE`·`MAX_PER_USER_HOUR` 은 안쪽에서도 이 패키지를 통해 읽는다. 그래서 검사가
`ask.build_table = ...` 로 바꾸면 반복문 안에서도 그 값이 보인다.
"""

import logging

from .. import masking, proxy, registry   # noqa: F401  (밖에서 ask.proxy 로 쓴다)

log = logging.getLogger("gateway.ask")

from .config import (ANON, ASK_SYSTEM, CAP_NOTE, DEADLINE_S, DEFAULT_ALLOWED_REALMS,
                     DROP_NOTE, FACTS_FILE, HISTORY_MAX_CHARS, HISTORY_MAX_MSGS,
                     MAX_PER_USER_HOUR, MAX_ROUNDS, MENTION_MIN, NO_EVIDENCE,
                     PANELS_TTL_S, PREWARM_TIMEOUT_S, QUESTION_MAX_CHARS, RESULT_BYTES,
                     SESSION_TTL_S, TABLE_TTL_S, USER_MAX_CHARS)  # noqa: F401
from .policy import allowed_realms, allowed_sources, target_allowed  # noqa: F401
from .session import (_cancelled, _lock, _now, _sessions, cancel, cancelled,  # noqa: F401
                      forget_all, prune_cancels, prune_sessions, remember,
                      session_key, session_masker)
from .table import (_alias, _tables, build_table, forget_tables,  # noqa: F401
                    resolve_mentions)
from .hygiene import sanitize_question, trim_history  # noqa: F401
from .answer import (_blocks_text, chosen_images, load_facts, render_answer,  # noqa: F401
                     stall_note, strip_handles, system_prompt, with_evidence_note)
from .budget import user_budget_ok, who  # noqa: F401
from .fetch.judgments import fetch_judgments, judgment_body  # noqa: F401
from .fetch.loki import fetch_logs  # noqa: F401
from .fetch.panels import (fetch_panel, fetch_panel_list, var_host_of)  # noqa: F401
from .fetch.wazuh import fetch_security  # noqa: F401
from .fetch.zabbix import (fetch_metrics, fetch_problems, metric_item,  # noqa: F401
                           metrics_result, problems_result)
from .loop import drop_dangling, force_answer, prewarm, run_ask  # noqa: F401
from .engine import engine_name  # noqa: F401
