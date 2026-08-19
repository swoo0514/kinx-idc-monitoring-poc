"""대화형 질의 — 사람이 관측 화면에서 자연어로 묻는 창구. 설계는 bot/GATEWAY_GUIDE.md §27."""

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
from . import graph, tools  # noqa: F401
