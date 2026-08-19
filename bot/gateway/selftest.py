"""셀프테스트 실행기. 검사는 `gateway/checks/` 에 영역별로 있다.

    python -m gateway.selftest

**한 파일이 6,801줄이었다.** 검사를 하나 더할 때마다 어디에 넣을지 매번 찾았고, 실패한
검사를 읽으려면 그 파일 안을 헤맸다. 2026-08-19 에 영역별로 나눴고 검사 내용은 그대로다.
총 assert 수가 유지되는지는 아래 `_assert_count` 가 센다 — 나누다 빠뜨리면 그 숫자가 준다.
"""

import logging
import os
import sys
import time

from . import llm, masking
from .alerts import collector, prejudge, router, severity
from .checks.common import (CASES_CLASSIFY, CASES_ROUTER, CASES_SEVERITY, _assert_count,
                            _read_source)
from .checks.ask import (_ask_dispatch_checks,
    _ask_loop_checks,
    _ask_masking_checks,
    _ask_question_checks,
    _ask_result_checks,
    _ask_scope_checks,
    _ask_table_checks,
    _ask_tool_checks,
    _ask_user_checks,
    _cache_checks,
    _cap_answer_checks,
    _convo_checks,
    _empty_table_checks,
    _event_loop_checks,
    _graph_engine_checks,
    _graph_state_checks,
    _item_rank_checks,
    _list_truncation_checks,
    _log_cap_checks,
    _metric_batch_checks,
    _model_tier_checks,
    _no_evidence_checks,
    _now_context_checks,
    _panel_route_checks,
    _panel_status_checks,
    _panel_window_checks,
    _prewarm_checks,
    _prompt_file_checks,
    _query_masking_checks,
    _session_isolation_checks,
    _table_cache_checks,
    _tool_schema_checks,
    _tool_timeout_checks,
    _tracing_checks,
    _usage_metadata_checks)
from .checks.alerts import (_analyze_ref_checks,
    _class_map_checks,
    _class_tag_checks,
    _collect_failure_checks,
    _contract_checks,
    _destructive_advice_checks,
    _event_time_checks,
    _fastpath_checks,
    _holmes_egress_checks,
    _holmes_gate_checks,
    _idempotency_checks,
    _incident_checks,
    _log_select_checks,
    _open_limit_checks,
    _open_link_checks,
    _open_link_masking_checks,
    _open_link_rule_checks,
    _overflow_checks,
    _remediation_checks,
    _site_keyword_checks,
    _source_status_checks,
    _timer_close_checks,
    _truncation_checks,
    _wrong_server_checks)
from .checks.masking import (_model_kind_wiring_checks,
    _nametable_checks,
    _nametable_freshness_checks,
    _proxy_gate_checks,
    _proxy_mask_checks,
    _registry_fill_checks,
    _repo_secret_checks,
    _tenant_scope_checks,
    _token_scope_checks)
from .checks.store import (_annotation_checks,
    _dashboard_annotation_checks,
    _evidence_checks,
    _feedback_checks,
    _judgment_wiring_checks,
    _prior_checks,
    _quality_checks,
    _route_record_checks,
    _select_invariant_checks,
    _store_checks,
    _store_schema_checks)
from .checks.ops import (_flush_checks,
    _heartbeat_checks,
    _llm_concurrency_checks,
    _pending_checks,
    _registry_checks)

log = logging.getLogger("gateway.selftest")


def main():
    fails = 0
    for source, level, expected in CASES_SEVERITY:
        got = severity.normalize(source, level)
        if got != expected:
            fails += 1
            print(f"FAIL severity: ({source},{level}) -> {got}, expected {expected}")
    for sev, tags, value, expected in CASES_ROUTER:
        got = router.decide(sev, tags, value)["route"]
        if got != expected:
            fails += 1
            print(f"FAIL router: ({sev},{tags},{value}) -> {got}, expected {expected}")
    assert severity.notifies("SEV1") and severity.notifies("SEV2")
    assert not severity.notifies("SEV3") and not severity.notifies("SEV4")

    # 만성/신규 선판정 — 결정적 판정 검증
    now = time.time()
    day = 86400
    # 창과 만성 하한을 인자로 준다. 배포된 서버에서 그대로 돌리면 그 서버의 값을 읽어
    # 실패하고(랩은 PREJUDGE_CHRONIC_MIN=20), 설정이 맞는지 코드가 틀렸는지 알 수 없다.
    fix = {"window_s": 90 * day, "chronic_min": 5}
    j = prejudge.judge([], now=now, **fix)
    assert j["verdict"] == "신규" and j["count_window"] == 0, j
    j = prejudge.judge([now - 2 * day, now - 30 * day], now=now, **fix)
    assert j["verdict"] == "재발" and j["count_window"] == 2 and j["last_seen_days"] == 2.0, j
    j = prejudge.judge([now - i * 10 * day for i in range(1, 7)], now=now, **fix)
    assert j["verdict"] == "만성" and j["count_window"] == 6, j
    j = prejudge.judge([now - 120 * day], now=now, **fix)   # 창 밖 이력은 무시 → 신규
    assert j["verdict"] == "신규", j

    # 만성 하한은 횟수가 아니라 재발 간격에서 나온다. 창을 늘리면 하한도 같이 올라가야
    # 한다 — 안 그러면 같은 값이 조용히 두 배로 느슨해진다.
    assert prejudge.chronic_min_for(90, 30) == 3, "월 1회 = 90일에 3회"
    assert prejudge.chronic_min_for(180, 30) == 6, "창이 두 배면 하한도 두 배"
    assert prejudge.chronic_min_for(90, 10) == 9, "ITIL 관행(30일 3건) 환산"
    assert prejudge.chronic_min_for(30, 30) == 2, "1회는 반복이 아니므로 하한 2"
    assert prejudge.chronic_min_for(90, 0) == 2, "간격 0 이어도 죽지 않아야"
    assert prejudge.chronic_min_for(90, 100) == 2, "창보다 긴 간격도 하한 2"

    # 발생 횟수는 목록 길이가 아니라 따로 센 개수를 쓴다. 목록은 상한에 걸리므로
    # 상한을 넘는 것들이 전부 같은 수로 보이면 무엇이 더 자주 나는지 가릴 수 없다
    # (실환경 90일: 상한 초과 12계열이 이벤트의 95%, 실제 값은 547~21,585회).
    from .alerts import collector as _col
    lim = _col.PAST_EVENT_LIMIT
    packed = [now - (i % 80) * day for i in range(lim)]      # 창 안에 상한만큼
    j = prejudge.judge(packed, now=now, **fix)
    assert j["count_window"] == lim and j["count_truncated"] is True, j
    assert "상한" in j["statement"], j["statement"]

    j = prejudge.judge(packed, now=now, total_count=3000, **fix)
    assert j["count_window"] == 3000 and j["count_truncated"] is False, j
    assert "상한" not in j["statement"], j["statement"]

    # 개수가 목록보다 작게 오면(창 경계에서 어긋날 수 있다) 목록 길이를 쓴다 —
    # 실제로 본 것보다 적게 세지 않는다.
    j = prejudge.judge(packed, now=now, total_count=3, **fix)
    assert j["count_window"] == lim, j

    # 응답 형태가 이상하면 개수를 지어내지 않는다
    assert _col._as_count("41") == 41
    assert _col._as_count(41) == 41
    assert _col._as_count(["a"]) is None
    assert _col._as_count(None) is None
    prejudge_checks = 19

    # 수집기 읽기 전용 가드 — .get 이외 메서드는 코드 레벨에서 거부
    import asyncio

    from .alerts import collector
    zbx = collector.ZabbixClient(url="http://invalid", token="x")

    async def _guard():
        try:
            await zbx.call(None, "host.create", {})
            return False
        except ValueError:
            return True
    assert asyncio.run(_guard()), "read-only guard failed"

    # 마스킹 — 가역 치환 + 화이트리스트에 원문 식별자 부재
    import json
    import os

    from . import llm, masking
    mk = masking.Masker()
    ctx = {
        "event": {"name": "disk on lab-web01", "clock": "1"},
        "trigger": {"description": "d", "expression": "last(/lab-web01/key)>90"},
        "host": {"host": "lab-web01", "interfaces": [{"ip": "192.0.2.5"}],
                 "hostgroups": [{"name": "Customer-A"}]},
        "metrics": [],
        "logs": ["lab-web01 sshd: login from 192.0.2.9 user admin"],   # Loki 라인
        "security": [{"level": 10, "desc": "brute force on lab-web01", "ts": "t",
                      "rule_id": "5712", "groups": "authentication_failed",
                      "path": "/etc/ssh/lab-web01.conf", "change": "modified"}],
        "prejudge": {"verdict": "신규", "statement": "s"},
        "secret_field": "MUST-NOT-LEAK",   # 화이트리스트 밖 필드
    }
    masked = masking.build_llm_context(ctx, "SEV2", mk)
    blob = json.dumps(masked, ensure_ascii=False)
    assert "lab-web01" not in blob, "hostname leaked"
    assert "192.0.2.5" not in blob, "ip leaked"
    assert "192.0.2.9" not in blob, "log-line ip leaked"      # 로그 라인 IP 마스킹
    assert "Customer-A" not in blob, "customer group leaked"
    assert "MUST-NOT-LEAK" not in blob, "non-whitelisted field leaked"
    assert masked["logs"] and masked["security"], "logs/security dropped"
    assert masked["security"][0]["path"] and "lab-web01" not in masked["security"][0]["path"], \
        "syscheck path 의 호스트명이 마스킹되지 않음"
    assert masked["security"][0]["rule_id"] == "5712", "rule_id 가 전송되지 않음"
    assert mk.unmask(mk.mask("lab-web01 at 192.0.2.5")) == "lab-web01 at 192.0.2.5"

    # 월간 리포트 경로도 같은 규율을 받는다 — 이쪽은 나가는 곳이 고객 문서라 더 엄격하다.
    mk2 = masking.Masker()
    incs = [{"host": "custa-db-01", "name": "복제 지연 on custa-db-01", "prejudge": "만성",
             "alert_count": 2, "classes": "replication", "sources": "logs:ok",
             "analysis": "MUST-NOT-LEAK-ANALYSIS", "secret": "MUST-NOT-LEAK-FIELD"}]
    for a in incs:
        mk2.register("host", a["host"])
    mblob = json.dumps(llm.build_monthly_context(
        {"report.incidents": 1, "report.summary": "MUST-NOT-LEAK-SUMMARY"}, incs, mk2),
        ensure_ascii=False)
    assert "custa-db-01" not in mblob, "monthly hostname leaked"
    assert "MUST-NOT-LEAK-FIELD" not in mblob, "monthly non-whitelisted field leaked"
    # 사건별 분석 본문은 월간 입력에 넣지 않는다 — 월 단위 판단에 불필요하고 반출만 늘린다.
    assert "MUST-NOT-LEAK-ANALYSIS" not in mblob, "monthly analysis body leaked"
    # 승인 전 자리표시자를 LLM 에 넣으면 모델이 그걸 사실로 읽는다.
    assert "MUST-NOT-LEAK-SUMMARY" not in mblob, "monthly summary placeholder leaked"
    masking_checks = 13

    # 열화 모드 — LLM 어댑터 전멸 시 선판정만으로 회신 (외부 호출 0)
    for k in ("ANTHROPIC_API_KEY", "OLLAMA_URL"):
        os.environ.pop(k, None)
    reply = llm.triage_reply(ctx, "SEV2")
    assert reply["degraded"] and reply["provider"] == "none" and "신규" in reply["text"], reply
    degraded_checks = 1

    incident_checks = _incident_checks()
    source_checks = _source_status_checks()
    remediation_checks = _remediation_checks()
    holmes_checks = _holmes_gate_checks()
    fastpath_checks = _fastpath_checks()
    open_link_checks = _open_link_checks()
    site_kw_checks = _site_keyword_checks()
    class_tag_checks = _class_tag_checks()
    class_map_checks = _class_map_checks()
    pending_checks = _pending_checks()
    idem_checks = _idempotency_checks()
    overflow_checks = _overflow_checks()
    timer_checks = _timer_close_checks()
    holmes_eg_checks = _holmes_egress_checks()
    tenant_checks = _tenant_scope_checks() + _contract_checks()
    nametable_checks = _nametable_checks()
    proxy_checks = (_proxy_mask_checks() + _ask_masking_checks()
                    + _ask_question_checks() + _ask_scope_checks()
                    + _ask_tool_checks() + _ask_result_checks() + _tool_schema_checks() + _cache_checks() + _item_rank_checks() + _registry_fill_checks() + _proxy_gate_checks()
                    + _panel_window_checks() + _model_tier_checks() + _graph_state_checks() + _prompt_file_checks()
                    + _panel_route_checks()
                    + _ask_dispatch_checks() + _cap_answer_checks()
                    + _query_masking_checks() + _empty_table_checks()
                    + _log_cap_checks() + _prewarm_checks()
                    + _repo_secret_checks() + _session_isolation_checks()
                    + _panel_status_checks() + _token_scope_checks()
                    + _event_loop_checks() + _nametable_freshness_checks()
                    + _model_kind_wiring_checks() + _now_context_checks()
                    + _no_evidence_checks() + _metric_batch_checks()
                    + _tool_timeout_checks() + _table_cache_checks()
                    + _list_truncation_checks() + _tracing_checks()
                    + _usage_metadata_checks()
                    + _ask_table_checks() + _ask_loop_checks()
                    + _ask_user_checks() + _convo_checks()
                    + _graph_engine_checks())
    store_checks = (_store_checks() + _store_schema_checks()
                    + _judgment_wiring_checks() + _feedback_checks()
                    + _route_record_checks() + _annotation_checks()
                    + _evidence_checks() + _select_invariant_checks()
                    + _quality_checks() + _prior_checks()
                    + _dashboard_annotation_checks())
    collect_fail_checks = (_collect_failure_checks() + _truncation_checks()
                           + _log_select_checks() + _destructive_advice_checks())
    wrong_srv_checks = _wrong_server_checks()
    evt_time_checks = _event_time_checks()
    open_limit_checks = _open_limit_checks()
    analyze_checks = _analyze_ref_checks()
    beat_checks = _heartbeat_checks()
    registry_checks = _registry_checks()
    concurrency_checks = _llm_concurrency_checks()
    flush_checks = _flush_checks()

    if fails:
        raise SystemExit(f"{fails} case(s) failed")
    declared = (len(CASES_SEVERITY) + len(CASES_ROUTER) + 2 + prejudge_checks + 1
                + masking_checks + degraded_checks + incident_checks + source_checks
                + remediation_checks + holmes_checks + fastpath_checks + open_link_checks
                + site_kw_checks + class_tag_checks + class_map_checks + pending_checks
                + analyze_checks + beat_checks + flush_checks + registry_checks + idem_checks + overflow_checks + timer_checks + holmes_eg_checks + tenant_checks + collect_fail_checks + nametable_checks + proxy_checks + store_checks + wrong_srv_checks + evt_time_checks + open_limit_checks
                + concurrency_checks)
    counted = _assert_count()
    print(f"ALL OK ({counted} asserts / 선언 {declared})")
    # 선언 숫자는 사람이 적는다. 실제보다 작으면 어딘가 검사가 세어지지 않은 것이고,
    # 지나치게 크면 지운 검사의 숫자가 남은 것이다. 반복문 안의 assert 때문에 정확히
    # 같을 수는 없으므로, 눈에 띄게 벌어질 때만 알린다.
    if not (counted * 0.7 <= declared <= counted * 2.0):
        print(f"[!] 선언 {declared} 과 실제 {counted} 가 많이 어긋난다 — 검사 개수를 확인할 것")

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")
    main()
