"""게이트웨이 순수 로직 셀프테스트 (fastapi 불필요 — severity/router만 검증).

실행: python -m gateway.selftest   (bot/ 디렉토리에서)
전부 통과하면 'ALL OK'를 출력한다. docs/02-design/severity-normalization.md 표와의
일치가 검증 대상이다 — 표를 고치면 이 케이스부터 고친다.
"""

import shutil
import time

from . import prejudge, router, severity

CASES_SEVERITY = [
    # (source, level, expected)
    ("zabbix-internal", 5, "SEV1"),
    ("zabbix-internal", 4, "SEV2"),
    ("zabbix-internal", 3, "SEV3"),
    ("zabbix-internal", 2, "SEV4"),   # 사내 Warning = 노이즈 → SEV4
    ("zabbix-internal", 0, "NONE"),
    ("zabbix-msp", 2, "SEV3"),        # MSP Warning = 신호 → SEV3 (비대칭 핵심)
    ("zabbix-msp", 5, "SEV1"),
    ("wazuh", 15, "SEV1"),
    ("wazuh", 14, "SEV1"),
    ("wazuh", 12, "SEV2"),
    ("wazuh", 10, "SEV2"),            # 팀 Slack 컷라인(10+) 보존 — 브루트포스 룰 5712
    ("wazuh", 9, "SEV3"),
    ("wazuh", 7, "SEV3"),
    ("wazuh", 6, "SEV4"),
    ("wazuh", 3, "SEV4"),
    ("wazuh", 2, "NONE"),
    ("wazuh", 0, "NONE"),
    ("unknown-source", 3, "SEV2"),    # 페일세이프: 미지 소스는 SEV2
    ("wazuh", 99, "SEV2"),            # 페일세이프: 범위 밖 레벨
]

CASES_ROUTER = [
    # (sev, tags, event_value, expected_route)
    ("SEV1", [], 1, "triage"),
    ("SEV2", [], 1, "triage"),
    ("SEV2", [{"tag": "automate", "value": "service_restart"}], 1, "remediate"),
    ("SEV2", [{"tag": "automate", "value": "service_restart"},
              {"tag": "scope", "value": "notify_only"}], 1, "triage"),  # 계약이 조치를 차단
    ("SEV3", [], 1, "digest"),
    ("SEV4", [], 1, "dashboard_only"),
    ("NONE", [], 1, "drop"),
    ("SEV1", [], 0, "resolve"),       # 복구 이벤트
]


# 분류 — Zabbix 7.0 표준 템플릿 트리거명·랩 실측 알림명·Wazuh 룰 설명 기준 (G2a).
# 오분류는 인시던트 키를 갈라 병합·브리지를 조용히 실패시키므로 케이스를 넓게 잠근다.
CASES_CLASSIFY = [
    ("MySQL: Replication lag is too high (over 60 for 5m)", "replication"),
    ("MySQL 복제 지연 512초", "replication"),
    ("Linux: Load average is too high (per CPU load over 1.5 for 5m)", "cpu_io_pressure"),
    ("high iowait on data volume", "cpu_io_pressure"),
    ("Linux: High CPU utilization (over 90% for 5m)", "cpu_io_pressure"),
    ("CPU 사용률 95%", "cpu_io_pressure"),
    ("Linux: High memory utilization (>90% for 5m)", "memory_pressure"),
    ("메모리 사용률 95% 초과", "memory_pressure"),          # 예전엔 disk_space 로 오분류
    ("Linux: High swap space usage", "memory_pressure"),
    ("Out of memory (OOM) killer invoked", "memory_pressure"),
    ("Linux: FS [/]: Space is critically low (used > 90%)", "disk_space"),
    ("디스크 사용률 92%", "disk_space"),
    ("Filesystem /data is running out of free inodes", "disk_space"),
    ("SSH 브루트포스 탐지", "auth_security"),
    ("sshd: Attempt to login using a non-existent user", "auth_security"),
    ("Linux: SSH service is down", "service_down"),          # 예전엔 auth_security 로 오분류
    ("Zabbix agent is not available (for 3m)", "service_down"),   # 예전엔 other
    ("Nginx process is not running", "service_down"),
    ("Interface eth0(): Link down", "network"),              # 예전엔 service_down("down")
    ("Interface eth0(): High error rate", "network"),
    # 한글 알림명 — 클래스마다 한글 키워드가 고르지 않아 21/41 이 틀렸다(전수 감사).
    # 특히 "응답 없음"은 느린 것이 아니라 죽은 것인데 service_latency 의 "응답"이 가로챘고,
    # service_down 에는 한글이 "재기동" 하나뿐이었다.
    ("Ethernet1/1: 인바운드 에러 급증", "network"),
    ("인터페이스 링크 다운", "network"),
    ("패킷 유실 급증", "network"),
    ("회선 단절", "network"),
    ("SSH 서비스 응답 없음", "service_down"),
    ("웹 서비스 무응답", "service_down"),
    ("서버 무응답 (ping fail)", "service_down"),
    ("프로세스 다운 - nginx", "service_down"),
    ("nginx 프로세스 중지됨", "service_down"),
    ("서비스 정지", "service_down"),
    ("데몬 죽음", "service_down"),
    ("포트 미개방", "service_down"),
    ("응답 시간 초과", "service_latency"),      # "응답"이 여기 남아야 하는 경우
    ("웹 응답 지연", "service_latency"),
    ("큐 적체", "service_latency"),
    ("디스크 응답 지연", "cpu_io_pressure"),    # 지연이지만 자원 압박 — 앞 순서가 이긴다
    ("부하 평균 높음", "cpu_io_pressure"),
    ("아이오웨이트 상승", "cpu_io_pressure"),
    ("리플리케이션 끊김", "replication"),
    ("로그인 실패 반복", "auth_security"),
    ("권한 상승 시도", "auth_security"),
    ("디스크 여유 공간 부족", "disk_space"),
    ("파일시스템 가득 참", "disk_space"),
    ("루트 파티션 용량 부족", "disk_space"),
    ("설정 파일 변경됨", "config_change"),      # auth_security 의 "파일 무결성"과 갈라진다
    ("패키지 목록 변경", "config_change"),
    ("Website response time is too high", "service_latency"),
    # 아래는 2026-08-10 실환경 90일 실측에서 미분류(other)로 확인돼 키워드를 보강한 것들.
    # 상위 유형이 미분류의 97%를 차지했고, 보강 후 기존 분류를 뺏은 건은 0건이었다.
    ("vdb: Disk read/write request responses are too high (read > 20 ms for 15m)",
     "cpu_io_pressure"),                                     # 미분류의 92%를 차지하던 단일 유형
    ("HAProxy acc-api-backend acc01: Health check error", "service_down"),
    ("HAProxy: has been restarted (uptime < 10m)", "service_down"),
    ("some-api.example.net is not response", "service_down"),
    ("No SNMP data collection", "service_down"),          # Zabbix 표준 SNMP 템플릿
    ("/etc/passwd has been changed", "auth_security"),
    # 보강이 기존 판정을 뺏지 않는지 고정한다 — "restarted" 가 network 를 가로채면 안 된다.
    ("Interface ae1: Link down after restart", "network"),
    # BGP 피어 단절은 회선 사건 — service_down 의 "down" 이 먼저 잡던 것을 고정한다
    ("BGP peer 10.0.0.1 is down", "network"),
    ("BGP 피어 다운", "network"),
    ("Route server BGP session flapping", "network"),
    # "무엇이 잘못됐나"가 아니라 "무엇이 바뀌었나" — 다른 축이라 별도 클래스로 둔다.
    ("Listened ports status (netstat) changed (new port opened or closed).", "config_change"),
    ("Linux: Number of installed packages has been changed", "config_change"),
    ("Operating system description has changed", "config_change"),
    # config_change 를 마지막에 둬야 앞 판정을 안 뺏는다 — 이 둘로 고정한다.
    ("/etc/passwd has been changed", "auth_security"),
    ("MySQL: Buffer pool utilization is too low", "other"),  # 미분류가 정답 — 지어내지 않는다
    ("무슨무슨 알림", "other"),
]


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
    from . import collector as _col
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

    from . import collector
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
                    + _ask_tool_checks() + _ask_result_checks() + _tool_schema_checks() + _cache_checks()
                    + _ask_dispatch_checks()
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


def _assert_count() -> int:
    """이 파일에 적힌 assert 문 수. 소스에서 세므로 손으로 못 어긋난다.

    각 검사 함수가 돌려주는 숫자는 사람이 적은 값이라 실제와 어긋날 수 있다. 실제로
    2026-08-11 에 숫자를 고치다가 같은 값이 먼저 나오는 다른 함수를 바꿨고, 합계가
    우연히 맞아 드러나지 않았다. 그러면 검사를 지워도 총계가 안 변해 티가 안 난다.

    반복문 안의 assert 는 여러 번 도니까 이 수가 실행 횟수는 아니다. 목적은 그게
    아니라 **검사를 지우면 숫자가 줄어드는 것**이다. 두 값을 같이 찍어서 어긋나면
    사람이 보게 한다.
    """
    import ast
    import io as _io
    with _io.open(__file__, encoding="utf-8") as f:
        tree = ast.parse(f.read())
    return sum(1 for n in ast.walk(tree) if isinstance(n, ast.Assert))


class _FakeHttpx:
    """collector.httpx 를 대신한다. 본 조회는 항상 0건이고, 이름 확인 응답만 바꾼다."""

    def __init__(self, known, wazuh_total, fail_check=False):
        self.known, self.wazuh_total, self.fail_check = known, wazuh_total, fail_check

    def AsyncClient(self, **_kw):
        outer = self

        class _Resp:
            def __init__(self, payload):
                self._p = payload

            def raise_for_status(self):
                pass

            def json(self):
                return self._p

        class _Client:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *_a):
                return False

            async def get(self, url, params=None, timeout=None):
                if "/values" in url:
                    if outer.fail_check:
                        raise RuntimeError("label values down")
                    return _Resp({"data": outer.known})
                return _Resp({"data": {"result": []}})

            async def post(self, url, json=None, auth=None, timeout=None):
                if (json or {}).get("size") == 0:
                    if outer.fail_check:
                        raise RuntimeError("indexer down")
                    return _Resp({"hits": {"total": {"value": outer.wazuh_total}}})
                return _Resp({"hits": {"hits": []}})

        return _Client()


def _source_status_checks() -> int:
    """G1 — "조회 실패"와 "신호 없음"의 구분이 수집기·게이트·마스킹·카드까지 전파되는지.

    이 구분이 없으면 Wazuh 인덱서 장애가 "침해 흔적 없음"으로 둔갑하고(프롬프트가 그렇게
    해석하라고 지시한다), 게이트는 교차 신호 0으로 보아 LLM을 스킵한다. 즉 관측 백엔드가
    죽을수록 봇이 조용해지고 자신만만해진다. 아래는 그 경로가 막혀 있는지 확인한다.
    외부 호출 0 — 미배선·라벨 미해석 경로만 검증한다.
    """
    import asyncio
    import os

    from . import collector, incident, llm, masking, slack

    # 축 면제·명부도 같이 지운다. 우선순위가 명부 → 축별 변수 → 옛 변수 순이라
    # 위쪽이 살아 있으면 아래 검사가 통째로 무너진다.
    saved = {k: os.environ.pop(k, None) for k in
             ("LOKI_URL", "WAZUH_INDEXER_URL", "LOGS_EXEMPT_HOSTS",
              "SECURITY_EXEMPT_HOSTS", "LOG_AXIS_EXEMPT_HOSTS", "HOST_REGISTRY_FILE")}
    try:
        # 미배선(URL 없음) = disabled, 호스트 라벨 미해석 = unavailable (성공이 아니다)
        assert asyncio.run(collector._loki_logs("h", 0))[:2] == ([], collector.SOURCE_DISABLED)
        assert asyncio.run(collector._wazuh_alerts("h", 0)) == ([], collector.SOURCE_DISABLED)
        os.environ["LOKI_URL"] = "http://127.0.0.1:1"
        assert asyncio.run(collector._loki_logs("", 0))[:2] == ([], collector.SOURCE_UNAVAILABLE)

        # 로그 축이 없는 것이 정상인 호스트는 조회하지 않는다 — 인증서·리포트용 가상 호스트를
        # 이름 불일치로 보면 알림마다 분석이 돌고 상한을 먼저 소진한다.
        os.environ["LOG_AXIS_EXEMPT_HOSTS"] = "cert-*,report-*"
        try:
            assert collector.axis_exempt("cert-example.com", "logs") is True
            assert collector.axis_exempt("cert-example.com", "security") is True
            assert collector.axis_exempt("node1", "logs") is False
            assert asyncio.run(collector._loki_logs("x", 0, "cert-example.com"))[:2] \
                == ([], collector.SOURCE_DISABLED)
            assert asyncio.run(collector._wazuh_alerts("x", 0, "report-Customer-B")) \
                == ([], collector.SOURCE_DISABLED)

            # 축을 따로 적으면 그 축만 꺼진다 — 컨테이너는 로그는 있고 보안 축이 없다
            os.environ["SECURITY_EXEMPT_HOSTS"] = "customer-*"
            os.environ["LOGS_EXEMPT_HOSTS"] = "cert-*"
            try:
                assert collector.axis_exempt("customer-a", "security") is True
                assert collector.axis_exempt("customer-a", "logs") is False, \
                    "축별 설정이 있으면 옛 변수로 되돌아가면 안 된다"
                assert asyncio.run(collector._wazuh_alerts("x", 0, "customer-a")) \
                    == ([], collector.SOURCE_DISABLED)
            finally:
                os.environ.pop("SECURITY_EXEMPT_HOSTS", None)
                os.environ.pop("LOGS_EXEMPT_HOSTS", None)
        finally:
            os.environ.pop("LOG_AXIS_EXEMPT_HOSTS", None)

        # dns 칸에 컨테이너 이름이 들어 있으면 쓰지 않는다 — 여러 호스트가 같은 이름을
        # 가질 수 있어 남의 로그를 이 호스트 것으로 읽는다 (랩 실측: zabbix-agent2·snmpsim)
        assert collector._resolve_label("lab-db", {"interfaces": [{"dns": "zabbix-agent2"}]}) \
            == "lab-db"
        assert collector._resolve_label("n2", {"interfaces": [{"dns": "n2.example.com"}]}) \
            == "n2.example.com"
        os.environ["HOST_LABEL_MAP"] = "n1=vm-target-001.novalocal"
        try:
            assert collector._resolve_label("n1", {"interfaces": [{"dns": "agent"}]}) \
                == "vm-target-001.novalocal", "명시 매핑이 dns 보다 우선이어야"
        finally:
            os.environ.pop("HOST_LABEL_MAP", None)

        # 0건일 때 이름 등록 여부로 ok / unmatched 를 가른다 (§1-1-2). 가짜 응답으로 검증.
        os.environ["WAZUH_INDEXER_URL"] = "https://127.0.0.1:1"
        real = collector.httpx
        try:
            collector.httpx = _FakeHttpx(known=["known-host"], wazuh_total=0)
            assert asyncio.run(collector._loki_logs("known-host", 0))[:2] == ([], collector.SOURCE_OK)
            assert asyncio.run(collector._loki_logs("other", 0))[:2] == ([], collector.SOURCE_UNMATCHED)
            assert asyncio.run(collector._wazuh_alerts("a", 0)) == ([], collector.SOURCE_UNMATCHED)
            collector.httpx = _FakeHttpx(known=[], wazuh_total=3)
            assert asyncio.run(collector._wazuh_alerts("a", 0)) == ([], collector.SOURCE_OK)
            # 확인 질의가 실패하면 판정할 수 없으므로 ok 로 내리지 않는다
            collector.httpx = _FakeHttpx(known=["known-host"], wazuh_total=0, fail_check=True)
            assert asyncio.run(collector._loki_logs("known-host", 0))[:2] == ([], collector.SOURCE_UNAVAILABLE)
            assert asyncio.run(collector._wazuh_alerts("a", 0)) == ([], collector.SOURCE_UNAVAILABLE)
        finally:
            collector.httpx = real
    finally:
        os.environ.pop("LOKI_URL", None)
        for k, v in saved.items():
            if v is not None:
                os.environ[k] = v

    # 게이트 — 조회 실패는 미상이므로 보수적 발동, 미배선은 의도된 구성이라 발동 사유 아님
    single = incident.Incident(
        key=("h1", "disk_space"), host="h1", opened_at=0.0, last_at=0.0,
        alerts=[incident.Alert(source="zabbix-internal", event_id="e", trigger_id="1",
                               host="h1", alert_name="disk", sev="SEV2",
                               incident_class="disk_space", recv=0.0)])
    base = {"logs": [], "security": []}
    ok_ctx = {**base, "sources": {"logs": collector.SOURCE_OK, "security": collector.SOURCE_OK}}
    fail_ctx = {**base, "sources": {"logs": collector.SOURCE_OK,
                                    "security": collector.SOURCE_UNAVAILABLE}}
    off_ctx = {**base, "sources": {"logs": collector.SOURCE_DISABLED,
                                   "security": collector.SOURCE_DISABLED}}
    for q in incident._fires.values():
        q.clear()
    assert incident.should_triage(single, ok_ctx)[0] is False, "정상 조회·무신호는 스킵이어야"
    fired, why = incident.should_triage(single, fail_ctx)
    assert fired is True and "조회 실패" in why, why
    assert incident.should_triage(single, off_ctx)[0] is False, "미배선은 발동 사유가 아니어야"

    # 이름 불일치(§1-1-2) — 조회는 됐지만 그 소스가 이 호스트를 모르므로 "없음"이 아니다
    un_ctx = {**base, "sources": {"logs": collector.SOURCE_UNMATCHED,
                                  "security": collector.SOURCE_OK}}
    fired, why = incident.should_triage(single, un_ctx)
    assert fired is True and "이름 불일치" in why, why

    # 절단은 조회한 쪽이 알려 준다. 받는 쪽이 개수로 추측하면, 조회 측이 현재
    # 이벤트를 목록에서 빼는 순간 199 가 되어 200 과 비교하는 판정이 영원히 안 걸린다.
    many = [1000.0 - i for i in range(199)]
    assert prejudge.judge(many, now=1000.0, listed_truncated=True)["count_truncated"] is True
    assert prejudge.judge(many, now=1000.0, listed_truncated=False)["count_truncated"] is False
    # 개수를 받았으면 절단이 아니다 — 목록이 잘렸어도 총계는 정확하다
    assert prejudge.judge(many, now=1000.0, total_count=5000,
                          listed_truncated=True)["count_truncated"] is False

    # 사유별 수치는 통제가 아니라 관측이다. 게이트는 몇 번이 오든 판단을 바꾸지
    # 않고, 대신 무엇 때문에 돌았는지를 센다. 부하 보호는 호출 지점이 맡는다.
    for q in incident._fires.values():
        q.clear()
    fired_n = sum(1 for _ in range(40)
                  if incident.should_triage(single, fail_ctx, now=500.0)[0])
    assert fired_n == 40, f"관측 수치가 판단을 막았다: {fired_n}"
    assert incident.fire_counts(now=500.0)["degraded"] == 40, incident.fire_counts(now=500.0)
    # 1시간이 지난 것은 세지 않는다 — 누계가 아니라 최근 1시간이어야 신호가 된다
    assert incident.fire_counts(now=500.0 + 3601)["degraded"] == 0
    for q in incident._fires.values():
        q.clear()
    assert "unmatched" in masking._STATUS_VALUES, "이름 불일치 상태가 전송 화이트리스트에 있어야"
    note = slack._source_note({"logs": collector.SOURCE_UNMATCHED,
                               "security": collector.SOURCE_OK})
    assert "이름 불일치" in note, note
    assert "unmatched" in llm.TRIAGE_SYSTEM, "프롬프트가 새 상태를 모르면 LLM 이 '없음'으로 읽는다"

    # 지식 공백 발동(§1-1-4) — 단일 소스 환경에서 처음 보는 문제는 발동, 만성은 스킵
    new_ctx = {**ok_ctx, "alerts": [{"prejudge": {"verdict": "신규"}}]}
    chronic_ctx = {**ok_ctx, "alerts": [{"prejudge": {"verdict": "만성"}}]}
    incident._fires["new"].clear()
    fired, why = incident.should_triage(single, new_ctx, now=1000.0)
    assert fired is True and "처음 보는 문제" in why, why
    assert incident.should_triage(single, chronic_ctx, now=1000.0)[0] is False, "만성은 스킵이어야"

    # 사유는 섞이지 않아야 한다. 섞이면 "관측 소스가 죽었다"와 "새 트리거를 대량으로
    # 붙였다"가 한 숫자로 합쳐져, 수치가 올라도 무엇을 고쳐야 할지 알 수 없다.
    for q in incident._fires.values():
        q.clear()
    for _ in range(7):
        incident.should_triage(single, new_ctx, now=1000.0)
    for _ in range(3):
        incident.should_triage(single, fail_ctx, now=1000.0)
    cnt = incident.fire_counts(now=1000.0)
    assert cnt == {"new": 7, "degraded": 3}, cnt
    for q in incident._fires.values():
        q.clear()

    # 마스킹 — 상태는 전송하되 알려진 키·값만(화이트리스트 유지)
    ctx = {"event": {"name": "n"}, "trigger": {}, "host": {}, "metrics": [],
           "logs": [], "security": [], "prejudge": {},
           "sources": {"logs": collector.SOURCE_OK,
                       "security": collector.SOURCE_UNAVAILABLE, "evil": "LEAK"}}
    masked = masking.build_llm_context(ctx, "SEV2", masking.Masker())
    assert masked["sources"] == {"logs": "ok", "security": "unavailable"}, masked["sources"]
    ctx["sources"]["security"] = "weird-value"
    masked = masking.build_llm_context(ctx, "SEV2", masking.Masker())
    assert masked["sources"]["security"] == "unknown", masked["sources"]

    # Slack 카드 — 실패를 사람 눈에 드러낸다
    note = slack._source_note({"logs": collector.SOURCE_OK,
                               "security": collector.SOURCE_UNAVAILABLE})
    assert "조회 실패" in note and "보안" in note, note
    assert slack._source_note({"logs": collector.SOURCE_OK,
                               "security": collector.SOURCE_OK}) == ""

    # 프롬프트와 코드의 동기 — 상태를 안 보는 프롬프트로 되돌아가면 실패
    assert "sources.security" in llm.TRIAGE_SYSTEM, "프롬프트가 조회 상태를 안 본다"
    assert "sources.open_problems" in llm.TRIAGE_SYSTEM, "프롬프트가 열린 문제 상태를 안 본다"
    # 축을 늘리면 프롬프트도 같이 늘어야 한다. 안 그러면 그 축이 실패했을 때 모델이
    # 빈 값을 "이상 없음"으로 읽는다.
    assert "sources.metrics" in llm.TRIAGE_SYSTEM, "프롬프트가 지표 축 상태를 안 본다"
    assert "collect_failed" in llm.TRIAGE_SYSTEM, "프롬프트가 알림별 수집 실패를 안 본다"
    # 화이트리스트가 실제로 통과시키는지 — 목록에 없으면 프롬프트에 안 실린다
    m = masking.Masker()
    built = masking.build_llm_context(
        {"incident": {"host": "h1"}, "host": {},
         "alerts": [{"name": "n", "source": "s", "sev": "SEV3", "class": "disk_space",
                     "error": "collect_failed"}],
         "logs": [], "security": [], "sources": {}}, "SEV3", m)
    assert built["alerts"][0].get("error") == "collect_failed",         f"수집 실패 표시가 전송 전에 사라진다: {built['alerts'][0]}"
    assert "stale" in llm.TRIAGE_SYSTEM, "프롬프트가 장기 미해소를 구분하지 않는다"
    return 47


def _class_map_checks() -> int:
    """분류 선언 파일 — 태그와 같은 선언이고 위치만 다르다.

    발행 측에 태그를 못 다는 동안 쓰며(실환경은 읽기 전용), 태그가 붙으면 무시된다.
    """
    import importlib
    import json
    import os
    import tempfile

    from . import incident as inc_mod

    doc = {"zabbix": {"Cert expires in # days": "config_change",
                      "Bogus name": "no_such_class"},
           "wazuh": {"533": "config_change"}}
    fd, path = tempfile.mkstemp(suffix=".json")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(doc, f, ensure_ascii=False)
    saved = os.environ.get("INCIDENT_CLASS_FILE")
    try:
        os.environ["INCIDENT_CLASS_FILE"] = path
        m = importlib.reload(inc_mod)
        # 모르는 클래스는 실어 오지 않는다 — 오타 하나가 판정을 통째로 바꾸면 안 된다
        assert len(m.CLASS_MAP_ZBX) == 1 and len(m.CLASS_MAP_WZH) == 1, m.CLASS_MAP_ZBX
        # 키는 정규화된 이름 — 호스트마다 항목이 늘지 않게
        assert m.classify("Cert expires in 30 days") == "config_change"
        assert m.classify("Cert expires in 7 days") == "config_change"
        # Wazuh 는 rule_id 로
        assert m.classify("아무 이름", rule_id="533") == "config_change"
        # 태그가 파일보다 우선
        tags = [{"tag": m.CLASS_TAG, "value": "network"}]
        assert m.classify("Cert expires in 30 days", tags=tags) == "network"
        # 파일에 없으면 키워드 폴백
        assert m.classify("Interface eth0(): Link down") == "network"

        # ── 배선 검사 — 함수가 맞게 도는 것과 그 함수가 불리는 것은 다른 문제다 ──
        # 위 검사들은 classify 를 직접 부른다. 실제로는 웹훅이 rule_id 를 안 넘겨서
        # 파일의 wazuh 절이 통째로 죽어 있었는데, 파일 로드 로그는 정상이라 설정한
        # 사람은 적용됐다고 믿었다. 그래서 웹훅이 넘기는지를 따로 본다.
        import shutil
        import tempfile

        from . import app as app_mod, pending

        importlib.reload(app_mod)
        # 이 검사는 실제 triage 경로를 태우므로 대기 파일에 쓴다. 배포된 서버에서
        # 돌리면 운영 대기 목록에 검사 기록이 들어가고, 재기동 때 그것이 되살아나
        # 없는 알림으로 사건이 열린다. 랩에서 실제로 그렇게 남아 있었다.
        _tmpd = tempfile.mkdtemp(prefix="classmap-test-")
        _saved_pending = pending.PATH
        pending.PATH = os.path.join(_tmpd, "pending.jsonl")

        class _FakeBg:
            def __init__(self):
                self.tasks = []

            def add_task(self, fn, *a, **kw):
                self.tasks.append((fn, a, kw))

        bg = _FakeBg()
        app_mod._dispatch(bg, "wazuh", "e1", "", "h1", "아무 이름", "SEV2",
                          {"route": "triage", "playbook": ""}, rule_id="533")
        alerts = [a[0] for _fn, a, _kw in bg.tasks if a]
        assert alerts, "triage 경로가 아무것도 안 넘겼다"
        assert alerts[0].incident_class == "config_change", \
            f"웹훅이 rule_id 를 분류로 안 넘긴다 — 파일의 wazuh 절이 죽는다: {alerts[0].incident_class}"
        # 검사가 운영 대기 목록을 건드리지 않았는지도 본다
        assert pending.PATH.startswith(_tmpd), pending.PATH
        pending.PATH = _saved_pending
        shutil.rmtree(_tmpd, ignore_errors=True)
        return 9
    finally:
        os.unlink(path)
        if saved is None:
            os.environ.pop("INCIDENT_CLASS_FILE", None)
        else:
            os.environ["INCIDENT_CLASS_FILE"] = saved
        importlib.reload(inc_mod)


def _class_tag_checks() -> int:
    """선언 태그 이름이 벤더 표준과 충돌하지 않는지.

    실측(2026-08-10) — Zabbix 표준 템플릿 트리거가 `class=os`·`class=database` 를 달고
    나온다. 우리가 같은 이름을 쓰면 한 트리거에 의미가 다른 두 값이 공존하고, 어느 쪽이
    읽힐지가 태그 순서에 좌우된다.
    """
    from . import incident

    assert incident.CLASS_TAG != "class", "벤더 표준 태그 이름과 충돌한다"
    vendor = [{"tag": "class", "value": "os"}, {"tag": "class", "value": "database"}]
    # 표준 태그만 달린 알림은 선언이 없는 것으로 보고 폴백해야 한다
    assert incident.classify("Linux: High CPU utilization (over 90% for 5m)",
                             tags=vendor) == "cpu_io_pressure"
    assert incident.classify("무슨무슨 알림", tags=vendor) == "other"
    # 우리 태그가 있으면 그것이 이긴다
    ours = vendor + [{"tag": incident.CLASS_TAG, "value": "network"}]
    assert incident.classify("무슨무슨 알림", tags=ours) == "network"
    return 4


def _site_keyword_checks() -> int:
    """사이트 고유 키워드가 코드가 아니라 환경변수로 들어오는지.

    왜 — 한 조직의 커스텀 트리거명("... not connect" 같은 관용구)을 범용 규칙에 섞으면
    다른 환경에서는 뜻 없는 줄이 되고, 나중에 왜 있는지 아무도 모르게 된다. 범용 규칙에는
    표준 템플릿·일반 용어만 두고 사이트 고유분은 밖에서 주입한다.
    """
    import importlib
    import os

    from . import incident as inc_mod

    saved = os.environ.get("SITE_CLASS_KEYWORDS")
    # 배포 서버에는 이 값이 들어 있다. 지우지 않으면 그 서버에서만 실패하고, 설정
    # 문제인지 코드 문제인지 구분할 수 없다. 몇 번 겪으면 "저 서버는 원래 빨간불"이
    # 되고, 그때부터 진짜 회귀가 같은 빨간불에 섞여 안 보인다.
    os.environ.pop("SITE_CLASS_KEYWORDS", None)
    inc_mod = importlib.reload(inc_mod)
    try:
        # 주입 전 — 사이트 관용구는 분류되지 않는 것이 정상
        assert inc_mod.classify("ixapi.example.net not connect") == "other"

        os.environ["SITE_CLASS_KEYWORDS"] = "service_down=not connect|check is fail"
        m = importlib.reload(inc_mod)
        assert m.classify("ixapi.example.net not connect") == "service_down"
        assert m.classify("https://intra.example.net Site Check is Fail") == "service_down"
        # 모르는 클래스는 무시하고 죽지 않는다
        os.environ["SITE_CLASS_KEYWORDS"] = "nonexistent_class=foo"
        m = importlib.reload(inc_mod)
        assert m.classify("foo bar") == "other"
        return 4
    finally:
        if saved is None:
            os.environ.pop("SITE_CLASS_KEYWORDS", None)
        else:
            os.environ["SITE_CLASS_KEYWORDS"] = saved
        importlib.reload(inc_mod)


def _open_link_checks() -> int:
    """열린 문제 연계 — 규칙 매칭·경과 필터·마스킹 누수·상태 계약.

    왜 이 검사들인가: 실측상 게이트웨이 시간창 안에서는 서로 다른 클래스가 함께 나지 않아
    (유형 혼합 0건) 브리지 그룹만으로는 발동하지 않는다. 이 경로가 그 공백을 메우므로
    조용히 죽으면 알아채기 어렵다. 설계는 private/docs/open_problem_linkage_design.md.
    """
    import importlib
    import os

    from . import incident, masking

    n = 0
    # 측정 파일이 없으면 연계 자체가 꺼져야 한다. 예전에는 예시값(비율 0.90)이 실렸는데,
    # 시스템 프롬프트가 그 수치를 "실제로 측정된 값"이라고 모델에 알려 주므로 근거 없는
    # 비율이 분석 근거로 게시됐다. 없는 근거보다 없는 문장이 낫다.
    saved_rules = os.environ.pop("OPEN_LINK_RULES_FILE", None)
    try:
        m0 = importlib.reload(incident)
        assert m0.OPEN_LINK_RULES == {}, f"파일이 없는데 규칙이 있다: {m0.OPEN_LINK_RULES}"
        assert m0.OPEN_LINK_MEASURED == "", m0.OPEN_LINK_MEASURED
        n += 2
    finally:
        if saved_rules is not None:
            os.environ["OPEN_LINK_RULES_FILE"] = saved_rules
        incident = importlib.reload(incident)

    # 규칙 매칭 — **값이 아니라 기제를 검사한다.** 특정 수치에 묶으면 측정 파일을 바꿀 때마다
    # 테스트가 깨지고, 그 결합이야말로 이 설계가 없애려던 것이다.
    #
    # 규칙은 검사하는 동안만 우리가 아는 것으로 바꿔 끼운다. 배포된 서버에는 그 서버의
    # 측정 결과가 실려 있어서(랩은 2건, 실환경은 재측정마다 달라진다) 파일을 그대로 쓰면
    # 코드가 멀쩡해도 테스트가 깨지고, 설정 탓인지 코드 탓인지 구분할 수 없다.
    saved_rules, saved_measured = incident.OPEN_LINK_RULES, incident.OPEN_LINK_MEASURED
    incident.OPEN_LINK_RULES = {
        ("disk_space", "cpu_io_pressure"): {"rate": 0.96, "days": 13, "overlaps": 24},
        ("disk_space", "service_down"): {"rate": 0.74, "days": 11, "overlaps": 17},
    }
    incident.OPEN_LINK_MEASURED = "셀프테스트 고정값"
    try:
        n += _open_link_rule_checks(incident)
        n += _open_link_masking_checks()
    finally:
        incident.OPEN_LINK_RULES = saved_rules
        incident.OPEN_LINK_MEASURED = saved_measured
    return n


def _open_link_rule_checks(incident) -> int:
    hit = incident.open_link("disk_space", {"cpu_io_pressure"})
    assert hit and 0 < hit["rate"] <= 1 and hit["days"] >= 1, hit
    assert hit["open_class"] == "disk_space" and hit["followed_class"] == "cpu_io_pressure"
    assert hit["measured"], "측정 조건 문자열이 비었다 — 근거 없이 프롬프트에 실린다"
    assert incident.open_link("cpu_io_pressure", {"disk_space"}) == {}, "방향 없는 매칭"
    assert incident.open_link("network", {"cpu_io_pressure"}) == {}

    # BRIDGE_GROUPS 와 달리 겹침이 허용돼야 한다 — disk_space 가 두 규칙에 모두 있다
    keys = [k[0] for k in incident.OPEN_LINK_RULES]
    assert keys.count("disk_space") == 2, "겹침 금지 제약이 잘못 들어왔다"
    return 6


def _open_link_masking_checks() -> int:
    from . import incident, masking

    n = 0
    # 마스킹 — 열린 문제 이름의 실 호스트명이 새면 안 된다
    masker = masking.Masker()
    ctx = {
        "incident": {"host": "prod-db-01", "classes": ["cpu_io_pressure"],
                     "alert_count": 1, "merge_reason": "", "dominant_sev": "SEV2"},
        "host": {"host": "prod-db-01", "interfaces": [{"ip": "10.9.9.9"}]},
        "alerts": [], "logs": [], "security": [],
        "open_problems": [{
            "name": "prod-db-01: Free disk space is less than 10%",
            "class": "disk_space", "open_for_s": 10800,
            "link": {"rate": 0.9, "days": 10, "overlaps": 20,
                     "open_class": "disk_space", "followed_class": "cpu_io_pressure",
                     "measured": incident.OPEN_LINK_MEASURED},
        }],
        "sources": {"logs": "ok", "security": "ok", "open_problems": "ok"},
    }
    masked = masking.build_llm_context(ctx, "SEV2", masker)
    blob = repr(masked)
    assert "prod-db-01" not in blob, "열린 문제 이름에서 호스트명 누수"
    assert "10.9.9.9" not in blob, "IP 누수"
    assert masked["open_problems"][0]["link"]["rate"] == 0.9, "측정 수치가 유실됐다"
    assert masked["open_problems"][0]["link"]["measured"], "측정 조건이 유실됐다"
    assert masked["open_problems"][0]["stale"] is False
    n += 5

    # 장기 미해소는 선행 원인이 아니라 방치 항목 — 지우지 않고 표시한다.
    # 실측(2026-08-10 실환경): 3년 넘게 열린 문제가 있었고 90일 창 미해소는 전부 7일 이상이었다.
    import asyncio

    from . import collector
    now = 1_800_000_000

    class _FakeZbx:
        async def call(self, client, method, params):
            return [
                {"eventid": "1", "name": "Free disk space is less than 10%",
                 "clock": now - 3 * 3600},                    # 3시간 — 선행 후보
                {"eventid": "2", "name": "/data: Disk space is low (used > 90%)",
                 "clock": now - 40 * 86400},                  # 40일 — 방치
            ]
    out, st = asyncio.run(collector._open_problems(
        _FakeZbx(), None, "1", {"cpu_io_pressure"}, set(), now))
    assert st == "ok" and len(out) == 2, out
    # 인시던트에 이미 그 유형이 있으면 선행이 아니라 같은 문제의 다른 임계 트리거다.
    # 실측 2026-08-10: 복제 지연을 임계값만 달리 본 두 트리거가 각각 "이번 알림"과
    # "선행 문제"로 잡혔다.
    same, st2 = asyncio.run(collector._open_problems(
        _FakeZbx(), None, "1", {"cpu_io_pressure", "disk_space"}, set(), now))
    assert st2 == "ok" and same == [], "같은 유형이 선행 문제로 붙었다"
    n += 2
    # 최근 것이 먼저 — 상한에 잘릴 때 방치 항목이 아니라 선행 후보가 남아야 한다
    assert out[0]["stale"] is False and out[1]["stale"] is True, out
    assert out[0]["open_for_s"] < out[1]["open_for_s"]
    n += 4

    # 상태 계약 — 조회 실패가 "선행 문제 없음"으로 읽히면 안 된다
    ctx2 = dict(ctx, open_problems=[],
                sources={"logs": "ok", "security": "ok", "open_problems": "unavailable"})
    assert masking.build_llm_context(ctx2, "SEV2", masking.Masker())["sources"][
        "open_problems"] == "unavailable"
    # 알 수 없는 상태값은 통과시키지 않는다(화이트리스트 유지)
    ctx3 = dict(ctx, sources={"logs": "ok", "security": "ok", "open_problems": "weird"})
    assert masking.build_llm_context(ctx3, "SEV2", masking.Masker())["sources"][
        "open_problems"] == "unknown"
    n += 2

    # 열린 문제가 없으면 기존 출력과 형태가 같아야 한다(가산 변경)
    ctx4 = dict(ctx, open_problems=[], sources={"logs": "ok", "security": "ok"})
    out = masking.build_llm_context(ctx4, "SEV2", masking.Masker())
    assert out["open_problems"] == [] and "open_problems" not in out["sources"]
    n += 1
    return n


def _remediation_checks() -> int:
    """P0-1 — 조치 후보가 Keep 승인 큐로 가는 경로(데모 B). 외부 호출 0(KEEP_URL 없으면 skip)."""
    import os

    from . import app as gw_app
    from . import keep, router

    saved = os.environ.pop("KEEP_URL", None)
    try:
        # 태그 조회는 공개 헬퍼 — remediate 분기가 service 태그를 읽는다
        tags = [{"tag": "automate", "value": "service_restart"},
                {"tag": "service", "value": "nginx"}]
        assert router.tag_value(tags, "service") == "nginx"
        assert router.tag_value(tags, "없는태그") is None

        # 조치 후보 등록이 예외 없이 끝나고, KEEP_URL 미설정이면 조용히 skip 된다
        gw_app._queue_remediation("h1", "Nginx process is not running", "SEV2",
                                  "service_restart", "nginx")
        assert keep.push_alert("n", "SEV2", "h1", "a", playbook="service_restart") == \
            {"ok": False, "skipped": True}

        # 채널 계층화 — SEV3(digest)·SEV4(dashboard_only)가 조용히 버려지지 않는다
        saved_digest = os.environ.pop("SLACK_CHANNEL_ID_DIGEST", None)
        try:
            from . import slack
            # 채널 미설정이면 메인 채널로 흘려보내지 않고 게시를 건너뛴다
            assert slack.post_digest("n", "SEV3", "h1") == {"ok": False, "skipped": True}
            gw_app._queue_low_severity("h1", "디스크 사용률 82%", "SEV3", "disk_space", True)
            gw_app._queue_low_severity("h1", "메모리 사용률 70%", "SEV4", "memory_pressure", False)
        finally:
            if saved_digest is not None:
                os.environ["SLACK_CHANNEL_ID_DIGEST"] = saved_digest

        # G5 — 게이트에서 걸러진 사건도 Keep 에 남긴다(분석 없이 판정·유형만)
        from . import incident, triage
        inc = incident.Incident(
            key=("h1", "disk_space"), host="h1", opened_at=0.0, last_at=0.0,
            alerts=[incident.Alert(source="zabbix-internal", event_id="e", trigger_id="1",
                                   host="h1", alert_name="디스크 사용률 92%", sev="SEV2",
                                   incident_class="disk_space", recv=0.0)])
        ctx = {"alerts": [{"prejudge": {"verdict": "만성"}}]}
        assert triage._push_gated(inc, ctx, "단일 축·교차 신호 없음") == \
            {"ok": False, "skipped": True}

        # 근거 축 기록 — 조회 실패와 신호 없음의 구분(G1)이 Keep 레코드까지 간다.
        # 이게 비면 월간 리포트의 "로그를 근거로 판단한 사건 수"가 통째로 0이 된다.
        assert triage._sources_note(
            {"sources": {"security": "ok", "logs": "unavailable"}}) == \
            "logs:unavailable,security:ok"
        assert triage._sources_note({}) == ""
        assert triage._sources_note({"sources": "깨진값"}) == ""
    finally:
        if saved is not None:
            os.environ["KEEP_URL"] = saved
    return 11


def _fastpath_checks() -> int:
    """P1-A — 원시 신호가 인시던트당 부모 1개, 후속은 그 스레드 답글."""
    import asyncio

    from . import incident

    calls = []

    async def on_signal(alert, thread_ts):
        # 실제 Slack 게시는 수백 ms 걸린다. 그 사이 다음 알림이 도착하는 상황을 흉내낸다.
        await asyncio.sleep(0.05)
        calls.append((alert.incident_class, thread_ts))
        return "ts-anchor"

    def _a(cls, host="h1", t=0.0):
        return incident.Alert(source="zabbix-internal", event_id="e", trigger_id="1",
                              host=host, alert_name=cls, sev="SEV2",
                              incident_class=cls, recv=t)

    async def _run():
        closed = []
        mgr = incident.IncidentManager(
            on_close=lambda i: closed.append(i) or asyncio.sleep(0),
            on_signal=on_signal, debounce_s=0.05, max_window_s=5,
            priority_debounce_s=0.02, max_alerts=20)
        mono = time.monotonic()
        # 랩 실측처럼 거의 동시에 도착시킨다. 잠금이 없으면 두 번째 알림이 앵커가 빈 것을
        # 보고 그냥 버려져 답글이 사라진다(2026-07-29 실측으로 발견).
        await asyncio.gather(mgr.submit(_a("replication", t=mono)),
                             mgr.submit(_a("cpu_io_pressure", t=mono)))
        await asyncio.sleep(0.3)
        return closed

    closed = asyncio.run(_run())
    assert len(calls) == 2, f"동시 도착 시 후속 신호가 버려짐: {calls}"
    assert calls[0][1] is None, "첫 신호는 최상위 카드여야"
    assert calls[1][1] == "ts-anchor", "후속 신호는 앵커 스레드 답글이어야"
    assert len(closed) == 1 and closed[0].anchor_ts == "ts-anchor", closed
    return 4


def _holmes_gate_checks() -> int:
    """G9 — 심층조사 발동을 지식 공백 기준으로. 만성은 억제, 신규는 발동."""
    import os

    from . import holmes, incident

    # 인시던트 전체 판정 접기 — 모르는 게 하나라도 있으면 신규
    assert incident.dominant_verdict({"alerts": [{"prejudge": {"verdict": "만성"}},
                                                 {"prejudge": {"verdict": "신규"}}]}) == "신규"
    assert incident.dominant_verdict({"alerts": [{"prejudge": {"verdict": "만성"}},
                                                 {"prejudge": {"verdict": "만성"}}]}) == "만성"
    assert incident.dominant_verdict({"alerts": [{"prejudge": {"verdict": "만성"}},
                                                 {"prejudge": {"verdict": "재발"}}]}) == "재발"
    assert incident.dominant_verdict({"prejudge": {"verdict": "신규"}}) == "신규"   # 단건 경로
    assert incident.dominant_verdict({}) == ""

    saved = {k: os.environ.get(k) for k in ("HOLMES_ENABLED", "HOLMES_ALLOW_MSP_RAW")}
    os.environ["HOLMES_ENABLED"] = "1"
    os.environ.pop("HOLMES_ALLOW_MSP_RAW", None)
    try:
        zbx = ["zabbix-internal"]
        # 만성 = 아는 문제 → 병합이어도 억제 (G6 흡수)
        fired, why = holmes.should_investigate("SEV2", False, zbx, merged=True, verdict="만성")
        assert fired is False and "chronic" in why, why
        # 신규 = 모르는 문제 → 단일 알림이어도 발동 (종래엔 발동 안 했다)
        fired, why = holmes.should_investigate("SEV2", False, zbx, merged=False, verdict="신규")
        assert fired is True and "novel" in why, why
        # 위중·열화는 지식 여부와 무관하게 우선 — 만성이어도 발동
        assert holmes.should_investigate("SEV1", False, zbx, verdict="만성")[0] is True
        assert holmes.should_investigate("SEV2", True, zbx, verdict="만성")[0] is True
        # 판정이 없으면 종래 규칙(병합) 유지
        assert holmes.should_investigate("SEV2", False, zbx, merged=True)[0] is True
        assert holmes.should_investigate("SEV2", False, zbx, merged=False)[0] is False
        # MSP 는 원문이 나가므로 신규여도 금지 (테넌트 경계가 우선)
        assert holmes.should_investigate("SEV2", False, ["zabbix-msp"], verdict="신규")[0] is False
        # 차단이 기본이어야 한다. 예전 플래그(HOLMES_MASKED)는 이름과 예시 파일 주석이
        # "켜면 가려진다"로 읽히는데 실제로는 차단만 풀었고 기본값이 1이었다.
        os.environ["HOLMES_MASKED"] = "1"
        try:
            assert holmes.should_investigate("SEV2", False, ["zabbix-msp"],
                                             verdict="신규")[0] is False,                 "옛 이름이 아직 차단을 푼다"
        finally:
            os.environ.pop("HOLMES_MASKED", None)
        # 실제 의미대로 이름을 바꾼 플래그만 차단을 푼다
        os.environ["HOLMES_ALLOW_MSP_RAW"] = "1"
        try:
            assert holmes.should_investigate("SEV2", False, ["zabbix-msp"],
                                             verdict="신규")[0] is True
        finally:
            os.environ.pop("HOLMES_ALLOW_MSP_RAW", None)
        # 심층조사 질문에 원문 호스트명이 들어간다는 사실을 검사로 고정한다.
        # 심층조사가 호스트명을 원문으로 보낸다는 사실을 검사로 고정한다. 마스킹이
        # 붙으면 이 검사가 깨지고, 그때 위 차단 플래그를 없애야 한다는 신호가 된다.
        sent = {}
        real_post = holmes.httpx.post

        def _capture(url, **kw):
            sent.update(kw.get("json") or {})
            raise RuntimeError("보내지 않는다 — 잡기만 한다")

        holmes.httpx.post = _capture
        os.environ["HOLMES_URL"] = "http://127.0.0.1:1"
        try:
            holmes.investigate("cust-db01", "why")
        finally:
            holmes.httpx.post = real_post
            os.environ.pop("HOLMES_URL", None)
        assert "cust-db01" in str(sent.get("ask", "")),             f"원문 전송 사실이 바뀌었다 — 차단 플래그를 재검토할 것: {sent}"

        # 조사 질문이 "무슨 사건인지"를 담는가 (2026-07-31 회귀).
        # 종래에는 "{n}건이 1개 사건 · {host}" 만 넘겨서, 에이전틱인 홈즈가 사건과 무관하게
        # 그 순간 활성인 아무 문제를 조사했다(SSH 브루트포스 사건에 MySQL buffer pool 회신).
        q = holmes.build_question(
            ["sshd: brute force trying to get access to the system. Non existent user.",
             "Multiple authentication failures followed by a success."],
            {"auth_security"}, 17.2)
        assert "brute force" in q, q                 # 알림 이름이 실려야 한다
        assert "authentication failures" in q, q
        assert "auth_security" in q, q               # 유형도
        assert "17" in q                             # 관측창
        assert "ONLY" in q and "Do NOT" in q, q      # 범위 고정 지시
        assert q.startswith("Incident:")             # 호출부가 접두를 덧붙이지 않는다
        # 비어 있어도 죽지 않는다(알림명 없는 경로)
        assert "(unnamed)" in holmes.build_question([""], set(), 0)
    finally:
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
    return 19


def _incident_checks() -> int:
    """인시던트 병합 — 순수 로직 + 비동기 버퍼(짧은 디바운스) + 마스킹 누수."""
    import asyncio
    import importlib
    import json
    import os

    from . import incident, llm, masking

    # 분류 사례는 배포 서버의 선언 파일·사이트 관용구에 영향을 받는다. 그 서버에서만
    # 결과가 갈리면 설정 문제인지 코드 문제인지 구분할 수 없다. 지우고 돌린다.
    _env_saved = {k: os.environ.pop(k, None)
                  for k in ("INCIDENT_CLASS_FILE", "SITE_CLASS_KEYWORDS")}
    incident = importlib.reload(incident)

    # 분류 — 표준 템플릿·랩 실측 알림명 전수
    for name, expected in CASES_CLASSIFY:
        got = incident.classify(name)
        assert got == expected, f"classify({name!r}) -> {got}, expected {expected}"

    # memory_pressure 는 어떤 브리지에도 속하지 않는다 — 자원 경합(swap→iowait)과 OOM→서비스
    # 정지 양쪽에 인과 후보가 걸치는데 그룹은 겹칠 수 없고, 실측 근거도 아직 없다(P0-3 판정).
    assert (incident.incident_key("zabbix-internal", "h1", "memory_pressure")
            != incident.incident_key("zabbix-internal", "h1", "cpu_io_pressure"))
    assert (incident.incident_key("zabbix-internal", "h1", "memory_pressure")
            != incident.incident_key("zabbix-internal", "h1", "service_down"))

    # 브리지 그룹은 서로 겹치면 안 된다 — 겹치면 뒤 그룹이 死코드가 되므로 import 때 막는다
    try:
        incident._validate_bridges([frozenset({"a", "b"}), frozenset({"b", "c"})])
        raise AssertionError("겹치는 브리지 그룹을 검출하지 못했다")
    except ValueError:
        pass

    # 브리지 — replication + cpu_io_pressure 는 같은 키, auth_security 는 분리
    k_repl = incident.incident_key("zabbix-internal", "h1", "replication")
    k_io = incident.incident_key("zabbix-internal", "h1", "cpu_io_pressure")
    k_sec = incident.incident_key("zabbix-internal", "h1", "auth_security")
    assert k_repl == k_io, (k_repl, k_io)
    assert k_sec != k_repl
    assert incident.incident_key("zabbix-internal", "h2", "replication") != k_repl   # 호스트 다르면 분리

    # 브리지 2번 그룹 — 디스크 포화 + 서비스 정지 = 한 사건 (데모 B), 1번 그룹과는 분리
    # 감시 서버가 둘이면 호스트 이름이 겹칠 수 있다. 이름만으로 묶으면 남의 고객
    # 알림이 한 사건이 된다 — 이름은 감시 서버 안에서만 유일하다.
    saved_realm = os.environ.get("INCIDENT_REALM_MAP")
    os.environ["INCIDENT_REALM_MAP"] = "zabbix-internal=internal,zabbix-msp=msp,wazuh=internal"
    try:
        importlib.reload(incident)
        same = incident.incident_key("zabbix-internal", "db01", "disk_space")
        other = incident.incident_key("zabbix-msp", "db01", "disk_space")
        assert same != other, "이름이 같아도 감시 서버가 다르면 갈라져야"
        # 같은 영역이면 소스가 달라도 묶인다 — 교차 소스 병합이 막히면 안 된다
        wz = incident.incident_key("wazuh", "db01", "disk_space")
        assert wz == same, "같은 영역의 다른 소스는 계속 묶여야"
        assert incident.realm_for("zabbix-msp") == "msp"
        assert incident.realm_for("모르는소스") == "모르는소스", "안 적은 소스는 자기 이름이 영역"

        # 지문도 갈라져야 관제 화면에서 두 고객이 한 행으로 합쳐지지 않는다
        def _inc(src):
            a = incident.Alert(source=src, event_id="1", trigger_id="1", host="db01",
                               alert_name="n", sev="SEV2", incident_class="disk_space",
                               recv=0.0)
            return incident.Incident(key=incident.incident_key(src, "db01", "disk_space"),
                                     host="db01", alerts=[a], opened_at=0.0, last_at=0.0)
        assert _inc("zabbix-internal").fingerprint() != _inc("zabbix-msp").fingerprint()
    finally:
        if saved_realm is None:
            os.environ.pop("INCIDENT_REALM_MAP", None)
        else:
            os.environ["INCIDENT_REALM_MAP"] = saved_realm
        importlib.reload(incident)

    # 매핑을 안 적어도 소스가 다르면 갈라진다. 설정을 안 한 사람이 가장 위험한 상태가
    # 되면 안 된다 — 모르면 나뉘는 쪽으로 틀려야 한다.
    assert (incident.incident_key("zabbix-internal", "db01", "disk_space")
            != incident.incident_key("zabbix-msp", "db01", "disk_space"))
    # 같은 소스면 당연히 같다
    assert (incident.incident_key("zabbix-internal", "db01", "disk_space")
            == incident.incident_key("zabbix-internal", "db01", "disk_space"))

    k_disk = incident.incident_key("zabbix-internal", "h1", "disk_space")
    k_svc = incident.incident_key("zabbix-internal", "h1", "service_down")
    assert k_disk == k_svc, (k_disk, k_svc)
    assert k_disk != k_repl, "두 브리지 그룹이 같은 키로 뭉쳤다"

    # Incident 집계
    def _a(cls, sev="SEV2", host="h1", t=0.0, trig="1"):
        return incident.Alert(source="zabbix-internal", event_id="e", trigger_id=trig,
                              host=host, alert_name=cls, sev=sev, incident_class=cls, recv=t)
    inc = incident.Incident(key=k_repl, host="h1", alerts=[_a("replication")],
                            opened_at=0.0, last_at=0.0)
    inc.add(_a("cpu_io_pressure", sev="SEV1", t=3.0), 20)
    assert inc.is_merged() and inc.dominant_sev() == "SEV1"
    assert inc.classes() == {"replication", "cpu_io_pressure"}
    assert len(inc.fingerprint()) == 12
    assert "알려진 인과 조합" in inc.merge_reason()
    capped = incident.Incident(key=k_repl, host="h1", alerts=[_a("replication")],
                               opened_at=0.0, last_at=0.0)
    assert capped.add(_a("replication"), 1) is False   # max_alerts 캡
    disk_inc = incident.Incident(key=k_disk, host="h1", opened_at=0.0, last_at=0.0,
                                 alerts=[_a("disk_space"), _a("service_down")])
    assert "알려진 인과 조합" in disk_inc.merge_reason(), disk_inc.merge_reason()

    # 비동기 버퍼 — 짧은 디바운스로 병합/분리/멀티호스트 검증
    async def _run():
        closed = []
        mgr = incident.IncidentManager(
            on_close=lambda i: closed.append(i) or asyncio.sleep(0),
            debounce_s=0.05, max_window_s=5, priority_debounce_s=0.02, max_alerts=20)
        mono = time.monotonic()
        # h1: replication + iowait + cpu → 1건 (브리지)
        await mgr.submit(_a("replication", host="h1", t=mono))
        await mgr.submit(_a("cpu_io_pressure", host="h1", t=mono))
        await mgr.submit(_a("cpu_io_pressure", host="h1", t=mono))
        # h1: 보안 → 별개 인시던트
        await mgr.submit(_a("auth_security", host="h1", t=mono))
        # h2: replication → 별개 (호스트 다름)
        await mgr.submit(_a("replication", host="h2", t=mono))
        # h3: 디스크 + 서비스 정지 → 1건 (브리지 2번 그룹, 데모 B 시나리오)
        await mgr.submit(_a("disk_space", host="h3", t=mono))
        await mgr.submit(_a("service_down", host="h3", t=mono))
        await asyncio.sleep(0.2)   # 디바운스 창 마감 대기
        return closed

    closed = asyncio.run(_run())
    assert len(closed) == 4, [len(c.alerts) for c in closed]
    h3 = [c for c in closed if c.host == "h3"][0]
    assert len(h3.alerts) == 2 and h3.is_merged(), h3.alerts
    resource = [c for c in closed if c.classes() & {"replication", "cpu_io_pressure"}
                and c.host == "h1"][0]
    assert len(resource.alerts) == 3, resource.alerts   # 3건이 1개로 병합
    assert any(c.classes() == {"auth_security"} for c in closed)
    assert any(c.host == "h2" for c in closed)

    # 발동조건 게이트 — 교차 상관 있을 때만 LLM
    def _inc(alerts, host="h1", key=("h1", "replication")):
        return incident.Incident(key=key, host=host, alerts=alerts, opened_at=0.0, last_at=0.0)
    merged = _inc([_a("replication"), _a("cpu_io_pressure")])
    single = _inc([_a("disk_space", sev="SEV2")], key=("h1", "disk_space"))
    single_p1 = _inc([_a("disk_space", sev="SEV1")], key=("h1", "disk_space"))
    assert incident.should_triage(merged, {"logs": [], "security": []})[0] is True      # 병합
    assert incident.should_triage(single_p1, {"logs": [], "security": []})[0] is True    # SEV1
    assert incident.should_triage(single, {"logs": ["x"], "security": []})[0] is True    # 단일+로그
    assert incident.should_triage(single, {"logs": [], "security": []})[0] is False      # 단일·무신호
    gate_checks = 4

    # 마스킹 — 인시던트 형태도 원문 식별자 누수 없음
    mk = masking.Masker()
    inc_ctx = {
        "incident": {"host": "db-prod-01", "classes": ["replication", "cpu_io_pressure"],
                     "alert_count": 2, "merge_reason": "동일 호스트 · 2건", "dominant_sev": "SEV2"},
        "host": {"host": "db-prod-01", "interfaces": [{"ip": "192.0.2.7"}],
                 "hostgroups": [{"name": "Customer-B"}]},
        "alerts": [{"name": "복제 지연 on db-prod-01", "source": "zabbix-internal",
                    "sev": "SEV2", "class": "replication",
                    "trigger": {"description": "repl", "expression": "last(/db-prod-01/k)>60"},
                    "metrics": [{"key": "mysql.repl", "units": "s", "lastvalue": "512"}],
                    "prejudge": {"verdict": "신규", "statement": "s"}}],
        "logs": ["db-prod-01 mysqld: replica lag from 192.0.2.9"],
        "security": [],
    }
    masked = masking.build_llm_context(inc_ctx, "SEV2", mk)
    blob = json.dumps(masked, ensure_ascii=False)
    assert "db-prod-01" not in blob, "incident hostname leaked"
    assert "192.0.2.7" not in blob and "192.0.2.9" not in blob, "incident ip leaked"
    assert "Customer-B" not in blob, "incident group leaked"
    assert masked["alerts"] and masked["alerts"][0]["metrics"], "incident alerts dropped"

    # 열화 — 인시던트 컨텍스트에서도 코드 판정만으로 회신
    for k in ("ANTHROPIC_API_KEY", "OLLAMA_URL"):
        os.environ.pop(k, None)
    r = llm.triage_reply(inc_ctx, "SEV2")
    assert r["degraded"] and "병합" in r["text"], r
    for _k, _v in _env_saved.items():
        if _v is not None:
            os.environ[_k] = _v
    importlib.reload(incident)
    return 25 + len(CASES_CLASSIFY) + gate_checks


def _idempotency_checks() -> int:
    """중복 판정 — 여러 스레드가 동시에 들어와도 한 번만 통과해야 한다.

    웹훅이 `async def` 가 아니라 동기 함수라 FastAPI 가 워커 스레드에서 돌린다. 즉 이
    판정은 처음부터 멀티스레드에 노출돼 있었다. 확인과 등록 사이에 틈이 있으면 같은
    이벤트가 둘 다 통과해 인시던트에 두 번 담기고, 그러면 병합으로 보여 발동 조건까지
    바뀐다. 낡은 항목을 지우는 순회 중에 다른 스레드가 넣으면 예외도 난다.
    """
    import threading
    import time

    from . import app as app_mod

    # 확인과 등록 사이의 틈을 **강제로 벌린다.** 그냥 스레드를 여럿 던지면 CPython
    # 에서는 틈이 너무 좁아 우연히 통과한다. 그러면 잠금을 안 걸어도 통과하는 검사가
    # 되어, 검사가 아니라 운을 시험하는 것이 된다. 조회에 아주 짧은 지연을 넣어
    # 논리 자체를 본다 — 잠금이 있으면 지연이 있어도 한 번만 통과해야 한다.
    class _SlowSeen(dict):
        def __contains__(self, k):
            res = dict.__contains__(self, k)   # 판정을 먼저 하고
            time.sleep(0.05)                   # 등록하기 전에 밀린다 — 이게 그 틈이다
            return res

    real_seen = app_mod._seen
    app_mod._seen = _SlowSeen()
    passed, errors = [], []
    key = ("zabbix-internal", "e-1", 1)

    # 출발선을 맞춘다. 스레드를 그냥 던지면 시작 간격이 지연보다 커서 겹치지 않는다.
    n_threads = 8
    bar = threading.Barrier(n_threads)

    def _hit():
        try:
            bar.wait(timeout=10)
            if not app_mod._duplicate(key):
                passed.append(1)
        except Exception as e:      # noqa: BLE001 — 무엇이든 기록만
            errors.append(e)

    ts = [threading.Thread(target=_hit) for _ in range(n_threads)]
    for t in ts:
        t.start()
    for t in ts:
        t.join(timeout=10)
    app_mod._seen = real_seen
    assert not errors, f"동시 판정에서 예외: {errors[:2]}"
    assert len(passed) == 1, f"같은 이벤트가 {len(passed)}번 통과했다 — 중복 억제가 뚫린다"

    # 낡은 항목 청소가 도는 동안 새 항목이 들어와도 예외가 나면 안 된다
    app_mod._seen.clear()
    for i in range(500):
        app_mod._seen[("s", "old-%d" % i, 1)] = 0.0      # 아주 오래된 것으로 심는다
    errors2 = []

    def _churn(n):
        for i in range(200):
            try:
                app_mod._duplicate(("s", "new-%d-%d" % (n, i), 1))
            except Exception as e:  # noqa: BLE001
                errors2.append(e)

    ts2 = [threading.Thread(target=_churn, args=(n,)) for n in range(4)]
    for t in ts2:
        t.start()
    for t in ts2:
        t.join(timeout=15)
    assert not errors2, f"청소 중 예외: {errors2[:2]}"
    app_mod._seen.clear()
    return 4


def _open_limit_checks() -> int:
    """선행 문제 조회가 상한에 걸렸을 때 "없음" 으로 단언하지 않는가.

    조회를 최근 순 100건으로 받는데, 폭주 중이면 그 100건이 전부 5분 미만이라 경과
    필터에서 전멸한다. 그러면 빈 목록에 "조회 성공" 이 붙어, 세 시간째 미해소인 선행
    문제가 "선행 문제 없음" 으로 단언된다. 선행 문제는 원래 **오래된** 것이므로
    최근 순으로 받는 것 자체가 목적과 어긋난다.
    """
    import asyncio

    from . import collector

    asked = {}

    class _Zbx:
        def __init__(self, rows):
            self.rows = rows

        async def call(self, client, method, params):
            asked["params"] = params
            return self.rows

    # 상한만큼 받았고 전부 최근 것 — 필터에서 전멸한다
    now = 1_700_000_000
    fresh = [{"eventid": str(9000 + i), "name": "n%d" % i, "clock": now - 10,
              "severity": "3", "tags": []} for i in range(100)]
    out, status = asyncio.run(
        collector._open_problems(_Zbx(fresh), None, "10084", {"disk_space"}, set(), now))
    assert not (out == [] and status == collector.SOURCE_OK),         "상한에 걸려 다 걸러졌는데 '선행 문제 없음' 으로 단언한다"

    # 오래된 것부터 받아야 한다 — 선행 문제는 오래된 쪽이다
    assert asked["params"].get("sortorder") == "ASC", asked["params"]
    return 2


def _event_time_checks() -> int:
    """로그·보안 조회 창을 **사건이 난 시각** 기준으로 잡는가.

    알림에는 단조 시계 기준 `recv` 만 있고 벽시계 시각이 없었다. 재기동 후 대기
    알림을 다시 넣으면 그 시각이 새로 찍히므로, 두 시간 전 사건인데 로그를 지금
    기준 15분만 본다. 실제 장애 로그는 창 밖이라 빈 결과가 오고, 이름은 알려져
    있으니 상태는 ok 다 — 모델은 "로그에 기록 없음"을 사실로 단언한다.
    """
    import os
    import time as _t

    from . import collector, incident as inc_mod

    def _alert(clock):
        return inc_mod.Alert(source="zabbix-internal", event_id="e1", trigger_id="t1",
                             host="h1", alert_name="n", sev="SEV3",
                             incident_class="disk_space", recv=_t.monotonic(),
                             clock=clock)

    now = 1_700_000_000
    old_inc = inc_mod.Incident(key=("internal", "h1", "disk_space"), host="h1",
                               alerts=[_alert(now - 7200)],
                               opened_at=0.0, last_at=0.0)
    ref = collector.reference_time(old_inc, now)
    assert abs(ref - (now - 7200)) < 5,         f"두 시간 전 사건인데 조회 기준이 지금이다 — 실제 로그 구간을 안 본다: {ref}"

    # 시각을 모르는 알림(옛 대기 파일 등)은 지금 기준으로 — 없는 값을 지어내지 않는다
    no_clock = inc_mod.Incident(key=("internal", "h1", "disk_space"), host="h1",
                                alerts=[_alert(0)], opened_at=0.0, last_at=0.0)
    assert collector.reference_time(no_clock, now) == now

    # 미래 시각은 안 믿는다 — 발행 측 시계가 어긋나면 창이 통째로 빗나간다
    future = inc_mod.Incident(key=("internal", "h1", "disk_space"), host="h1",
                              alerts=[_alert(now + 99999)], opened_at=0.0, last_at=0.0)
    assert collector.reference_time(future, now) == now

    # 감시 서버가 돌려준 이벤트 시각이 가장 정확하고, 발송 설정과 무관하게 온다.
    # 알림에 시각이 없어도 이 값으로 창을 맞춘다.
    assert collector.reference_time(no_clock, now, [now - 5400]) == now - 5400
    # 둘 다 있으면 이른 쪽을 쓴다 — 사건이 시작된 시점이 기준이다
    assert collector.reference_time(old_inc, now, [now - 9000]) == now - 9000

    # **지금으로 떨어진 사실이 밖으로 드러나야 한다.** 2026-08-13 랩에서 사건 두 시간
    # 뒤에 재분석을 돌렸는데 시각을 아무도 못 줘서 창이 조용히 "지금"이 됐고, 그 조용한
    # 창에서 잡힌 6줄을 보고 모델이 "로그 축에는 이번 사건을 설명할 신호가 없다"고 썼다.
    # 신호가 없던 것이 아니라 사건이 없던 시간대를 본 것이다.
    assert hasattr(collector, "reference_guessed"), \
        "창 기준을 지금으로 떨어뜨린 사실을 알릴 방법이 없다"
    assert collector.reference_guessed(no_clock, now, []) is True
    assert collector.reference_guessed(old_inc, now, []) is False

    # 배선 — 웹훅이 받은 시각이 알림과 대기 기록까지 이어져야 한다. 한 군데만 끊겨도
    # 재기동 뒤에는 값이 없어 지금 기준으로 떨어진다.
    import importlib
    import shutil
    import tempfile

    from . import app as app_mod, pending

    importlib.reload(app_mod)
    d = tempfile.mkdtemp(prefix="clock-test-")
    saved_path = pending.PATH
    pending.PATH = os.path.join(d, "pending.jsonl")
    try:
        class _FakeBg:
            def __init__(self):
                self.tasks = []

            def add_task(self, fn, *a, **kw):
                self.tasks.append((fn, a, kw))

        bg = _FakeBg()
        app_mod._dispatch(bg, "zabbix-internal", "e9", "t9", "h1", "n", "SEV3",
                          {"route": "triage", "playbook": ""}, clock=str(now - 3600))
        alerts = [a[0] for _fn, a, _kw in bg.tasks if a]
        assert alerts and alerts[0].clock == now - 3600,             f"웹훅이 받은 시각이 알림까지 안 갔다: {alerts[0].clock if alerts else None}"
        recs = pending.load()
        assert recs and recs[0].get("clock") == now - 3600,             f"대기 기록에 시각이 없다 — 재기동하면 지금 기준으로 떨어진다: {recs}"
    finally:
        pending.PATH = saved_path
        shutil.rmtree(d, ignore_errors=True)
    return 7


def _wrong_server_checks() -> int:
    """명부를 못 읽었을 때 남의 감시 서버에 되묻지 않는가.

    명부 로드가 실패하면 조용히 환경변수로 떨어진다. 그러면 MSP 알림의 이벤트·트리거
    ID 를 사내 서버에 묻게 되는데, ID 는 서버마다 따로 증가하므로 (a) 없으면 빈 결과라
    "90일 내 이력 없음 = 신규"로 확정되고 (b) 겹치면 사내 다른 호스트의 트리거명·지표·
    이력이 그 고객 사건의 컨텍스트로 실린다. 어느 쪽도 예외가 아니라 상태는 전부 ok 다.
    """
    import importlib
    import os

    from . import collector, registry

    saved = {k: os.environ.get(k) for k in ("HOST_REGISTRY_FILE", "ZABBIX_URL",
                                            "ZABBIX_TOKEN")}
    os.environ["HOST_REGISTRY_FILE"] = os.path.join(os.path.dirname(__file__),
                                                    "없는-명부.yml")
    os.environ["ZABBIX_URL"] = "http://내부:8080"
    os.environ["ZABBIX_TOKEN"] = "내부토큰"
    try:
        importlib.reload(registry)
        assert registry.status()["error"], "명부 로드 실패를 만들지 못했다"
        # 명부를 못 읽었으면 소스를 지정한 조회는 **막아야** 한다. 조용히 기본 서버로
        # 떨어지면 남의 서버에 묻는 것이 된다.
        try:
            c = collector.ZabbixClient(source="zabbix-msp")
            fell_back = c.api.startswith("http://내부")
        except RuntimeError:
            fell_back = False
        assert not fell_back, ("명부를 못 읽었는데 MSP 조회가 사내 서버로 떨어졌다 — "
                               "없는 호스트라 '신규'로 확정되거나 남의 자료가 실린다")
        # 소스를 안 주는 단건 경로는 예전대로 기본 서버를 쓴다(감시 서버 하나인 환경)
        assert collector.ZabbixClient().api.startswith("http://내부")
        return 3
    finally:
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        importlib.reload(registry)


def _collect_failure_checks() -> int:
    """Zabbix 수집이 전부 실패했을 때 그 사실이 밖으로 드러나는가.

    수집은 `gather(return_exceptions=True)` 로 돌므로 전건 실패해도 예외가 안 난다.
    그러면 폴백 컨텍스트도 안 만들어지고, 로그·보안은 따로 조회되어 ok 가 된다.
    게이트는 그 두 축만 보므로 "교차 신호 없음(조회는 정상) — LLM 스킵" 으로 남는다.
    Zabbix 가 죽어 있던 시간대의 사건이 전부 "봐줬는데 볼 게 없었다"로 기록된다.
    """
    import asyncio
    import time as _t

    from . import collector, incident as inc_mod

    class _DeadZbx:
        source = "zabbix-internal"

        async def call(self, *a, **kw):
            raise RuntimeError("zabbix down")

    inc = inc_mod.Incident(
        key=("internal", "h1", "disk_space"), host="h1",
        alerts=[inc_mod.Alert(source="zabbix-internal", event_id="e1", trigger_id="t1",
                              host="h1", alert_name="disk full", sev="SEV3",
                              incident_class="disk_space", recv=_t.monotonic())],
        opened_at=_t.monotonic(), last_at=_t.monotonic())

    ctx = asyncio.run(collector.collect_incident_context(_DeadZbx(), inc))
    st = ctx.get("sources") or {}
    assert "metrics" in st, ("Zabbix 수집 상태가 sources 에 없다 — 통째로 실패해도 "
                            f"밖에서 구분할 수 없다: {st}")
    assert st["metrics"] == collector.SOURCE_UNAVAILABLE, st

    # 게이트도 그 축을 봐야 한다. 안 보면 "조회는 정상"으로 스킵된다.
    fire, why = inc_mod.should_triage(inc, ctx)
    assert fire is True, f"Zabbix 가 죽었는데 조회 정상으로 보고 스킵했다: {why}"
    assert "실패" in why or "미상" in why, why

    # 사람 눈에도 보여야 한다. 카드에 표시가 없으면 알아채는 경로가 로그뿐이다.
    from . import masking, slack
    note = slack._source_note(ctx["sources"])
    assert "지표" in note, f"카드에 Zabbix 축 실패가 안 보인다: {note!r}"
    # 전송 화이트리스트에도 있어야 LLM 이 그 상태를 읽는다
    assert "metrics" in masking._STATUS_KEYS, masking._STATUS_KEYS

    # **사유가 로그에 남아야 한다.** 2026-08-13 랩에서 Zabbix 수집이 전건 실패했는데
    # 원인이 어디에도 안 남았다. JSON-RPC 는 오류도 HTTP 200 으로 돌려주므로 접근
    # 로그에는 `200 OK` 만 열 줄 찍혔고, 실제 사유는 `API token expired.` 였다.
    # 예외는 gather(return_exceptions=True) 에 담긴 채 버려졌다.
    import logging as _lg

    class _Grab(_lg.Handler):
        def __init__(self):
            super().__init__()
            self.msgs = []

        def emit(self, rec):
            self.msgs.append(rec.getMessage())

    grab = _Grab()
    collector.log.addHandler(grab)
    try:
        asyncio.run(collector.collect_incident_context(_DeadZbx(), inc))
    finally:
        collector.log.removeHandler(grab)
    joined = " / ".join(grab.msgs)
    assert "zabbix down" in joined, (
        "수집 실패 사유가 로그에 안 남는다 — 토큰 만료·권한 부족을 구분할 방법이 "
        "없다: %s" % joined)

    # **사건이 나기 전에 알아야 한다.** 사후 경고만 있으면 토큰이 만료된 채로 며칠이
    # 지나고, 그동안의 사건은 전부 "지표 미상"으로 기록된다. 기동 때 한 번 확인한다.
    assert hasattr(collector, "zabbix_probe"), \
        "조회 토큰 점검이 없다 — 만료를 사건이 날 때에야 안다"

    class _Expired:
        source = "zabbix-internal"

        async def call(self, *a, **kw):
            raise RuntimeError("zabbix api error on host.get: "
                               "{'data': 'API token expired.'}")

    st = asyncio.run(collector.zabbix_probe(client=_Expired()))
    assert st["ok"] is False and "expired" in st["error"], st
    st = asyncio.run(collector.zabbix_probe(client=_LiveZbx()))
    assert st["ok"] is True and st["error"] == "", st
    return 11


class _LiveZbx:
    source = "zabbix-internal"

    async def call(self, *a, **kw):
        return [{"hostid": "1"}]


def _nametable_checks() -> int:
    """전역 이름 표 — 경계 일치·대소문자·긴 것 우선.

    지금 마스킹은 그 사건의 호스트 정보에서 이름을 뽑아 등록한다. 그래서 사건 당사자가
    아닌 호스트명은 안 가려진다. 로그 한 줄에 다른 서버 이름이 섞이면 원문 그대로 나간다.

    표로 잡되 두 가지를 지켜야 한다. 등록되지 않은 더 긴 문자열 안에서는 바뀌면 안 되고
    (db01 이 mydb01 안에서), 대소문자가 달라도 잡아야 한다(DB01). 선례는 Presidio 의
    금지 목록 인식기로, 경계 lookaround 와 대소문자 무시를 쓴다.
    """
    import json

    from . import masking

    mk = masking.Masker()
    for n in ("db01", "report-Customer-B", "customer-b", "node1"):
        mk.register("host", n)

    # ① 더 긴 낱말 안에서는 안 바뀐다
    assert mk.mask("mydb01 로그") == "mydb01 로그", mk.mask("mydb01 로그")
    assert mk.mask("db011 재기동") == "db011 재기동", mk.mask("db011 재기동")
    assert mk.mask("node10 상태") == "node10 상태", mk.mask("node10 상태")
    # ② 낱말로 서 있으면 바뀐다
    assert "[host-" in mk.mask("db01 재기동"), mk.mask("db01 재기동")
    assert "[host-" in mk.mask("호스트 db01."), mk.mask("호스트 db01.")
    # ③ 대소문자가 달라도 잡는다
    assert "[host-" in mk.mask("DB01 down"), mk.mask("DB01 down")
    # ④ 긴 것이 먼저 — 짧은 이름이 긴 이름 안을 먹지 않는다
    out = mk.mask("report-Customer-B 리포트")
    assert out.count("[host-") == 1, out
    # ⑤ 등록 원문 왕복은 그대로
    assert mk.unmask(mk.mask("db01")) == "db01"
    # ⑥ 대소문자가 다른 자리는 정규형으로 돌아온다 — 의도한 동작임을 못 박는다
    assert mk.unmask(mk.mask("DB01")) == "db01"

    # ── 표가 마지막 그물로 실제로 걸리는가 ──
    from . import nametable
    saved = (dict(nametable._terms), dict(nametable._by_source))
    try:
        nametable._terms = {"other-db-77": "host", "KINX WEB": "group"}
        # 사건 당사자가 아닌 호스트명이 로그에 섞인 상황
        ctx = {"incident": {"host": "h1"}, "host": {"host": "h1"},
               "alerts": [{"name": "n", "source": "s", "sev": "SEV3",
                           "class": "disk_space"}],
               "logs": ["backup from other-db-77 failed"], "security": [],
               "sources": {}}
        m2 = masking.Masker()
        blob = json.dumps(masking.build_llm_context(ctx, "SEV3", m2), ensure_ascii=False)
        assert "other-db-77" not in blob,             f"사건 당사자가 아닌 호스트명이 그대로 나간다: {blob}"
        # 표에 없는 낱말은 안 건드린다
        assert "backup" in blob and "failed" in blob, blob
    finally:
        nametable._terms, nametable._by_source = saved

    # 위험 판정이 실제로 위험한 것을 집는가. 치환은 대소문자를 무시하므로 판정도
    # 그래야 한다 — Test 는 일반 문장의 test 를 바꾸는데 위험으로 안 잡혔다.
    saved2 = dict(nametable._terms)
    try:
        nametable._terms = {"Test": "group", "kdhtest": "host", "임시": "group"}
        why = {r["name"]: r["why"] for r in nametable.risky()}
        assert "Test" in why, f"흔한 낱말인데 위험으로 안 잡힌다: {why}"
        assert any("낱말" in w for w in why["Test"]), why["Test"]
        assert "임시" in why, why
        assert "kdhtest" in why, why
    finally:
        nametable._terms = saved2

    return 15


def _store_checks() -> int:
    """판정 이력 저장소 — 남기고, 세고, 재기동을 견디는가 (§24)."""
    import os
    import shutil
    import tempfile

    from . import store

    d = tempfile.mkdtemp(prefix="store-test-")
    saved = store.PATH
    try:
        store.PATH = os.path.join(d, "hist.db")
        store.init()

        # ① 판정 한 건을 남기고 되읽는다
        store.record_judgment({
            "fingerprint": "fp1", "host": "h1", "realm": "internal",
            "source": "zabbix-internal", "classes": "disk_space", "alert_count": 2,
            "sev": "SEV2", "verdict": "만성", "gate_fired": 1,
            "gate_reason": "2건 병합", "sources": "logs:ok,security:ok",
            "provider": "claude", "degraded": 0, "total_s": 21.4,
        }, now=1000.0)
        rows = store.judgments(since=0, now=2000.0)
        assert len(rows) == 1, rows
        assert rows[0]["fingerprint"] == "fp1" and rows[0]["verdict"] == "만성", rows[0]

        # ② 중복 판정 — 같은 키는 한 번만 통과하고 창이 지나면 다시 통과
        assert store.seen_once("k1", ttl_s=3600, now=1000.0) is True
        assert store.seen_once("k1", ttl_s=3600, now=1100.0) is False
        assert store.seen_once("k1", ttl_s=3600, now=1000.0 + 3601) is True

        # ③ 호출 창 — 시간이 지나면 빠진다
        for i in range(5):
            store.record_call("triage", now=1000.0 + i)
        assert store.calls_since(3600, now=1010.0) == 5
        assert store.calls_since(3600, now=1000.0 + 3700) == 0
        assert store.calls_since(3600, now=1010.0, kind="triage") == 5
        assert store.calls_since(3600, now=1010.0, kind="monthly") == 0

        # ④ 재기동을 견딘다 — 이게 이 저장소의 존재 이유다
        store.close()
        store.init()
        assert store.calls_since(3600, now=1010.0) == 5, "재기동에 호출 창이 사라졌다"
        assert store.seen_once("k1", ttl_s=3600, now=1100.0) is False,             "재기동에 중복 판정 창이 사라졌다"
        assert len(store.judgments(since=0, now=2000.0)) == 1

        # ⑤ 저장소를 못 쓰면 조용히 멈추지 않는다
        store.close()
        # 없는 디렉토리는 코드가 만들어 주므로 실패가 아니다. 디렉토리 자체를 지정한다.
        store.PATH = d
        assert store.init() is False, "쓸 수 없는 경로인데 성공으로 봤다"
        assert store.record_judgment({"fingerprint": "fp2"}) is None
        assert store.seen_once("k2", ttl_s=10) is True, "저장소가 죽어도 알림은 흘러야"

        # ⑥ 배선 — 사건을 마감하면 이력이 남는가. 함수가 아니라 경로를 본다.
        import asyncio
        import time as _t

        from . import incident as inc_mod, triage

        store.PATH = os.path.join(d, "wire.db")
        store.close()
        store.init()
        inc = inc_mod.Incident(
            key=("internal", "h9", "disk_space"), host="h9",
            alerts=[inc_mod.Alert(source="zabbix-internal", event_id="e9",
                                  trigger_id="", host="h9", alert_name="n",
                                  sev="SEV3", incident_class="disk_space",
                                  recv=_t.monotonic())],
            opened_at=_t.monotonic(), last_at=_t.monotonic())

        class _DeadZbx:
            source = "zabbix-internal"

            async def call(self, *a, **kw):
                raise RuntimeError("down")

        saved_keep = os.environ.pop("KEEP_URL", None)
        saved_slack = os.environ.pop("SLACK_BOT_TOKEN", None)
        try:
            asyncio.run(triage.run_incident(inc))
        finally:
            if saved_keep is not None:
                os.environ["KEEP_URL"] = saved_keep
            if saved_slack is not None:
                os.environ["SLACK_BOT_TOKEN"] = saved_slack
        rows = store.judgments(since=0)
        assert rows, "사건을 마감했는데 이력이 안 남았다"
        assert rows[0]["fingerprint"] == inc.fingerprint(), rows[0]
        assert rows[0]["gate_reason"], rows[0]
        return 18
    finally:
        store.close()
        store.PATH = saved
        shutil.rmtree(d, ignore_errors=True)


def _store_schema_checks() -> int:
    """스키마 판올림과 판정 식별자 (§24-4)."""
    import os
    import shutil
    import sqlite3
    import tempfile
    import time as _time

    from . import store

    d = tempfile.mkdtemp(prefix="store-v1-")
    saved = store.PATH
    try:
        # ⓪ 물결표를 편다. 안 펴면 작업 디렉토리 밑 `~` 폴더에 조용히 쌓인다.
        import importlib
        saved_env = os.environ.get("GATEWAY_STORE_FILE")
        os.environ["GATEWAY_STORE_FILE"] = "~/.kinx-gateway/history.db"
        try:
            got = importlib.reload(store).PATH
            assert "~" not in got, got
        finally:
            if saved_env is None:
                os.environ.pop("GATEWAY_STORE_FILE", None)
            else:
                os.environ["GATEWAY_STORE_FILE"] = saved_env
            importlib.reload(store)

        # ① 구스키마 파일 — 판올림이 컬럼을 만들고 기존 행을 보존한다
        p = os.path.join(d, "old.db")
        c = sqlite3.connect(p)
        c.executescript(
            "CREATE TABLE judgment (ts REAL NOT NULL, fingerprint TEXT, host TEXT,"
            " realm TEXT, source TEXT, classes TEXT, alert_count INTEGER, sev TEXT,"
            " verdict TEXT, gate_fired INTEGER, gate_reason TEXT, sources TEXT,"
            " provider TEXT, degraded INTEGER, total_s REAL);"
            "CREATE TABLE seen (key TEXT PRIMARY KEY, ts REAL NOT NULL);"
            "CREATE TABLE call (ts REAL NOT NULL, kind TEXT);")
        c.execute("INSERT INTO judgment (ts,fingerprint,host) VALUES (?,?,?)",
                  (500.0, "old-fp", "old-host"))
        c.commit()
        c.close()

        store.PATH = p
        store.close()
        assert store.init() is True, "구스키마를 판올림하지 못했다"
        rows = store.judgments(since=0, now=9e9)
        assert len(rows) == 1 and rows[0]["fingerprint"] == "old-fp", rows
        assert rows[0]["id"], "판올림 뒤 옛 행에 식별자가 없다"
        for col in ("event_ts", "ikey", "origin", "summary", "change",
                    "prior_used", "annotation_id"):
            assert col in rows[0], col

        # ② 두 번 열어도 예외가 없다 — mark CLI 가 같은 파일을 따로 연다
        store.close()
        assert store.init() is True, "두 번째 판올림이 실패했다"

        # ③ 식별자는 재사용되지 않는다
        j1 = store.record_judgment({"fingerprint": "a", "host": "h"}, now=1000.0)
        j2 = store.record_judgment({"fingerprint": "b", "host": "h"}, now=1001.0)
        assert isinstance(j1, int) and j2 > j1, (j1, j2)
        store._exec("DELETE FROM judgment")
        j3 = store.record_judgment({"fingerprint": "c", "host": "h"}, now=1002.0)
        assert j3 > j2, "표를 비웠더니 식별자가 되돌아갔다 — 옛 카드가 남의 판정을 가리킨다"

        # ④ finish 는 해당 행만 갱신하고 없는 식별자는 무시한다
        j4 = store.record_judgment({"fingerprint": "d", "host": "h"}, now=1003.0)
        store.finish(j4, {"provider": "claude", "total_s": 12.5, "summary": "결론"})
        store.finish(999999, {"provider": "x"})
        rows = {r["id"]: r for r in store.judgments(since=0, now=9e9)}
        assert rows[j4]["provider"] == "claude" and rows[j4]["total_s"] == 12.5
        assert rows[j4]["summary"] == "결론"
        assert rows[j3]["provider"] in (None, ""), rows[j3]

        # ⑤ 라벨 — 같은 판정·같은 축에 둘이면 나중 것이 이긴다
        store.record_feedback(j4, "overall", ok=False, who="t", now=2000.0)
        store.record_feedback(j4, "overall", ok=True, who="t", now=2100.0)
        labels = store.labels_for([j4])
        assert labels[j4]["overall"]["ok"] == 1, labels

        # ⑥ 라우팅 기록 — 중복으로 걸린 것도 분모에 남는다
        store.record_route({"source": "zabbix-internal", "host": "h", "sev": "SEV3",
                            "cls": "disk_space", "route": "triage", "dup": 0},
                           now=3000.0)
        store.record_route({"source": "zabbix-internal", "host": "h", "sev": "SEV3",
                            "cls": "disk_space", "route": "triage", "dup": 1},
                           now=3001.0)
        rt = store.routes(since=0, now=9e9)
        assert len(rt) == 2 and sum(r["dup"] for r in rt) == 1, rt

        # ⑦ 서술만 먼저 지운다 — 행은 남고 지표는 그대로 산출된다
        store.prune(now=1003.0 + store.SUMMARY_DAYS * 86400 + 10)
        rows = {r["id"]: r for r in store.judgments(since=0, now=9e9)}
        assert j4 in rows, "보관 기한이 남았는데 행이 사라졌다"
        assert not rows[j4]["summary"], "서술 보관 기한이 지났는데 남아 있다"

        # ⑧ 주기 정리가 실제로 돈다 — 기동 때 한 번뿐이면 보관 기한을 못 지킨다
        old = _time.time() - (store.SUMMARY_DAYS + 10) * 86400
        jp = store.record_judgment({"fingerprint": "p", "host": "h",
                                    "summary": "옛 서술"}, now=old)
        pr = store.Pruner(interval_s=0.05)
        pr.start()
        try:
            for _ in range(40):
                _time.sleep(0.05)
                if not store.get_judgment(jp).get("summary"):
                    break
        finally:
            pr.stop()
        row = store.get_judgment(jp)
        assert row, "보관 기한이 남은 행을 주기 정리가 지웠다"
        assert not row.get("summary"), "주기 정리가 안 돌았다"
        return 19
    finally:
        store.close()
        store.PATH = saved
        shutil.rmtree(d, ignore_errors=True)


def _judgment_wiring_checks() -> int:
    """판정 행이 카드보다 먼저 생기는가 — 정정 버튼이 가리킬 대상 (§25-1)."""
    import asyncio
    import os
    import shutil
    import tempfile
    import time as _t

    from . import collector, incident as inc_mod, keep, llm, store, triage

    d = tempfile.mkdtemp(prefix="wire-")
    saved_path, saved_push, saved_llm = store.PATH, keep.push_alert, llm.triage_reply
    saved_zbx, saved_ctx = collector.ZabbixClient, collector.collect_incident_context
    saved_keep = os.environ.pop("KEEP_URL", None)
    saved_slack = os.environ.pop("SLACK_BOT_TOKEN", None)
    cards = []

    def _fake_push(*a, **kw):
        cards.append(kw)
        return {"ok": True}

    def _fake_llm(context, sev):
        return {"text": "원인은 백업 부하다", "provider": "claude", "degraded": False,
                "change": "이전과 동일", "reason": ""}

    class _Zbx:
        def __init__(self, *a, **kw):
            self.source = "zabbix-internal"

    async def _fake_ctx(zbx, inc):
        # 조회는 전부 성공했고 교차 신호만 없는 상태 — 게이트가 정상적으로 건너뛴다
        return {"incident": {"host": inc.host, "classes": sorted(inc.classes()),
                             "alert_count": len(inc.alerts),
                             "fingerprint": inc.fingerprint()},
                "host": {}, "logs": [], "security": [], "open_problems": [],
                "alerts": [{"name": a.alert_name, "source": a.source, "sev": a.sev,
                            "class": a.incident_class,
                            "prejudge": {"verdict": "만성"}} for a in inc.alerts],
                "sources": {"logs": "ok", "security": "ok", "metrics": "ok",
                            "open_problems": "ok"}}

    def _mk(cls="disk_space", clock=1700000000.0):
        return inc_mod.Incident(
            key=("internal", "h7", cls), host="h7",
            alerts=[inc_mod.Alert(source="zabbix-internal", event_id="e7",
                                  trigger_id="t7", host="h7", alert_name="디스크",
                                  sev="SEV2", incident_class=cls,
                                  recv=_t.monotonic(), clock=clock)],
            opened_at=_t.monotonic(), last_at=_t.monotonic())

    try:
        store.PATH = os.path.join(d, "w.db")
        store.close()
        store.init()
        keep.push_alert = _fake_push
        llm.triage_reply = _fake_llm
        collector.ZabbixClient = _Zbx
        collector.collect_incident_context = _fake_ctx

        # ① 게이트 스킵 — 카드에 판정 식별자가 실리고 DB 행과 같다
        inc = _mk()
        asyncio.run(triage.run_incident(inc))
        rows = store.judgments(since=0, now=9e9)
        assert len(rows) == 1 and rows[0]["gate_fired"] == 0, rows
        assert cards and cards[-1].get("extra", {}).get("judgment_id") == rows[0]["id"], cards[-1]
        assert rows[0]["origin"] == "auto", rows[0]
        assert rows[0]["event_ts"] == 1700000000.0, "사건 발생 시각이 안 들어왔다"
        assert rows[0]["ikey"], "폴백 키가 비었다"

        # ② 사람이 강제한 재분석 — 분모에서 빼야 하므로 표시가 남는다
        cards.clear()
        inc2 = _mk()
        asyncio.run(triage.run_incident(inc2, force=True))
        rows = [r for r in store.judgments(since=0, now=9e9) if r["origin"] == "forced"]
        assert len(rows) == 1, "강제 재분석이 auto 와 구분되지 않는다"
        assert rows[0]["gate_fired"] == 1 and rows[0]["provider"] == "claude", rows[0]
        assert rows[0]["summary"] == "원인은 백업 부하다", "분석 결론이 안 남았다"
        assert rows[0]["change"] == "이전과 동일", rows[0]
        assert rows[0]["total_s"] is not None, "finish 가 안 불렸다"
        assert cards and cards[-1].get("extra", {}).get("judgment_id") == rows[0]["id"]

        # ③ 저장소가 죽어도 카드는 나가고 흐름이 안 깨진다
        store.close()
        store.PATH = d
        store.init()
        cards.clear()
        asyncio.run(triage.run_incident(_mk()))
        assert cards, "저장소가 죽자 카드까지 멈췄다"
        assert not cards[-1].get("extra", {}).get("judgment_id")
        return 14
    finally:
        store.close()
        store.PATH, keep.push_alert, llm.triage_reply = saved_path, saved_push, saved_llm
        collector.ZabbixClient, collector.collect_incident_context = saved_zbx, saved_ctx
        if saved_keep is not None:
            os.environ["KEEP_URL"] = saved_keep
        if saved_slack is not None:
            os.environ["SLACK_BOT_TOKEN"] = saved_slack
        shutil.rmtree(d, ignore_errors=True)


def _feedback_checks() -> int:
    """사람이 남기는 판정 라벨 — 틀린 대상에 붙지 않고, 실패가 성공으로 안 보이는가 (§25-2)."""
    import os
    import shutil
    import sys
    import tempfile

    from . import store

    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    import mark_judgment

    d = tempfile.mkdtemp(prefix="mark-")
    saved = store.PATH
    try:
        store.PATH = os.path.join(d, "m.db")
        store.close()
        store.init()
        jid = store.record_judgment({"fingerprint": "fp-a", "host": "h1"}, now=1000.0)

        # ① 없는 판정·지문 불일치·모르는 축은 전부 실패로 끝난다.
        #    워크플로는 종료코드로만 성패를 안다. 0 을 돌려주면 사람은 정정이 된 줄 안다.
        assert mark_judgment.run(jid=999999, fingerprint="fp-a", ok=False) != 0
        assert mark_judgment.run(jid=jid, fingerprint="다른지문", ok=False) != 0
        assert mark_judgment.run(jid=jid, fingerprint="fp-a", ok=False, axis="없는축") != 0
        assert not store.labels_for([jid]), "실패한 요청이 라벨을 남겼다"

        # ② 정상 정정
        assert mark_judgment.run(jid=jid, fingerprint="fp-a", ok=False,
                                 note="봤어야 했다", who="tester") == 0
        lab = store.labels_for([jid])
        assert lab[jid]["overall"]["ok"] == 0 and lab[jid]["overall"]["who"] == "tester"

        # ③ 지문 없이도 식별자만으로 되지만, 그건 사람이 직접 부를 때다
        assert mark_judgment.run(jid=jid, fingerprint="", ok=True) == 0
        assert store.labels_for([jid])[jid]["overall"]["ok"] == 1, "나중 라벨이 안 이겼다"

        # ④ 저장소를 못 쓰면 실패로 끝낸다 — 아무도 안 읽는 파일에 쌓이면 안 된다
        store.close()
        store.PATH = d
        assert mark_judgment.run(jid=1, fingerprint="", ok=True) != 0

        # ⑤ 사람이 재분석을 누른 것 자체가 게이트 판정에 대한 음성 라벨이다
        import analyze_now
        store.close()
        store.PATH = os.path.join(d, "m.db")
        store.init()
        n = analyze_now.label_previous("fp-a")
        assert n == 1, "직전 판정에 라벨이 안 붙었다"
        lab = store.labels_for([jid])
        assert lab[jid]["gate"]["ok"] == 0, lab
        assert lab[jid]["gate"]["who"] == "workflow:analyze-now", lab
        assert analyze_now.label_previous("없는지문") == 0
        return 12
    finally:
        store.close()
        store.PATH = saved
        shutil.rmtree(d, ignore_errors=True)


def _route_record_checks() -> int:
    """라우팅 판정이 남는가 — 판정 이력만 보면 triage 경로밖에 안 보인다 (§25-3)."""
    import os
    import shutil
    import tempfile

    from . import app as app_mod, pending, store

    d = tempfile.mkdtemp(prefix="route-")
    saved_path, saved_pending = store.PATH, pending.PATH
    saved_tok = os.environ.get("GATEWAY_TOKEN")
    os.environ["GATEWAY_TOKEN"] = "t-route"

    class _FakeBg:
        def add_task(self, fn, *a, **kw):
            pass

    try:
        store.PATH = os.path.join(d, "r.db")
        pending.PATH = os.path.join(d, "pending.jsonl")
        store.close()
        store.init()

        def _ev(eid, nsev):
            return app_mod.ZabbixEvent(source="zabbix-internal", event_id=eid,
                                       trigger_id="t1", nseverity=nsev, host="h1",
                                       event_name="Disk space is low")

        r1 = app_mod.webhook_zabbix(_ev("e1", 4), _FakeBg(), "t-route")
        r2 = app_mod.webhook_zabbix(_ev("e1", 4), _FakeBg(), "t-route")   # 같은 알림
        app_mod.webhook_zabbix(_ev("e2", 1), _FakeBg(), "t-route")        # 낮은 심각도
        assert r1["status"] == "accepted" and r2["status"] == "duplicate"

        rows = store.routes(since=0, now=9e9)
        assert len(rows) == 3, "중복이 분모에서 조용히 빠졌다: %s" % rows
        dups = [r for r in rows if r["dup"]]
        assert len(dups) == 1 and dups[0]["route"], "중복 행에 경로가 안 실렸다"
        assert {r["route"] for r in rows} == {"triage", "dashboard_only"}, rows
        assert all(r["cls"] == "disk_space" for r in rows), rows
        assert all(r["host"] == "h1" and r["source"] == "zabbix-internal" for r in rows)
        return 8
    finally:
        store.close()
        store.PATH, pending.PATH = saved_path, saved_pending
        if saved_tok is None:
            os.environ.pop("GATEWAY_TOKEN", None)
        else:
            os.environ["GATEWAY_TOKEN"] = saved_tok
        shutil.rmtree(d, ignore_errors=True)


def _annotation_checks() -> int:
    """판정 주석 — 지표 스파이크와 같은 자리에 찍히는가, 실패가 조용한가 (§25-4)."""
    import os

    from . import grafana

    saved_env = {k: os.environ.get(k) for k in
                 ("GATEWAY_GRAFANA_URL", "GRAFANA_INTERNAL_URL", "GRAFANA_TOKEN")}
    saved_httpx = grafana.httpx
    sent = []

    class _Resp:
        def __init__(self, code, payload):
            self.status_code, self._p, self.text = code, payload, str(payload)

        def json(self):
            return self._p

    class _FakeHttpx:
        def __init__(self, code=200, payload=None, boom=False):
            self.code, self.payload, self.boom = code, payload or {"id": 77}, boom

        def post(self, url, **kw):
            sent.append((url, kw))
            if self.boom:
                raise RuntimeError("연결 거부")
            return _Resp(self.code, self.payload)

        def get(self, url, **kw):
            sent.append((url, kw))
            return _Resp(self.code, self.payload)

    try:
        for k in saved_env:
            os.environ.pop(k, None)

        # ① 주소·토큰이 없으면 발행하지 않는다. 예외도 아니다.
        grafana.httpx = _FakeHttpx()
        assert grafana.annotate("x", 1700000000.0) is None
        assert not sent, "주소가 없는데 어딘가로 보냈다"

        os.environ["GATEWAY_GRAFANA_URL"] = "http://grafana.local:3000"
        assert grafana.annotate("x", 1700000000.0) is None, "토큰 없이 보냈다"

        # ② 정상 발행 — 시각은 밀리초이고 사건 발생 시각이다
        os.environ["GRAFANA_TOKEN"] = "tok"
        sent.clear()
        aid = grafana.annotate("복제 지연 · SEV2", 1700000000.0,
                               tags=["kinx-bot", "SEV2"])
        assert aid == 77, aid
        url, kw = sent[-1]
        assert url.endswith("/api/annotations"), url
        body = kw["json"]
        assert body["time"] == 1700000000000, \
            "초로 보내면 1970년에 찍히고 화면에서 조용히 사라진다: %s" % body["time"]
        assert "timeEnd" not in body, "해소 시각을 모르는데 구간으로 찍었다"
        assert body["tags"] == ["kinx-bot", "SEV2"] and body["text"]
        assert kw["headers"]["Authorization"] == "Bearer tok"

        # ③ 실패는 조용히 넘어간다 — 트리아지를 막지 않는다
        grafana.httpx = _FakeHttpx(boom=True)
        assert grafana.annotate("x", 1700000000.0) is None
        grafana.httpx = _FakeHttpx(code=401, payload={"message": "unauthorized"})
        assert grafana.annotate("x", 1700000000.0) is None

        # ④ 사건 시각을 모르면(0) 발행하지 않는다 — 1970년 주석을 만들지 않는다
        grafana.httpx = _FakeHttpx()
        assert grafana.annotate("x", 0) is None

        # ⑤ 주석은 판정 행에 남은 사건 시각을 그대로 쓴다. 다시 계산하면 발행 측이 시각을
        #    안 실어 보낸 알림에서 분석에 걸린 시간만큼 밀린다(2026-08-12 랩 실측 21초).
        import asyncio
        import time as _t

        from . import incident as inc_mod, triage

        sent.clear()
        grafana.httpx = _FakeHttpx()
        inc = inc_mod.Incident(
            key=("internal", "h1", "other"), host="h1",
            alerts=[inc_mod.Alert(source="zabbix-internal", event_id="e1",
                                  trigger_id="", host="h1", alert_name="n",
                                  sev="SEV1", incident_class="other",
                                  recv=_t.monotonic())],   # clock 없음 = 발행 측 미제공
            opened_at=_t.monotonic(), last_at=_t.monotonic())
        asyncio.run(triage._annotate(None, inc, "SEV1", "헤드", "단일", "본문",
                                     event_ts=1700000000.0))
        assert sent and sent[-1][1]["json"]["time"] == 1700000000000, sent[-1][1]["json"]
        # 사건 유형이 태그에 실려야 패널이 자기가 다루는 것만 골라 갈 수 있다
        assert "other" in sent[-1][1]["json"]["tags"], sent[-1][1]["json"]["tags"]
        return 15
    finally:
        grafana.httpx = saved_httpx
        for k, v in saved_env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


def _quality_checks() -> int:
    """판정 정확도 산출 — 라벨이 없을 때 숫자를 지어내지 않는가 (§25-5)."""
    import os
    import shutil
    import tempfile

    from . import quality, store

    d = tempfile.mkdtemp(prefix="quality-")
    saved = store.PATH
    T = 1700000000.0
    try:
        store.PATH = os.path.join(d, "q.db")
        store.close()
        store.init()

        ids = []
        for i in range(10):
            ids.append(store.record_judgment({
                "fingerprint": "fp%d" % i, "ikey": "internal|h1|bridge1",
                "host": "h1", "realm": "internal", "classes": "disk_space",
                "alert_count": 1 + (i % 3), "sev": "SEV2", "verdict": "만성",
                "gate_fired": 1 if i < 6 else 0, "origin": "auto",
                "event_ts": T - 3600 + i, "provider": "claude", "degraded": i == 0,
                "total_s": None if i < 2 else 10.0 + i,
                "change": "이전과 동일" if i < 5 else "새 증상",
                "annotation_id": 5 if i < 4 else None,
                "sources": "logs:ok,security:unavailable"}, now=T - 3600 + i))
        store.record_judgment({"fingerprint": "fpF", "host": "h1", "origin": "forced",
                               "gate_fired": 1, "event_ts": T - 100,
                               "total_s": 99.0}, now=T - 100)

        # ① 라벨이 하나도 없으면 정확도 칸에 백분율이 없어야 한다.
        #    각주 붙은 92%는 슬라이드에 92%로 옮겨진다.
        m = quality.collect(days=30, now=T)
        acc = quality.render_accuracy(m)
        assert "%" not in acc, "라벨 0건인데 백분율을 만들었다:\n%s" % acc
        assert "판정 불가" in acc and "0/10" in acc, acc

        # ② 강제 재분석은 분모에서 빠진다
        assert m["judgments"] == 10 and m["forced"] == 1, m
        assert abs(m["gate_fire_rate"] - 0.6) < 1e-9, m

        # ③ 응답시간은 값이 없는 행을 빼고, 뺀 건수를 함께 낸다
        assert m["latency"]["n"] == 8 and m["latency"]["excluded"] == 2, m["latency"]
        assert "%.1f" % m["latency"]["p50"] not in ("0.0",), m["latency"]

        # ④ 라벨이 임계 미만이면 점추정을 만들지 않는다
        for i in range(3):
            store.record_feedback(ids[i], "overall", ok=True, who="t", now=T)
        m = quality.collect(days=30, now=T)
        acc = quality.render_accuracy(m)
        assert "%" not in acc and "3/10" in acc, acc

        # ⑤ 임계를 넘으면 점추정과 신뢰구간이 함께 나온다
        saved_min = quality.MIN_LABELS
        quality.MIN_LABELS = 3
        try:
            m = quality.collect(days=30, now=T)
            acc = quality.render_accuracy(m)
            assert "100.0%" in acc and "95% CI" in acc, acc
            lo, hi = m["accuracy"]["overall"]["ci"]
            assert 0.0 < lo < 1.0 and abs(hi - 1.0) < 1e-9, (lo, hi)
        finally:
            quality.MIN_LABELS = saved_min

        # ⑥ 조치 성공률은 지어내지 않고 사유를 남긴다
        assert "미확인" in quality.render(m), quality.render(m)

        # ⑦ 라벨 없이 재는 병합 축 — 같은 호스트에서 창 안에 갈라진 사건
        assert m["split_incidents"] >= 1, m

        # ⑧ 측정 조건이 헤더에 박힌다
        head = quality.render(m)
        assert "창 30일" in head and "판정 10건" in head, head

        # ⑨ 보낼 키와 받을 아이템이 문자 단위로 같다. 어긋나면 전송은 성공인데 화면만 빈다.
        import io
        import re as _re
        root = os.path.dirname(os.path.dirname(os.path.dirname(
            os.path.abspath(__file__))))
        with io.open(os.path.join(root, "ansible", "quality_metrics.yml"),
                     encoding="utf-8") as f:
            declared = set(_re.findall(r'key:\s*"(quality\.[a-z0-9_]+)"', f.read()))
        sending = set(quality.trapper_values(m))
        assert sending == declared, "키 불일치: 보냄-선언 %s / 선언-보냄 %s" % (
            sorted(sending - declared), sorted(declared - sending))

        # ⑩ 산출 안 된 정확도는 0 이 아니라 -1 로 간다 — 0 은 "정확도 0%" 로 읽힌다
        assert quality.trapper_values(m)["quality.acc_gate"] == -1, "미산출을 0 으로 보냈다"
        return 19
    finally:
        store.close()
        store.PATH = saved
        shutil.rmtree(d, ignore_errors=True)


def _prior_checks() -> int:
    """과거 결론 연계 — 무엇을 고르고, 무엇을 절대 안 싣는가 (§25-6)."""
    import json
    import os
    import shutil
    import tempfile
    import time as _t

    from . import incident as inc_mod, masking, nametable, prior, store

    d = tempfile.mkdtemp(prefix="prior-")
    saved_path, saved_terms = store.PATH, dict(nametable._terms)
    saved_mode = prior.MODE
    T = 1700000000.0

    def _inc(host="db01", cls="replication"):
        return inc_mod.Incident(
            key=("internal", host, "bridge1"), host=host,
            alerts=[inc_mod.Alert(source="zabbix-internal", event_id="e1",
                                  trigger_id="t1", host=host, alert_name="복제 지연",
                                  sev="SEV2", incident_class=cls,
                                  recv=_t.monotonic(), clock=T)],
            opened_at=_t.monotonic(), last_at=_t.monotonic())

    try:
        store.PATH = os.path.join(d, "p.db")
        store.close()
        store.init()
        inc = _inc()
        fp, ikey = inc.fingerprint(), "|".join(str(x) for x in inc.key)

        def _add(fingerprint, ikey_, host, ts, summary, classes="replication"):
            return store.record_judgment({
                "fingerprint": fingerprint, "ikey": ikey_, "host": host,
                "realm": "internal", "classes": classes, "sev": "SEV2",
                "verdict": "만성", "gate_fired": 1, "origin": "auto",
                "event_ts": ts, "summary": summary, "prior_used": 0}, now=ts)

        old = _add(fp, ikey, "db01", T - 20 * 86400, "20일 전 결론: 백업 I/O 경합")
        recent = _add(fp, ikey, "db01", T - 2 * 86400,
                      "2일 전 결론: sw-core-01 상류에서 지연")
        _add("다른지문", ikey, "db01", T - 5 * 86400, "유형만 같은 결론")
        _add("또다른", "internal|db01|bridge9", "db01", T - 6 * 86400, "호스트만 같은 결론")
        me = _add(fp, ikey, "db01", T, "지금 사건")

        # ① 자기 자신은 안 고른다. 시각 역순이고 상한을 지킨다.
        got = prior.select(inc, me, now=T)
        assert all(p["id"] != me for p in got), got
        assert len(got) <= prior.MAX_ITEMS, got
        assert got[0]["match"] == "동일 사건", got[0]

        # ② 폴백 3단 — 지문이 갈려도 유형·호스트로 찾아낸다
        inc2 = _inc()
        store._exec("DELETE FROM judgment WHERE fingerprint=?", (fp,))
        g2 = prior.select(inc2, None, now=T)
        assert g2 and g2[0]["match"] == "같은 유형", g2
        store._exec("DELETE FROM judgment WHERE ikey=?", (ikey,))
        g3 = prior.select(inc2, None, now=T)
        assert g3 and g3[0]["match"] == "같은 호스트", g3

        # ③ 본문은 사람이 확인한 결론에만 붙는다. 기본은 구조화만이다.
        store.close()
        store.PATH = os.path.join(d, "p2.db")
        store.init()
        old = _add(fp, ikey, "db01", T - 20 * 86400, "20일 전 결론: 백업 I/O 경합")
        recent = _add(fp, ikey, "db01", T - 2 * 86400,
                      "2일 전 결론: sw-core-01 상류에서 지연")
        nametable._terms = {"db01": "host", "sw-core-01": "host"}
        store.record_feedback(recent, "cause", ok=True, who="t", now=T)
        got = prior.select(inc, None, now=T)
        assert all(not p["summary"] for p in got), \
            "기본 모드인데 본문이 실렸다 — 확인된 결론이라도 기본은 구조화만이다"
        assert [p for p in got if p["confirmed"]], got

        prior.MODE = "full"
        got = prior.select(inc, None, now=T)
        body = [p for p in got if p["summary"]]
        assert len(body) == 1 and body[0]["id"] == recent, got

        # ④ 오답 표시된 결론은 본문 없이 개수만 — 모델은 틀린 문장도 베낀다
        store.record_feedback(old, "cause", ok=False, who="t", now=T)
        got = prior.select(inc, None, now=T)
        wrong = [p for p in got if p["confirmed"] is False and p.get("wrong")]
        assert wrong and not wrong[0]["summary"], got

        # ⑤ 프롬프트로 나가는 전문에 다른 호스트 실명이 남지 않는다
        ctx = {"incident": {"host": "db01", "classes": ["replication"],
                            "alert_count": 1, "merge_reason": "단일"},
               "host": {"host": "db01"}, "alerts": [], "logs": [], "security": [],
               "sources": {"logs": "ok"}, "prior": got}
        out = masking.build_llm_context(ctx, "SEV2", masking.Masker())
        blob = json.dumps(out, ensure_ascii=False)
        assert "sw-core-01" not in blob, "표에 있는 다른 호스트명이 그대로 나갔다"
        assert "db01" not in blob, blob[:200]
        assert out["prior"] and out["prior"][0]["match"], out["prior"]

        # ⑥ 이름 표가 비면 본문을 아예 안 싣는다 — 가릴 대상을 모르는 상태다
        nametable._terms = {}
        out = masking.build_llm_context(ctx, "SEV2", masking.Masker())
        assert all(not p.get("summary") for p in out["prior"]), out["prior"]

        # ⑦ 길이 상한 — 과거 결론이 길어도 프롬프트가 그만큼 늘지 않는다
        nametable._terms = {"db01": "host"}
        big = dict(got[0], summary="가" * 10000, confirmed=True)
        out = masking.build_llm_context(dict(ctx, prior=[big]), "SEV2", masking.Masker())
        assert len(out["prior"][0]["summary"]) <= prior.MAX_BODY_CHARS + 10, \
            len(out["prior"][0]["summary"])

        # ⑧ 과거 결론이 붙을 때만 변화 판정을 요구하고, 그 줄을 코드가 읽는다
        from . import llm
        assert llm.PRIOR_INSTRUCTION not in llm.build_user_prompt({"prior": []})
        assert llm.PRIOR_INSTRUCTION in llm.build_user_prompt({"prior": [{"match": "x"}]})
        assert llm.extract_change("본문\n변화: 달라짐 — 이번엔 백업이 아니다") \
            == "달라짐 — 이번엔 백업이 아니다"
        assert llm.extract_change("변화 판정 줄이 없는 회신") == ""

        # ⑨ 꺼 두면 아무것도 안 고른다
        prior.MODE = "off"
        assert prior.select(inc, None, now=T) == []
        return 22
    finally:
        prior.MODE = saved_mode
        nametable._terms = saved_terms
        store.close()
        store.PATH = saved_path
        shutil.rmtree(d, ignore_errors=True)


def _dashboard_annotation_checks() -> int:
    """주석이 어느 패널에 서는가 — 번호가 어긋난 채 커밋되는 것을 잡는다 (§25-4)."""
    import io
    import json
    import os
    import sys

    root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    sys.path.insert(0, os.path.join(root, "tools"))
    import set_judgment_annotation as sja

    from . import incident as inc_mod

    n = 0
    for uid, spec in sja.SPEC.items():
        path = os.path.join(root, "lab", "grafana", "provisioning", "dashboards",
                            "json", uid + ".json")
        dash = json.load(io.open(path, encoding="utf-8"))
        qs = [a for a in (dash.get("annotations") or {}).get("list") or []
              if (a.get("name") or "").startswith(sja.QUERY_NAME)]
        assert qs, "%s: 판정 주석 질의가 없다 — set_judgment_annotation.py 를 돌린다" % uid
        assert qs == sja.queries(dash, spec), (
            "%s: 주석 질의가 선언과 어긋난다. set_judgment_annotation.py 를 다시 돌린다" % uid)
        by_id = {p.get("id"): p for p in dash.get("panels", [])}
        for q in qs:
            ids = (q.get("filter") or {}).get("ids")
            # 범위를 안 좁히면 통계 숫자 패널 옆까지 세로선이 선다
            assert ids, "%s: 표시 패널을 안 좁혔다" % uid
            for pid in ids:
                assert pid in by_id, "%s: 없는 패널 번호 %s" % (uid, pid)
                assert by_id[pid].get("type") in ("timeseries", "graph"), (
                    "%s: 주석이 안 그려지는 패널을 골랐다 — %s" % (uid, by_id[pid].get("type")))
            # 태그 조건은 AND 다. 봇이 안 다는 유형을 적으면 그 질의는 영원히 빈다.
            for tag in q["target"]["tags"][1:]:
                assert tag in inc_mod._KNOWN_CLASSES, (
                    "%s: 봇이 달지 않는 유형이다 — %s" % (uid, tag))
            assert q["target"]["tags"][0] == sja.TAG, q["target"]
        n += 5
    return n


def _contract_checks() -> int:
    """위탁 계약 제약이 분석 문장까지 가는가 (§2-3-3)."""
    import json
    import time as _t

    from . import app as gw_app, incident as inc_mod, llm, masking

    def _alert(scope="", automate=""):
        return inc_mod.Alert(source="zabbix-msp", event_id="e1", trigger_id="t1",
                             host="custa-db01", alert_name="MySQL is down",
                             sev="SEV2", incident_class="service_down",
                             recv=_t.monotonic(), scope=scope, automate=automate)

    def _inc(*alerts):
        return inc_mod.Incident(key=("msp", "custa-db01", "service_down"),
                                host="custa-db01", alerts=list(alerts),
                                opened_at=_t.monotonic(), last_at=_t.monotonic())

    # ① 계약 표시가 알림에 실려 인시던트까지 온다. 라우팅에서 쓰고 버리면 안 된다.
    assert _inc(_alert("notify_only")).scope() == "notify_only"
    assert _inc(_alert()).scope() == ""
    # 병합 시 하나라도 금지면 금지다 — 느슨한 쪽으로 접으면 금지 대상에 조치를 권한다
    assert _inc(_alert(), _alert("notify_only")).scope() == "notify_only"
    # 자동 조치 가능 여부도 근거가 있어야 한다. 모델이 지어내는 자리였다.
    assert _inc(_alert("", "service_restart")).automate() is True
    assert _inc(_alert()).automate() is False

    # ② 웹훅이 태그에서 받아 알림에 싣는다
    class _Bg:
        def add_task(self, fn, *a, **kw):
            fn(*a, **kw)          # 배경으로 미루지 않고 바로 돌린다

    import os
    import shutil
    import tempfile

    from . import pending
    d = tempfile.mkdtemp(prefix="scope-")
    saved_pending = pending.PATH
    captured = []
    saved_submit = gw_app._incidents.submit
    try:
        pending.PATH = os.path.join(d, "p.jsonl")
        gw_app._incidents.submit = lambda alert: captured.append(alert)
        gw_app._dispatch(_Bg(), "zabbix-msp", "e9", "t9", "custa-db01", "MySQL is down",
                         "SEV2", {"route": "triage", "playbook": None},
                         tags=[{"tag": "scope", "value": "notify_only"},
                               {"tag": "automate", "value": "service_restart"}])
    finally:
        pending.PATH = saved_pending
        gw_app._incidents.submit = saved_submit
        shutil.rmtree(d, ignore_errors=True)
    assert captured and captured[0].scope == "notify_only", captured
    assert captured[0].automate == "service_restart", captured

    # ③ 전송 형태에 실린다. 계약 표시는 식별자가 아니라 라벨이라 마스킹 대상이 아니다.
    ctx = {"incident": {"host": "custa-db01", "classes": ["service_down"],
                        "alert_count": 1, "merge_reason": "단일",
                        "scope": "notify_only", "automate": False},
           "host": {}, "alerts": [], "logs": [], "security": [],
           "sources": {"logs": "ok"}}
    out = masking.build_llm_context(ctx, "SEV2", masking.Masker())
    assert out["incident"]["scope"] == "notify_only", out["incident"]
    assert out["incident"]["automate"] is False, out["incident"]

    # ④ 금지일 때만 규칙이 프롬프트에 붙는다
    p_block = llm.build_user_prompt(out)
    assert llm.NOTIFY_ONLY_RULE in p_block
    ok = masking.build_llm_context(dict(ctx, incident=dict(ctx["incident"],
                                                          scope="")), "SEV2",
                                  masking.Masker())
    assert llm.NOTIFY_ONLY_RULE not in llm.build_user_prompt(ok)
    assert "custa-db01" not in json.dumps(out, ensure_ascii=False)
    return 13


def _destructive_advice_checks() -> int:
    """회신에 파괴적 복구 명령이 섞이면 사람에게 표시가 붙는가.

    2026-08-13 랩에서 haiku 로 내린 뒤 복제 지연 사건 회신에 `RESET SLAVE; START SLAVE;`
    가 권장 조치로 들어왔다. `RESET SLAVE` 는 복제 설정과 위치를 지운다. 같은 시나리오
    에서 opus 는 "복제 리셋 금지"를 명시했었다. 즉 이 안전 제약이 모델 품질에 얹혀
    있었다는 뜻이다. 판정과 안전은 코드가 진다는 원칙에 맞게 코드로 내린다.
    """
    from . import llm

    danger = ("복제를 되살리려면 `RESET SLAVE; START SLAVE;` 를 실행하십시오.",
              "RESET MASTER 후 재구성",
              "kill -9 로 mysqld 를 종료",
              "rm -rf /var/lib/mysql/relay-log.info")
    for text in danger:
        found = llm.destructive_ops(text)
        assert found, "파괴적 명령을 못 잡았다: %r" % text
        marked = llm.mark_destructive(text)
        assert marked != text and "확인" in marked, marked

    safe = ("SHOW SLAVE STATUS 로 상태를 확인하십시오.",
            "복제 리셋은 하지 마십시오 — 위치가 사라집니다.",
            "systemctl restart mariadb 로 재기동을 검토하십시오.")
    for text in safe:
        assert not llm.destructive_ops(text), "정상 문장을 잡았다: %r" % text
        assert llm.mark_destructive(text) == text, text

    # 프롬프트에도 금지가 적혀 있어야 한다. 코드 표시는 사후이고, 애초에 안 쓰게
    # 만드는 것이 먼저다.
    assert "RESET SLAVE" in llm.TRIAGE_SYSTEM, "프롬프트에 금지 항목이 없다"
    return 15


def _truncation_checks() -> int:
    """자른 것을 자랐다고 말하는가 (§1-1-8).

    로그는 40줄에서 잘리고 줄도 글자 수로 잘리는데 상태는 늘 ok 다. 모델은 그 40줄에
    없는 것을 없는 것으로 읽는다. 사건이 클수록 잘리는 비율이 높으니 하필 분석이 가장
    필요할 때 가장 크게 틀린다.
    """
    import asyncio
    import json
    import os

    from . import collector, llm, masking

    class _Resp:
        def __init__(self, lines):
            self._lines = lines

        def raise_for_status(self):
            pass

        def json(self):
            # 스트림 하나에 순번을 시각으로. 나노초 문자열이 Loki 형식이다.
            return {"data": {"result": [{"values": [
                [str((1700000000 + i) * 10 ** 9), ln]
                for i, ln in enumerate(self._lines)]}]}}

    class _Fake:
        def __init__(self, lines):
            self.lines = lines

        def AsyncClient(self, **_kw):
            outer = self

            class _C:
                async def __aenter__(self):
                    return self

                async def __aexit__(self, *a):
                    return False

                async def get(self, url, **kw):
                    return _Resp(outer.lines)
            return _C()

    saved_httpx = collector.httpx
    saved_url = os.environ.get("LOKI_URL")
    os.environ["LOKI_URL"] = "http://loki.invalid"
    try:
        # ① 조회 상한에 딱 찼으면 창에 더 있었다고 본다
        collector.httpx = _Fake(["line %d" % i
                                 for i in range(collector.LOKI_FETCH_LIMIT)])
        lines, status, trunc, clipped = asyncio.run(
            collector._loki_logs("h1", 1700000000))
        assert status == collector.SOURCE_OK and trunc is True, (status, trunc)
        assert clipped == 0, clipped

        # ② 상한 미만이면 아니다
        collector.httpx = _Fake(["a", "b"])
        _l, _s, trunc, clipped = asyncio.run(collector._loki_logs("h1", 1700000000))
        assert trunc is False and clipped == 0

        # ③ 줄이 잘린 개수를 센다 — 스택 추적 꼬리가 사라지는 자리다
        collector.httpx = _Fake(["x" * (collector.LOKI_LINE_MAX + 50), "짧은 줄"])
        recs, _s, _t, clipped = asyncio.run(collector._loki_logs("h1", 1700000000))
        assert clipped == 1, clipped
        assert max(len(r["line"]) for r in recs) == collector.LOKI_LINE_MAX, recs[:1]

        # ④ 전송 형태에 실린다. 수치라 마스킹 대상이 아니다.
        ctx = {"incident": {"host": "h1", "classes": ["disk_space"], "alert_count": 1},
               "host": {}, "alerts": [], "logs": ["a"], "security": [],
               "sources": {"logs": "ok"}, "logs_fetch_capped": True,
               "logs_clipped": 2}
        out = masking.build_llm_context(ctx, "SEV2", masking.Masker())
        assert out["logs_fetch_capped"] is True and out["logs_clipped"] == 2, out

        # ⑤ 잘렸을 때만 규칙이 붙는다. 안 잘렸는데 의심하게 만들면 그것도 오도다.
        assert llm.TRUNCATION_RULE in llm.build_user_prompt(out)
        whole = masking.build_llm_context(
            dict(ctx, logs_fetch_capped=False, logs_clipped=0), "SEV2", masking.Masker())
        assert llm.TRUNCATION_RULE not in llm.build_user_prompt(whole)
        assert "logs_fetch_capped" in json.dumps(out, ensure_ascii=False)

        # ⑥ 시각을 살린다. 정렬·증거 범위·"첫 오류 직전"이 전부 이 값을 요구한다.
        collector.httpx = _Fake(["a", "b", "c"])
        recs, _s, _t, _c = asyncio.run(collector._loki_logs("h1", 1700000000))
        assert recs and isinstance(recs[0], dict), recs[:1]
        assert all("t" in r and "line" in r for r in recs), recs[:1]

        # ⑦ 스트림이 여럿이면 이어 붙인 순서가 시각순이 아니다. 합친 뒤 정렬해야 한다.
        class _MultiResp:
            def raise_for_status(self):
                pass

            def json(self):
                return {"data": {"result": [
                    {"values": [["3000000000", "늦은 줄"]]},
                    {"values": [["1000000000", "이른 줄"]]}]}}

        class _MultiFake:
            def AsyncClient(self, **_kw):
                class _C:
                    async def __aenter__(self):
                        return self

                    async def __aexit__(self, *a):
                        return False

                    async def get(self, url, **kw):
                        return _MultiResp()
                return _C()

        collector.httpx = _MultiFake()
        recs, _s, _t, _c = asyncio.run(collector._loki_logs("h1", 1700000000))
        assert [r["line"] for r in recs] == ["이른 줄", "늦은 줄"], recs
        assert recs[0]["t"] < recs[1]["t"]

        # ⑧ 전송 제동은 줄 수가 아니라 글자 수로 건다. 지연 실측(2026-08-13)에서
        #    입력을 75배 늘려도 응답 시간이 2.2초밖에 안 늘어, 줄 수 상한이 지키던
        #    것이 사실상 없었다. 줄 수 상한은 안전망으로만 남기고 조회 상한을 넘지
        #    않게만 잠근다.
        assert collector.LOKI_FETCH_LIMIT >= collector.LOKI_SEND_LIMIT
        assert collector.LOKI_SEND_BYTES > 0

        # ⑨ 표시를 쪼갠다. 한 불리언에 "창에 더 있었다"와 "조회가 상한에 닿았다"를
        #    같이 실으면 오늘 고친 문제가 이름만 바꿔 재발한다.
        collector.httpx = _Fake(["line %d" % i for i in range(120)])
        recs, _s, capped, _c = asyncio.run(collector._loki_logs("h1", 1700000000))
        assert len(recs) == 120 and capped is False, (len(recs), capped)

        collector.httpx = _Fake(["x %d" % i for i in range(collector.LOKI_FETCH_LIMIT)])
        recs, _s, capped, _c = asyncio.run(collector._loki_logs("h1", 1700000000))
        assert capped is True, capped

        # ⑩ 바이트 예산 — 줄 수만으로는 부족하다. 300자 절단은 클라이언트에서 하므로
        #    와이어에는 전장이 온다. 긴 줄이면 300줄이 수 MB 가 되고 파싱이 루프를 막는다.
        collector.httpx = _Fake(["y" * 20000 for _ in range(200)])
        recs, _s, capped, _c = asyncio.run(collector._loki_logs("h1", 1700000000))
        assert capped is True and len(recs) < 200, (len(recs), capped)

        # ⑪ 전송 형태에 세 값이 실린다
        ctx = {"incident": {"host": "h1", "classes": ["disk_space"], "alert_count": 1},
               "host": {}, "alerts": [], "logs": [{"t": 1.0, "line": "a"}],
               "security": [], "sources": {"logs": "ok"},
               "logs_fetched": 263, "logs_selected": 40, "logs_fetch_capped": False}
        out = masking.build_llm_context(ctx, "SEV2", masking.Masker())
        assert out["logs_fetched"] == 263 and out["logs_selected"] == 40
        assert out["logs_fetch_capped"] is False

        # ⑫ 문구가 사실과 어긋나면 안 된다. 선별을 켜면 "가장 최근 것만"은 거짓이 된다.
        assert "가장 최근 것만" not in llm.TRUNCATION_RULE
        return 25


    finally:
        collector.httpx = saved_httpx
        if saved_url is None:
            os.environ.pop("LOKI_URL", None)
        else:
            os.environ["LOKI_URL"] = saved_url


def _log_select_checks() -> int:
    """무엇을 실을지 — 랩에서 오류 3줄이 정상 260줄에 묻혀 사라졌다 (§1-1-8)."""
    import json

    from . import collector as c

    def _r(t, line):
        return {"t": float(t), "line": line}

    # ① 등급 파싱 — 앵커를 요구한다. 부분 문자열로 잡으면 정상 줄이 오류가 된다.
    assert c.log_level("2026-08-13 10:00:00 ERROR connection reset") == "error"
    assert c.log_level('{"level":"error","msg":"x"}') == "error"
    assert c.log_level("[WARN] pool wait 120ms") == "warn"
    assert c.log_level("kernel: Out of memory: Killed process 1234") == "error"
    assert c.log_level("systemd: Failed to start nginx.service") == "error"
    for benign in ("GET /health 200 3ms", "0 errors in last hour",
                   "error_rate=0", "ErrorDocument 404 /e.html",
                   "log_level=ERROR is disabled"):
        assert c.log_level(benign) == "", benign

    # ② 랩 실측 재현 — 정상 260줄에 오류 3줄. 전송 40줄에 오류가 전부 들어와야 한다.
    recs = [_r(i, "INFO request completed status=200 dur=%dms" % (i % 80))
            for i in range(200)]
    recs += [_r(200 + i, "ERROR connection reset by peer upstream=db-pool-%d" % i)
             for i in range(3)]
    recs += [_r(300 + i, "INFO request completed status=200 dur=%dms" % (i % 80))
             for i in range(60)]
    picked = c.select_logs(recs)
    assert len([r for r in picked if "line" in r]) <= c.LOKI_SEND_LIMIT, len(picked)
    errs = [r for r in picked if "connection reset" in r.get("line", "")]
    assert len(errs) == 3, "오류 3줄이 안 실렸다: %d" % len(errs)

    # ③ 고른 뒤에는 시각순이다. 모델이 인접성에서 인과를 만들기 때문이다.
    assert [r["t"] for r in picked] == sorted(r["t"] for r in picked)

    # ④ 접은 줄은 개수로 알린다. 안 알리면 260줄이 3줄로 조용히 줄어든다.
    info = [r for r in picked if "request completed" in r.get("line", "")]
    assert info and info[0]["n"] >= 200, info[:1]
    assert all("why" in r for r in picked if "line" in r), picked[:1]

    # ⑤ 같은 오류가 쏟아져도 40칸을 다 먹지 않는다. 문맥이 남아야 인과를 본다.
    flood = [_r(i, "ERROR upstream timeout retry=%d" % i) for i in range(300)]
    flood += [_r(1000 + i, "INFO warmup step %d" % i) for i in range(20)]
    picked = c.select_logs(flood)
    same = [r for r in picked if "upstream timeout" in r.get("line", "")]
    assert len(same) <= c.SAME_SHAPE_MAX, "같은 형태가 %d줄" % len(same)
    assert any("warmup" in r.get("line", "") for r in picked), "문맥이 통째로 밀렸다"

    # ⑥ 첫 오류 직전 구간이 보존된다 — 원인은 대개 그 앞에 있다
    seq = [_r(i, "INFO steady %d" % i) for i in range(100)]
    seq += [_r(200 + i, "ERROR boom %d" % i) for i in range(100)]
    picked = c.select_logs(seq)
    pre = [r for r in picked if "line" in r and r["t"] < 200]
    assert pre, "첫 오류 직전 줄이 하나도 안 남았다"

    # ⑦-0 완전히 같은 줄이 같은 초에 여러 개여도 상한을 넘지 않는다.
    #      값으로 같은지 보면 되찾을 때 같은 항목이 여러 번 붙는다. 실제로 300줄이
    #      그대로 나갔다(2026-08-13 감사). 나노초를 초로 바꾸면서 해상도가 사라져
    #      서로 다른 줄이 같은 시각이 되는 경로가 실재한다.
    dup = [_r(1.0, "INFO steady") for _ in range(100)]
    dup += [_r(500.0, "ERROR upstream refused connection") for _ in range(200)]
    picked = c.select_logs(dup)
    body = [r for r in picked if "line" in r]
    assert len(body) <= c.LOKI_SEND_LIMIT, "상한을 넘었다: %d" % len(body)
    same = [r for r in body if "upstream refused" in r["line"]]
    assert len(same) <= c.SAME_SHAPE_MAX, "같은 형태가 %d줄" % len(same)

    # ⑦-1 첫 오류 직전은 오류에 **가까운** 쪽을 고른다. 원인은 바로 앞에 있다.
    #      몫 선별은 예산을 넘을 때만 도는 경로라, 검사도 예산을 좁혀 그 경로로 넣는다.
    seq2 = [_r(i, "INFO steady %d" % i) for i in range(200)]
    seq2 += [_r(300 + i, "ERROR boom %d" % i) for i in range(20)]
    picked = c.select_logs(seq2, limit=40)
    pre = [r["t"] for r in picked if r.get("why") == "pre"]
    assert pre and max(pre) >= 190, "오류에서 먼 쪽만 골랐다: %s" % sorted(pre)[:3]

    # ⑦-1a **접기가 먼저고 선별은 예산을 넘을 때만이다.** 랩 실측(2026-08-13):
    #       평상시 15분 120줄이 접기만으로 12줄이 되어 몫 선별은 할 일이 없었다.
    #       그런데 옛 코드는 40줄 상한 때문에 몫 선별이 늘 돌았고, 문서는 그 죽은
    #       분기를 규칙인 것처럼 적고 있었다. 평상시 창에서 몫이 등장하면 실패다.
    normal = [_r(i, "INFO request completed status=200 dur=%dms" % (i % 80))
              for i in range(120)]
    picked = c.select_logs(normal)
    assert all(r["why"] == "fold" for r in picked if "line" in r), \
        "평상시 창에 몫 선별이 개입했다: %s" % {r.get("why") for r in picked}
    assert len([r for r in picked if "line" in r]) <= c.SAME_SHAPE_MAX

    # ⑦-1b 예산을 글자 수로 건다. 줄 수는 줄 길이에 따라 같은 값이 열 배 차이가 난다.
    long_recs = [_r(i, "ERROR distinct failure %d %s" % (i, "x" * 500))
                 for i in range(300)]
    picked = c.select_logs(long_recs)
    sent = sum(len(r["line"]) for r in picked if "line" in r)
    assert sent <= c.LOKI_SEND_BYTES, "글자 예산을 넘었다: %d" % sent

    # ⑦ 등급 미상이 오류 몫을 먹지 않는다
    assert c.log_level("something happened") == ""

    # ⑦-1b 게이트웨이·감시 서버가 평상시 쓰는 낱말이 오류로 잡히면 안 된다.
    #       alert·critical 은 이 환경의 일상 어휘라 맨낱말로 잡으면 자기 로그가
    #       오류 자리를 먹는다 (2026-08-13 감사).
    for benign in ("gateway: alert received eventid=12345 host=db01",
                   "zabbix_server: alert manager #1 started",
                   "config: cpu critical threshold = 90",
                   "nagios: service state changed from CRITICAL to OK",
                   "app: Error Rate: 0%", "app: warning: none",
                   "systemd: Started Error Reporting Service."):
        assert c.log_level(benign) == "", benign

    # ⑦-1c 실제 형식에서 등급이 잡혀야 한다
    for line, want in (('{"severity":"ERROR","msg":"x"}', "error"),
                       ('{"lvl":"error"}', "error"),
                       ('{"levelname":"ERROR"}', "error"),
                       ("[core:error] [pid 1] AH00037: x", "error"),
                       ("[ssl:warn] [pid 1] AH01906: x", "warn"),
                       ("2026/08/13 10:00:00 [error] 123#0: upstream timed out", "error"),
                       ("ERROR:  relation \"x\" does not exist", "error")):
        assert c.log_level(line) == want, (line, c.log_level(line))

    # ⑦-1d systemd 유닛 실패의 현행 문구. Rocky 8·9 에서 실제로 보이는 줄이다.
    assert c.log_level("mariadb.service: Failed with result 'exit-code'.") == "error"
    assert c.log_level("Dependency failed for MariaDB database server.") == "error"

    # ⑦-2 정규화 — 접어야 할 것과 남겨야 할 것
    assert c.log_shape("GET /a 500 12ms") != c.log_shape("GET /a 200 3ms"), "상태 코드가 접혔다"
    assert c.log_shape("req path=/v1/pay/151") == c.log_shape("req path=/v1/pay/9")
    assert c.log_shape("/etc/shadow changed") != c.log_shape("/tmp/junk changed")
    assert (c.log_shape("2026-08-13 10:00:01 pid=41 from 10.0.0.5 done")
            == c.log_shape("2026-08-13 11:22:33 pid=7 from 10.0.0.9 done"))
    # 시각 형식이 ISO 만이 아니다. 랩 실측에서 슬래시 날짜 때문에 469줄이 408가지
    # 모양으로 세어져 반복 접기가 통째로 동작하지 않았다.
    for a, b in (("2026/08/13 01:58:33.666159 [Mysql] Cannot fetch data",
                  "2026/08/13 01:58:34.112233 [Mysql] Cannot fetch data"),
                 ("Aug 13 10:00:00 host sshd: session opened",
                  "Aug 13 10:00:07 host sshd: session opened"),
                 ("[Wed Aug 13 10:00:00 2026] [core:error] x",
                  "[Wed Aug 13 10:11:22 2026] [core:error] x")):
        assert c.log_shape(a) == c.log_shape(b), (c.log_shape(a), c.log_shape(b))
    # 오류 번호는 접히면 안 된다. MySQL 오류 번호가 4자리라 자리수 규칙에 먹혔다.
    assert c.log_shape("errno=1062 dup key") != c.log_shape("errno=1236 relay log")
    # 낱말 뒤에 맨 숫자로 오는 오류 번호도 남는다. MySQL 형식이 그렇다.
    assert c.log_shape("Error 1045 access denied") != c.log_shape("Error 1213 deadlock")
    # MariaDB 오류 로그는 시가 한 자리다
    assert (c.log_shape("2026-08-13  2:13:33 0 [Warning] Access denied")
            == c.log_shape("2026-08-13 11:04:05 0 [Warning] Access denied"))
    assert c.log_shape("uid=0 session") != c.log_shape("uid=1000 session")
    assert c.log_shape("killed sig=9") != c.log_shape("killed sig=11")

    # ⑦-3 생략 구간을 표시한다. 안 하면 모델이 떨어진 줄을 붙은 것으로 읽고
    #      인접성에서 인과를 만든다. 줄 수와 시간 범위를 함께 낸다.
    #      반복이 있어야 접기가 줄을 버리고 그 자리에 표시가 들어간다. 두 형태를
    #      번갈아 넣어 생략 구간이 여러 곳에 생기게 한다.
    many = [_r(i * 10, ("INFO step done in %dms" % i) if i % 2 else
                       ("INFO flush wrote %dKB" % i)) for i in range(200)]
    picked = c.select_logs(many)
    gaps = [r for r in picked if "gap" in r]
    assert gaps, "생략 표시가 없다"
    assert all(g.get("to") is not None and g["gap"] > 0 for g in gaps), gaps[:1]
    lines = [r for r in picked if "line" in r]
    assert sum(g["gap"] for g in gaps) + len(lines) == len(many), (
        "생략 수와 실린 수의 합이 조회 수와 다르다: %d + %d != %d"
        % (sum(g["gap"] for g in gaps), len(lines), len(many)))

    # ⑧ 고른 이유와 개수가 전송 형태에 실린다. 안 실리면 모델은 40줄이 전부인 줄 안다.
    from . import llm, masking
    ctx = {"incident": {"host": "h1", "classes": ["disk_space"], "alert_count": 1},
           "host": {}, "alerts": [], "security": [], "sources": {"logs": "ok"},
           "logs": [{"t": 1700000000.5, "line": "ERROR reset", "why": "error", "n": 137}]}
    out = masking.build_llm_context(ctx, "SEV2", masking.Masker())
    item = out["logs"][0]
    assert item["why"] == "error" and item["n"] == 137, item
    assert item["t"] == 1700000000, item
    # 정규화형은 비교 키일 뿐이다. 전송에 섞이면 마스킹을 우회한다.
    assert "shape" not in item and "<N>" not in json.dumps(item, ensure_ascii=False)
    # 프롬프트가 이 필드를 설명해야 한다. 안 하면 모델이 n 을 무시한다.
    assert "`n`" in llm.TRIAGE_SYSTEM and "`why`" in llm.TRIAGE_SYSTEM
    return 26


def _select_invariant_checks() -> int:
    """무작위·극단 입력으로 불변 조건을 흔든다.

    2026-08-13 에 상한 40줄짜리 선별기가 300줄을 내보내고 있었는데 검사는 통과했다.
    사람이 상상한 입력만 넣었기 때문이다. 같은 줄이 같은 초에 겹치는 경우가 없었다.
    아래는 그 형태를 포함해 무작위로 흔든다.
    """
    import random

    from . import collector as c

    rnd = random.Random(20260813)
    shapes = ["INFO request completed status=200 dur=%dms path=/v1/pay/%d",
              "ERROR connection reset by peer upstream=db-pool-%d retry=%d",
              "WARN pool wait %dms queue=%d",
              "kernel: Out of memory: Killed process %d (app%d)",
              "2026/08/13 01:58:%02d.6661 [Mysql] Cannot fetch data: Error %d"]
    n = 0
    for _ in range(300):
        size = rnd.choice([0, 1, 39, 40, 41, 120, 300, 900])
        recs = []
        for i in range(size):
            # 시각이 겹치는 경우를 일부러 만든다 — 나노초를 초로 바꾸면 실제로 겹친다
            t = float(rnd.choice([1000, 1000, 1001, 1002 + i // 7]))
            recs.append({"t": t, "line": rnd.choice(shapes)
                         % (rnd.randint(0, 3), rnd.randint(0, 3))})
        out = c.select_logs(recs)
        body = [r for r in out if "line" in r]
        gaps = [r for r in out if "gap" in r]

        assert len(body) <= c.LOKI_SEND_LIMIT, (size, len(body))
        assert sum(g["gap"] for g in gaps) + len(body) == len(recs), (size, len(body))
        assert all(r.get("why") for r in body), body[:1]
        assert all(g["gap"] > 0 and g["to"] >= g["t"] for g in gaps), gaps[:1]
        assert [r["t"] for r in out] == sorted(r["t"] for r in out), "시각순이 아니다"
        # 같은 형태가 상한을 넘지 않는다. 단 창이 작아 전부 실린 경우는 접지 않는다.
        if len(recs) > c.LOKI_SEND_LIMIT:
            per = {}
            for r in body:
                s = c.log_shape(r["line"])
                per[s] = per.get(s, 0) + 1
            assert max(per.values(), default=0) <= c.SAME_SHAPE_MAX, per
        n += 0
    return 6


def _evidence_checks() -> int:
    """원문으로 되짚을 재료를 남기는가 — 사람용이고 모델에는 안 간다 (§25-7)."""
    import json
    import os
    import shutil
    import tempfile

    from . import masking, prior, slack, store

    # ① 조회 참조가 컨텍스트에 있어도 전송 형태에는 없다. 모델의 분석 재료가 아니다.
    ctx = {"incident": {"host": "h1", "classes": ["disk_space"], "alert_count": 1},
           "host": {}, "alerts": [], "security": [], "sources": {"logs": "ok"},
           "logs": [{"t": 1.0, "line": "a", "why": "recent"}],
           "logs_query": '{host="h1"}', "logs_from": 1700000000,
           "logs_to": 1700000900}
    out = masking.build_llm_context(ctx, "SEV2", masking.Masker())
    blob = json.dumps(out, ensure_ascii=False)
    assert "logs_query" not in blob and 'host="h1"' not in blob, blob[:200]

    # ② 판정 이력에 남고, 서술과 같은 시점에 지워진다. Loki 보존이 31일인데 판정 행은
    #    90일이라, 오래된 참조를 눌러 0건이 나오면 "로그가 없었다"로 읽힌다.
    d = tempfile.mkdtemp(prefix="evi-")
    saved = store.PATH
    try:
        store.PATH = os.path.join(d, "e.db")
        store.close()
        store.init()
        jid = store.record_judgment({"fingerprint": "fp", "host": "h1",
                                     "summary": "결론", "evidence": '{"q":"x"}'},
                                    now=1000.0)
        assert store.get_judgment(jid)["evidence"], "증거가 안 남았다"
        store.prune(now=1000.0 + store.SUMMARY_DAYS * 86400 + 10)
        row = store.get_judgment(jid)
        assert row and not row["summary"], "서술이 안 지워졌다"
        assert not row["evidence"], "증거가 서술보다 오래 남았다"

        # ③ 과거 결론 경로에 새 컬럼이 안 섞인다
        got = prior.select.__doc__ is not None
        assert got
        item = masking._prior_item({"summary": "", "match": "동일 사건"}, lambda x: x)
        assert "evidence" not in item and "logs_query" not in item, item
    finally:
        store.close()
        store.PATH = saved
        shutil.rmtree(d, ignore_errors=True)

    # ④ Grafana 링크가 사건 시각 기준 절대 창이다. 지금은 게시 시각 기준 상대 창이라
    #    재기동 후 대기 알림을 다시 넣으면 엉뚱한 구간이 열린다.
    saved_url = os.environ.get("GRAFANA_URL")
    os.environ["GRAFANA_URL"] = "http://g.local"
    try:
        link = slack._grafana_link("h1", event_ts=1700000000)
        assert "from=now-" not in link, link
        assert "1699999" in link or "1700000" in link, link
    finally:
        if saved_url is None:
            os.environ.pop("GRAFANA_URL", None)
        else:
            os.environ["GRAFANA_URL"] = saved_url
    return 11


def _ask_masking_checks() -> int:
    """여러 턴에 걸쳐도 같은 이름이 같은 토큰인가 (대화형 질의의 선결 조건).

    토큰이 턴마다 달라지면 모델은 같은 기계를 다른 기계로 읽는다. 더 나쁜 경우는
    **같은 토큰이 다른 기계를 가리키는 것**이다 — 그때 사람은 되돌아온 이름을 사실로
    읽는다.
    """
    from . import masking, nametable, proxy

    # ① 이름은 이미 결정적이다. 표를 새로 만들어도 같은 토큰이어야 한다.
    saved = dict(nametable._terms)
    try:
        nametable._terms = {"db-prod-01": "host", "web-01": "host"}
        a = proxy.build_masker()
        nametable._terms = {"web-01": "host", "db-prod-01": "host", "새이름": "host"}
        b = proxy.build_masker()
        assert a._fwd["db-prod-01"] == b._fwd["db-prod-01"], "표가 바뀌자 토큰이 달라졌다"

        # ② **해시 자릿수가 좁으면 충돌한다.** sha256[:6] 은 16진 6자리 = 약 1,678만
        #    가지뿐이라 이름 3,708개에서 실제 충돌이 나왔다(2026-08-13 탐색).
        #    충돌하면 `_rev` 가 덮여 역치환이 **다른 호스트 이름**을 돌려준다.
        x, y = "host-1422.kinx.net", "host-3707.kinx.net"
        assert proxy.token_for("host", x) != proxy.token_for("host", y), (
            "6자리 시절 충돌 쌍이 여전히 같은 토큰이다 — 자릿수를 넓혀야 한다")

        # ③ 그래도 충돌은 원리상 남으므로 **검출**해야 한다. 조용히 덮이면 안 된다.
        assert hasattr(proxy, "token_collisions"), "충돌 검출 수단이 없다"
        real = proxy.token_for
        proxy.token_for = lambda kind, name: "[host-000000000000]"   # 전부 충돌시킨다
        try:
            nametable._terms = {"a-host": "host", "b-host": "host"}
            hits = proxy.token_collisions(nametable.terms())
            assert hits, "모든 이름이 같은 토큰인데 충돌을 못 잡았다"
        finally:
            proxy.token_for = real

        # ④ **IP 는 아직 일련번호다.** 1턴에 두 개가 나오면 [ip-1]·[ip-2] 인데,
        #    3턴에 두 번째 것만 나오면 그게 [ip-1] 이 된다. 같은 토큰이 다른 기계를
        #    가리킨다.
        nametable._terms = {}
        m1 = proxy.build_masker()
        m1.mask("10.0.0.1 과 10.0.0.2 에서 오류")
        m2 = proxy.build_masker()
        m2.mask("10.0.0.2 만 오류")
        assert m1._fwd["10.0.0.2"] == m2._fwd["10.0.0.2"], (
            "같은 IP 가 턴마다 다른 토큰을 받는다: %s vs %s"
            % (m1._fwd["10.0.0.2"], m2._fwd["10.0.0.2"]))

        # ⑤ 트리아지 경로(요청 단위)는 종전 동작을 유지한다 — 바꿀 이유가 없다.
        plain = masking.Masker()
        plain.register("host", "db-prod-01")
        assert plain._fwd["db-prod-01"] == "[host-1]", plain._fwd
        return 7
    finally:
        nametable._terms = saved


def _ask_question_checks() -> int:
    """사람이 자유롭게 친 질문을 어떻게 다루는가.

    컨텍스트는 `build_llm_context` 화이트리스트가 지켜 준다. 질문 문자열에는 그런
    보호가 없다 — 사람은 호스트명이든 IP든 계정명이든 아무거나 친다.
    """
    from . import ask, nametable

    saved = dict(nametable._terms)
    try:
        nametable._terms = {"db-prod-01": "host"}
        mk = ask.session_masker("s1")

        # ① 이름과 IP 는 가려서 보낸다
        r = ask.sanitize_question("db-prod-01 이 10.0.0.7 로 못 붙는다", mk)
        assert r["ok"], r
        assert "db-prod-01" not in r["text"] and "10.0.0.7" not in r["text"], r["text"]

        # ② **가린 뒤에도 아는 이름이 남으면 보내지 않고 거절한다.** 낱말 경계 밖에
        #    붙어 있으면 치환기가 못 잡는다. 조용히 내보내는 것보다 되묻는 것이 낫다.
        r = ask.sanitize_question("xdb-prod-01y 가 이상함", mk)
        assert not r["ok"] and r["reason"], r

        # ③ 길이 상한. 이력까지 매 턴 다시 마스킹하므로 무한정 받을 수 없다.
        r = ask.sanitize_question("가" * (ask.QUESTION_MAX_CHARS + 1), mk)
        assert not r["ok"] and "길이" in r["reason"], r

        # ④ 제어문자는 지운다 — 프롬프트 구조를 흉내 내는 입력을 막는다
        r = ask.sanitize_question("정상\x00질문\x1b[31m입니다", mk)
        assert r["ok"] and "\x00" not in r["text"] and "\x1b" not in r["text"], r

        # ⑤ 빈 질문은 거절
        assert not ask.sanitize_question("   ", mk)["ok"]

        # ⑥ **표에서 이름이 빠져도 앞 턴의 토큰을 되돌릴 수 있어야 한다.**
        #    이름 표는 1시간마다 다시 만들어진다. 대화 도중 갱신되면 앞 턴에 발행한
        #    토큰이 표에 없어져 역치환이 안 되고, 사람은 토큰 문자열을 받는다.
        tok = mk._fwd["db-prod-01"]
        ask.remember("s1", mk)
        nametable._terms = {}                      # 표에서 사라졌다
        mk2 = ask.session_masker("s1")
        assert mk2.unmask("%s 를 보라" % tok) == "db-prod-01 를 보라", mk2.unmask(tok)

        # ⑦ 다른 세션에는 안 샌다
        mk3 = ask.session_masker("s2")
        assert mk3.unmask(tok) == tok, "세션 사이로 역치환 표가 샜다"

        # ⑧ 오래된 세션은 지운다 — 메모리에 무한정 쌓이면 안 된다
        ask.prune_sessions(now=ask._now() + ask.SESSION_TTL_S + 1)
        mk4 = ask.session_masker("s1")
        assert mk4.unmask(tok) == tok, "만료된 세션이 남아 있다"
        return 11
    finally:
        nametable._terms = saved
        ask.forget_all()


def _ask_scope_checks() -> int:
    """질의가 닿을 수 있는 대상을 서버가 정하는가.

    호출자가 신고한 값은 믿지 않는다. `/v1/messages` 의 테넌트 판정이
    `metadata.user_id` 로 되어 있는데 그건 호출자가 채우는 값이라 격리 근거가 못 된다.
    """
    import os

    from . import ask, incident as inc_mod, registry

    saved_env = os.environ.get("ASK_ALLOWED_REALMS")
    saved_src = list(registry._SOURCES)
    saved_map = dict(inc_mod.REALM_MAP)
    try:
        registry._SOURCES = [{"name": "zabbix-internal", "realm": "internal"},
                             {"name": "zabbix-msp", "realm": "msp"},
                             {"name": "zabbix-etc"}]
        inc_mod.REALM_MAP = {}
        os.environ.pop("ASK_ALLOWED_REALMS", None)

        # ① 사내는 허용, MSP 는 거부
        ok, why = ask.target_allowed("zabbix-internal", "db01")
        assert ok, why
        ok, why = ask.target_allowed("zabbix-msp", "db01")
        assert not ok and why, (ok, why)

        # ② **영역을 안 적은 소스는 거부가 기본이다.** 설정을 빠뜨린 사람이 가장
        #    위험해지면 안 된다. `registry.realm()` 이 소스 이름을 그대로 돌려주므로
        #    허용 목록에 없는 값이 되어 자동으로 막힌다.
        ok, why = ask.target_allowed("zabbix-etc", "db01")
        assert not ok, "영역 미기재 소스가 통과했다"

        # ③ 허용 목록은 환경변수로 넓힌다. 코드를 고쳐야 넓어지면 안 된다.
        os.environ["ASK_ALLOWED_REALMS"] = "internal,lab"
        registry._SOURCES = [{"name": "lab-zbx", "realm": "lab"}]
        ok, _ = ask.target_allowed("lab-zbx", "node1")
        assert ok, "허용 목록을 넓혔는데 안 통한다"

        # ④ 허용된 감시 서버 목록도 서버가 만든다
        names = ask.allowed_sources()
        assert names == ["lab-zbx"], names
        return 6
    finally:
        registry._SOURCES = saved_src
        inc_mod.REALM_MAP = saved_map
        if saved_env is None:
            os.environ.pop("ASK_ALLOWED_REALMS", None)
        else:
            os.environ["ASK_ALLOWED_REALMS"] = saved_env


def _ask_tool_checks() -> int:
    """도구가 무엇을 조회할 수 있는가.

    Zabbix 축에는 `.get` 아닌 메서드를 거부하는 검사가 있지만 Loki·Wazuh 에는 없다.
    두 축의 등가물은 **호출자가 질의문을 못 주는 것**이다. 도구는 라벨·기간·문자열
    필터만 받고 질의문은 코드가 만든다.
    """
    from . import asktools

    # ① 창 길이는 상한을 넘지 못한다. 모델이 큰 값을 넣어도 잘린다.
    assert asktools.clamp_window(999999) == asktools.WINDOW_MAX_M
    assert asktools.clamp_window(0) == asktools.WINDOW_DEFAULT_M
    assert asktools.clamp_window(30) == 30

    # ①-b **절대 구간을 받는다.** 사람은 "8월 13일 12시" 를 보고 묻는데 도구에
    #      상대 창만 있으면 모델이 '지금부터 N분' 으로 바꿔 **엉뚱한 날을 본다**
    #      (2026-08-18 랩 실측: 8월 13일 화면을 보고 물었는데 8월 18일을 조회했다).
    assert asktools.parse_when("2026-08-13T02:56:26.163Z") == 1786589786
    assert asktools.parse_when(1786589786) == 1786589786
    assert asktools.parse_when("말도 안 되는 값") is None
    a, b, _ = asktools.window_bounds({"from": "2026-08-13T02:56:26Z",
                                      "to": "2026-08-13T06:57:43Z"}, now=1787000000)
    assert (a, b) == (1786589786, 1786604263), (a, b)
    # 절대 구간이 없으면 상대 창으로 떨어진다
    a, b, _ = asktools.window_bounds({"window_m": 60}, now=1787000000)
    assert b == 1787000000 and a == 1787000000 - 3600, (a, b)
    # 뒤집힌 구간은 바로잡는다
    a, b, _ = asktools.window_bounds({"from": 1786600000, "to": 1786590000},
                                     now=1787000000)
    assert (a, b) == (1786590000, 1786600000), (a, b)

    # ①-c **구간을 골고루 보되 극단은 살린다.** 최신순으로 상한만큼만 받으면 긴
    #      구간에서 앞부분이 통째로 잘려 **먼저 난 스파이크를 못 본다**
    #      (2026-08-18 랩 실측: 4시간 구간에서 최근 1시간만 봤다).
    pts = [{"t": i, "v": 1.0} for i in range(600)]
    pts[10]["v"] = 99.0          # 앞쪽 스파이크
    pts[590]["v"] = 98.0         # 뒤쪽 스파이크
    got = asktools.downsample(pts, 60)
    assert len(got) <= 60 * 2, len(got)
    vals = [p["v"] for p in got]
    assert max(vals) >= 99.0, "앞쪽 스파이크가 사라졌다"
    assert 98.0 in vals, "뒤쪽 스파이크가 사라졌다"
    assert got == sorted(got, key=lambda p: p["t"]), "시각순이 아니다"
    # 적으면 그대로 둔다 — 없는 가공을 하지 않는다
    assert asktools.downsample(pts[:20], 60) == pts[:20]

    # ② 로그 필터는 정규식이 아니라 문자열이다. 질의문을 깨뜨릴 글자는 거부한다.
    for bad in ('a"b', "a}b", "a{b", "a\nb", "a\\b", "x" * 200):
        ok, why = asktools.check_filter(bad)
        assert not ok and why, bad
    for good in ("timeout", "connection reset", "zbx_monitor", "/etc/ssh"):
        assert asktools.check_filter(good)[0], good

    # ③ **질의문은 코드가 만든다.** 라벨 등식 하나에 문자열 필터만 붙는다.
    q = asktools.build_logql("vm-a.example", "timeout")
    assert q == '{host="vm-a.example"} |= "timeout"', q
    assert asktools.build_logql("vm-a.example", "") == '{host="vm-a.example"}'

    # ④ 라벨 값에 질의문을 깨뜨릴 글자가 있으면 만들지 않는다
    for bad in ('a"b', "a}b", "a b"):
        try:
            asktools.build_logql(bad, "")
            raise AssertionError("깨뜨릴 라벨을 통과시켰다: %r" % bad)
        except ValueError:
            pass

    # ⑤ Zabbix 는 도구가 쓰는 메서드로만 좁힌다. `.get` 이어도 목록 밖이면 거부다.
    assert asktools.zbx_method_ok("host.get")
    assert not asktools.zbx_method_ok("user.get"), "목록 밖 조회를 허용했다"
    assert not asktools.zbx_method_ok("host.update")

    # ⑥ Wazuh 질의 본문은 고정 틀에서 만든다. 에이전트명은 정확 일치다.
    body = asktools.build_wazuh_query("vm-a.example", 60, 7, 1786590000)
    assert body["query"]["bool"]["filter"][0]["term"]["agent.name"] == "vm-a.example", body
    assert set(body) <= {"size", "sort", "query", "_source"}, body
    return 32



def _ask_result_checks() -> int:
    """조회 결과가 사람에게 닿기까지 무엇이 사라지는가.

    2026-08-18 랩 실측에서 봇이 "수집된 데이터가 없습니다" 라고 답했는데, 실제로는
    보안 경보 50건이 왔고 그 50건이 전부 공백으로 채워져 있었다. 조회 실패가 아니라
    **성공한 조회를 없음으로 바꾸는** 경로였다. 그런 경로만 모은다.
    """
    from . import asktools, collector, masking, ask

    # (1) **Wazuh 응답은 중첩이고 화이트리스트는 평탄하다.** 옮기는 단계를 건너뛰면
    #     50건이 전부 공백이 되고, 모델은 그것을 "기록 없음" 으로 읽는다.
    raw = {"@timestamp": "2026-07-20T01:00:00.000Z",
           "rule": {"level": 10, "id": "5710", "description": "SSH 로그인 실패",
                    "groups": ["authentication_failed", "sshd"]},
           "agent": {"name": "vm-a.example"},
           "syscheck": {"path": "/etc/ssh/sshd_config", "event": "modified"}}
    flat = collector.flatten_alert(raw)
    assert flat["level"] == 10, flat
    assert flat["desc"] == "SSH 로그인 실패", flat
    assert flat["rule_id"] == "5710", flat
    assert flat["ts"] == "2026-07-20T01:00:00.000Z", flat
    assert flat["groups"] == "authentication_failed,sshd", flat
    assert flat["path"] == "/etc/ssh/sshd_config", flat
    item = masking._security_item(flat, lambda x: x)
    assert item["level"] == 10 and item["desc"], item
    assert not all(v is None for v in item.values()), "화이트리스트가 전부 공백이다"

    # (2) **여러 낱말 중 하나를 찾는 필터.** 모델은 `a|b|c` 를 정규식으로 쓴다.
    #     그것을 글자 그대로 찾으면 절대 안 맞고, 결과가 비어 "기록 없음" 이 된다.
    q = asktools.build_logql("vm-a.example", "failed|invalid user")
    assert q == '{host="vm-a.example"} |~ "(failed|invalid user)"', q
    # 낱말 하나면 정규식으로 만들지 않는다
    assert asktools.build_logql("vm-a.example", "timeout") == '{host="vm-a.example"} |= "timeout"'
    # 낱말마다 검사한다 — 하나라도 위험하면 만들지 않는다
    # 뒤에 구분자만 남은 것은 낱말 하나로 받는다 — 되묻는 값이 아니다
    assert asktools.build_logql("vm-a.example", "failed|") == '{host="vm-a.example"} |= "failed"'
    for bad in ('failed|a"b', "failed|a}b", "|", "a|b|c|d|e|f|g"):
        try:
            asktools.build_logql("vm-a.example", bad)
            raise AssertionError("위험한 필터를 통과시켰다: %r" % bad)
        except ValueError:
            pass

    # (3) **구간을 잘랐으면 잘랐다고 말한다.** 7일을 물었는데 1일만 보고 "없음" 이라
    #     답하면 사람은 7일에 아무것도 없었다고 읽는다.
    T0 = 1786500000
    a, b, cut = asktools.window_bounds({"from": T0, "to": T0 + 30 * 86400}, now=T0)
    assert cut, "7일을 1일로 자르고도 알리지 않았다"
    assert b - a == asktools.WINDOW_MAX_M * 60, (a, b)
    # **남기는 쪽은 최신이다.** 조회가 최신순 정렬이라 앞쪽을 남기면 사람이 보고 있는
    # 화면의 오른쪽 끝이 통째로 빠진다.
    assert b == T0 + 30 * 86400, (a, b)
    a, b, cut = asktools.window_bounds({"from": T0, "to": T0 + 3600}, now=T0)
    assert not cut and b - a == 3600, (a, b, cut)
    # 보안·문제 조회는 건수 상한이 있어 더 긴 구간을 본다
    a, b, cut = asktools.window_bounds({"from": T0, "to": T0 + 7 * 86400}, now=T0,
                                       max_m=asktools.WINDOW_MAX_WIDE_M)
    assert not cut and b - a == 7 * 86400, (a, b, cut)

    # (3)-b **상대 구간도 잘렸으면 잘렸다고 말한다.** 절대 구간에만 통지를 붙였더니
    #       90일(window_m=129600)을 물은 요청이 조용히 하루가 됐고, 하루치를 줄인
    #       24개 점을 모델이 "24일치"로 읽어 "90일간 건강하다"고 답했다(2026-08-18 실측).
    a, b, cut = asktools.window_bounds({"window_m": 129600}, now=T0)
    assert cut, "90일을 하루로 자르고도 알리지 않았다"
    assert b - a == asktools.WINDOW_MAX_M * 60, (a, b)
    a, b, cut = asktools.window_bounds({"window_m": 60}, now=T0)
    assert not cut and b - a == 3600, (a, b, cut)
    # `at` 으로 시점을 줄 때도 마찬가지다
    a, b, cut = asktools.window_bounds({"at": T0, "window_m": 129600}, now=T0)
    assert cut, "시점 앞뒤 구간을 자르고도 알리지 않았다"

    # (3)-c **실제로 본 구간을 사람이 읽는 형태로 함께 준다.** 잘렸는지만 알려서는
    #       모델이 몇 시부터 몇 시까지를 봤는지 모른다.
    span = asktools.window_label(T0, T0 + 86400)
    assert "2026" in span and "~" not in span, span

    # (3)-d **긴 구간은 추세(trend)로 본다.** 이력은 보관 기간이 짧아 90일을 물으면
    #       비거나 잘린다. 사람이 "90일 추이" 를 묻는 것은 정상적인 요구다.
    assert asktools.zbx_method_ok("trend.get"), "추세 조회를 막고 있다"
    assert asktools.use_trend(1786500000, 1786500000 + 86400) is False
    assert asktools.use_trend(1786500000, 1786500000 + 30 * 86400) is True
    # 지표 조회의 상한은 추세를 볼 수 있는 만큼까지 넓다
    a, b, cut = asktools.window_bounds({"window_m": 129600}, now=T0,
                                       max_m=asktools.WINDOW_MAX_TREND_M)
    assert not cut and b - a == 90 * 86400, (a, b, cut)

    # (4) **잘린 사실은 도구 결과에 실린다.** 프롬프트가 아니라 결과에 실어야
    #     모델이 답에 옮긴다.
    note = asktools.cut_note(True, 1440)
    assert note and "1일" in note and "최근" in note, note
    assert asktools.cut_note(False, 1440) == ""

    # (5) 그림 손잡이를 걷어내고 남은 빈 괄호까지 정리한다. "패널()의" 가 화면에
    #     그대로 나왔다(2026-08-18 실측).
    assert ask.strip_handles("패널(img-6598)의 그래프") == "패널의 그래프"
    assert ask.strip_handles("패널 [img-6598] 참고") == "패널 참고"
    assert ask.strip_handles("image-6598 은 그대로") == "image-6598 은 그대로"
    # 마크다운 그림 표기를 통째로 걷어 낸다. 손잡이만 빼면 `![image]()` 같은 깨진
    # 표기가 남아 화면에 "!(image)" 로 찍힌다(2026-08-18 실측).
    assert ask.strip_handles("![image](img-6598)" + chr(10) + "90일 추이") == "90일 추이"
    assert ask.strip_handles("보기: ![복제 지연]([img-6598])") == "보기:"
    return 24



def _tool_schema_checks() -> int:
    """도구 스키마가 모델이 고를 수 있는 값을 얼마나 좁히는가.

    프롬프트로 "지어내지 마라" 라고 부탁하는 것과, 스키마가 값의 집합을 좁히는 것은
    다르다. 부탁은 지켜지기도 하고 안 지켜지기도 하지만 스키마는 표현 자체를 막는다.
    2026-08-18 랩에서 봇이 없는 보관 정책을 지어내고 24개 점을 "24일치" 로 읽었다.

    **접두사 안정성도 여기서 지킨다.** 도구 정의는 프롬프트 맨 앞에 놓이므로 바이트가
    흔들리면 캐시가 영영 안 걸린다.
    """
    import json

    from . import asktools

    table = {"[host-b]": {"host": "b1"}, "[host-a]": {"host": "a1"}}

    # ① 대상 토큰을 enum 으로 묶는다. 표에 없는 이름은 표현할 수 없다.
    specs = asktools.build_tool_specs(table)
    by_name = {t["name"]: t for t in specs}
    for name in ("host_logs", "host_metrics", "security_alerts", "panel_image"):
        enum = by_name[name]["input_schema"]["properties"]["host"].get("enum")
        assert enum == ["[host-a]", "[host-b]"], (name, enum)

    # ② **같은 표는 같은 바이트를 만든다.** 정렬을 빠뜨리면 매 요청 접두사가 달라져
    #    캐시가 한 번도 안 걸린다(조용히 실패한다).
    other = {"[host-a]": {"host": "a1"}, "[host-b]": {"host": "b1"}}   # 순서만 다름
    assert (json.dumps(specs, ensure_ascii=False, sort_keys=True)
            == json.dumps(asktools.build_tool_specs(other), ensure_ascii=False,
                          sort_keys=True))

    # ③ 표가 비면 enum 을 넣지 않는다. 빈 enum 은 모든 값을 막아 도구를 죽인다.
    for t in asktools.build_tool_specs({}):
        for prop in t["input_schema"].get("properties", {}).values():
            assert prop.get("enum") != [], t["name"]

    # ④ 인자를 스키마대로 검증하게 한다. 목록 밖 인자는 아예 못 넣는다.
    for t in specs:
        assert t.get("strict") is True, t["name"]
        assert t["input_schema"].get("additionalProperties") is False, t["name"]

    # ⑤ **답도 도구로 받는다.** 산문으로 받으면 손잡이가 글자로 남고 구간이 지어내진다.
    ans = by_name["answer"]
    props = ans["input_schema"]["properties"]
    for field in ("summary", "window_utc", "findings", "image_ids"):
        assert field in props, field
    assert "summary" in ans["input_schema"]["required"]

    # ⑥ 턴 중에 생기는 값(그림 손잡이·조회 구간)은 enum 으로 못 묶는다. 묶으면 도구
    #    정의가 라운드마다 바뀌어 캐시가 죽는다. 그래서 **코드가 검증한다.**
    seen_windows = {"2026-08-15 04:44 → 2026-08-18 04:44 UTC"}
    ok, why = asktools.check_answer(
        {"summary": "정상", "window_utc": "2026-08-15 04:44 → 2026-08-18 04:44 UTC",
         "image_ids": ["img-1234"]},
        images={"img-1234"}, windows=seen_windows)
    assert ok, why
    ok, why = asktools.check_answer(
        {"summary": "정상", "image_ids": ["img-9999"]},
        images={"img-1234"}, windows=seen_windows)
    assert not ok and "img-9999" in why, why
    ok, why = asktools.check_answer(
        {"summary": "정상", "window_utc": "지난 90일"},
        images=set(), windows=seen_windows)
    assert not ok and why, "조회한 적 없는 구간을 통과시켰다"
    # 구간을 안 적는 것은 허용한다. 조회를 안 한 질문도 있다.
    assert asktools.check_answer({"summary": "정상"}, images=set(), windows=set())[0]

    # ⑦ 중복 키가 없다. 같은 키를 여러 번 쓰면 마지막 것만 남아 조용히 사라진다.
    src = _read_source("gateway/asktools.py")
    assert src.count('"description": "절대 구간 시작. ISO8601 또는 유닉스 초"') <= 2,         "from/to 정의가 중복돼 있다"
    return 22


def _read_source(rel: str) -> str:
    import io
    import os
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return io.open(os.path.join(here, rel), encoding="utf-8").read()



def _cache_checks() -> int:
    """프롬프트 캐싱이 실제로 걸릴 모양인가.

    캐싱은 접두사 일치다. 앞에서 한 바이트만 달라져도 그 뒤 전부가 캐시에서 빠진다.
    걸리지 않아도 오류가 나지 않으므로 **조용히 비용만 낸다.** 그래서 모양을 검사로 잠근다.
    """
    from . import asktools, llm, store

    # ① 시스템 문구를 블록으로 감싸고 마지막 블록에 표시를 단다. 렌더 순서가
    #    도구 → 시스템 → 대화라서 이 한 곳이 도구와 시스템을 함께 캐시한다.
    blocks = llm.cached_system("긴 시스템 문구")
    assert isinstance(blocks, list) and blocks[-1]["cache_control"]["type"] == "ephemeral"
    assert blocks[-1]["text"] == "긴 시스템 문구"

    # ② 끌 수 있어야 한다. 최소 길이에 못 미치는 배포에서는 쓰기 값만 더 낸다.
    import os
    saved = os.environ.get("LLM_CACHE")
    try:
        os.environ["LLM_CACHE"] = "0"
        assert llm.cached_system("x") == "x", "끄면 문자열 그대로여야 한다"
    finally:
        if saved is None:
            os.environ.pop("LLM_CACHE", None)
        else:
            os.environ["LLM_CACHE"] = saved

    # ③ 도구 정의가 같은 표에 대해 같은 바이트다(캐시 접두사의 맨 앞).
    t = {"[host-b]": {}, "[host-a]": {}}
    import json
    a = json.dumps(asktools.build_tool_specs(t), ensure_ascii=False)
    b = json.dumps(asktools.build_tool_specs(dict(reversed(list(t.items())))),
                   ensure_ascii=False)
    assert a == b, "도구 정의가 요청마다 달라진다. 캐시가 한 번도 안 걸린다"

    # ④ **캐시 토큰을 따로 센다.** 읽기는 정가의 0.1배, 쓰기는 1.25배라 입력에 뭉뚱그리면
    #    절감분이 숫자에 안 나타난다.
    import tempfile
    d = tempfile.mkdtemp(prefix="cache-")
    saved_path = store.PATH
    try:
        store.PATH = os.path.join(d, "c.db")
        store.close()
        store.init()
        store.record_tokens("ask", "u", 100, 20, now=1000.0,
                            cache_write=500, cache_read=4000, model="m1")
        got = store.tokens_since(3600, now=1001.0, kind="ask")
        assert got["in"] == 100 and got["out"] == 20, got
        assert got["cache_read"] == 4000 and got["cache_write"] == 500, got
        # 옛 호출 방식도 받는다. 기록이 끊기면 비교 자체가 안 된다.
        store.record_tokens("ask", "u", 10, 5, now=1002.0)
        assert store.tokens_since(3600, now=1003.0, kind="ask")["in"] == 110
    finally:
        store.close()
        store.PATH = saved_path
    return 12


def _ask_dispatch_checks() -> int:
    """도구를 실제로 부를 때 무엇을 막는가.

    모델이 도구 이름과 인자를 정한다. 그 값이 어떻든 **거부는 예외가 아니라 도구
    결과로 돌려준다** — 예외로 끝내면 모델이 스스로 고칠 기회가 없다.
    """
    import asyncio
    import json

    from . import asktools, store

    table = {
        "[host-aaa]": {"host": "web-01", "source": "zabbix-internal",
                       "logs": "web-01.example", "security": "web-01.example"},
    }
    async def _logs(q, a, b, lim):
        assert a < b, (a, b)
        return {"logs": [], "status": "ok"}

    ctx = {"table": table, "now": 1786590000, "zbx": None, "fetch_logs": _logs}

    # ① 목록에 없는 도구는 거부한다. 모델이 이름을 지어내도 실행되면 안 된다.
    r = asyncio.run(asktools.run_tool("delete_host", {}, ctx))
    assert r.get("error"), r
    assert "delete_host" in str(r), r

    # ①-b **모델은 형식을 바꿔 쓴다.** 대괄호를 떼고 넣어도 같은 대상으로 본다
    #      (2026-08-18 랩 실측: host-aaa 로 넣어 '알 수 없는 대상' 으로 튕겼다).
    r = asyncio.run(asktools.run_tool("host_logs", {"host": "host-aaa"}, ctx))
    assert not r.get("error"), r

    # ①-c **대상을 찾는 규칙은 도구마다 다르면 안 된다.** 대괄호 완화를 한 곳에만
    #      넣었더니 past_judgments·open_problems 가 같은 값을 거부했다(2026-08-18 실측).
    async def _j(host, days):
        return {"judgments": [], "status": "ok"}

    async def _p(ent):
        return {"problems": [], "status": "ok"}

    ctx2 = dict(ctx, fetch_judgments=_j, fetch_problems=_p)
    for tool_name in ("past_judgments", "open_problems"):
        r = asyncio.run(asktools.run_tool(tool_name, {"host": "host-aaa"}, ctx2))
        assert not r.get("error"), (tool_name, r)

    # ①-d **일수는 분 상한에 걸리면 안 된다.** days 를 분 상한(1440)에 통과시켜
    #      30일을 넣어도 1일이 됐다. 기록이 있는데 "없다"고 답했다(2026-08-18 실측).
    got_days = []

    async def _j2(host, days):
        got_days.append(days)
        return {"judgments": [], "status": "ok"}

    asyncio.run(asktools.run_tool("past_judgments", {"days": 30},
                                  dict(ctx, fetch_judgments=_j2)))
    assert got_days == [30], got_days
    got_days.clear()
    asyncio.run(asktools.run_tool("past_judgments", {"days": 9999},
                                  dict(ctx, fetch_judgments=_j2)))
    assert got_days == [asktools.JUDGMENT_DAYS_MAX], got_days

    # ② 표에 없는 대상은 거부한다. 표는 허용된 감시 서버에서만 만들어진다.
    r = asyncio.run(asktools.run_tool("host_logs", {"host": "[host-zzz]"}, ctx))
    assert r.get("error") and "대상" in r["error"], r

    # ③ 대상 인자가 아예 없어도 예외가 아니라 결과로 돌려준다
    r = asyncio.run(asktools.run_tool("host_logs", {}, ctx))
    assert r.get("error"), r

    # ④ 질의문을 깨뜨리는 필터는 거부한다 (asktools.check_filter 와 같은 기준)
    r = asyncio.run(asktools.run_tool(
        "host_logs", {"host": "[host-aaa]", "contains": 'a"b'}, ctx))
    assert r.get("error"), r

    # ⑤ 호스트 목록은 표에서 만든다 — 조회 없이 답할 수 있어야 라운드를 아낀다
    r = asyncio.run(asktools.run_tool("list_hosts", {}, ctx))
    assert r.get("hosts") and r["hosts"][0]["host"] == "[host-aaa]", r
    # **실명이 아니라 토큰으로 돌려준다.** 도구 결과는 그대로 모델에 실린다.
    assert "web-01" not in json.dumps(r, ensure_ascii=False), r

    # ⑥ 도구 목록이 모델에 줄 형태를 갖췄는가
    names = {t["name"] for t in asktools.TOOL_SPECS}
    assert {"list_hosts", "host_logs", "security_alerts", "past_judgments"} <= names, names
    for t in asktools.TOOL_SPECS:
        assert t.get("description") and t.get("input_schema", {}).get("type") == "object", t

    # ⑦ 판정 이력은 영역으로 걸러 읽는다. 기존 함수를 고치면 품질 지표의 분모가 바뀐다.
    assert hasattr(store, "judgments_in_realms"), "영역 조건이 붙은 읽기 함수가 없다"
    assert store.judgments_in_realms([]) == [], "허용 영역이 없으면 아무것도 안 준다"
    return 17


def _ask_table_checks() -> int:
    """조회 대상 표를 서버가 만드는가.

    표에 없으면 도구가 대상을 지정할 방법이 없다. 그래서 이 표가 곧 경계다.
    """
    import asyncio
    import json
    import os

    from . import ask, collector, incident as inc_mod, registry

    saved_src = list(registry._SOURCES)
    saved_map = dict(inc_mod.REALM_MAP)
    saved_env = os.environ.get("ASK_ALLOWED_REALMS")
    saved_entries = list(registry._ENTRIES)
    try:
        registry._SOURCES = [{"name": "zabbix-internal", "realm": "internal"},
                             {"name": "zabbix-msp", "realm": "msp"}]
        registry._ENTRIES = []
        inc_mod.REALM_MAP = {}
        os.environ.pop("ASK_ALLOWED_REALMS", None)

        asked = []

        class _Fake:
            def __init__(self, source=""):
                self.source = source

            async def call(self, client, method, params):
                asked.append((self.source, method))
                if self.source == "zabbix-internal":
                    return [{"hostid": "1", "host": "web-01", "status": "0",
                             "interfaces": [{"ip": "10.0.0.5", "dns": "web-01.example"}]}]
                return [{"hostid": "9", "host": "cust-db", "status": "0", "interfaces": []}]

        table = asyncio.run(ask.build_table(client_factory=_Fake))

        # ① **허용된 감시 서버에만 묻는다.** MSP 서버에는 조회조차 가지 않는다.
        assert {s for s, _m in asked} == {"zabbix-internal"}, asked
        assert all(m == "host.get" for _s, m in asked), asked

        # ② 열쇠는 토큰이고 실명은 값 안에만 있다. 표 자체가 모델에 나가지 않는다.
        assert table and all(k.startswith("[host-") for k in table), list(table)[:3]
        assert "cust-db" not in json.dumps(table, ensure_ascii=False), "MSP 호스트가 실렸다"

        ent = list(table.values())[0]
        assert ent["host"] == "web-01" and ent["source"] == "zabbix-internal", ent
        # ③ 축 이름은 명부·인터페이스에서 푼다. 못 풀면 빈 값이고 그건 '없음'이 아니다.
        assert ent["logs"] == "web-01.example", ent

        # ④ 조회가 실패해도 예외로 끝내지 않는다 — 답을 못 하더라도 이유를 말해야 한다
        class _Dead(_Fake):
            async def call(self, client, method, params):
                raise RuntimeError("zabbix down")

        assert asyncio.run(ask.build_table(client_factory=_Dead)) == {}
        return 9
    finally:
        registry._SOURCES = saved_src
        registry._ENTRIES = saved_entries
        inc_mod.REALM_MAP = saved_map
        if saved_env is None:
            os.environ.pop("ASK_ALLOWED_REALMS", None)
        else:
            os.environ["ASK_ALLOWED_REALMS"] = saved_env


def _ask_loop_checks() -> int:
    """모델이 도구를 고르는 루프가 상한 안에서 도는가."""
    import asyncio
    import json

    from . import ask, asktools, nametable

    saved = dict(nametable._terms)
    try:
        nametable._terms = {"web-01": "host"}
        table = {ask.proxy.token_for("host", "web-01"):
                 {"host": "web-01", "source": "zabbix-internal",
                  "logs": "web-01.example", "security": "web-01.example"}}

        def _tool_use(name, args):
            return {"stop_reason": "tool_use", "content": [
                {"type": "tool_use", "id": "t1", "name": name, "input": args}]}

        def _text(t):
            return {"stop_reason": "end_turn", "content": [{"type": "text", "text": t}]}

        # ① 도구를 한 번 부르고 답한다. 추적에 무엇을 불렀는지 남는다.
        calls = []

        def model(system, messages, tools):
            calls.append(len(messages))
            return _tool_use("list_hosts", {}) if len(calls) == 1 else _text("web-01 이 원인이다")

        r = asyncio.run(ask.run_ask("무슨 호스트가 있나", table=table, model_fn=model))
        assert r["text"] == "web-01 이 원인이다", r
        assert [t["tool"] for t in r["trace"]] == ["list_hosts"], r["trace"]

        # ①-b **답을 도구로 받는다.** 산문으로 받으면 손잡이가 글자로 남고 구간이
        #      지어내진다(2026-08-18 실측).
        def answers(system, messages, tools):
            return {"stop_reason": "tool_use", "content": [
                {"type": "tool_use", "id": "t1", "name": "answer",
                 "input": {"summary": "복제는 정상이다",
                           "findings": ["지연 0초", "IO/SQL 모두 Yes"]}}]}

        r = asyncio.run(ask.run_ask("복제 상태", table=table, model_fn=answers))
        assert "복제는 정상이다" in r["text"], r["text"]
        assert "지연 0초" in r["text"], r["text"]
        assert r["stopped"] == "end_turn", r["stopped"]

        # ①-c **없는 그림 손잡이는 되돌려 고치게 한다.** 예외로 끝내면 사람은 답 대신
        #      오류를 본다.
        seen = {"n": 0}

        def bad_then_good(system, messages, tools):
            seen["n"] += 1
            if seen["n"] == 1:
                return {"stop_reason": "tool_use", "content": [
                    {"type": "tool_use", "id": "t1", "name": "answer",
                     "input": {"summary": "보라", "image_ids": ["img-9999"]}}]}
            return {"stop_reason": "tool_use", "content": [
                {"type": "tool_use", "id": "t2", "name": "answer",
                 "input": {"summary": "다시 보라"}}]}

        r = asyncio.run(ask.run_ask("그림", table=table, model_fn=bad_then_good))
        assert r["text"].startswith("다시 보라"), r["text"]
        assert any(t.get("error") for t in r["trace"]), r["trace"]

        # ② **라운드 상한.** 모델이 계속 도구만 불러도 멈추고, 멈춘 이유를 남긴다.
        def loop_forever(system, messages, tools):
            return _tool_use("list_hosts", {})

        r = asyncio.run(ask.run_ask("무한", table=table, model_fn=loop_forever))
        assert len(r["trace"]) <= ask.MAX_ROUNDS, len(r["trace"])
        assert r["stopped"] == "rounds", r
        assert r["text"], "상한에 닿아도 사람에게 할 말은 있어야 한다"

        # ③ **시간 상한.** 시계를 주입해 결정적으로 검증한다.
        clock = [1000.0]

        def slow(system, messages, tools):
            clock[0] += ask.DEADLINE_S
            return _tool_use("list_hosts", {})

        r = asyncio.run(ask.run_ask("느림", table=table, model_fn=slow,
                                    clock=lambda: clock[0]))
        assert r["stopped"] == "deadline", r

        # ④ 모델이 표에 없는 대상을 부르면 거부가 **도구 결과로** 돌아가 스스로 고친다
        seq = [_tool_use("host_logs", {"host": "[host-000000000000]"}),
               _text("대상을 다시 확인하겠다")]

        def bad_then_fix(system, messages, tools):
            return seq.pop(0)

        r = asyncio.run(ask.run_ask("엉뚱", table=table, model_fn=bad_then_fix))
        assert r["text"] and r["trace"][0]["error"], r["trace"]

        # ⑤ 질문이 위생 검사를 통과 못 하면 모델을 부르지 않는다
        called = []
        r = asyncio.run(ask.run_ask("xweb-01y 가 이상함", table=table,
                                    model_fn=lambda *a: called.append(1) or _text("x")))
        assert r.get("error") and not called, r

        # ⑥ **표를 먼저 만들고 질문을 가린다.** 순서가 거꾸로면 이름 표에 없는
        #    호스트가 질문에서 안 가려진 채 나간다. 랩에서 실제로 그랬다(2026-08-18).
        seen_q = []

        def capture(system, messages, tools):
            seen_q.append(messages[-1]["content"])
            return _text("확인했다")

        nametable._terms = {}          # 이름 표에는 없고 대상 표에만 있는 호스트
        asyncio.run(ask.run_ask("web-01 로그 봐줘", table=table, model_fn=capture))
        assert "web-01" not in seen_q[0], "표의 호스트가 질문에서 안 가려졌다: %s" % seen_q[0]

        # ⑦ 호스트 목록 검색은 **실명**으로 맞는다. 사람은 실명으로 묻는다.
        found = asyncio.run(asktools.run_tool("list_hosts", {"query": "web"},
                                              {"table": table}))
        assert found["n"] == 1, found
        assert "web-01" not in json.dumps(found, ensure_ascii=False), found

        # ⑧ **줄여 쓴 이름도 같은 토큰으로 가린다.** 사람은 도메인 접미사를 빼고
        #    친다. 안 가리면 실명 조각이 그대로 나가고, 모델은 그 문자열을 도구
        #    인자로 넣어 '알 수 없는 대상' 으로 튕긴다(2026-08-18 랩 실측).
        long_tbl = {ask.proxy.token_for("host", "vm-p3-target-002.novalocal"):
                    {"host": "vm-p3-target-002.novalocal", "source": "zabbix-internal",
                     "logs": "vm-p3-target-002.novalocal",
                     "security": "vm-p3-target-002.novalocal"}}
        seen2 = []

        def cap2(system, messages, tools):
            seen2.append(messages[-1]["content"])
            return _text("확인")

        nametable._terms = {}
        asyncio.run(ask.run_ask("vm-p3-target-002 로그 봐줘", table=long_tbl, model_fn=cap2))
        assert "vm-p3-target-002" not in seen2[0], "줄여 쓴 이름이 안 가려졌다: %s" % seen2[0]

        # ⑨ 호스트 목록은 지표 축도 알려 준다. 안 알리면 모델이 '지표가 없다'고 단정한다.
        got = asyncio.run(asktools.run_tool("list_hosts", {}, {"table": long_tbl}))
        assert "metrics" in got["hosts"][0]["axes"], got

        # ⑩ **일부만 적은 이름도 대상으로 푼다.** 사람은 vm-p3-target-002.novalocal 을
        #    target-002 로 줄여 말한다. 못 풀면 모델이 '등록되지 않은 호스트' 라고
        #    답하고 대화가 막힌다(2026-08-18 랩 실측).
        seen3 = []

        def cap3(system, messages, tools):
            seen3.append(messages[-1]["content"])
            return _text("확인")

        nametable._terms = {}
        asyncio.run(ask.run_ask("target-002 상태 알려줘", table=long_tbl, model_fn=cap3))
        assert "target-002" not in seen3[0], "부분 이름이 안 풀렸다: %s" % seen3[0]

        # 여러 호스트에 걸리는 조각은 **풀지 않는다.** 엉뚱한 기계를 짚으면 더 나쁘다.
        two = dict(long_tbl)
        two[ask.proxy.token_for("host", "vm-b.novalocal")] = {
            "host": "vm-b.novalocal", "source": "zabbix-internal", "logs": "", "security": ""}
        assert ask.resolve_mentions("vm 상태", two) == "vm 상태"

        # ⑪ **이력은 창으로 자른다.** 다 보내면 턴이 쌓일수록 비용과 지연이 늘고
        #    상한에 닿으면 최신 질문이 밀린다. 오래된 것부터 버리고, 버린 사실을
        #    모델에게 알린다 — 조용히 버리면 모델이 앞 대화를 기억한다고 착각한다.
        long_hist = []
        for i in range(40):
            long_hist.append({"role": "user", "content": "질문 %d %s" % (i, "가" * 400)})
            long_hist.append({"role": "assistant", "content": "답 %d" % i})
        seen4 = []

        def cap4(system, messages, tools):
            seen4.append(messages)
            return _text("확인")

        asyncio.run(ask.run_ask("마지막 질문", history=long_hist, table=long_tbl,
                                model_fn=cap4))
        sent = seen4[0]
        assert len(sent) <= ask.HISTORY_MAX_MSGS + 2, len(sent)
        blob = json.dumps(sent, ensure_ascii=False)
        assert len(blob) <= ask.HISTORY_MAX_CHARS * 2, len(blob)
        assert sent[-1]["content"].endswith("마지막 질문"), sent[-1]
        assert any("앞선 대화" in str(m.get("content")) for m in sent), "생략 사실을 안 알렸다"

        # 짧은 이력은 그대로 간다 — 필요 없는 안내를 붙이지 않는다
        seen4.clear()
        asyncio.run(ask.run_ask("짧게", history=[{"role": "user", "content": "안녕"},
                                                 {"role": "assistant", "content": "네"}],
                                table=long_tbl, model_fn=cap4))
        assert not any("앞선 대화" in str(m.get("content")) for m in seen4[0]), seen4[0]

        # ⑫ **패널 그림은 손잡이만 모델에 준다.** 주소에는 대시보드 식별자와
        #    var-host 실명이 들어가므로 그대로 실으면 마스킹이 무너진다. 그림은
        #    화면이 받아 그리고, 모델은 손잡이로만 가리킨다.
        shots = []

        def cap5(system, messages, tools):
            shots.append(json.dumps(messages, ensure_ascii=False))
            if len(shots) == 1:
                return {"stop_reason": "tool_use", "content": [
                    {"type": "tool_use", "id": "p1", "name": "panel_image",
                     "input": {"host": list(long_tbl)[0], "match": "CPU"}}]}
            return _text("아래 그림을 보라 img-1")

        async def fake_panel(ent, m, a, b):
            return {"id": "img-1", "title": "CPU 사용률",
                    "url": "/render/d-solo/x?var-host=%s" % ent["host"]}

        r = asyncio.run(ask.run_ask("CPU 그림 보여줘", table=long_tbl, model_fn=cap5,
                                    panel_fn=fake_panel))
        assert r["images"] and r["images"][0]["id"] == "img-1", r.get("images")
        assert "vm-p3-target-002" in r["images"][0]["url"], r["images"][0]
        # 모델이 본 것에는 주소도 실명도 없어야 한다
        blob = chr(10).join(shots)
        assert "/render/" not in blob, "이미지 주소가 모델에 갔다"
        assert "vm-p3-target-002" not in blob, "실명이 모델에 갔다"

        # ⑬ **같은 조회를 두 번 하지 않는다.** 오늘 list_hosts 를 세 번 부르며
        #    라운드를 태웠다. 두 번째부터는 실행하지 않고 이미 불렀다고 돌려준다.
        dup = []

        def cap6(system, messages, tools):
            dup.append(1)
            if len(dup) <= 3:
                return {"stop_reason": "tool_use", "content": [
                    {"type": "tool_use", "id": "d%d" % len(dup), "name": "list_hosts",
                     "input": {}}]}
            return _text("끝")

        r = asyncio.run(ask.run_ask("반복", table=long_tbl, model_fn=cap6))
        repeats = [t for t in r["trace"] if "이미" in (t["error"] or "")]
        assert repeats, "같은 조회가 그대로 다시 실행됐다: %s" % r["trace"]

        # ⑭ **빈 결과에 다음 수를 알려 준다.** 그냥 비어 있으면 모델이 포기한다.
        empty = asyncio.run(asktools.run_tool("list_hosts", {"query": "없는이름"},
                                              {"table": long_tbl}))
        assert empty.get("hint"), empty

        # ⑮ 프롬프트가 범위를 못 박는가 — 관측과 무관한 질문에는 답을 아낀다
        assert "관측" in ask.ASK_SYSTEM and "범위" in ask.ASK_SYSTEM, "범위 규칙이 없다"

        # ⑯ **과거 판정의 분석 문장을 읽는다.** 시각·유형만 주면 "예전에도 있었다"
        #    까지밖에 못 말한다. 무엇이라고 판단했는지가 값이다. 다만 본문에는 실명이
        #    섞이므로 마스킹 뒤 누수 검사를 통과할 때만 싣는다(prior 와 같은 규칙).
        # 누수 판정은 이름 표를 실시간으로 본다. 이 검사만 표를 채워 둔다.
        nametable._terms = {"vm-p3-target-002.novalocal": "host"}
        mk_all = ask.proxy.build_masker()
        row = {"fingerprint": "f1", "host": "vm-p3-target-002.novalocal",
               "realm": "internal", "classes": "replication", "sev": "SEV2",
               "verdict": "만성", "summary": "백업 부하로 복제가 밀렸다"}
        assert hasattr(ask, "judgment_body"), "판정 본문을 다루는 자리가 없다"
        assert ask.judgment_body(row, mk_all) == "백업 부하로 복제가 밀렸다"
        # 가린 뒤에도 아는 이름이 남으면 본문을 버린다 — 구조화 값은 그대로 간다
        row2 = dict(row, summary="xvm-p3-target-002.novalocaly 가 문제")
        assert ask.judgment_body(row2, mk_all) == ""

        # ⑰ **관측 지식 조각이 프롬프트에 실린다.** 없으면 모델이 match 를 헤맨다.
        facts = ask.load_facts()
        assert facts and "replication" in facts, facts[:200]
        sys_txt = ask.system_prompt()
        assert "replication" in sys_txt and "범위" in sys_txt, sys_txt[:200]
        # 조각을 못 읽어도 창구는 돌아야 한다 — 없는 파일이면 빈 문자열
        saved_path = ask.FACTS_FILE
        try:
            ask.FACTS_FILE = "/없는/경로.yml"
            ask.load_facts.cache_clear()
            assert ask.load_facts() == ""
            assert ask.system_prompt(), "조각이 없다고 프롬프트가 비면 안 된다"
        finally:
            ask.FACTS_FILE = saved_path
            ask.load_facts.cache_clear()

        # ⑱ **실제 토큰 수로 센다.** 호출 횟수만 세면 짧은 질문과 긴 조사가 같은
        #    한 건이다. 응답에 실려 오는 값으로 사후 정산한다.
        import os as _os
        import shutil as _sh
        import tempfile as _tf

        from . import store as st2

        _d = _tf.mkdtemp(prefix="ask-tok-")
        _saved_p = st2.PATH
        st2.PATH = _os.path.join(_d, "h.db")
        assert st2.init(), "검사용 저장소를 열지 못했다"

        def with_usage(system, messages, tools):
            return {"stop_reason": "end_turn", "content": [{"type": "text", "text": "답"}],
                    "usage": {"input_tokens": 1200, "output_tokens": 300}}

        base_tok = st2.tokens_since(3600, user="tester")
        asyncio.run(ask.run_ask("토큰 세기", table=long_tbl, model_fn=with_usage,
                                user="tester"))
        got = st2.tokens_since(3600, user="tester")
        assert got["in"] - base_tok["in"] == 1200, (got, base_tok)
        assert got["out"] - base_tok["out"] == 300, got

        st2.close()
        st2.PATH = _saved_p
        _sh.rmtree(_d, ignore_errors=True)

        # ⑲ **멈추면 그때까지 본 것으로 끝낸다.** 사람이 끊었는데 계속 돌면 비용만 든다.
        def keeps_going(system, messages, tools):
            ask.cancel("sess-x")          # 첫 라운드 뒤 사람이 멈춤 단추를 눌렀다
            return {"stop_reason": "tool_use", "content": [
                {"type": "tool_use", "id": "c1", "name": "list_hosts", "input": {}}]}

        r = asyncio.run(ask.run_ask("멈춤", table=long_tbl, model_fn=keeps_going,
                                    sid="sess-x"))
        assert r["stopped"] == "cancelled", r["stopped"]
        assert len(r["trace"]) <= 1, r["trace"]
        assert r["text"], "멈춰도 사람에게 할 말은 있어야 한다"

        # ⑳ **보던 패널은 맥락으로만 알린다.** 무조건 붙이면 이어지는 질문마다 같은
        #    그림이 다시 그려진다. 붙일지는 모델이 정하되, 무엇을 보고 있는지는
        #    알려 줘야 고를 수 있다.
        ctx_seen = []

        def cap_ctx(system, messages, tools):
            ctx_seen.append(str(messages[-1]["content"]))
            return _text("확인했다")

        r = asyncio.run(ask.run_ask("이 구간 뭐였나", table=long_tbl, model_fn=cap_ctx,
                                    panel={"uid": "d1", "panelId": 2,
                                           "host": "vm-p3-target-002.novalocal",
                                           "title": "복제 지연",
                                           "from": 1786589786, "to": 1786604263}))
        assert "보고 있는 패널" in ctx_seen[0], ctx_seen[0][:200]
        assert r["images"] == [], "모델이 안 불렀는데 그림이 붙었다"
        # 지시문이 언제 붙일지 말해 줘야 모델이 고른다
        assert "panel_image" in ask.ASK_SYSTEM, "그림 지침이 없다"

        # ㉑ **이력도 가린다.** 화면은 사람이 읽는 글(실명으로 되돌린 것)을 이력으로
        #    되보낸다. 그대로 실으면 앞 턴의 실명이 모델에 간다. 실제로 갔다
        #    (2026-08-18 실측: 도구 인자에 실명이 찍혔다).
        nametable._terms = {"vm-p3-target-002.novalocal": "host"}
        seen6 = []

        def cap7(system, messages, tools):
            seen6.append(json.dumps(messages, ensure_ascii=False))
            return _text("확인")

        asyncio.run(ask.run_ask(
            "이어서", table=long_tbl, model_fn=cap7,
            history=[{"role": "user", "content": "vm-p3-target-002.novalocal 상태"},
                     {"role": "assistant",
                      "content": "vm-p3-target-002.novalocal 은 정상입니다"}]))
        assert "vm-p3-target-002.novalocal" not in seen6[0],             "이력의 실명이 모델에 갔다: %s" % seen6[0][:200]

        # ㉒ **한 기계의 세 이름을 모두 가린다.** Zabbix 는 node1, Loki·Wazuh 는 FQDN
        #    으로 부른다. 패널이 넘기는 것은 축 이름이라 Zabbix 이름만 등록하면
        #    안 가려진 채 나가고 대상도 못 찾는다(2026-08-18 실측).
        three = {ask.proxy.token_for("host", "node1"):
                 {"host": "node1", "source": "zabbix-internal",
                  "logs": "vm-target-001.novalocal",
                  "security": "vm-target-001.novalocal"}}
        seen7 = []

        def cap8(system, messages, tools):
            seen7.append(str(messages[-1]["content"]))
            return _text("확인")

        nametable._terms = {}
        asyncio.run(ask.run_ask("vm-target-001.novalocal 로그 봐줘", table=three,
                                model_fn=cap8))
        assert "vm-target-001" not in seen7[0], "축 이름이 안 가려졌다: %s" % seen7[0]
        # 그리고 그 이름이 같은 대상으로 풀려야 도구를 부를 수 있다
        assert ask.proxy.token_for("host", "node1") in seen7[0], seen7[0]

        # ㉓ **손잡이는 화면에 글자로 남기지 않는다.** 그림을 따로 그리므로 [img-1]
        #    같은 문자열이 본문에 남으면 그냥 지저분한 글자다(2026-08-18 실측).
        assert ask.strip_handles("아래 [img-6598] 를 보라") == "아래 를 보라"
        assert ask.strip_handles("img-6598 참고") == "참고"
        # 비슷하지만 손잡이가 아닌 말은 안 건드린다
        assert ask.strip_handles("image-6598 은 그대로") == "image-6598 은 그대로"

        # ㉔ 모델이 죽어도 예외를 위로 던지지 않는다
        def dead(system, messages, tools):
            raise RuntimeError("model down")

        r = asyncio.run(ask.run_ask("무슨 호스트", table=table, model_fn=dead))
        assert r.get("error") and "모델" in r["error"], r
        return 59
    finally:
        nametable._terms = saved
        ask.forget_all()



def _graph_engine_checks() -> int:
    """LangGraph 엔진이 기존 반복문과 **같은 계약**을 지키는가.

    이관의 통과 조건이다. 프레임워크가 흐름만 맡고 도구·마스킹·상한은 우리 것이므로,
    같은 가짜 모델을 주면 두 엔진의 답·추적·멈춘 이유가 같아야 한다. 다르면 그 차이가
    곧 이관으로 잃은 것이다.

    프레임워크가 안 깔린 곳에서는 건너뛴다 — 선택 의존이라 없다고 검사가 깨지면 안 된다.
    """
    import asyncio
    import os

    from . import ask, graph, nametable

    if not graph.available():
        return 0

    saved_terms, saved_env = dict(nametable._terms), os.environ.get("ASK_ENGINE")
    try:
        nametable._terms = {"web-01": "host"}
        table = {ask.proxy.token_for("host", "web-01"):
                 {"host": "web-01", "source": "zabbix-internal",
                  "logs": "web-01.example", "security": "web-01.example"}}

        def _tool_use(name, args):
            return {"stop_reason": "tool_use", "content": [
                {"type": "tool_use", "id": "t1", "name": name, "input": args}]}

        def _text(t):
            return {"stop_reason": "end_turn", "content": [{"type": "text", "text": t}]}

        def run(engine, model_fn, q="무슨 호스트가 있나"):
            os.environ["ASK_ENGINE"] = engine
            return asyncio.run(ask.run_ask(q, table=table, model_fn=model_fn))

        # ① 한 번 부르고 답하는 흐름이 두 엔진에서 같다
        def one_call():
            n = {"i": 0}

            def model(system, messages, tools):
                n["i"] += 1
                return _tool_use("list_hosts", {}) if n["i"] == 1 else _text("web-01 이 원인이다")
            return model

        a, b = run("loop", one_call()), run("graph", one_call())
        assert a["text"] == b["text"] == "web-01 이 원인이다", (a["text"], b["text"])
        assert [t["tool"] for t in a["trace"]] == [t["tool"] for t in b["trace"]], (a, b)
        assert a["stopped"] == b["stopped"] == "end_turn", (a["stopped"], b["stopped"])

        # ② **라운드 상한이 그래프에서도 걸린다.** 프레임워크 자체 상한에 먼저 닿으면
        #    사람은 이유 대신 예외를 본다.
        def forever(system, messages, tools):
            return _tool_use("list_hosts", {})

        g = run("graph", forever, q="무한")
        assert len(g["trace"]) <= ask.MAX_ROUNDS, len(g["trace"])
        assert g["stopped"] == "rounds", g["stopped"]
        assert g["text"], "상한에 닿아도 사람에게 할 말은 있어야 한다"

        # ③ **같은 조회를 두 번 하지 않는다.** 중복 차단이 두 엔진 공용이다.
        assert sum(1 for t in g["trace"] if t.get("error")) >= 1, g["trace"]

        # ④ 모델 호출이 실패하면 사람이 읽을 문장으로 끝난다
        def blows(system, messages, tools):
            raise RuntimeError("모델 없음")

        f = run("graph", blows)
        assert f["stopped"] == "llm_failed" and f["error"], f

        # ⑤ 프레임워크가 없다고 적혀 있어도 답은 나온다(기존 반복문으로 떨어진다)
        os.environ["ASK_ENGINE"] = "graph"
        assert ask.engine_name() in ("graph", "loop")
    finally:
        nametable._terms = saved_terms
        if saved_env is None:
            os.environ.pop("ASK_ENGINE", None)
        else:
            os.environ["ASK_ENGINE"] = saved_env
    return 12


def _ask_user_checks() -> int:
    """사용량이 사용자별로 세어지는가.

    공유 토큰 하나로 들어오면 누가 얼마나 썼는지 알 수 없다. 파트·팀원별 관리가
    필요해지는 순간 이 계수기가 근거가 된다.
    """
    import os
    import shutil
    import tempfile

    from . import ask, store

    d = tempfile.mkdtemp(prefix="ask-user-")
    saved_path = store.PATH
    store.PATH = os.path.join(d, "hist.db")
    assert store.init(), "검사용 저장소를 열지 못했다"
    now = 1786600000.0
    base = store.calls_since(3600, now=now, user="hong")
    store.record_call("ask", now=now, user="hong")
    store.record_call("ask", now=now, user="hong")
    store.record_call("ask", now=now, user="kim")

    # 1) 사용자별로 갈라 센다
    assert store.calls_since(3600, now=now, user="hong") - base == 2
    assert store.calls_since(3600, now=now, user="kim") >= 1
    # 2) 사용자를 안 주면 전체다 — 기존 호출자의 의미가 바뀌면 안 된다
    assert store.calls_since(3600, now=now) >= 3

    # 3) 신원이 없으면 익명으로 센다. 세지 않으면 상한이 무의미해진다.
    assert ask.who("") == ask.ANON and ask.who(None) == ask.ANON
    # 4) 헤더 값을 그대로 믿지 않고 길이와 글자를 다듬는다
    assert ask.who("a" * 500) == "a" * ask.USER_MAX_CHARS
    assert chr(10) not in ask.who("hong" + chr(10) + "doe")

    # 5) 사용자 상한이 걸리는가
    saved = ask.MAX_PER_USER_HOUR
    try:
        ask.MAX_PER_USER_HOUR = 1
        ok, why = ask.user_budget_ok("kim", now=now)
        assert not ok and why, (ok, why)
        ask.MAX_PER_USER_HOUR = 10000
        assert ask.user_budget_ok("kim", now=now)[0]
    finally:
        ask.MAX_PER_USER_HOUR = saved
        # **열어 둔 채 끝내지 않는다.** store.init() 은 이미 열려 있으면 아무것도
        # 안 하므로, 뒤 검사가 store.PATH 를 바꿔도 무시되고 남의 파일에 쓴다.
        store.close()
        store.PATH = saved_path
        shutil.rmtree(d, ignore_errors=True)
    return 9


def _convo_checks() -> int:
    """대화 이력 — 사용자별로 나뉘고, 목록이 보이고, 만료가 있는가.

    저장소가 죽어도 질의 자체는 돌아야 한다. 대화는 다시 물으면 되지만 조회는 아니다.
    """
    from . import convo

    convo.use_memory()          # 검사에서는 메모리 구현으로 돈다
    try:
        cid = convo.create("hong", "복제 지연 확인")
        convo.append(cid, "hong", "user", "질문 1")
        convo.append(cid, "hong", "assistant", "답 1")

        # ① 사용자별로 나뉜다. 남의 대화는 목록에도 안 나오고 열리지도 않는다.
        other = convo.create("kim", "다른 사람 것")
        mine = [c["id"] for c in convo.listing("hong")]
        assert cid in mine and other not in mine, mine
        assert convo.load(cid, "kim") == [], "남의 대화가 열렸다"
        assert len(convo.load(cid, "hong")) == 2

        # **그림도 함께 남긴다.** 답 본문만 저장하면 새로고침한 순간 화면에 붙어 있던
        # 패널 그림이 사라진다(2026-08-18 실측). 주소만 남기므로 부피는 작다.
        imgs = [{"id": "img-1234", "title": "복제 지연",
                 "url": "/render/d-solo/abc?panelId=7"}]
        convo.append(cid, "hong", "assistant", "답 2", images=imgs)
        rows = convo.load(cid, "hong")
        assert rows[-1].get("images") == imgs, rows[-1]
        # 그림이 없는 줄에는 아무것도 붙이지 않는다
        assert not rows[-2].get("images"), rows[-2]

        # ② 제목은 첫 질문에서 만들되 사람이 바꿀 수 있다
        convo.rename(cid, "hong", "백업 때문에 밀린 복제")
        assert convo.listing("hong")[0]["title"] == "백업 때문에 밀린 복제"

        # ③ 목록은 최근 것이 위다 — 사람이 방금 하던 대화를 먼저 찾는다
        cid2 = convo.create("hong", "두 번째")
        assert [c["id"] for c in convo.listing("hong")][0] == cid2

        # ④ 지우면 목록과 본문이 함께 사라진다
        convo.remove(cid2, "hong")
        assert cid2 not in [c["id"] for c in convo.listing("hong")]
        assert convo.load(cid2, "hong") == []

        # ⑤ **저장소가 죽어도 질의는 돌아야 한다.** 대화만 포기한다.
        convo.use_none()
        assert convo.create("hong", "무시됨") == ""
        assert convo.listing("hong") == [] and convo.load("x", "hong") == []
        return 12
    finally:
        convo.use_memory()


def _proxy_mask_checks() -> int:
    """수신 지점의 왕복 변환 — 중첩 JSON 마스킹과 도구 인자 역치환 (§23)."""
    import json

    from . import masking, nametable, proxy

    saved = dict(nametable._terms)
    try:
        nametable._terms = {"goal.kinx.net": "host", "db-prod-01": "host",
                            "Test": "group"}
        mk = masking.Masker()
        nametable.apply_to(mk)

        req = {
            "model": "claude-opus-4-8",
            "system": "goal.kinx.net 을 조사하라",
            "messages": [
                {"role": "user", "content": "db-prod-01 장애"},
                {"role": "user", "content": [
                    {"type": "tool_result", "tool_use_id": "toolu_1",
                     "content": "goal.kinx.net 의 CPU 99%"},
                ]},
            ],
            "tools": [{"name": "zabbix_query", "description": "호스트 상태 조회"}],
        }
        out = proxy.mask_json(req, mk)
        blob = json.dumps(out, ensure_ascii=False)
        assert "goal.kinx.net" not in blob, f"중첩 안 이름이 안 가려졌다: {blob}"
        assert "db-prod-01" not in blob, blob
        # 프로토콜 자리는 그대로여야 한다. 여기가 바뀌면 도구가 깨진다.
        assert out["model"] == "claude-opus-4-8", out["model"]
        assert out["tools"][0]["name"] == "zabbix_query", out["tools"][0]
        assert out["messages"][1]["content"][0]["type"] == "tool_result"
        assert out["messages"][1]["content"][0]["tool_use_id"] == "toolu_1"
        # 서로 다른 호스트는 서로 다른 토큰이어야 관계 분석이 남는다
        t1 = mk._fwd["goal.kinx.net"]
        t2 = mk._fwd["db-prod-01"]
        assert t1 != t2, (t1, t2)
        # 같은 이름은 어디서 나오든 같은 토큰
        assert out["system"].count(t1) == 1 and t1 in blob

        # 응답 — 도구 호출 인자가 실명으로 돌아와야 도구가 조회할 수 있다
        resp = {"id": "msg_1", "type": "message", "role": "assistant",
                "content": [
                    {"type": "text", "text": "%s 를 확인하라" % t1},
                    {"type": "tool_use", "id": "toolu_2", "name": "zabbix_query",
                     "input": {"host": t1, "metric": "cpu.util"}},
                ]}
        back = proxy.unmask_json(resp, mk)
        assert back["content"][1]["input"]["host"] == "goal.kinx.net", back["content"][1]
        assert "goal.kinx.net" in back["content"][0]["text"]
        assert back["content"][1]["name"] == "zabbix_query"

        # 되돌리지 못한 토큰이 도구 인자에 남으면 조용히 깨진 조회가 나간다
        # 표에 없는 토큰(모델이 지어냈거나 표가 바뀐 경우) — 형태는 같고 뜻이 없다
        bad = {"content": [{"type": "tool_use", "input": {"host": "[host-deadbe]"}}]}
        assert proxy.leftover_tokens(proxy.unmask_json(bad, mk)),             "역치환 못 한 토큰을 못 잡는다"
        assert not proxy.leftover_tokens(back), back
        return 12
    finally:
        nametable._terms = saved


def _tenant_scope_checks() -> int:
    """보안 조회가 남의 호스트까지 긁어오지 않는가.

    양쪽 와일드카드로 이름을 맞추면 `db01` 조회가 `customer-b-db01` 의 경보까지
    가져온다. 그 항목은 이번 사건 호스트만 등록된 마스커를 거치므로 **다른 고객의
    파일 경로·규칙 설명이 원문 그대로** 외부로 나가고, Slack 카드에는 이 호스트의
    침해 신호처럼 보인다.
    """
    import asyncio
    import json
    import os

    from . import collector

    sent = {}

    class _Resp:
        def raise_for_status(self):
            pass

        def json(self):
            return {"hits": {"hits": []}}

    class _Client:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def post(self, url, **kw):
            # 조회가 두 번 간다(본 조회 + 이름 확인). 덮어쓰면 한쪽만 보게 되므로
            # 전부 모은다.
            sent.setdefault("bodies", []).append(kw.get("json"))
            return _Resp()

    class _Httpx:
        def AsyncClient(self, **_kw):
            return _Client()

    saved_httpx = collector.httpx
    saved_env = {k: os.environ.get(k) for k in ("WAZUH_INDEXER_URL",)}
    collector.httpx = _Httpx()
    os.environ["WAZUH_INDEXER_URL"] = "https://127.0.0.1:9200"
    try:
        asyncio.run(collector._wazuh_alerts("db01", 1000.0))
    finally:
        collector.httpx = saved_httpx
        for k, v in saved_env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    bodies = sent.get("bodies") or []
    assert len(bodies) >= 2, f"본 조회와 이름 확인이 다 안 갔다: {len(bodies)}"
    text = json.dumps(bodies, ensure_ascii=False)
    assert "wildcard" not in text,         f"보안 조회가 부분 일치다 — 다른 고객 호스트 경보가 섞인다: {text}"
    assert '"db01"' in text, text
    return 3


def _holmes_egress_checks() -> int:
    """심층조사도 출구를 지나는가.

    이 도구는 별도 프로세스라 자기 키로 나갔다. 그래서 (a) 호출량 지표에 안 잡혀
    사용량이 실제보다 적게 보고되고 (b) 동시 호출 제한 밖이라 폭주 때 인시던트마다
    최대 300초짜리 호출이 무제한으로 떠 공용 스레드를 다 차지한다.

    호스트명은 가리지 못한다. 그 이름으로 감시 서버를 조회해야 도구가 일을 하기
    때문이다. 반출 통제는 그 도구의 모델 호출을 우리 쪽으로 돌려야 가능하다.
    여기서는 집계와 동시 제한까지만 본다.
    """
    import os
    import threading

    from . import egress, holmes

    sent = {}

    class _Resp:
        status_code = 200

        def json(self):
            return {"analysis": "원인은 디스크다"}

    def _fake_post(url, **kw):
        sent["url"] = url
        sent["body"] = kw.get("json")
        return _Resp()

    saved = (holmes.httpx.post, egress.MAX_PER_HOUR, dict(egress._stats))
    holmes.httpx.post = _fake_post
    os.environ["HOLMES_URL"] = "http://127.0.0.1:9999"
    egress._calls.clear()
    egress._by_kind.clear()
    try:
        res = holmes.investigate("cust-db01", "why")
        assert res.get("ok") and "디스크" in res.get("analysis", ""), res
        assert egress.kind_counts().get("holmes") == 1,             f"심층조사가 호출 집계에 안 잡힌다 — 사용량 지표가 실제보다 적게 나온다: {egress.kind_counts()}"
        # 호스트명은 그대로 나간다(가리면 도구가 조회를 못 한다). 그 사실을 고정한다.
        assert "cust-db01" in str(sent.get("body")), sent

        # 시간당 총량에도 걸려야 한다
        egress.MAX_PER_HOUR = 1
        blocked = holmes.investigate("cust-db01", "why")
        assert blocked.get("ok") is False, f"상한을 넘겼는데 나갔다: {blocked}"
        return 4
    finally:
        holmes.httpx.post, egress.MAX_PER_HOUR, restore = saved
        os.environ.pop("HOLMES_URL", None)
        egress._stats.clear()
        egress._stats.update(restore)
        egress._calls.clear()
        egress._by_kind.clear()


def _timer_close_checks() -> int:
    """창이 닫힐 때 마감 처리가 끝까지 도는가.

    마감은 타이머 태스크 안에서 돈다. 그 안에서 자기 타이머를 취소하면, 마감 처리가
    처음 기다리는 지점에서 취소되어 조용히 죽는다. 알림은 대기 파일에 남고 카드도
    안 올라가는데 오류 한 줄 없다.

    기존 검사는 `on_close` 가 아무것도 안 기다려서 이 상황을 못 만들었다. 실제
    경로는 수집·분석·게시를 전부 기다리므로 반드시 기다리는 것으로 검사한다.
    """
    import asyncio
    import time as _t

    from . import incident as inc_mod

    done = []

    async def _slow_close(inc):
        await asyncio.sleep(0.02)      # 실제 경로는 여기서 수집·분석을 기다린다
        done.append(inc)

    mgr = inc_mod.IncidentManager(on_close=_slow_close, debounce_s=0.05,
                                  max_window_s=0.5)

    async def _run():
        await mgr.submit(inc_mod.Alert(
            source="zabbix-internal", event_id="e1", trigger_id="t1", host="h1",
            alert_name="n", sev="SEV2", incident_class="disk_space",
            recv=_t.monotonic()))
        await asyncio.sleep(0.4)

    asyncio.run(_run())
    assert done, "창이 닫혔는데 마감 처리가 끝까지 안 갔다 — 타이머가 자기를 취소한다"
    return 1


def _overflow_checks() -> int:
    """창 안에 알림이 상한을 넘겼을 때 넘친 것이 어떻게 되는가.

    넘친 알림은 어떤 사건에도 안 들어가므로, 사건이 끝날 때 대기 파일에서 지워지지
    않는다(지우는 목록이 `inc.alerts` 이기 때문이다). 그러면 재기동마다 되살아나
    이미 끝난 사건의 알림으로 새 사건이 열리고, 세 번 반복하면 버려진다. 웹훅은
    200 을 줬고 파일에도 적혔는데 아무도 안 본 알림이 된다.
    """
    import asyncio
    import os
    import shutil
    import tempfile
    import time as _t

    from . import incident, pending

    d = tempfile.mkdtemp(prefix="overflow-test-")
    saved_path = pending.PATH
    pending.PATH = os.path.join(d, "pending.jsonl")
    try:
        closed = []

        async def _on_close(inc):
            closed.append(inc)

        mgr = incident.IncidentManager(on_close=_on_close, debounce_s=0.05,
                                       max_window_s=0.3, max_alerts=3)

        async def _run():
            for i in range(6):
                rec = {"source": "zabbix-internal", "event_id": "e%d" % i}
                pending.append(rec)
                await mgr.submit(incident.Alert(
                    source="zabbix-internal", event_id="e%d" % i, trigger_id="1",
                    host="h1", alert_name="disk full", sev="SEV3",
                    incident_class="disk_space", recv=_t.monotonic()))
            await asyncio.sleep(0.6)

        asyncio.run(_run())
        assert closed, "사건이 안 닫혔다"
        assert len(closed[0].alerts) == 3, f"상한이 안 걸렸다: {len(closed[0].alerts)}"
        # 사건이 끝날 때마다 실제 경로처럼 대기 목록에서 지운다
        for inc in closed:
            pending.drop([{"source": a.source, "event_id": a.event_id}
                          for a in inc.alerts])
        left = {r.get("event_id") for r in pending.load()}
        assert not left, (f"넘친 알림 {sorted(left)} 이 어떤 사건에도 안 들어가 대기 "
                          "파일에 남았다 — 재기동마다 되살아나 이미 끝난 사건의 알림으로 "
                          "새 사건이 열린다")
        # 버리지 않고 다음 사건으로 넘겼는지 — 사건 수와 알림 총수로 확인한다
        assert len(closed) >= 2, f"넘친 알림이 새 사건으로 안 이어졌다: {len(closed)}"
        assert sum(len(i.alerts) for i in closed) == 6,             [len(i.alerts) for i in closed]
        return 4
    finally:
        pending.PATH = saved_path
        shutil.rmtree(d, ignore_errors=True)


def _pending_checks() -> int:
    """대기 알림 기록 — 창이 닫히기 전에 죽어도 알림이 남아 있는지.

    기록에 실패했는데 참을 돌려주면 웹훅이 200 을 주고, 그러면 Zabbix 는 재시도하지
    않는다. 그 경로가 가장 중요하므로 먼저 잠근다.
    """
    import os
    import tempfile

    from . import pending

    saved_path, saved_max = pending.PATH, pending.MAX_REPLAY
    d = tempfile.mkdtemp(prefix="pending-test-")
    pending.PATH = os.path.join(d, "pending.jsonl")
    try:
        assert pending.load() == [], "파일이 없으면 빈 목록이어야"

        a = {"source": "zabbix-internal", "event_id": "1", "host": "h1"}
        b = {"source": "zabbix-internal", "event_id": "2", "host": "h2"}
        assert pending.append(a) is True and pending.append(b) is True
        assert [r["event_id"] for r in pending.load()] == ["1", "2"]

        # 끝난 것만 빠지고 나머지는 남는다
        pending.drop([{"source": "zabbix-internal", "event_id": "1"}])
        assert [r["event_id"] for r in pending.load()] == ["2"]

        # 깨진 줄이 있어도 나머지는 읽는다 — 한 줄 때문에 전부 버리면 유실이다
        with open(pending.PATH, "a", encoding="utf-8") as f:
            f.write("{망가진 줄" + chr(10))
        assert [r["event_id"] for r in pending.load()] == ["2"]

        # 재시도 횟수가 올라가고 한도를 넘으면 버린다
        pending.MAX_REPLAY = 2
        assert [r["replays"] for r in pending.take_for_replay()] == [1]
        assert [r["replays"] for r in pending.take_for_replay()] == [2]
        assert pending.take_for_replay() == [], "한도를 넘으면 버려야"
        assert pending.load() == []

        # 쓸 수 없으면 반드시 거짓 — 여기서 참이 나오면 웹훅이 거짓 200 을 준다
        pending.PATH = os.path.join(d, "no-such-dir", "x", "pending.jsonl")
        os.makedirs(os.path.dirname(pending.PATH))
        os.chmod(os.path.dirname(pending.PATH), 0o500)
        try:
            wrote = pending.append(a)
        finally:
            os.chmod(os.path.dirname(pending.PATH), 0o700)
        if os.name != "nt" and os.geteuid() != 0:
            assert wrote is False, "쓰지 못했는데 참을 돌려줬다"

        # 동시성 — drop 은 파일 전체를 읽어 다시 쓴다. 그 사이에 다른 스레드가 넣은
        # 줄이 덮어쓰기에 밀려 사라지면, 웹훅이 이미 200 을 준 알림이 없어진다.
        # Zabbix 는 성공을 받았으므로 다시 보내지 않는다. 실제로 이 순서는 폭주 때
        # 늘 일어난다 — 사건 마감(drop)과 새 알림 도착(append)이 겹친다.
        import threading

        for i in range(60):
            pending.append({"source": "s", "event_id": "old-%d" % i})
        added, errors = [], []

        def _adder():
            for i in range(120):
                try:
                    if pending.append({"source": "s", "event_id": "new-%d" % i}):
                        added.append("new-%d" % i)
                except Exception as e:      # noqa: BLE001 — 무엇이든 기록만
                    errors.append(e)

        def _dropper():
            for i in range(60):
                try:
                    pending.drop([{"source": "s", "event_id": "old-%d" % i}])
                except Exception as e:      # noqa: BLE001
                    errors.append(e)

        t1 = threading.Thread(target=_adder)
        t2 = threading.Thread(target=_dropper)
        t1.start(), t2.start()
        t1.join(timeout=30), t2.join(timeout=30)
        assert not errors, f"동시 접근에서 예외: {errors[:2]}"
        left = {r.get("event_id") for r in pending.load()}
        lost = [k for k in added if k not in left]
        assert not lost, (f"append 가 참을 돌려줬는데 파일에서 사라졌다 {len(lost)}건 "
                          f"(예: {lost[:3]}). 200 을 준 알림이 유실되는 경로다")
    finally:
        pending.PATH, pending.MAX_REPLAY = saved_path, saved_max
        shutil.rmtree(d, ignore_errors=True)
    return 12


def _analyze_ref_checks() -> int:
    """사람이 요청하는 분석 — 카드에 실은 재료로 사건이 되살아나는지.

    이 왕복이 깨지면 Run Workflow 를 눌러도 아무 일이 없거나 엉뚱한 사건을 분석한다.
    둘 다 눌러 본 사람은 알 수 없는 실패라 여기서 잠근다.
    """
    import os
    import sys
    import time

    from . import incident, triage

    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from analyze_now import parse_ref

    def _a(eid, tid, cls):
        return incident.Alert(source="zabbix-internal", event_id=eid, trigger_id=tid,
                              host="h1", alert_name="n", sev="SEV2",
                              incident_class=cls, recv=time.monotonic())

    inc = incident.Incident(key=("h1", "replication"), host="h1",
                            alerts=[_a("101", "25", "replication"),
                                    _a("102", "26", "cpu_io_pressure")],
                            opened_at=0.0, last_at=0.0)
    ref = triage.analyze_ref(inc)
    back = parse_ref(ref, "h1")
    assert [x.event_id for x in back] == ["101", "102"], back
    assert [x.trigger_id for x in back] == ["25", "26"], back
    assert [x.incident_class for x in back] == ["replication", "cpu_io_pressure"], back
    assert all(x.host == "h1" for x in back)

    # 트리거 없는 알림(Wazuh 등)도 되살아나야 한다 — 빈 칸이 형식을 깨면 안 된다
    inc2 = incident.Incident(key=("h2", "auth_security"), host="h2",
                             alerts=[_a("7", "", "auth_security")],
                             opened_at=0.0, last_at=0.0)
    back2 = parse_ref(triage.analyze_ref(inc2), "h2")
    assert len(back2) == 1 and back2[0].trigger_id == "" and back2[0].event_id == "7"

    # 값이 망가졌으면 조용히 넘어가지 말고 거부한다
    for bad in ("", "쓰레기", "zabbix-internal,"):
        try:
            parse_ref(bad, "h1")
            raise AssertionError("망가진 ref 를 받아들였다: %r" % bad)
        except RuntimeError:
            pass
    return 8


def _heartbeat_checks() -> int:
    """생존 신호 — 프로토콜이 실제로 통하는지, 안 켰을 때 조용한지.

    가짜 Zabbix 를 띄워 바이트를 그대로 주고받는다. 헤더를 손으로 조립하는 코드라
    형식이 틀리면 실환경에서야 드러나고, 그때는 신호가 끊긴 것과 구분되지 않는다.
    """
    import json
    import os
    import socket
    import struct
    import threading

    from . import heartbeat

    got = {}

    def fake_server(sock):
        conn, _ = sock.accept()
        with conn:
            head = conn.recv(13)
            got["head"] = head
            (n,) = struct.unpack("<I", head[5:9])
            body = b""
            while len(body) < n:
                body += conn.recv(n - len(body))
            got["body"] = json.loads(body.decode("utf-8"))
            res = json.dumps({"response": "success",
                              "info": "processed: 7; failed: 0; total: 7"}).encode()
            conn.sendall(b"ZBXD\x01" + struct.pack("<II", len(res), 0) + res)

    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]
    t = threading.Thread(target=fake_server, args=(srv,), daemon=True)
    t.start()

    saved = {k: os.environ.get(k) for k in
             ("HEARTBEAT_ZABBIX_SERVER", "HEARTBEAT_ZABBIX_PORT", "HEARTBEAT_HOST")}
    # 배포된 서버에는 이 값이 들어 있다. 지우고 검사하지 않으면 그 서버에서만 깨지고,
    # 설정 문제인지 코드 문제인지 구분할 수 없다(선판정·연계 규칙에서 겪은 것과 같다).
    for k in saved:
        os.environ.pop(k, None)
    try:
        assert heartbeat.enabled() is False, "설정이 없으면 꺼져 있어야"
        assert heartbeat.send({"x": 1})["ok"] is False, "미설정이면 보내지 말아야"

        os.environ["HEARTBEAT_ZABBIX_SERVER"] = "127.0.0.1"
        os.environ["HEARTBEAT_ZABBIX_PORT"] = str(port)
        os.environ["HEARTBEAT_HOST"] = "gw-01"
        assert heartbeat.enabled() is True

        beat = heartbeat.Beat(interval_s=999)
        beat.mark_alert()
        beat.mark_alert()
        beat.mark("incidents")
        beat.mark("analyzed")
        beat.mark("없는이름")   # 모르는 이름은 조용히 무시한다
        v = beat.values(now=beat.started_at + 30)
        assert v["gateway.alerts"] == 2 and v["gateway.incidents"] == 1, v
        assert v["gateway.analyzed"] == 1 and v["gateway.skipped"] == 0, v
        assert v["gateway.uptime"] == 30, v

        res = heartbeat.send(v)
        t.join(timeout=5)
        assert res["ok"] is True, res
        assert got["head"][:5] == b"ZBXD\x01", got.get("head")
        assert got["body"]["request"] == "sender data", got["body"]
        keys = {d["key"] for d in got["body"]["data"]}
        assert "gateway.alive" in keys and "gateway.since_last_alert" in keys, keys
        assert all(d["host"] == "gw-01" for d in got["body"]["data"])
        # 값은 문자열로 보낸다 — Zabbix 는 아이템 자료형에 맞춰 해석한다
        assert all(isinstance(d["value"], str) for d in got["body"]["data"])
    finally:
        srv.close()
        for k, val in saved.items():
            if val is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = val

    # Zabbix 가 response=success 를 주면서 failed 를 세는 경우. 아이템이 없거나 호스트가
    # 미등록이면 이렇게 온다. 이걸 성공으로 읽으면 값이 하나도 안 쌓이는 동안 로그는
    # 계속 성공이고, 아이템이 없으니 nodata 트리거도 없다 — 이 기능이 막으려던 상태다.
    assert heartbeat._accepted("processed: 7; failed: 0; total: 7") is True
    assert heartbeat._accepted("processed: 0; failed: 7; total: 7") is False
    assert heartbeat._accepted("형식이 바뀐 문자열") is True, "못 읽으면 오탐 대신 통과"
    assert heartbeat._accepted("") is True

    srv2 = socket.socket()
    srv2.bind(("127.0.0.1", 0))
    srv2.listen(1)
    port2 = srv2.getsockname()[1]

    def fake_reject(sock):
        conn, _ = sock.accept()
        with conn:
            head = conn.recv(13)
            (n,) = struct.unpack("<I", head[5:9])
            body = b""
            while len(body) < n:
                body += conn.recv(n - len(body))
            res = json.dumps({"response": "success",
                              "info": "processed: 0; failed: 7; total: 7"}).encode()
            conn.sendall(b"ZBXD\x01" + struct.pack("<II", len(res), 0) + res)

    t2 = threading.Thread(target=fake_reject, args=(srv2,), daemon=True)
    t2.start()
    os.environ["HEARTBEAT_ZABBIX_SERVER"] = "127.0.0.1"
    os.environ["HEARTBEAT_ZABBIX_PORT"] = str(port2)
    os.environ["HEARTBEAT_HOST"] = "gw-01"
    try:
        rej = heartbeat.send({"gateway.alive": 1})
        t2.join(timeout=5)
        assert rej["ok"] is False, f"전건 거부인데 성공으로 읽었다: {rej}"
        assert "failed: 7" in rej["info"], rej
    finally:
        srv2.close()

    # 닿지 않는 곳으로 보내도 예외를 던지지 않는다 — 봇 흐름이 멈추면 안 된다
    os.environ["HEARTBEAT_ZABBIX_SERVER"] = "127.0.0.1"
    os.environ["HEARTBEAT_ZABBIX_PORT"] = "1"
    os.environ["HEARTBEAT_HOST"] = "gw-01"
    try:
        assert heartbeat.send({"gateway.alive": 1})["ok"] is False
    finally:
        for k, val in saved.items():
            if val is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = val
    return 14


def _flush_checks() -> int:
    """정상 종료 시 마감 — 대기 중인 사건이 버려지지 않는지.

    버려져도 대기 파일이 받아 주므로 겉으로는 멀쩡해 보인다. 그래서 조용히 깨진다.
    깨지면 재기동마다 창을 처음부터 다시 세고 재시도 횟수가 올라가, 배포 몇 번에
    아직 처리도 안 한 알림이 한도에 걸려 버려진다.
    """
    import asyncio
    import time

    from . import incident

    def _alert(host, cls, name="n"):
        return incident.Alert(source="zabbix-internal", event_id=name, trigger_id="1",
                              host=host, alert_name=name, sev="SEV2",
                              incident_class=cls, recv=time.monotonic())

    closed = []

    async def _run2():
        async def on_close(inc):
            closed.append(inc.key)
        m = incident.IncidentManager(on_close=on_close, debounce_s=999, max_window_s=999)
        await m.submit(_alert("h1", "disk_space"))
        await m.submit(_alert("h2", "cpu_io_pressure"))
        n = await m.flush()
        return n, len(m._open), len(m._timers)

    n, left, timers = asyncio.run(_run2())
    assert n == 2 and left == 0, (n, left)
    assert timers == 0, "마감 후 타이머가 남으면 종료가 안 끝난다"
    # 키는 (영역, 호스트, 브리지) 세 칸이다 — 호스트 자리로 확인한다
    assert sorted(k[1] for k in closed) == ["h1", "h2"], closed

    # 열린 사건이 없으면 아무 일도 하지 않는다
    async def _empty():
        m = incident.IncidentManager(on_close=lambda inc: None)
        return await m.flush()
    assert asyncio.run(_empty()) == 0

    # 제한 시간을 넘기면 남은 것은 그대로 둔다 — 대기 파일이 받아 재기동 후 처리한다
    async def _slow():
        async def never(inc):
            await asyncio.sleep(5)
        m = incident.IncidentManager(on_close=never, debounce_s=999, max_window_s=999)
        await m.submit(_alert("h3", "disk_space"))
        n = await m.flush(timeout_s=0.2)
        return n
    # 마감 건수에 안 잡혀야 한다. 메모리에 남는지는 중요하지 않다 — 종료 중이고,
    # 처리를 못 끝냈으므로 대기 파일이 그대로 갖고 있어 재기동 후 다시 처리된다.
    assert asyncio.run(_slow()) == 0

    # 마감 중 예외가 나도 종료가 멈추면 안 된다
    async def _boom():
        async def boom(inc):
            raise RuntimeError("분석 실패")
        m = incident.IncidentManager(on_close=boom, debounce_s=999, max_window_s=999)
        await m.submit(_alert("h4", "disk_space"))
        return await m.flush(timeout_s=2), len(m._open)
    n3, left3 = asyncio.run(_boom())
    assert n3 == 1 and left3 == 0, (n3, left3)
    return 8


def _llm_concurrency_checks() -> int:
    """LLM 동시 호출 상한 — 상한이 실제로 걸리는지, 대기를 포기하면 열화로 내려가는지.

    상한이 안 걸려도 평소에는 아무 증상이 없다. 여러 호스트가 한꺼번에 무너져
    창이 동시에 닫힐 때만 드러나고, 그때는 429 와 비용으로 나타난다.
    """
    import io
    import os
    import threading
    import time

    from . import egress, llm

    ctx = {"prejudge": {"verdict": "신규", "statement": "처음"}, "sources": {}}

    class _Slow:
        name = "fake"

        def available(self):
            return True

        def complete(self, _sys, _user):
            time.sleep(0.3)
            return "분석 결과"

    class _Absent:
        name = "absent"

        def available(self):
            return False

        def complete(self, _sys, _user):
            raise AssertionError("불러선 안 된다")

    saved = (llm.ClaudeAdapter, llm.OllamaAdapter, egress._sem, egress.MAX_CONCURRENCY,
             egress.QUEUE_WAIT_S, egress.MAX_PER_HOUR, dict(egress._stats))
    llm.ClaudeAdapter, llm.OllamaAdapter = _Slow, _Absent
    egress.MAX_CONCURRENCY = 2
    egress._sem = threading.BoundedSemaphore(2)
    egress._stats.update({"inflight": 0, "peak_inflight": 0, "queue_timeouts": 0})
    try:
        # **절대값이 아니라 증가분으로 본다.** 앞선 검사가 같은 계수기를 쓰면 절대값
        # 비교는 검사 순서에 따라 깨진다(2026-08-13 질의 루프 검사 추가 시 발생).
        base_calls = egress.calls_last_hour()
        out = []
        ts = [threading.Thread(target=lambda: out.append(llm.triage_reply(ctx, "SEV3")))
              for _ in range(8)]
        for t in ts:
            t.start()
        for t in ts:
            t.join(timeout=20)
        assert len(out) == 8, len(out)
        assert all(not r["degraded"] for r in out), "상한을 걸어도 전부 성공해야"
        st = egress.stats()
        assert st["peak_inflight"] <= 2, f"동시 호출이 상한을 넘었다: {st}"
        assert st["peak_inflight"] >= 2, f"직렬로만 돌았다 — 상한 자체가 무의미: {st}"
        assert st["inflight"] == 0, st
        assert st["queue_timeouts"] == 0, st

        # 앞선 8건은 실제로 나갔으므로 예산을 쓴 것이 맞다. 아래에서 "안 나간 호출"만
        # 따로 보려면 창을 비우고 시작해야 한다.
        assert egress.calls_last_hour() - base_calls == 8, egress.calls_last_hour()
        egress._calls.clear()
        egress._by_kind.clear()

        # 자리를 못 잡으면 던지지 않고 열화로 내려간다 — 알림이 사라지면 안 된다
        egress.QUEUE_WAIT_S = 0.01
        egress._sem = threading.BoundedSemaphore(1)
        egress._sem.acquire()          # 자리를 미리 다 차지한다
        r = llm.triage_reply(ctx, "SEV3")
        assert r["degraded"] is True and r["provider"] == "none", r
        assert "대기를 포기" in r["text"], r["text"]
        assert "처음" in r["text"], "열화여도 코드 판정은 실어야"
        assert egress.stats()["queue_timeouts"] == 1, egress.stats()
        # 나가지도 않은 호출이 시간당 예산을 먹으면 안 된다. 예전에는 확인과 세기를
        # 같이 해서, 키가 만료된 채 200건이 들어오면 실제 호출 0건으로 상한에 닿았다.
        # 그리고 지표는 200건을 정상으로 썼다고 보고했다.
        assert egress.calls_last_hour() == 0, \
            f"대기 포기가 예산을 먹었다: {egress.calls_last_hour()}건"
        assert egress.kind_counts() == {}, egress.kind_counts()
        # 어댑터가 전멸해도 마찬가지다
        egress._sem = threading.BoundedSemaphore(2)

        class _Dead:
            name = "dead"

            def available(self):
                return True

            def complete(self, _s, _u):
                raise RuntimeError("죽었다")

        llm.ClaudeAdapter = _Dead
        dead = llm.triage_reply(ctx, "SEV3")
        assert dead["degraded"] is True, dead
        # 붙을 어댑터가 있었으므로 시도는 셌다. 실제로 나갔기 때문이다.
        assert egress.calls_last_hour() == 1, egress.calls_last_hour()
        llm.ClaudeAdapter = _Slow
        egress._calls.clear()
        egress._by_kind.clear()

        # 시간당 총량 — 동시 수를 눌러도 폭풍이 길게 이어지면 총량은 계속 는다.
        # 게이트가 아니라 여기서 세므로, 게이트 규칙이 몇 개든 구멍이 안 생긴다.
        egress._sem = threading.BoundedSemaphore(2)
        egress.QUEUE_WAIT_S = 5
        egress.MAX_PER_HOUR = 3
        egress._calls.clear()
        egress._stats["hour_blocked"] = 0
        assert [llm.triage_reply(ctx, "SEV3")["degraded"] for _ in range(3)] == [False] * 3
        blocked = llm.triage_reply(ctx, "SEV3")
        assert blocked["degraded"] is True, "상한을 넘겼는데 호출됐다"
        assert "1시간 호출이 상한" in blocked["text"], blocked["text"]
        assert egress.stats()["hour_blocked"] == 1, egress.stats()
        # 위중한 사건은 상한을 안 받는다 — 폭풍 때 정작 위중한 것이 막히면 사고가 커진다
        assert llm.triage_reply(ctx, "SEV1")["degraded"] is False, "SEV1 이 상한에 막혔다"
        # 1시간이 지나면 창이 비므로 다시 부른다
        egress._calls[:] = [t - 3601 for t in egress._calls]
        assert llm.triage_reply(ctx, "SEV3")["degraded"] is False, "1시간 뒤엔 회복해야"

        # 월간 리포트도 같은 출구를 지나야 한다. 예전에는 이 경로가 어댑터를 직접
        # 불러서 상한 밖에 있었고, 코드를 읽기 전까지 그 사실이 드러나지 않았다.
        # 나가는 길이 하나라는 것은 주장이 아니라 검사로 붙들어야 한다.
        egress._calls.clear()
        egress._by_kind.clear()
        r = llm.monthly_reply({"report.sev1": 1}, [{"host": "h1", "name": "n"}])
        assert r["degraded"] is False, r
        assert egress.kind_counts() == {"monthly": 1}, egress.kind_counts()
        # 총량이 차면 월간도 막힌다 — 위중 면제는 트리아지의 SEV1 에만 있다
        egress.MAX_PER_HOUR = 1
        r2 = llm.monthly_reply({"report.sev1": 1}, [])
        assert r2["degraded"] is True and "상한" in r2["text"], r2["text"]
        assert "집계 수치는 유효" in r2["text"], "리포트는 수치가 살아 있어야"

        # 출구를 우회하는 코드가 어디에도 없어야 한다. llm.py 만 검사하면 다른 파일에
        # 새 길이 나도 못 잡는다 — 월간 리포트에서 겪은 것이 바로 그 경우다.
        #
        # 그리고 철자 몇 개만 막으면 안 된다. 처음엔 `.complete(` 와 어댑터 반복문만
        # 봤는데, 심층조사는 `httpx.post(.../api/chat)` 으로 나가므로 그 그물에 안
        # 걸렸다. 지금은 LLM 으로 나가는 표현을 모아서 보고, **아직 못 옮긴 것은
        # 예외 목록에 이유와 함께 적게** 한다. 목록에 없는 새 경로가 생기면 실패한다.
        import glob
        import re
        # 파일 -> 왜 아직 출구 밖인가. 옮기면 여기서 지운다.
        KNOWN_OUTSIDE = {
            "latency_bench.py": "응답시간 실측 도구 — 출구를 거치면 상한·마스킹이 "
                                "측정값을 흐린다. 운영 경로가 아니다",
        }
        # 어댑터를 부르는 것은 출구만 한다.
        CALLS_ADAPTER = [(r"\.complete\s*\(", "어댑터 직접 호출"),
                         (r"^\s+for adapter in ", "어댑터 반복문")]
        # 공급자에 직접 말을 거는 것은 어댑터가 사는 곳(llm.py)만 한다.
        # Slack 은 chat.postMessage 라 `/api/chat` 로 잡으면 오검출된다. Ollama·Holmes 의
        # `/api/chat` 만 잡도록 뒤에 점이나 글자가 오면 제외한다.
        TALKS_PROVIDER = [(r"/api/chat(?![.\w])", "채팅 API"),
                          (r"/v1/messages", "Anthropic 메시지 API"),
                          (r"\banthropic\.", "Anthropic SDK")]
        # gateway/ 만 보면 그 바깥에 새 길이 나도 못 잡는다. bot/ 도 같이 본다 —
        # latency_bench.py 가 실제로 공급자를 직접 부르고 있었고, 이 검사는 그걸
        # 보지 못했다. "출구가 하나"라는 말의 범위를 좁게 잡으면 말만 남는다.
        here = os.path.dirname(__file__)
        files = (sorted(glob.glob(os.path.join(here, "*.py")))
                 + sorted(glob.glob(os.path.join(here, "..", "*.py"))))
        for f in files:
            base = os.path.basename(f)
            if base == "selftest.py":
                continue
            src = io.open(f, encoding="utf-8").read()
            hits = []
            if base != "egress.py":
                hits += [w for p, w in CALLS_ADAPTER if re.search(p, src, re.M)]
            # 어댑터가 사는 곳은 공급자에 직접 말을 걸어도 된다. 지금은 두 곳이다 —
            # llm.py(Claude·Ollama)와 holmes.py(심층조사). 둘 다 출구가 부른다.
            # proxy.py 는 상류로 그대로 중계하는 것이 일이라 공급자 주소를 쓴다.
            # app.py 는 그 경로를 라우팅만 한다.
            if base not in ("egress.py", "llm.py", "holmes.py", "proxy.py", "app.py"):
                hits += [w for p, w in TALKS_PROVIDER if re.search(p, src, re.M)]
            if base in KNOWN_OUTSIDE:
                assert hits, (f"{base} 가 예외 목록에 있는데 나가는 코드가 없다 — "
                              "옮겼으면 목록에서 지운다")
                continue
            assert not hits, (f"{base} 가 출구를 우회한다({', '.join(hits)}). "
                              "egress.call 로 보내거나, 못 옮기면 KNOWN_OUTSIDE 에 "
                              "이유를 적는다")
    finally:
        (llm.ClaudeAdapter, llm.OllamaAdapter, egress._sem, egress.MAX_CONCURRENCY,
         egress.QUEUE_WAIT_S, egress.MAX_PER_HOUR, restore) = saved
        egress._calls.clear()
        egress._stats.clear()
        egress._stats.update(restore)
    return 24


def _registry_checks() -> int:
    """호스트 명부 — 한 호스트의 사실이 한 곳에서 읽히는지.

    명부에 없는 호스트도 그대로 돌아야 한다. 명부는 식별이 아니라 성질을 담고,
    식별은 (감시 서버, 호스트명)이 이미 한다.
    """
    import importlib
    import os
    import tempfile

    from . import registry

    try:
        import yaml   # noqa: F401
    except ImportError:
        return 0   # 파서가 없으면 명부 기능 자체가 비활성 — 검사할 것이 없다

    d = tempfile.mkdtemp(prefix="registry-test-")
    path = os.path.join(d, "hosts.yml")
    with open(path, "w", encoding="utf-8") as f:
        f.write("""hosts:
  - name: node1
    source: zabbix-internal
    realm: internal
    loki: vm-target-001.novalocal
    wazuh: vm-target-001.novalocal
    logs: true
    security: true
  - name: cert-example.com
    realm: internal
    logs: false
    security: false
  - name: db01
    source: zabbix-msp
    realm: msp
""")
    saved = os.environ.get("HOST_REGISTRY_FILE")
    os.environ["HOST_REGISTRY_FILE"] = path
    try:
        importlib.reload(registry)
        assert registry.status()["entries"] == 3, registry.status()

        # 축마다 다른 이름을 쓸 수 있다
        assert registry.label("zabbix-internal", "node1", "logs") == "vm-target-001.novalocal"
        assert registry.label("zabbix-internal", "node1", "security") == "vm-target-001.novalocal"
        # 소스가 다르면 그 항목이 아니다 — 이름이 같아도 다른 기계일 수 있다
        assert registry.label("zabbix-msp", "node1", "logs") == ""

        # source 를 안 적은 항목은 어느 소스에서 와도 걸린다
        assert registry.axis_on("zabbix-internal", "cert-example.com", "logs") is False
        assert registry.axis_on("zabbix-msp", "cert-example.com", "security") is False
        # 명부에 없으면 모름 — 기존 규칙으로 넘어간다
        assert registry.axis_on("zabbix-internal", "무명호스트", "logs") is None

        # 감시 서버 절 — 알림이 온 곳에 되물어야 한다
        with open(path, "a", encoding="utf-8") as f:
            f.write("""sources:
  - name: zabbix-internal
    realm: internal
    url: http://internal:8080
    token_env: TOK_INTERNAL
  - name: zabbix-msp
    realm: msp
    url: http://msp:8080
    token_env: TOK_MSP
""")
        importlib.reload(registry)
        assert registry.status()["sources"] == 2, registry.status()
        assert registry.source_conf("zabbix-msp")["url"] == "http://msp:8080"
        assert registry.source_conf("없는서버") == {}

        from . import collector as _c
        os.environ["TOK_INTERNAL"] = "tok-a"
        os.environ["TOK_MSP"] = "tok-b"
        try:
            a = _c.ZabbixClient(source="zabbix-internal")
            b = _c.ZabbixClient(source="zabbix-msp")
            assert a.api == "http://internal:8080/api_jsonrpc.php", a.api
            assert b.api == "http://msp:8080/api_jsonrpc.php", b.api
            assert (a.token, b.token) == ("tok-a", "tok-b"), "서버마다 다른 토큰을 써야"
            # 명부에 없는 소스는 환경변수 하나로 떨어진다(감시 서버가 하나인 환경)
            os.environ["ZABBIX_URL"] = "http://only:8080"
            assert _c.ZabbixClient(source="모르는곳").api == "http://only:8080/api_jsonrpc.php"
        finally:
            for k in ("TOK_INTERNAL", "TOK_MSP", "ZABBIX_URL"):
                os.environ.pop(k, None)

        # 감시 서버 절의 영역이 호스트에 상속된다 — 호스트마다 안 적어도 된다
        assert registry.realm("zabbix-msp", "무명호스트", {}) == "msp"
        assert registry.source_names() == ["zabbix-internal", "zabbix-msp"]

        # 생존 신호도 서버마다 따로 센다. 한 곳만 세면 그 서버는 멀쩡한데 다른 서버의
        # 알림 경로가 끊긴 상태를 못 잡는다 — 판정이 절반만 도는 셈이다.
        from . import heartbeat as _hb
        b = _hb.Beat(interval_s=999)
        for src in ("zabbix-internal", "zabbix-msp", "zabbix-internal"):
            b.mark_alert(src)
        now = b.started_at + _hb.MIN_COMPARE_WINDOW_S + 60
        assert b.recent_alerts(now) == 3
        assert b.recent_alerts(now, source="zabbix-internal") == 2
        assert b.recent_alerts(now, source="zabbix-msp") == 1
        os.environ["ZABBIX_URL"] = "http://global:8080"
        os.environ["ZABBIX_TOKEN"] = "global-tok"
        try:
            # 명부에 적힌 서버인데 그 토큰이 비어 있으면 조회하지 않는다. 전역 토큰으로
            # 대신 찌르면 남의 서버 수치를 그 서버 것으로 기록하게 된다.
            assert _hb.zabbix_recent_events(600, source="zabbix-msp") is None
            v = b.values(now=now)
        finally:
            for k in ("ZABBIX_URL", "ZABBIX_TOKEN"):
                os.environ.pop(k, None)
        assert v["gateway.recent_alerts[zabbix-internal]"] == 2, v
        assert v["gateway.recent_alerts[zabbix-msp]"] == 1, v
        assert v["gateway.alerts"] == 3, v
        # 서버를 적었으면 뭉뚱그린 발행 측 수는 안 보낸다 — 서버별로 봐야 갈린다
        assert "gateway.zbx_events" not in v, v

        # 영역: 명부 > 환경변수 > 소스 그대로
        assert registry.realm("zabbix-msp", "db01", {}) == "msp"
        # 명부에 없는 소스만 환경변수로 떨어진다(우선순위: 명부 > 서버 절 > 환경변수 > 소스)
        assert registry.realm("옛소스", "무명", {"옛소스": "x"}) == "x"
        assert registry.realm("zabbix-internal", "무명", {"zabbix-internal": "x"}) == "internal",             "감시 서버 절이 환경변수보다 우선이어야"
        assert registry.realm("새소스", "무명", {}) == "새소스", "안 적으면 소스가 곧 영역"
    finally:
        if saved is None:
            os.environ.pop("HOST_REGISTRY_FILE", None)
        else:
            os.environ["HOST_REGISTRY_FILE"] = saved
        importlib.reload(registry)
        shutil.rmtree(d, ignore_errors=True)

    # 파일을 안 지정하면 비어 있고 조용하다 — 기존 환경은 그대로 돈다
    assert registry.status()["entries"] == 0
    assert registry.entry("zabbix-internal", "node1") == {}
    return 30


if __name__ == "__main__":
    main()
