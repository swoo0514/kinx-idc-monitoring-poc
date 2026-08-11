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
                + analyze_checks + beat_checks + flush_checks + registry_checks + idem_checks
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
        assert asyncio.run(collector._loki_logs("h", 0)) == ([], collector.SOURCE_DISABLED)
        assert asyncio.run(collector._wazuh_alerts("h", 0)) == ([], collector.SOURCE_DISABLED)
        os.environ["LOKI_URL"] = "http://127.0.0.1:1"
        assert asyncio.run(collector._loki_logs("", 0)) == ([], collector.SOURCE_UNAVAILABLE)

        # 로그 축이 없는 것이 정상인 호스트는 조회하지 않는다 — 인증서·리포트용 가상 호스트를
        # 이름 불일치로 보면 알림마다 분석이 돌고 상한을 먼저 소진한다.
        os.environ["LOG_AXIS_EXEMPT_HOSTS"] = "cert-*,report-*"
        try:
            assert collector.axis_exempt("cert-example.com", "logs") is True
            assert collector.axis_exempt("cert-example.com", "security") is True
            assert collector.axis_exempt("node1", "logs") is False
            assert asyncio.run(collector._loki_logs("x", 0, "cert-example.com")) \
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
            assert asyncio.run(collector._loki_logs("known-host", 0)) == ([], collector.SOURCE_OK)
            assert asyncio.run(collector._loki_logs("other", 0)) == ([], collector.SOURCE_UNMATCHED)
            assert asyncio.run(collector._wazuh_alerts("a", 0)) == ([], collector.SOURCE_UNMATCHED)
            collector.httpx = _FakeHttpx(known=[], wazuh_total=3)
            assert asyncio.run(collector._wazuh_alerts("a", 0)) == ([], collector.SOURCE_OK)
            # 확인 질의가 실패하면 판정할 수 없으므로 ok 로 내리지 않는다
            collector.httpx = _FakeHttpx(known=["known-host"], wazuh_total=0, fail_check=True)
            assert asyncio.run(collector._loki_logs("known-host", 0)) == ([], collector.SOURCE_UNAVAILABLE)
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
        from . import app as app_mod

        importlib.reload(app_mod)

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
        return 8
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
        assert egress.calls_last_hour() == 8, egress.calls_last_hour()
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
            "holmes.py": "심층조사는 별도 프로세스 API 호출 — 미해소(가이드 §21)",
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
            if base not in ("egress.py", "llm.py"):
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
