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
    prejudge_checks = 4

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
    analyze_checks = _analyze_ref_checks()
    beat_checks = _heartbeat_checks()
    flush_checks = _flush_checks()

    if fails:
        raise SystemExit(f"{fails} case(s) failed")
    total = (len(CASES_SEVERITY) + len(CASES_ROUTER) + 2 + prejudge_checks + 1
             + masking_checks + degraded_checks + incident_checks + source_checks
             + remediation_checks + holmes_checks + fastpath_checks + open_link_checks + site_kw_checks + class_tag_checks
             + class_map_checks + pending_checks + analyze_checks + beat_checks + flush_checks)
    print(f"ALL OK ({total} checks)")


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

    saved = {k: os.environ.pop(k, None) for k in ("LOKI_URL", "WAZUH_INDEXER_URL")}
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

    # 보수적 발동에도 상한이 있어야 한다 — 인덱서가 하루 죽으면 전 알림이 LLM 으로 간다
    for q in incident._fires.values():
        q.clear()
    fired_n = sum(1 for _ in range(incident.GATE_DEGRADED_MAX_PER_HOUR + 5)
                  if incident.should_triage(single, fail_ctx, now=500.0)[0])
    assert fired_n == incident.GATE_DEGRADED_MAX_PER_HOUR, fired_n
    assert incident.should_triage(single, fail_ctx, now=500.0 + 3601)[0] is True, "1시간 뒤엔 회복"
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

    # 시간당 상한 — 새 트리거가 다수 호스트에 한꺼번에 붙으면 발동이 폭주한다
    incident._fires["new"].clear()
    fired_n = sum(1 for _ in range(incident.GATE_NEW_MAX_PER_HOUR + 5)
                  if incident.should_triage(single, new_ctx, now=1000.0)[0])
    assert fired_n == incident.GATE_NEW_MAX_PER_HOUR, fired_n
    assert incident.should_triage(single, new_ctx, now=1000.0 + 3601)[0] is True, "1시간 뒤엔 회복"
    # 예산은 사유별로 따로 — 신규가 다 써도 조회 실패는 여전히 발동해야 한다
    assert incident.should_triage(single, fail_ctx, now=1000.0)[0] is True, "예산이 섞였다"
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
        return 6
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
    from . import incident, masking

    n = 0
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

    saved = {k: os.environ.get(k) for k in ("HOLMES_ENABLED", "HOLMES_MASKED")}
    os.environ["HOLMES_ENABLED"] = "1"
    os.environ.pop("HOLMES_MASKED", None)
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
        # MSP 는 마스킹 없으면 신규여도 금지 (테넌트 경계가 우선)
        assert holmes.should_investigate("SEV2", False, ["zabbix-msp"], verdict="신규")[0] is False

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
    import json
    import os

    from . import incident, llm, masking

    # 분류 — 표준 템플릿·랩 실측 알림명 전수
    for name, expected in CASES_CLASSIFY:
        got = incident.classify(name)
        assert got == expected, f"classify({name!r}) -> {got}, expected {expected}"

    # memory_pressure 는 어떤 브리지에도 속하지 않는다 — 자원 경합(swap→iowait)과 OOM→서비스
    # 정지 양쪽에 인과 후보가 걸치는데 그룹은 겹칠 수 없고, 실측 근거도 아직 없다(P0-3 판정).
    assert (incident.incident_key("h1", "memory_pressure")
            != incident.incident_key("h1", "cpu_io_pressure"))
    assert (incident.incident_key("h1", "memory_pressure")
            != incident.incident_key("h1", "service_down"))

    # 브리지 그룹은 서로 겹치면 안 된다 — 겹치면 뒤 그룹이 死코드가 되므로 import 때 막는다
    try:
        incident._validate_bridges([frozenset({"a", "b"}), frozenset({"b", "c"})])
        raise AssertionError("겹치는 브리지 그룹을 검출하지 못했다")
    except ValueError:
        pass

    # 브리지 — replication + cpu_io_pressure 는 같은 키, auth_security 는 분리
    k_repl = incident.incident_key("h1", "replication")
    k_io = incident.incident_key("h1", "cpu_io_pressure")
    k_sec = incident.incident_key("h1", "auth_security")
    assert k_repl == k_io, (k_repl, k_io)
    assert k_sec != k_repl
    assert incident.incident_key("h2", "replication") != k_repl   # 호스트 다르면 분리

    # 브리지 2번 그룹 — 디스크 포화 + 서비스 정지 = 한 사건 (데모 B), 1번 그룹과는 분리
    k_disk = incident.incident_key("h1", "disk_space")
    k_svc = incident.incident_key("h1", "service_down")
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
    return 25 + len(CASES_CLASSIFY) + gate_checks


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
    finally:
        pending.PATH, pending.MAX_REPLAY = saved_path, saved_max
        shutil.rmtree(d, ignore_errors=True)
    return 10


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
            conn.sendall(b"ZBXD" + struct.pack("<II", len(res), 0) + res)

    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]
    t = threading.Thread(target=fake_server, args=(srv,), daemon=True)
    t.start()

    saved = {k: os.environ.get(k) for k in
             ("HEARTBEAT_ZABBIX_SERVER", "HEARTBEAT_ZABBIX_PORT", "HEARTBEAT_HOST")}
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
        assert got["head"][:5] == b"ZBXD", got.get("head")
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
    # 키의 유형 자리는 브리지 식별자로 접히므로 호스트로 확인한다
    assert sorted(k[0] for k in closed) == ["h1", "h2"], closed

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


if __name__ == "__main__":
    main()
