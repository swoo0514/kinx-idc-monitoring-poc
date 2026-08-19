"""알림 경로 검사 — 심각도·병합·수집·조치."""

import logging
import asyncio
import importlib
import json
import os
import shutil
import tempfile
import threading
import time

from .common import CASES_CLASSIFY, _FakeHttpx, _LiveZbx
from .. import egress, llm, masking, registry
from ..alerts import collector, incident, pending, prejudge, router, triage
from ..integrations import holmes, keep, slack
log = logging.getLogger("gateway.selftest")




def _source_status_checks() -> int:
    """G1 — "조회 실패"와 "신호 없음"의 구분이 수집기·게이트·마스킹·카드까지 전파되는지."""
    import asyncio
    import os

    from .. import llm, masking
    from ..alerts import collector, incident
    from ..integrations import slack

    # 축 면제·명부도 같이 지운다 — 우선순위가 위쪽부터라 남으면 아래 검사가 무너진다
    saved = {k: os.environ.pop(k, None) for k in
             ("LOKI_URL", "WAZUH_INDEXER_URL", "LOGS_EXEMPT_HOSTS",
              "SECURITY_EXEMPT_HOSTS", "LOG_AXIS_EXEMPT_HOSTS", "HOST_REGISTRY_FILE")}
    try:
        # 미배선(URL 없음) = disabled, 호스트 라벨 미해석 = unavailable (성공이 아니다)
        assert asyncio.run(collector._loki_logs("h", 0))[:2] == ([], collector.SOURCE_DISABLED)
        assert asyncio.run(collector._wazuh_alerts("h", 0)) == ([], collector.SOURCE_DISABLED)
        os.environ["LOKI_URL"] = "http://127.0.0.1:1"
        assert asyncio.run(collector._loki_logs("", 0))[:2] == ([], collector.SOURCE_UNAVAILABLE)

        # 로그 축이 없는 것이 정상인 가상 호스트는 조회하지 않는다
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

        # dns 칸에 컨테이너 이름이 있으면 쓰지 않는다 — 여러 호스트가 같은 이름을 가진다
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

    # 절단은 조회한 쪽이 알려 준다 — 받는 쪽이 개수로 추측하면 영원히 안 걸린다
    many = [1000.0 - i for i in range(199)]
    assert prejudge.judge(many, now=1000.0, listed_truncated=True)["count_truncated"] is True
    assert prejudge.judge(many, now=1000.0, listed_truncated=False)["count_truncated"] is False
    # 개수를 받았으면 절단이 아니다 — 목록이 잘렸어도 총계는 정확하다
    assert prejudge.judge(many, now=1000.0, total_count=5000,
                          listed_truncated=True)["count_truncated"] is False

    # 사유별 수치는 통제가 아니라 관측 — 게이트는 몇 번이 오든 판단을 바꾸지 않는다
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

    # 사유는 섞이지 않아야 한다 — 섞이면 무엇을 고쳐야 할지 알 수 없다
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
    # 축을 늘리면 프롬프트도 같이 늘어야 한다 — 안 그러면 빈 값이 "이상 없음"이 된다
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

    from ..alerts import incident as inc_mod

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

        # 배선 검사 — 함수가 맞게 도는 것과 그 함수가 불리는 것은 다른 문제다
        import shutil
        import tempfile

        from .. import app as app_mod
        from ..alerts import pending

        importlib.reload(app_mod)
        # 실제 triage 경로를 태우므로 대기 파일에 쓴다 — 운영 서버면 검사 기록이 되살아난다
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
        return 24
    finally:
        os.unlink(path)
        if saved is None:
            os.environ.pop("INCIDENT_CLASS_FILE", None)
        else:
            os.environ["INCIDENT_CLASS_FILE"] = saved
        importlib.reload(inc_mod)




def _class_tag_checks() -> int:
    """선언 태그 이름이 벤더 표준과 충돌하지 않는지."""
    from ..alerts import incident

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
    """사이트 고유 키워드가 코드가 아니라 환경변수로 들어오는지."""
    import importlib
    import os

    from ..alerts import incident as inc_mod

    saved = os.environ.get("SITE_CLASS_KEYWORDS")
    # 배포 서버에 든 값을 지우고 돌린다 — 안 그러면 설정 문제인지 코드 문제인지 모른다
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
    """열린 문제 연계 — 규칙 매칭·경과 필터·마스킹 누수·상태 계약."""
    import importlib
    import os

    from .. import masking
    from ..alerts import incident

    n = 0
    # 측정 파일이 없으면 연계를 끈다 — 예시값이 "측정된 값"으로 모델에 갔다
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

    # 값이 아니라 기제를 검사한다 — 규칙은 검사하는 동안만 아는 것으로 바꿔 끼운다
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
    from .. import masking
    from ..alerts import incident

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

    # 장기 미해소는 선행 원인이 아니라 방치 항목 — 지우지 않고 표시한다
    import asyncio

    from ..alerts import collector
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
    # 이미 그 유형이 있으면 선행이 아니라 같은 문제의 다른 임계 트리거다
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

    from .. import app as gw_app
    from ..integrations import keep
    from ..alerts import router

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
            from ..integrations import slack
            # 채널 미설정이면 메인 채널로 흘려보내지 않고 게시를 건너뛴다
            assert slack.post_digest("n", "SEV3", "h1") == {"ok": False, "skipped": True}
            gw_app._queue_low_severity("h1", "디스크 사용률 82%", "SEV3", "disk_space", True)
            gw_app._queue_low_severity("h1", "메모리 사용률 70%", "SEV4", "memory_pressure", False)
        finally:
            if saved_digest is not None:
                os.environ["SLACK_CHANNEL_ID_DIGEST"] = saved_digest

        # G5 — 게이트에서 걸러진 사건도 Keep 에 남긴다(분석 없이 판정·유형만)
        from ..alerts import incident, triage
        inc = incident.Incident(
            key=("h1", "disk_space"), host="h1", opened_at=0.0, last_at=0.0,
            alerts=[incident.Alert(source="zabbix-internal", event_id="e", trigger_id="1",
                                   host="h1", alert_name="디스크 사용률 92%", sev="SEV2",
                                   incident_class="disk_space", recv=0.0)])
        ctx = {"alerts": [{"prejudge": {"verdict": "만성"}}]}
        assert triage._push_gated(inc, ctx, "단일 축·교차 신호 없음") == \
            {"ok": False, "skipped": True}

        # 근거 축 기록 — 비면 월간 리포트의 "로그를 근거로 판단한 사건 수"가 0이 된다
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

    from ..alerts import incident

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
        # 거의 동시에 도착시킨다 — 잠금이 없으면 두 번째 알림의 답글이 사라진다
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

    from ..integrations import holmes
    from ..alerts import incident

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
        # 차단이 기본이어야 한다 — 옛 플래그는 이름과 달리 차단만 풀었고 기본값이 1이었다
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
        # 심층조사가 호스트명을 원문으로 보낸다는 사실을 고정한다 — 마스킹이 붙으면 깨진다
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

        # 조사 질문이 "무슨 사건인지"를 담는가 — 안 담으면 무관한 문제를 조사한다
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

    from .. import llm, masking
    from ..alerts import incident

    # 분류 사례는 배포 서버의 선언 파일에 영향받는다 — 지우고 돌린다
    _env_saved = {k: os.environ.pop(k, None)
                  for k in ("INCIDENT_CLASS_FILE", "SITE_CLASS_KEYWORDS")}
    incident = importlib.reload(incident)

    # 분류 — 표준 템플릿·랩 실측 알림명 전수
    for name, expected in CASES_CLASSIFY:
        got = incident.classify(name)
        assert got == expected, f"classify({name!r}) -> {got}, expected {expected}"

    # memory_pressure 는 어떤 브리지에도 안 든다 — 양쪽에 걸치는데 그룹은 겹칠 수 없다
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

    # 브리지 2번 그룹 — 디스크 포화 + 서비스 정지 = 한 사건 (데모 B)
    # 감시 서버가 둘이면 이름이 겹친다 — 이름은 감시 서버 안에서만 유일하다
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

    # 매핑을 안 적어도 소스가 다르면 갈라진다 — 모르면 나뉘는 쪽으로 틀려야 한다
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
    """중복 판정 — 여러 스레드가 동시에 들어와도 한 번만 통과해야 한다."""
    import threading
    import time

    from .. import app as app_mod

    # 확인과 등록 사이의 틈을 강제로 벌린다 — 안 그러면 잠금 없이도 우연히 통과한다
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
    """선행 문제 조회가 상한에 걸렸을 때 "없음" 으로 단언하지 않는가."""
    import asyncio

    from ..alerts import collector

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
    """로그·보안 조회 창을 **사건이 난 시각** 기준으로 잡는가."""
    import os
    import time as _t

    from ..alerts import collector, incident as inc_mod

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

    # 감시 서버가 돌려준 이벤트 시각이 가장 정확하고 발송 설정과 무관하게 온다
    assert collector.reference_time(no_clock, now, [now - 5400]) == now - 5400
    # 둘 다 있으면 이른 쪽을 쓴다 — 사건이 시작된 시점이 기준이다
    assert collector.reference_time(old_inc, now, [now - 9000]) == now - 9000

    # 지금으로 떨어진 사실이 드러나야 한다 — 사건 없는 시간대를 보고 "신호 없음"이 된다
    assert hasattr(collector, "reference_guessed"), \
        "창 기준을 지금으로 떨어뜨린 사실을 알릴 방법이 없다"
    assert collector.reference_guessed(no_clock, now, []) is True
    assert collector.reference_guessed(old_inc, now, []) is False

    # 배선 — 웹훅이 받은 시각이 알림과 대기 기록까지 이어져야 한다
    import importlib
    import shutil
    import tempfile

    from .. import app as app_mod
    from ..alerts import pending

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
    """명부를 못 읽었을 때 남의 감시 서버에 되묻지 않는가."""
    import importlib
    import os

    from .. import registry
    from ..alerts import collector

    saved = {k: os.environ.get(k) for k in ("HOST_REGISTRY_FILE", "ZABBIX_URL",
                                            "ZABBIX_TOKEN")}
    os.environ["HOST_REGISTRY_FILE"] = os.path.join(os.path.dirname(__file__),
                                                    "없는-명부.yml")
    os.environ["ZABBIX_URL"] = "http://내부:8080"
    os.environ["ZABBIX_TOKEN"] = "내부토큰"
    try:
        importlib.reload(registry)
        assert registry.status()["error"], "명부 로드 실패를 만들지 못했다"
        # 명부를 못 읽었으면 소스 지정 조회를 막는다 — 남의 서버에 묻게 된다
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
    """Zabbix 수집이 전부 실패했을 때 그 사실이 밖으로 드러나는가."""
    import asyncio
    import time as _t

    from ..alerts import collector, incident as inc_mod

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
    from .. import masking
    from ..integrations import slack
    note = slack._source_note(ctx["sources"])
    assert "지표" in note, f"카드에 Zabbix 축 실패가 안 보인다: {note!r}"
    # 전송 화이트리스트에도 있어야 LLM 이 그 상태를 읽는다
    assert "metrics" in masking._STATUS_KEYS, masking._STATUS_KEYS

    # 사유가 로그에 남아야 한다 — JSON-RPC 는 오류도 200 이라 접근 로그엔 성공만 찍힌다
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

    # 사건이 나기 전에 알아야 한다 — 기동 때 한 번 확인한다
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




def _contract_checks() -> int:
    """위탁 계약 제약이 분석 문장까지 가는가 (§2-3-3)."""
    import json
    import time as _t

    from .. import app as gw_app, llm, masking
    from ..alerts import incident as inc_mod

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

    from ..alerts import pending
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
    """회신에 파괴적 복구 명령이 섞이면 사람에게 표시가 붙는가."""
    from .. import llm

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

    # 프롬프트에도 금지가 적혀 있어야 한다 — 코드 표시는 사후다
    assert "RESET SLAVE" in llm.TRIAGE_SYSTEM, "프롬프트에 금지 항목이 없다"
    return 15




def _truncation_checks() -> int:
    """자른 것을 자랐다고 말하는가 (§1-1-8)."""
    import asyncio
    import json
    import os

    from .. import llm, masking
    from ..alerts import collector

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

        # 전송 제동은 줄 수가 아니라 글자 수로 건다 — 줄 수는 안전망으로만 남긴다
        assert collector.LOKI_FETCH_LIMIT >= collector.LOKI_SEND_LIMIT
        assert collector.LOKI_SEND_BYTES > 0

        # 표시를 쪼갠다 — 한 불리언에 두 사실을 실으면 같은 문제가 이름만 바꿔 재발한다
        collector.httpx = _Fake(["line %d" % i for i in range(120)])
        recs, _s, capped, _c = asyncio.run(collector._loki_logs("h1", 1700000000))
        assert len(recs) == 120 and capped is False, (len(recs), capped)

        collector.httpx = _Fake(["x %d" % i for i in range(collector.LOKI_FETCH_LIMIT)])
        recs, _s, capped, _c = asyncio.run(collector._loki_logs("h1", 1700000000))
        assert capped is True, capped

        # 바이트 예산 — 긴 줄이면 300줄이 수 MB 가 되고 파싱이 루프를 막는다
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

    from ..alerts import collector as c

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

    # 완전히 같은 줄이 같은 초에 여러 개여도 상한을 넘지 않는다
    dup = [_r(1.0, "INFO steady") for _ in range(100)]
    dup += [_r(500.0, "ERROR upstream refused connection") for _ in range(200)]
    picked = c.select_logs(dup)
    body = [r for r in picked if "line" in r]
    assert len(body) <= c.LOKI_SEND_LIMIT, "상한을 넘었다: %d" % len(body)
    same = [r for r in body if "upstream refused" in r["line"]]
    assert len(same) <= c.SAME_SHAPE_MAX, "같은 형태가 %d줄" % len(same)

    # 첫 오류 직전은 오류에 가까운 쪽을 고른다 — 몫 선별은 예산을 넘을 때만 돈다
    seq2 = [_r(i, "INFO steady %d" % i) for i in range(200)]
    seq2 += [_r(300 + i, "ERROR boom %d" % i) for i in range(20)]
    picked = c.select_logs(seq2, limit=40)
    pre = [r["t"] for r in picked if r.get("why") == "pre"]
    assert pre and max(pre) >= 190, "오류에서 먼 쪽만 골랐다: %s" % sorted(pre)[:3]

    # 접기가 먼저고 선별은 예산을 넘을 때만 — 평상시 창에서 몫이 등장하면 실패다
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

    # alert·critical 은 이 환경의 일상 어휘라 맨낱말로 잡으면 자기 로그가 오류가 된다
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
    # 시각 형식이 ISO 만이 아니다 — 슬래시 날짜 때문에 반복 접기가 통째로 죽었다
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

    # 생략 구간을 표시한다 — 안 하면 모델이 인접성에서 인과를 만든다
    # 두 형태를 번갈아 넣어 생략 구간이 여러 곳에 생기게 한다
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
    from .. import llm, masking
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




def _holmes_egress_checks() -> int:
    """심층조사도 출구를 지나는가."""
    import os
    import threading

    from .. import egress
    from ..integrations import holmes

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
    """창이 닫힐 때 마감 처리가 끝까지 도는가."""
    import asyncio
    import time as _t

    from ..alerts import incident as inc_mod

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
    """창 안에 알림이 상한을 넘겼을 때 넘친 것이 어떻게 되는가."""
    import asyncio
    import os
    import shutil
    import tempfile
    import time as _t

    from ..alerts import incident, pending

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




def _analyze_ref_checks() -> int:
    """사람이 요청하는 분석 — 카드에 실은 재료로 사건이 되살아나는지."""
    import os
    import sys
    import time

    from ..alerts import incident, triage

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
