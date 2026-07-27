"""게이트웨이 순수 로직 셀프테스트 (fastapi 불필요 — severity/router만 검증).

실행: python -m gateway.selftest   (bot/ 디렉토리에서)
전부 통과하면 'ALL OK'를 출력한다. severity_map.md 표와의 일치가 검증 대상.
"""

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
              {"tag": "scope", "value": "notify_only"}], 1, "triage"),  # 계약이 조치 차단(A-6)
    ("SEV3", [], 1, "digest"),
    ("SEV4", [], 1, "dashboard_only"),
    ("NONE", [], 1, "drop"),
    ("SEV1", [], 0, "resolve"),       # 복구 이벤트
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
    j = prejudge.judge([], now=now)
    assert j["verdict"] == "신규" and j["count_window"] == 0, j
    j = prejudge.judge([now - 2 * day, now - 30 * day], now=now)
    assert j["verdict"] == "재발" and j["count_window"] == 2 and j["last_seen_days"] == 2.0, j
    j = prejudge.judge([now - i * 10 * day for i in range(1, 7)], now=now)
    assert j["verdict"] == "만성" and j["count_window"] == 6, j
    j = prejudge.judge([now - 120 * day], now=now)     # 창(90일) 밖 이력은 무시 → 신규
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
        "security": [{"level": 10, "desc": "brute force on lab-web01", "ts": "t"}],
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
    assert mk.unmask(mk.mask("lab-web01 at 192.0.2.5")) == "lab-web01 at 192.0.2.5"
    masking_checks = 7

    # 열화 모드 — LLM 어댑터 전멸 시 선판정만으로 회신 (외부 호출 0)
    for k in ("ANTHROPIC_API_KEY", "OLLAMA_URL"):
        os.environ.pop(k, None)
    reply = llm.triage_reply(ctx, "SEV2")
    assert reply["degraded"] and reply["provider"] == "none" and "신규" in reply["text"], reply
    degraded_checks = 1

    if fails:
        raise SystemExit(f"{fails} case(s) failed")
    total = (len(CASES_SEVERITY) + len(CASES_ROUTER) + 2 + prejudge_checks + 1
             + masking_checks + degraded_checks)
    print(f"ALL OK ({total} checks)")


if __name__ == "__main__":
    main()
