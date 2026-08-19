"""검사에 공통으로 쓰는 것 — 사례 표, 가짜 클라이언트, 소스 읽기, assert 세기."""


import shutil


import time


from ..alerts import prejudge, router, severity


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


# 분류 사례 — 오분류는 병합·브리지를 조용히 실패시키므로 케이스를 넓게 잠근다 (§8)
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
    # 한글 알림명 — 클래스마다 한글 키워드가 고르지 않아 21/41 이 틀렸다
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
    # 실환경 90일 실측에서 미분류로 확인돼 보강한 것들 — 기존 분류를 뺏은 건은 0건이다
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


def _assert_count() -> int:
    """검사 파일들에 적힌 assert 문 수. 소스에서 세므로 손으로 못 어긋난다."""
    import ast
    import glob
    import io as _io
    import os as _os

    total = 0
    here = _os.path.dirname(_os.path.abspath(__file__))
    # 실행기(selftest.py)에도 사례 표를 도는 검사가 남아 있다. 같이 센다.
    paths = sorted(glob.glob(_os.path.join(here, "*.py")))
    paths.append(_os.path.join(_os.path.dirname(here), "selftest.py"))
    for path in paths:
        with _io.open(path, encoding="utf-8") as f:
            tree = ast.parse(f.read())
        total += sum(1 for n in ast.walk(tree) if isinstance(n, ast.Assert))
    return total


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


class _LiveZbx:
    source = "zabbix-internal"

    async def call(self, *a, **kw):
        return [{"hostid": "1"}]


def _read_source(rel: str) -> str:
    """`bot/` 아래 상대 경로로 소스를 읽는다.

    검사 파일이 `gateway/checks/` 로 한 단계 깊어졌으므로 그만큼 더 올라간다.
    """
    import io
    import os
    here = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    return io.open(os.path.join(here, rel), encoding="utf-8").read()


if __name__ == "__main__":
    main()
