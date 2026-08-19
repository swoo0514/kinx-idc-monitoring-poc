"""이름 가림과 반출 경계 검사.

원본은 `selftest.py` 한 파일(6,801줄)이었다. 2026-08-19 에 영역별로
나눴고 검사 내용은 그대로다.
"""

import logging
import asyncio
import json
import os
import re
import subprocess
import tempfile
import time

from .. import collector, egress, heartbeat, llm, masking, nametable, proxy, registry
log = logging.getLogger("gateway.selftest")




def _nametable_checks() -> int:
    """전역 이름 표 — 경계 일치·대소문자·긴 것 우선.

    지금 마스킹은 그 사건의 호스트 정보에서 이름을 뽑아 등록한다. 그래서 사건 당사자가
    아닌 호스트명은 안 가려진다. 로그 한 줄에 다른 서버 이름이 섞이면 원문 그대로 나간다.

    표로 잡되 두 가지를 지켜야 한다. 등록되지 않은 더 긴 문자열 안에서는 바뀌면 안 되고
    (db01 이 mydb01 안에서), 대소문자가 달라도 잡아야 한다(DB01). 선례는 Presidio 의
    금지 목록 인식기로, 경계 lookaround 와 대소문자 무시를 쓴다.
    """
    import json

    from .. import masking

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
    from .. import nametable
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





def _registry_fill_checks() -> int:
    """명부가 이름의 주인 노릇을 하는가.

    지금은 세 시스템의 이름을 **살아 있는 조회로 추측**한다. 인터페이스 목록을 훑어 점이
    든 첫 dns 를 고른다. 추측이라 틀릴 수 있고 조회가 실패하면 빈다. 그 세 이름이
    확정되는 순간은 따로 있다 — Ansible 이 세 에이전트에 같은 FQDN 을 심는 때다.

    읽는 쪽(`_resolve_label` → `registry.label`)은 이미 있다. 여기서는 **명부가 인터페이스
    추측을 실제로 이기는지**와 **중복 항목이 조용히 사라지지 않는지**를 잠근다.
    """
    import logging

    from .. import collector, registry

    saved = list(registry._ENTRIES)
    try:
        # ① 명부가 이기면 인터페이스를 안 본다. 둘이 다를 때가 진짜 시험이다.
        registry._ENTRIES = [{"name": "node1", "source": "zabbix-internal",
                              "loki": "vm-target-001.novalocal",
                              "wazuh": "vm-target-001.novalocal"}]
        host_obj = {"interfaces": [{"dns": "node1.mgmt.local"}]}
        got = collector._resolve_label("node1", host_obj, "zabbix-internal", "logs")
        assert got == "vm-target-001.novalocal", got
        assert collector._resolve_label("node1", host_obj, "zabbix-internal",
                                        "security") == "vm-target-001.novalocal"

        # ①-b **추측이 갈릴 때는 조용히 넘어가지 않는다.** FQDN 이 둘이면 어느 쪽이 그
        #      축의 이름인지 고를 근거가 없다. 관리망 쪽이 먼저 오면 로그가 0줄이 되고
        #      사람은 "로그 없음" 으로 읽는다.
        two = {"interfaces": [{"dns": "node1.mgmt.local"}, {"dns": "node1.svc.local"}]}
        seen = []
        saved_warn = collector.log.warning
        try:
            collector.log.warning = lambda *a, **k: seen.append(a[0] if a else "")
            collector._resolve_label("node9", two, "zabbix-internal", "logs")
        finally:
            collector.log.warning = saved_warn
        assert seen, "FQDN 이 둘인데 아무 말도 안 했다"

        # ② 명부에 없으면 예전 경로로 떨어진다. 등록 안 된 호스트도 돌아야 한다.
        got = collector._resolve_label("node9", host_obj, "zabbix-internal", "logs")
        assert got == "node1.mgmt.local", got

        # ③ **같은 이름을 두 줄 적으면 알린다.** 지금은 뒷줄이 조용히 무시된다.
        registry._ENTRIES = [
            {"name": "node1", "source": "zabbix-internal", "loki": "a"},
            {"name": "node1", "source": "zabbix-internal", "loki": "b"},
        ]
        assert registry.duplicates() == [("zabbix-internal", "node1")],             registry.duplicates()
        registry._ENTRIES = [{"name": "node1", "source": "zabbix-internal"}]
        assert registry.duplicates() == []

        # ④ **명부 파일을 실제로 적재해 본다.** `_ENTRIES` 를 직접 넣는 검사만 있으면
        #    적재 경로가 한 번도 안 지나간다. 2026-08-18 에 그 안에서 이름 오류가 났는데
        #    검사는 전부 통과했다.
        import os
        import tempfile
        d = tempfile.mkdtemp(prefix="reg-")
        path = os.path.join(d, "hosts.yml")
        with open(path, "w", encoding="utf-8") as f:
            f.write("hosts:" + chr(10))
            f.write("  - name: node1" + chr(10))
            f.write("    source: zabbix-internal" + chr(10))
            f.write("    loki: vm-a.example" + chr(10))
        saved_path = registry.PATH
        try:
            registry.PATH = path
            registry._load()
            assert registry.status()["error"] == "", registry.status()
            assert registry.label("zabbix-internal", "node1", "logs") == "vm-a.example"
        finally:
            registry.PATH = saved_path
            registry._load()

        # ⑤ **불러오는 순간에 적재가 성공하는가.** 모듈을 새로 불러야 보인다. 위 검사는
        #    이미 불러온 모듈에서 `_load()` 를 다시 부르므로 임포트 시점 오류를 못 본다.
        import subprocess
        import sys as _sys
        code = ("import os,sys;os.environ['HOST_REGISTRY_FILE']=%r;"
                "sys.path.insert(0,%r);"
                "from gateway import registry;"
                "e=registry.status()['error'];"
                "print('ERR:'+e if e else 'OK')" % (path, os.getcwd()))
        r = subprocess.run([_sys.executable, "-c", code], capture_output=True, text=True)
        assert "OK" in (r.stdout or ""), (r.stdout, r.stderr[-300:])
    finally:
        registry._ENTRIES = saved
    return 6





def _proxy_gate_checks() -> int:
    """마스킹을 보장 못 할 때 무엇이 나가는가.

    지금은 **호출자가 스스로 적은** `metadata.user_id` 가 "msp" 로 시작할 때만 막았다.
    고객사 도구가 `customer-msp-01` 로 적으면 통과하고, 사내 사용자 `mspark` 는 막히며,
    같은 앱의 질의 경로는 "호출자가 신고한 값은 쓰지 않는다" 를 지킨다. 원칙이 갈렸다.
    """
    import os

    from .. import proxy

    saved = os.environ.get("PROXY_ALLOW_UNMASKED")
    try:
        os.environ.pop("PROXY_ALLOW_UNMASKED", None)
        # ① 기본은 차단이다. 호출자가 무엇을 적었든 상관없다.
        assert proxy.blocked_when_empty() is True
        # ② 운영자가 파일에 적으면 통과한다. 호출자의 주장이 아니다.
        os.environ["PROXY_ALLOW_UNMASKED"] = "1"
        assert proxy.blocked_when_empty() is False
        os.environ["PROXY_ALLOW_UNMASKED"] = "0"
        assert proxy.blocked_when_empty() is True
    finally:
        if saved is None:
            os.environ.pop("PROXY_ALLOW_UNMASKED", None)
        else:
            os.environ["PROXY_ALLOW_UNMASKED"] = saved

    # ③ 호출자가 적은 값은 판정에 안 쓴다. 함수 서명에서 사라져야 한다.
    import inspect
    src = inspect.getsource(proxy.handle)
    assert "tenant_scoped" not in src, "호출자 신고 값이 아직 판정에 쓰인다"
    return 6




def _model_kind_wiring_checks() -> int:
    """용도별 모델 등급이 **호출부까지** 배선돼 있는가.

    매핑에는 `"triage": "LLM_MODEL_INVESTIGATE"` 가 있는데 호출부가 용도를 안 넘겨
    기본 모델로 떨어졌다(2026-08-19 감사 F-5). 함수 단위 단언만 있으면 이런 누락이
    통과한다 — 매핑은 맞고 호출부만 틀렸기 때문이다. 그래서 호출부를 지나며 본다.
    """
    import os

    from .. import egress, llm

    saved_env = os.environ.get("LLM_MODEL_INVESTIGATE")
    saved_call = egress.call
    seen = {}
    try:
        os.environ["LLM_MODEL_INVESTIGATE"] = "모델-조사용"

        def spy(adapters, system, user, exempt=False, kind=""):
            seen["model"] = getattr(adapters[0], "model", "")
            seen["kind"] = kind
            return {"degraded": True, "text": "", "reason": "test"}

        egress.call = spy
        llm.triage_reply({"host": {"name": "h"}}, "SEV2")
        assert seen.get("kind") == "triage", seen
        assert seen.get("model") == "모델-조사용", seen
    finally:
        egress.call = saved_call
        if saved_env is None:
            os.environ.pop("LLM_MODEL_INVESTIGATE", None)
        else:
            os.environ["LLM_MODEL_INVESTIGATE"] = saved_env
    return 2




def _nametable_freshness_checks() -> int:
    """이름 표가 얼어붙은 것을 밖에서 볼 수 있는가.

    갱신 스레드는 예외를 삼키고 계속 돌며, 전건 실패가 이어져도 직전 표를 그대로 쓴다.
    조회 토큰이 만료되면 표가 그 시점에 멈추고 로그에만 오류가 쌓인다. 그 사이 온보딩한
    호스트는 표에 영영 없고, 질의 경로가 그 이름을 원문으로 내보낸다. **아무 지표도
    안 움직여 발견 계기가 없다**(2026-08-19 감사 E-9). 감시자를 감시한다는 이 프로젝트의
    진단이 게이트웨이 자신에게 그대로 되돌아온 자리다.
    """
    import time

    from .. import app as gw
    from .. import heartbeat, nametable

    saved = (dict(nametable._terms), nametable._built_at, nametable._error)
    try:
        nametable._terms = {"a": "host", "b": "group"}
        nametable._built_at = time.time() - 3 * 3600
        nametable._error = ""
        v = heartbeat.Beat().values()
        assert v["gateway.names"] == 2, v
        # 나이를 초로 싣는다. "3시간 넘게 안 갱신" 같은 판단을 Zabbix 쪽에서 한다.
        assert 3 * 3600 - 5 <= v["gateway.names_age"] <= 3 * 3600 + 5, v
        assert v["gateway.names_error"] == 0, v

        # 갱신이 실패하고 있으면 그것도 숫자로 나간다. 로그만 남으면 아무도 안 본다.
        nametable._error = "토큰 만료"
        assert heartbeat.Beat().values()["gateway.names_error"] == 1

        # 한 번도 못 만들었으면 나이를 지어내지 않는다.
        nametable._built_at = 0.0
        v2 = heartbeat.Beat().values()
        assert v2["gateway.names_age"] == -1, v2

        # /healthz 로도 본다. 사람이 가장 먼저 여는 곳이다.
        h = gw.healthz()
        assert h["names"] == 2 and h["names_error"] is True, h
    finally:
        nametable._terms, nametable._built_at, nametable._error = saved
    return 7




def _token_scope_checks() -> int:
    """질의용 토큰으로 웹훅과 LLM 중계를 부를 수 없는가.

    화면은 Grafana 데이터소스 프록시를 거쳐 게이트웨이를 부른다. 그 프록시는 선언된
    경로의 **하위 경로를 전부 통과시킨다.** 2026-08-19 랩 실측으로 Viewer 권한 계정이
    `/webhook/zabbix` 를 부르면 핸들러까지 닿았고(422), `/v1/messages` 는 회사 키로
    실제 답을 받았다(200). 토큰이 하나뿐이라 용도를 가릴 수 없었다.

    질의용 토큰은 `/ask*` 만 연다. 웹훅과 중계는 게이트웨이 토큰만 받는다.
    """
    import os

    from .. import app as gw

    saved = {k: os.environ.get(k) for k in ("GATEWAY_TOKEN", "ASK_TOKEN")}
    try:
        os.environ["GATEWAY_TOKEN"] = "gw-secret"
        os.environ["ASK_TOKEN"] = "ask-secret"
        # ① 질의는 두 토큰 다 받는다. 게이트웨이 토큰만 아는 배포도 계속 돌아야 한다.
        assert gw._ask_token_ok("ask-secret") is True
        assert gw._ask_token_ok("gw-secret") is True
        assert gw._ask_token_ok("아무거나") is False
        # ② 웹훅·중계는 질의용 토큰을 거부한다.
        assert gw._token_ok("gw-secret") is True
        assert gw._token_ok("ask-secret") is False
        # ③ 질의용 토큰을 안 적은 배포에서는 예전처럼 하나로 돈다.
        del os.environ["ASK_TOKEN"]
        assert gw._ask_token_ok("gw-secret") is True
        assert gw._token_ok("gw-secret") is True
    finally:
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
    return 7




def _repo_secret_checks() -> int:
    """리포에 실환경 주소가 커밋돼 있지 않은가.

    2026-08-19 감사에서 대시보드 JSON 한 곳에 실환경 공인 IP 가 다시 들어가 있는 것이
    확인됐다. Day6 에 자리표시자로 바꿔 둔 것이 대시보드를 다시 내보내면서 되돌아왔고
    `.bak` 만 남아 있었다. **되돌리는 것만으로는 같은 사고가 재현되므로** 검사를 세운다.

    사설 대역(10./192.168./172.16~31.)은 랩 구성이라 통과시킨다. 공인 IP 만 본다.
    """
    import io as _io
    import os
    import re
    import subprocess

    # gateway/selftest.py → gateway → bot → 리포 뿌리. 뿌리를 잘못 세면 bot 안만 훑고
    # 대시보드 JSON 이 검사 대상에서 통째로 빠진다.
    root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    if not os.path.isdir(os.path.join(root, ".git")):
        root = os.path.dirname(root)
    try:
        files = subprocess.check_output(["git", "ls-files"], cwd=root).decode().split()
    except Exception as e:                     # git 이 없는 곳에서는 건너뛴다
        log.info("리포 검사 건너뜀: %s", e)
        return 0
    ip = re.compile(r"\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b")

    def allowed(a, b, c):
        """랩 사설 대역과 **문서용 예시 대역**은 통과시킨다.

        예시 대역은 RFC 5737 이 문서에 쓰라고 비워 둔 것이라 이 리포가 자리표시자로
        쓰고 있다(192.0.2.0/24 · 198.51.100.0/24 · 203.0.113.0/24). 이것까지 막으면
        검사가 늘 빨개져 아무도 안 본다.
        """
        return (a in (0, 10, 127) or a >= 224
                or (a == 192 and b == 168)
                or (a == 172 and 16 <= b <= 31)
                or (a == 192 and b == 0 and c == 2)
                or (a == 198 and b == 51 and c == 100)
                or (a == 203 and b == 0 and c == 113))

    bad = []
    for rel in files:
        if not rel.endswith((".json", ".yml", ".yaml", ".md", ".py", ".ts", ".tsx")):
            continue
        path = os.path.join(root, rel)
        try:
            with _io.open(path, encoding="utf-8", errors="ignore") as f:
                text = f.read()
        except OSError:
            continue
        for m in ip.finditer(text):
            a, b, c, d = (int(x) for x in m.groups())
            if max(a, b, c, d) > 255 or allowed(a, b, c):
                continue
            # 판 번호(예: 1.2.3.4 형태의 버전)는 드물지만, 주소로 쓰이는 자리만 본다.
            line = text[max(0, m.start() - 60):m.start()]
            if "http" in line or "url" in line.lower() or "host" in line.lower():
                bad.append("%s: %s" % (rel, m.group(0)))
    assert not bad, "리포에 실환경 주소가 있다: %s" % ", ".join(sorted(set(bad))[:5])
    return 1




def _proxy_mask_checks() -> int:
    """수신 지점의 왕복 변환 — 중첩 JSON 마스킹과 도구 인자 역치환 (§23)."""
    import json

    from .. import masking, nametable, proxy

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

    from .. import collector

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
