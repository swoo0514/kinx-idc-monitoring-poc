"""질의 경로 검사 — 창구·도구·반복문·추적."""

import logging
import asyncio
import json
import os
import shutil
import tempfile
import time

from .common import _read_source
from .. import ask, convo, egress, llm, masking, nametable, prompts, proxy, registry, store, tracing
from ..alerts import collector
from ..integrations import grafana
from ..ask import tools as asktools
log = logging.getLogger("gateway.selftest")




def _ask_masking_checks() -> int:
    """여러 턴에 걸쳐도 같은 이름이 같은 토큰인가 (대화형 질의의 선결 조건)."""
    from .. import masking, nametable, proxy

    # ① 이름은 이미 결정적이다. 표를 새로 만들어도 같은 토큰이어야 한다.
    saved = dict(nametable._terms)
    try:
        nametable._terms = {"db-prod-01": "host", "web-01": "host"}
        a = proxy.build_masker()
        nametable._terms = {"web-01": "host", "db-prod-01": "host", "새이름": "host"}
        b = proxy.build_masker()
        assert a._fwd["db-prod-01"] == b._fwd["db-prod-01"], "표가 바뀌자 토큰이 달라졌다"

        # 해시 6자리는 이름 3,708개에서 충돌한다 — 역치환이 다른 호스트를 돌려준다
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

        # IP 토큰은 일련번호라 턴이 바뀌면 같은 토큰이 다른 기계를 가리킨다
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
    """사람이 자유롭게 친 질문을 어떻게 다루는가."""
    from .. import ask, nametable

    saved = dict(nametable._terms)
    try:
        nametable._terms = {"db-prod-01": "host"}
        mk = ask.session_masker("s1")

        # ① 이름과 IP 는 가려서 보낸다
        r = ask.sanitize_question("db-prod-01 이 10.0.0.7 로 못 붙는다", mk)
        assert r["ok"], r
        assert "db-prod-01" not in r["text"] and "10.0.0.7" not in r["text"], r["text"]

        # 가린 뒤에도 아는 이름이 남으면 보내지 않고 거절한다
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

        # 이름 표가 1시간마다 새로 만들어져도 앞 턴에 발행한 토큰은 되돌아가야 한다
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
    """질의가 닿을 수 있는 대상을 서버가 정하는가."""
    import os

    from .. import ask, registry
    from ..alerts import incident as inc_mod

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

        # 영역을 안 적은 소스는 거부가 기본 — 설정을 빠뜨린 사람이 가장 위험하면 안 된다
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
    """도구가 무엇을 조회할 수 있는가."""
    from ..ask import tools as asktools

    # ① 창 길이는 상한을 넘지 못한다. 모델이 큰 값을 넣어도 잘린다.
    assert asktools.clamp_window(999999) == asktools.WINDOW_MAX_M
    assert asktools.clamp_window(0) == asktools.WINDOW_DEFAULT_M
    assert asktools.clamp_window(30) == 30

    # 절대 구간을 받는다 — 상대 창만 있으면 모델이 엉뚱한 날을 본다
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

    # 구간을 골고루 보되 극단은 살린다 — 최신순 절단은 앞부분 스파이크를 버린다
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

    # 규칙 그룹 조건은 조회에 건다 — 받아 온 뒤 세면 조용히 적게 센다
    g = asktools.build_wazuh_query("vm-a.example", 60, 70, 0, "authentication_failed")
    assert {"term": {"rule.groups": "authentication_failed"}} in g["query"]["bool"]["filter"], g
    # 그룹을 안 주면 조건을 안 건다.
    plain = asktools.build_wazuh_query("vm-a.example", 60, 70, 0)
    assert all("rule.groups" not in str(f) for f in plain["query"]["bool"]["filter"]), plain

    # "전체"를 뜻하는 빈 값이 enum 에 있어야 모델이 실제로 넣을 수 있다
    for name in ("open_problems", "past_judgments"):
        prop = {t["name"]: t for t in asktools.build_tool_specs(
            {"[h-1]": {}})}[name]["input_schema"]["properties"]["host"]
        assert "" in (prop.get("enum") or []), (name, prop)

    # 선택 인자 한도는 선택만 센다 — 지우지 않고 필수로 옮기면 자리가 난다
    names = {t["name"]: t for t in asktools.build_tool_specs({"[h]": {}})}
    for name, key in (("list_hosts", "query"), ("open_problems", "host"),
                      ("list_panels", "dashboard")):
        sch = names[name]["input_schema"]
        assert key in (sch.get("required") or []), (name, sch.get("required"))

    # ⑥ Wazuh 질의 본문은 고정 틀에서 만든다. 에이전트명은 정확 일치다.
    body = asktools.build_wazuh_query("vm-a.example", 60, 7, 1786590000)
    assert body["query"]["bool"]["filter"][0]["term"]["agent.name"] == "vm-a.example", body
    assert set(body) <= {"size", "sort", "query", "_source", "track_total_hits"}, body
    # **총 건수를 함께 받는다.** 50건만 받아 세면 그보다 많을 때 조용히 적게 센다.
    assert body.get("track_total_hits") is True, body
    return 40





def _ask_result_checks() -> int:
    """조회 결과가 사람에게 닿기까지 무엇이 사라지는가."""
    from .. import masking, ask
    from ..alerts import collector
    from ..ask import tools as asktools

    # Wazuh 응답은 중첩이라 평탄화를 건너뛰면 50건이 전부 공백이 된다
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

    # 모델은 a|b|c 를 정규식으로 쓴다 — 글자 그대로 찾으면 결과가 빈다
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

    # 구간을 잘랐으면 잘랐다고 말한다 — 안 하면 "그 기간에 없었다"로 읽힌다
    T0 = 1786500000
    a, b, cut = asktools.window_bounds({"from": T0, "to": T0 + 30 * 86400}, now=T0)
    assert cut, "7일을 1일로 자르고도 알리지 않았다"
    assert b - a == asktools.WINDOW_MAX_M * 60, (a, b)
    # 남기는 쪽은 최신 — 조회가 최신순이라 앞을 남기면 화면 오른쪽 끝이 빠진다
    assert b == T0 + 30 * 86400, (a, b)
    a, b, cut = asktools.window_bounds({"from": T0, "to": T0 + 3600}, now=T0)
    assert not cut and b - a == 3600, (a, b, cut)
    # 보안·문제 조회는 건수 상한이 있어 더 긴 구간을 본다
    a, b, cut = asktools.window_bounds({"from": T0, "to": T0 + 7 * 86400}, now=T0,
                                       max_m=asktools.WINDOW_MAX_WIDE_M)
    assert not cut and b - a == 7 * 86400, (a, b, cut)

    # 상대 구간도 잘렸으면 말한다 — 90일 요청이 조용히 하루가 된 적이 있다
    a, b, cut = asktools.window_bounds({"window_m": 129600}, now=T0)
    assert cut, "90일을 하루로 자르고도 알리지 않았다"
    assert b - a == asktools.WINDOW_MAX_M * 60, (a, b)
    a, b, cut = asktools.window_bounds({"window_m": 60}, now=T0)
    assert not cut and b - a == 3600, (a, b, cut)
    # `at` 으로 시점을 줄 때도 마찬가지다
    a, b, cut = asktools.window_bounds({"at": T0, "window_m": 129600}, now=T0)
    assert cut, "시점 앞뒤 구간을 자르고도 알리지 않았다"

    # 실제로 본 구간을 사람이 읽는 형태로 함께 준다
    span = asktools.window_label(T0, T0 + 86400)
    assert "2026" in span and "~" not in span, span

    # 긴 구간은 추세로 본다 — 이력은 보관 기간이 짧아 90일이면 비거나 잘린다
    assert asktools.zbx_method_ok("trend.get"), "추세 조회를 막고 있다"
    assert asktools.use_trend(1786500000, 1786500000 + 86400) is False
    assert asktools.use_trend(1786500000, 1786500000 + 30 * 86400) is True
    # 지표 조회의 상한은 추세를 볼 수 있는 만큼까지 넓다
    a, b, cut = asktools.window_bounds({"window_m": 129600}, now=T0,
                                       max_m=asktools.WINDOW_MAX_TREND_M)
    assert not cut and b - a == 90 * 86400, (a, b, cut)

    # 패널은 번호로만 가리킨다 — 제목으로 찾으면 이름이 비슷한 옆 패널이 걸린다 (§31-5)
    ctx = {"uid": "kinx-overview", "panelId": 12, "title": "인증 활동 (Wazuh)"}
    assert asktools.panel_pick(ctx) == ("kinx-overview", 12)
    assert asktools.panel_pick({"uid": "kinx-overview"}) == (None, None)
    assert asktools.panel_pick(None) == (None, None)
    # 표시는 이번 턴 안에서만 뜻이 있고, 대시보드 식별자는 모델에 안 간다.
    import json as _js
    refs = {}
    shown = asktools.panel_refs(
        [{"uid": "u-msp", "panel_id": 16, "dashboard": "MSP 리포트", "title": "인증 활동",
          "source": "grafana-opensearch-datasource",
          "query": "rule.groups:authentication_failed"}],
        refs)
    assert shown == [{"ref": "pnl-1", "dashboard": "MSP 리포트", "title": "인증 활동",
                      "source": "grafana-opensearch-datasource",
                      "query": "rule.groups:authentication_failed"}], shown
    # 무엇을 조회하는 패널인지 함께 줘야 두 패널이 같은 값을 보는지 짐작하지 않는다.
    assert "authentication_failed" in _js.dumps(shown, ensure_ascii=False)
    assert refs["pnl-1"] == ("u-msp", 16, "인증 활동"), refs
    assert "u-msp" not in _js.dumps(shown, ensure_ascii=False)

    # at 은 없앤다 — from/to 와 window_m 이 덮으므로 덫이기만 하다
    for t in asktools.build_tool_specs({"[h]": {}}):
        assert "at" not in t["input_schema"]["properties"], t["name"]

    # 못 읽은 시각을 말해 준다 — 조용히 기본 창으로 떨어지면 같은 실수를 반복한다
    assert asktools.bad_when({"range": "90"}), "못 읽은 시각을 알리지 않았다"
    assert not asktools.bad_when({"range": "%d ~ %d" % (T0, T0 + 600)})
    assert not asktools.bad_when({"window_m": 129600})
    assert "range" in asktools.when_note({"range": "어제쯤"})
    assert asktools.when_note({"range": "%d ~ %d" % (T0, T0 + 600)}) == ""

    # 구간에 값이 없으면 그 자리에서 말한다 — 안 알리면 현재 값만 보고 답한다
    out = asktools.note_if_no_points(
        {"metrics": [{"name": "repl", "sampled_from": 0, "last": "0"}], "status": "ok"})
    assert "window_m" in (out.get("note") or ""), out
    keep = {"metrics": [{"name": "repl", "sampled_from": 120}], "status": "ok"}
    assert not (asktools.note_if_no_points(keep).get("note") or "")

    # 잘린 사실은 프롬프트가 아니라 도구 결과에 실어야 모델이 답에 옮긴다
    note = asktools.cut_note(True, 1440)
    assert note and "1일" in note and "최근" in note, note
    assert asktools.cut_note(False, 1440) == ""

    # 그림 표시를 걷어낸 뒤 남는 빈 괄호까지 정리한다
    assert ask.strip_handles("패널(img-6598)의 그래프") == "패널의 그래프"
    assert ask.strip_handles("패널 [img-6598] 참고") == "패널 참고"
    assert ask.strip_handles("image-6598 은 그대로") == "image-6598 은 그대로"
    # 마크다운 그림 표기를 통째로 걷어 낸다 — 표시만 빼면 깨진 표기가 남는다
    assert ask.strip_handles("![image](img-6598)" + chr(10) + "90일 추이") == "90일 추이"
    assert ask.strip_handles("보기: ![복제 지연]([img-6598])") == "보기:"
    return 24





def _tool_schema_checks() -> int:
    """도구 스키마가 모델이 고를 수 있는 값을 얼마나 좁히는가."""
    import json

    from ..ask import tools as asktools

    table = {"[host-b]": {"host": "b1"}, "[host-a]": {"host": "a1"}}

    # ① 대상 토큰을 enum 으로 묶는다. 표에 없는 이름은 표현할 수 없다.
    specs = asktools.build_tool_specs(table)
    by_name = {t["name"]: t for t in specs}
    for name in ("host_logs", "host_metrics", "security_alerts", "panel_image"):
        enum = by_name[name]["input_schema"]["properties"]["host"].get("enum")
        assert enum == ["[host-a]", "[host-b]"], (name, enum)

    # 같은 표는 같은 바이트를 만든다 — 정렬을 빠뜨리면 캐시가 한 번도 안 걸린다
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

    # ⑤ **답도 도구로 받는다.** 산문으로 받으면 표시가 글자로 남고 구간이 지어내진다.
    ans = by_name["answer"]
    props = ans["input_schema"]["properties"]
    for field in ("summary", "window_utc", "findings", "image_ids"):
        assert field in props, field
    assert "summary" in ans["input_schema"]["required"]

    # 턴 중에 생기는 값은 enum 으로 못 묶는다 — 정의가 바뀌면 캐시가 죽는다
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
    src = _read_source("gateway/ask/tools.py")
    assert src.count('"description": "절대 구간 시작. ISO8601 또는 유닉스 초"') <= 2,         "from/to 정의가 중복돼 있다"
    return 22





def _cache_checks() -> int:
    """프롬프트 캐싱이 실제로 걸릴 모양인가."""
    from .. import llm, store
    from ..ask import tools as asktools

    # 렌더 순서가 도구 → 시스템 → 대화라 이 한 곳이 둘을 함께 캐시한다
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

    # 캐시 토큰을 따로 센다 — 읽기 0.1배·쓰기 1.25배라 뭉뚱그리면 절감이 안 보인다
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





def _model_tier_checks() -> int:
    """호출 용도마다 모델 등급을 나눌 수 있는가."""
    import os

    from .. import llm

    saved = {k: os.environ.get(k) for k in
             ("LLM_CLAUDE_MODEL", "LLM_MODEL_INVESTIGATE", "LLM_MODEL_WRITE",
              "LLM_MODEL_ROUTE")}
    try:
        for k in saved:
            os.environ.pop(k, None)
        os.environ["LLM_CLAUDE_MODEL"] = "base-model"

        # ① 용도별 값이 없으면 기존 값으로 떨어진다. 설정을 안 바꾼 배포가 멈추면 안 된다.
        for kind in ("investigate", "write", "route", "triage", "없는용도"):
            assert llm.model_for(kind) == "base-model", kind

        # ② 적으면 그 용도만 바뀐다.
        os.environ["LLM_MODEL_WRITE"] = "cheap-model"
        assert llm.model_for("write") == "cheap-model"
        assert llm.model_for("investigate") == "base-model"
        # **트리아지는 조사와 같은 등급을 쓴다.** 판단이기 때문이다.
        assert llm.model_for("triage") == llm.model_for("investigate")

        # ③ 어댑터가 모델을 인자로 받는다. 환경변수를 직접 읽으면 용도를 못 나눈다.
        assert llm.ClaudeAdapter(model="x").model == "x"
        assert llm.ClaudeAdapter().model == "base-model"
    finally:
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
    return 9





def _graph_state_checks() -> int:
    """그래프 상태가 스스로를 검사하는가."""
    from ..ask import graph

    # 무거운 임포트를 기동 때 끝낸다 — 첫 질의가 뒤집어쓰면 화면에 502 가 뜬다
    assert graph.warmup() in (True, False)
    assert graph.warmup() is graph.warmup()      # 두 번 불러도 같은 답

    ok = {"trace": [{"tool": "host_logs"}], "called": {"k": 1}, "images": [],
          "spent": 10, "stopped": ""}
    assert graph.check_state(ok) == ""

    # 조회 기록과 중복 차단 표의 개수가 어긋나면 안 된다
    bad = dict(ok, called={"k": 1, "k2": 2})
    assert "조회" in graph.check_state(bad), graph.check_state(bad)

    # ② 같은 그림을 두 번 붙이지 않는다.
    dup = dict(ok, images=[{"id": "img-1"}, {"id": "img-1"}])
    assert graph.check_state(dup)

    # ③ 쓴 바이트는 줄지 않는다. 줄었다면 상태가 뒤섞인 것이다.
    assert graph.check_state(dict(ok, spent=-1))

    # ④ 멈춘 이유는 정해진 값 중 하나다. 모르는 값이 화면에 나가면 사람이 해석할 수 없다.
    assert graph.check_state(dict(ok, stopped="이상한값"))
    for good in ("", "budget", "llm_failed"):
        assert graph.check_state(dict(ok, stopped=good)) == "", good

    # 답 도구는 조회 상한에 안 센다 — 세면 조사할 수 있는 횟수가 하나 준다
    from ..ask import tools as asktools
    assert asktools.query_count([{"tool": "host_logs"}, {"tool": "answer"}]) == 1
    assert asktools.query_count([{"tool": "answer"}]) == 0
    assert asktools.query_count([]) == 0

    # ⑤ 분기 판단이 그래프 없이 돈다. 클로저 안에 있으면 단위 검사를 못 한다.
    class _Msg:
        tool_calls = [{"name": "host_logs"}]

    assert graph.should_continue({"messages": [_Msg()], "trace": []},
                                 max_calls=6, stop_now=lambda: False,
                                 answered=lambda: False) is True
    assert graph.should_continue({"messages": [_Msg()], "trace": []},
                                 max_calls=6, stop_now=lambda: False,
                                 answered=lambda: True) is False
    three = [{"tool": "host_logs"}] * 3
    assert graph.should_continue({"messages": [_Msg()], "trace": three},
                                 max_calls=3, stop_now=lambda: False,
                                 answered=lambda: False) is False
    assert graph.should_continue({"messages": [_Msg()], "trace": []},
                                 max_calls=6, stop_now=lambda: True,
                                 answered=lambda: False) is False
    return 14





def _prompt_file_checks() -> int:
    """프롬프트를 파일에서 읽는가."""
    import os
    import tempfile

    from .. import prompts

    d = tempfile.mkdtemp(prefix="prompt-")
    saved = prompts.PROMPT_DIR
    try:
        prompts.PROMPT_DIR = d
        prompts.forget()
        # ① 파일이 없으면 예비 문구로 떨어진다.
        assert prompts.load("ask", "예비 문구") == "예비 문구"

        # ② 파일이 있으면 그 내용이 쓰인다.
        with open(os.path.join(d, "ask.md"), "w", encoding="utf-8") as f:
            f.write("파일에서 온 문구" + chr(10))
        prompts.forget()
        assert prompts.load("ask", "예비 문구") == "파일에서 온 문구"

        # 실행 중에 다시 읽지 않는다 — 문구가 바뀌면 쌓인 캐시가 통째로 무효가 된다
        with open(os.path.join(d, "ask.md"), "w", encoding="utf-8") as f:
            f.write("몰래 바뀐 문구" + chr(10))
        assert prompts.load("ask", "예비 문구") == "파일에서 온 문구"
    finally:
        prompts.PROMPT_DIR = saved
        prompts.forget()

    # ④ 실제 세 프롬프트가 비어 있지 않다.
    from .. import ask, llm
    assert len(ask.system_prompt()) > 200
    assert len(llm.TRIAGE_SYSTEM) > 200
    assert len(llm.MONTHLY_SYSTEM) > 100
    return 8





def _panel_route_checks() -> int:
    """보고 있는 패널이 **실경로로** 그려지는가, 그리고 다른 패널을 가리킬 수 있는가."""
    import asyncio

    from .. import ask, nametable
    from ..integrations import grafana
    from ..ask import tools as asktools

    saved_terms = dict(nametable._terms)
    saved_list = grafana.list_panels
    calls = []

    def _spy(dash_match="", limit=40):
        calls.append(dash_match)
        return [{"uid": "u-msp", "panel_id": 16, "dashboard": "KINX MSP 월간 리포트",
                 "title": "인증 활동 — web-01 로그인 실패",
                 "source": "grafana-opensearch-datasource",
                 "query": "rule.groups:authentication_failed AND agent.name:/web-01/"}]

    try:
        nametable._terms = {"web-01": "host"}
        grafana.list_panels = _spy
        table = {ask.proxy.token_for("host", "web-01"):
                 {"host": "web-01", "source": "zabbix-internal",
                  "logs": "web-01.example", "security": "web-01.example"}}
        tok = list(table)[0]

        def model(system, messages, tools):
            if len(messages) == 1:
                return {"stop_reason": "tool_use", "content": [
                    {"type": "tool_use", "id": "t1", "name": "panel_image",
                     "input": {"host": tok}}]}
            return {"stop_reason": "end_turn", "content": [{"type": "text", "text": "끝"}]}

        # ① 화면이 번호를 주면 목록을 아예 안 부른다.
        r = asyncio.run(ask.run_ask("이 패널 뭐야", table=table, model_fn=model,
                                    panel={"uid": "kinx-overview", "panelId": 12,
                                           "title": "인증 활동 (Wazuh)"}))
        assert not calls, "번호를 쥐고도 목록을 뒤졌다: %r" % (calls,)
        assert r["images"] and "/render/d-solo/kinx-overview/" in r["images"][0]["url"],             r["images"]
        assert "panelId=12" in r["images"][0]["url"], r["images"][0]["url"]
        # 화면이 준 호스트 값을 쓴다 — Zabbix 축 이름을 넣으면 Loki·Wazuh 가 빈다
        r2 = asyncio.run(ask.run_ask("이 패널", table=table, model_fn=model,
                                     panel={"uid": "u1", "panelId": 3,
                                            "title": "t", "host": "web-01.example"}))
        assert "web-01.example" in r2["images"][0]["url"], r2["images"][0]["url"]

        # 행 안에 접힌 패널도 목록에 든다
        nested = [{"type": "row", "title": "묶음", "panels": [
            {"type": "timeseries", "title": "복제 지연", "id": 7}]}]
        assert [x["id"] for x in grafana._flatten(nested) if x.get("id")] == [7]
        assert grafana._flatten(None) == []

        # 선택 인자 수 한도 — 넘기면 API 가 호출을 통째로 거부한다
        n = asktools.optional_params(asktools.build_tool_specs(table))
        assert n <= asktools.OPTIONAL_PARAM_MAX, "선택 인자가 %d개다 (한도 %d)" % (
            n, asktools.OPTIONAL_PARAM_MAX)

        # 다른 대시보드 패널은 목록을 받아 번호로 가리킨다
        seen = {}

        def model2(system, messages, tools):
            if len(messages) == 1:
                return {"stop_reason": "tool_use", "content": [
                    {"type": "tool_use", "id": "t1", "name": "list_panels",
                     "input": {"dashboard": "월간 리포트"}}]}
            if len(messages) == 3:
                blob = str(messages[-1])
                seen["blob"] = blob
                return {"stop_reason": "tool_use", "content": [
                    {"type": "tool_use", "id": "t2", "name": "panel_image",
                     "input": {"host": tok, "panel_ref": "pnl-1"}}]}
            return {"stop_reason": "end_turn", "content": [{"type": "text", "text": "끝"}]}

        calls[:] = []
        r3 = asyncio.run(ask.run_ask("MSP 리포트 것도 보여줘", table=table, model_fn=model2,
                                     panel={"uid": "kinx-overview", "panelId": 12,
                                            "title": "인증 활동"}))
        assert calls == ["월간 리포트"], calls
        # 목록에는 표시와 제목만 간다. 대시보드 식별자는 서버가 들고 있는다.
        assert "pnl-1" in seen["blob"] and "u-msp" not in seen["blob"], seen["blob"][:200]
        # 이름 표를 거치므로 제목에도 질의문에도 실명이 그대로 나가지 않는다.
        assert "web-01" not in seen["blob"], seen["blob"][:200]
        assert "authentication_failed" in seen["blob"], seen["blob"][:200]
        assert r3["images"] and "/render/d-solo/u-msp/" in r3["images"][0]["url"], r3["images"]
        assert "panelId=16" in r3["images"][0]["url"], r3["images"][0]["url"]

        # ③ **모르는 표시는 거부한다.** 모델이 지어내면 엉뚱한 패널이 그려진다.
        def model3(system, messages, tools):
            if len(messages) == 1:
                return {"stop_reason": "tool_use", "content": [
                    {"type": "tool_use", "id": "t1", "name": "panel_image",
                     "input": {"host": tok, "panel_ref": "pnl-9"}}]}
            return {"stop_reason": "end_turn", "content": [{"type": "text", "text": "끝"}]}

        r4 = asyncio.run(ask.run_ask("저것도", table=table, model_fn=model3,
                                     panel={"uid": "kinx-overview", "panelId": 12}))
        assert not r4["images"], r4["images"]
        assert "list_panels" in r4["trace"][0]["error"], r4["trace"][0]

        # ④ 화면 맥락도 패널 번호도 없으면 무엇을 하라고 알린다.
        r5 = asyncio.run(ask.run_ask("이 패널 뭐야", table=table, model_fn=model))
        assert not r5["images"], r5["images"]
        assert "list_panels" in r5["trace"][0]["error"], r5["trace"][0]
    finally:
        grafana.list_panels = saved_list
        nametable._terms = saved_terms
    return 18






def _item_rank_checks() -> int:
    """이름으로 아이템을 고를 때 정작 원하는 것이 빠지지 않는가."""
    from ..ask import tools as asktools

    names = ["CPU guest nice time", "CPU guest time", "CPU idle time",
             "CPU interrupt time", "CPU iowait time", "CPU nice time",
             "CPU softirq time", "CPU steal time", "CPU system time",
             "CPU user time", "CPU utilization", "Load average (1m avg)",
             "Load average (5m avg)", "Load average (15m avg)",
             "Number of CPUs", "Context switches per second",
             "Interrupts per second"]
    items = [{"itemid": str(i), "name": n} for i, n in enumerate(names)]

    ranked = asktools.rank_items(items, "cpu")
    top = [x["name"] for x in ranked[:asktools.ITEM_LIMIT]]
    assert "CPU utilization" in top, top
    # 낱말이 적은 이름이 앞선다. 그 값을 직접 가리키기 때문이다.
    order = [x["name"] for x in ranked]
    assert order.index("CPU utilization") < order.index("CPU guest nice time"), order[:6]
    # 낱말로 안 맞는 것("Number of CPUs" 의 CPUs)은 뒤로 간다.
    assert order.index("CPU idle time") < order.index("Number of CPUs"), order

    # 검색어가 없으면 순서를 바꾸지 않는다. 근거 없는 재배열은 하지 않는다.
    assert [x["name"] for x in asktools.rank_items(items, "")] == names

    # **잘렸으면 안 본 이름을 말한다.** 이 저장소는 다른 곳에서 잘림을 꼬박 알린다.
    out = asktools.note_if_cut({"metrics": [{"name": n} for n in names[:8]]},
                               total=17, shown=8, dropped=names[8:])
    note = out.get("note") or ""
    assert "17" in note and "8" in note, note
    assert "Load average (1m avg)" in note, note
    assert not (asktools.note_if_cut({"metrics": []}, total=3, shown=3,
                                     dropped=[]).get("note") or "")
    return 8





def _panel_window_checks() -> int:
    """사람이 보던 구간이 도구까지 가는가."""
    from ..ask import tools as asktools

    T0, T1 = 1786475892, 1786627941      # 2026-08-11 19:18 ~ 08-13 13:32
    default = (T0, T1)

    # ① 모델이 아무 구간도 안 주면 화면이 준 구간을 쓴다.
    a, b, cut = asktools.window_bounds({}, now=1787000000,
                                       max_m=asktools.WINDOW_MAX_WIDE_M,
                                       default_span=default)
    assert (a, b) == default, (a, b)

    # ② 모델이 구간을 주면 그쪽이 이긴다. 사람이 "어제는?" 하고 물을 수 있다.
    a, b, cut = asktools.window_bounds({"window_m": 60}, now=1787000000,
                                       default_span=default)
    assert b == 1787000000 and a == 1787000000 - 3600, (a, b)
    a, b, cut = asktools.window_bounds({"from": T0, "to": T0 + 600}, now=1787000000,
                                       default_span=default)
    assert (a, b) == (T0, T0 + 600), (a, b)

    # ③ 화면 구간이 상한보다 길면 잘리고, 잘렸다고 말한다.
    a, b, cut = asktools.window_bounds({}, now=1787000000, max_m=60,
                                       default_span=(T0, T1))
    assert cut and b - a == 3600, (a, b, cut)

    # 절대 구간은 인자 하나로 받는다 — 둘로 나누면 스키마가 커져 전부 거부된다
    for t in asktools.build_tool_specs({"[h]": {}}):
        props = t["input_schema"]["properties"]
        assert "from" not in props and "to" not in props, t["name"]
    assert asktools.span_of({"range": "2026-08-11T19:18:12Z ~ 2026-08-13T13:32:21Z"})         == (T0 - 12 + 12, T1 - 21 + 21), asktools.span_of({"range": "x"})
    a, b, cut = asktools.window_bounds({"range": "1786475892 .. 1786627941"},
                                       now=1787000000, max_m=asktools.WINDOW_MAX_WIDE_M)
    assert (a, b) == (T0, T1), (a, b)
    # 못 읽으면 지어내지 않고 알린다.
    assert "range" in asktools.bad_when({"range": "어제쯤"}), asktools.bad_when({"range": "어제쯤"})

    # 모델이 스스로 창을 넣었을 때 되부르는 법을 결과에 적는다
    note = asktools.span_note(1787000000 - 3600, 1787000000, default)
    assert "시간 인자를 모두 비우고" in note, note
    assert not asktools.span_note(T0, T1, default)      # 같은 구간이면 안 붙인다
    assert not asktools.span_note(T0, T1, None)
    out = asktools._add_cut({}, False, 60, 1787000000 - 3600, 1787000000, {}, default)
    assert "화면 구간" in out["note"], out

    # ③-c 로그도 같은 상한을 쓴다. 하루로 자르면 이틀 구간의 앞 하루가 통째로 빠진다.
    a, b, cut = asktools.window_bounds({}, now=1787000000,
                                       max_m=asktools.WINDOW_MAX_WIDE_M,
                                       default_span=default)
    assert not cut and (a, b) == default, (a, b, cut)
    # 줄 수 상한을 채웠으면 앞부분이 안 실렸다고 말한다.
    from ..alerts import collector as _col
    capped = asktools.note_if_capped({"logs": [], "fetched": _col.LOKI_FETCH_LIMIT})
    assert "앞부분은 안 들어왔다" in capped["note"], capped
    assert not (asktools.note_if_capped({"logs": [], "fetched": 3}).get("note"))

    # 화면 없이 글만 붙여 넣는 경우 — 패널 맥락이 아예 안 온다
    q = ('지금 대시보드 "KINX 통합 관제" 의 "인증 활동" 패널을 보고 있습니다 '
         "(구간 2026-08-11T19:18:12.679Z ~ 2026-08-13T13:32:21.164Z).")
    assert asktools.span_in_text(q) == (T0, T1), asktools.span_in_text(q)
    assert asktools.span_in_text("어제 새벽에 무슨 일 있었어") is None
    assert asktools.span_in_text("2026-08-11T19:18:12.679Z 이후") is None   # 하나뿐이면 안 쓴다

    # ④ 화면 구간이 없으면 예전대로 최근 창을 본다.
    a, b, cut = asktools.window_bounds({}, now=1787000000)
    assert b == 1787000000, (a, b)

    # 실경로로 확인한다 — 함수를 직접 부르는 검사는 배선이 빠져도 통과한다
    import asyncio

    from .. import ask

    table = {ask.proxy.token_for("host", "web-01"):
             {"host": "web-01", "source": "zabbix-internal",
              "logs": "web-01.example", "security": "web-01.example"}}
    tok = list(table)[0]

    def model(system, messages, tools):
        if len(messages) == 1:                 # 구간을 인자로 **안 적는다**
            return {"stop_reason": "tool_use", "content": [
                {"type": "tool_use", "id": "t1", "name": "panel_image",
                 "input": {"host": tok}}]}
        return {"stop_reason": "end_turn", "content": [{"type": "text", "text": "끝"}]}

    r = asyncio.run(ask.run_ask("이 구간에 무슨 일 있었어", table=table, model_fn=model,
                                panel={"uid": "kinx-overview", "panelId": 12, "title": "t",
                                       "from": "2026-08-11T19:18:12.679Z",
                                       "to": "2026-08-13T13:32:21.164Z"}))
    url = (r.get("images") or [{}])[0].get("url", "")
    assert "from=%d" % (T0 * 1000) in url and "to=%d" % (T1 * 1000) in url, url
    return 9




def _cap_answer_checks() -> int:
    """상한에 닿았을 때 사람이 답을 받는가."""
    import asyncio

    from .. import ask

    table = {ask.proxy.token_for("host", "web-01"):
             {"host": "web-01", "source": "zabbix-internal",
              "logs": "web-01.example", "security": "web-01.example"}}
    tok = list(table)[0]
    seen = {"names": []}

    def model(system, messages, tools):
        seen["names"].append([t["name"] for t in tools])
        if len(tools) == 1:                      # 마무리 호출 — 답 도구만 있다
            assert tools[0]["name"] == "answer", tools
            assert "상한" in str(messages[-1]["content"]), messages[-1]
            return {"stop_reason": "tool_use", "content": [
                {"type": "tool_use", "id": "fin", "name": "answer",
                 "input": {"summary": "확인한 범위에서는 인증 실패가 없었다"}}]}
        # 조회만 되풀이하고 끝내지 않는다. 인자를 바꿔 중복 차단도 피한다.
        n = len(seen["names"])
        return {"stop_reason": "tool_use", "content": [
            {"type": "text", "text": "레벨을 더 낮춰서 다시 보겠습니다"},
            {"type": "tool_use", "id": "t%d" % n, "name": "security_alerts",
             "input": {"host": tok, "min_level": max(3, 12 - n)}}]}

    r = asyncio.run(ask.run_ask("이 구간 어땠어", table=table, model_fn=model))
    assert r["stopped"] == "rounds", r["stopped"]
    assert "인증 실패가 없었다" in r["text"], r["text"]
    # 중간 생각이 답으로 나가지 않는다.
    assert "다시 보겠습니다" not in r["text"], r["text"]
    assert r["trace"][-1]["tool"] == "answer", r["trace"][-1]

    # 마무리 호출이 실패해도 사람은 무엇을 조회했는지는 받는다.
    def dead(system, messages, tools):
        if len(tools) == 1:
            return {"stop_reason": "end_turn", "content": [{"type": "text", "text": "…"}]}
        return model(system, messages, tools)

    r2 = asyncio.run(ask.run_ask("이 구간 어땠어", table=table, model_fn=dead))
    assert "상한" in r2["text"] and "security_alerts" in r2["text"], r2["text"]

    # 결과가 안 붙은 도구 요청은 걷어 낸다 — 그대로 보내면 400 이다
    hang = [{"role": "user", "content": "질문"},
            {"role": "assistant", "content": [{"type": "tool_use", "id": "x",
                                               "name": "security_alerts", "input": {}}]}]
    assert len(ask.drop_dangling(hang)) == 1, ask.drop_dangling(hang)
    done = hang + [{"role": "user", "content": [{"type": "tool_result",
                                                 "tool_use_id": "x", "content": "{}"}]}]
    assert len(ask.drop_dangling(done)) == 3
    assert ask.drop_dangling([]) == []

    # 조회를 하나도 못 했으면 "조회한 것: 없음" 대신 무엇을 하라는 말을 준다.
    assert "다시 물어보라" in ask.stall_note("deadline", [])
    assert "host_logs" in ask.stall_note("rounds", [{"tool": "host_logs"}])
    return 14




def _usage_metadata_checks() -> int:
    """추적 화면에 토큰 수와 비용이 뜨는가."""
    from ..ask import graph

    if not graph.available():
        return 0
    msg = graph.to_ai_message({
        "content": [{"type": "text", "text": "끝"}],
        "model": "claude-haiku-4-5-20251001",
        "usage": {"input_tokens": 326, "output_tokens": 12,
                  "cache_read_input_tokens": 8803, "cache_creation_input_tokens": 0},
    })
    # 모델 이름이 없으면 개수는 떠도 단가를 몰라 비용 칸이 빈다
    rm = getattr(msg, "response_metadata", None) or {}
    assert rm.get("ls_model_name") == "claude-haiku-4-5-20251001", rm
    assert rm.get("ls_provider") == "anthropic", rm
    um = getattr(msg, "usage_metadata", None)
    assert um, "토큰 수를 안 실었다 — 추적 화면의 비용 칸이 빈다"
    assert um["input_tokens"] == 326 + 8803, um
    assert um["output_tokens"] == 12, um
    assert um["total_tokens"] == 326 + 8803 + 12, um
    assert um["input_token_details"]["cache_read"] == 8803, um
    # 사용량이 안 실려 온 응답에서도 터지지 않는다.
    assert graph.to_ai_message({"content": []}) is not None

    # 모델 이름은 run 메타데이터로 가야 한다 — 기본 구현은 비워 둔다
    import os

    saved = os.environ.get("LLM_MODEL_INVESTIGATE")
    try:
        os.environ["LLM_MODEL_INVESTIGATE"] = "claude-haiku-4-5-20251001"
        model = graph.make_model("시스템", [], "tester")
        ls = model._get_ls_params()
        assert ls.get("ls_model_name") == "claude-haiku-4-5-20251001", ls
        assert ls.get("ls_provider") == "anthropic", ls
    finally:
        if saved is None:
            os.environ.pop("LLM_MODEL_INVESTIGATE", None)
        else:
            os.environ["LLM_MODEL_INVESTIGATE"] = saved
    return 8




def _tracing_checks() -> int:
    """추적을 켜고 끄는 스위치가 실제로 동작하는가."""
    import os

    from .. import tracing

    saved = {k: os.environ.get(k) for k in
             ("LANGSMITH_TRACING", "LANGSMITH_API_KEY", "LANGCHAIN_TRACING_V2")}
    try:
        for k in saved:
            os.environ.pop(k, None)
        # ① 기본은 꺼짐. 아무것도 안 적으면 아무 데도 안 보낸다.
        assert tracing.enabled() is False
        st = tracing.setup()
        assert st["on"] is False and "미설정" in st["why"], st

        # ② 키 없이 켜기만 하면 켜지지 않는다. 조용히 켜진 척하는 것이 가장 나쁘다.
        os.environ["LANGSMITH_TRACING"] = "true"
        st = tracing.setup()
        assert st["on"] is False and "키" in st["why"], st

        # ③ 둘 다 있으면 켜고, 라이브러리가 읽는 변수까지 맞춰 준다.
        os.environ["LANGSMITH_API_KEY"] = "ls-test"
        st = tracing.setup()
        assert st["on"] is True, st
        assert os.environ.get("LANGCHAIN_TRACING_V2") == "true", os.environ
        assert os.environ.get("LANGSMITH_PROJECT"), "프로젝트 이름을 안 정했다"
    finally:
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        os.environ.pop("LANGSMITH_PROJECT", None)
    return 8




def _list_truncation_checks() -> int:
    """목록이 잘렸을 때 그 사실을 말하는가."""
    import asyncio

    from .. import ask
    from ..ask import tools as asktools

    # ① 열린 문제 — 총계를 함께 받아 잘림을 밝힌다.
    rows = [{"name": "p%d" % i, "severity": "3", "clock": "1786500000"}
            for i in range(50)]
    out = ask.problems_result(rows, None, total=137)
    assert out.get("total") == 137, out
    assert "137" in (out.get("note") or ""), out

    # 안 잘렸으면 붙이지 않는다.
    out2 = ask.problems_result(rows[:3], None, total=3)
    assert not (out2.get("note") or ""), out2

    # 총계를 세는 호출에 빈 값을 넣지 않는다 — Zabbix 가 output: None 을 거부한다
    class _Spy:
        def __init__(self, source=""):
            self.calls = []

        async def call(self, client, method, params):
            self.calls.append((method, dict(params)))
            if method == "host.get":
                return [{"hostid": "1"}]
            if params.get("countOutput"):
                return "137"
            return rows[:50]

    spy = _Spy()
    saved_cli = ask.collector.ZabbixClient if hasattr(ask, "collector") else None
    from ..alerts import collector
    saved_cli = collector.ZabbixClient
    try:
        collector.ZabbixClient = lambda source="": spy
        got = asyncio.run(ask.fetch_problems({"host": "web-01", "source": "s"}, None))
    finally:
        collector.ZabbixClient = saved_cli
    for method, params in spy.calls:
        assert not any(v is None for v in params.values()), (method, params)
    assert got.get("total") == 137, got
    assert got.get("status") == "ok", got

    # ② 호스트 목록 — 100개에서 자르면 몇 개 중 몇 개인지 말한다.
    table = {"[h-%d]" % i: {"host": "web-%d" % i, "source": "s"} for i in range(150)}
    got = asyncio.run(asktools.run_tool("list_hosts", {"query": ""}, {"table": table}))
    assert got["n"] == 150 and len(got["hosts"]) == 100, (got["n"], len(got["hosts"]))
    assert "150" in (got.get("note") or ""), got
    return 10




def _table_cache_checks() -> int:
    """질문마다 대상 표를 새로 만들지 않는가."""
    import asyncio
    import os

    from .. import ask, registry
    from ..alerts import collector, incident as inc_mod

    calls = {"n": 0}

    class FakeZbx:
        def __init__(self, source=""):
            pass

        async def call(self, client, method, params):
            calls["n"] += 1
            return [{"hostid": "1", "host": "web-01", "name": "web-01", "status": "0",
                     "interfaces": [{"ip": "192.0.2.9", "dns": "web-01.example"}]}]

    saved = collector.ZabbixClient
    saved_src, saved_map = list(registry._SOURCES), dict(inc_mod.REALM_MAP)
    saved_env = os.environ.get("ASK_ALLOWED_REALMS")
    try:
        registry._SOURCES = [{"name": "zabbix-internal", "realm": "internal"}]
        inc_mod.REALM_MAP = {}
        os.environ.pop("ASK_ALLOWED_REALMS", None)
        collector.ZabbixClient = FakeZbx
        ask.forget_tables()
        t1 = asyncio.run(ask.build_table(ask.proxy.build_masker()))
        n1 = calls["n"]
        t2 = asyncio.run(ask.build_table(ask.proxy.build_masker()))
        assert calls["n"] == n1, "표를 다시 만들었다"
        assert list(t1) == list(t2), (t1, t2)

        # 시한이 지나면 다시 만든다. 낡은 표로 답하면 없는 호스트를 있다고 한다.
        ask.forget_tables()
        asyncio.run(ask.build_table(ask.proxy.build_masker()))
        assert calls["n"] > n1

        # 조회가 실패하면 빈 표를 캐시하지 않는다. 다음 질문에서 다시 시도해야 한다.
        class Broken(FakeZbx):
            async def call(self, client, method, params):
                calls["n"] += 1
                raise RuntimeError("zabbix down")

        collector.ZabbixClient = Broken
        ask.forget_tables()
        empty = asyncio.run(ask.build_table(ask.proxy.build_masker()))
        assert empty == {}, empty
        before = calls["n"]
        asyncio.run(ask.build_table(ask.proxy.build_masker()))
        assert calls["n"] > before, "실패한 결과를 캐시했다"
    finally:
        collector.ZabbixClient = saved
        registry._SOURCES, inc_mod.REALM_MAP = saved_src, saved_map
        if saved_env is not None:
            os.environ["ASK_ALLOWED_REALMS"] = saved_env
        ask.forget_tables()
    return 6




def _tool_timeout_checks() -> int:
    """느린 조회 하나가 질의 전체를 잡아먹지 않는가."""
    import asyncio
    import os

    from ..alerts import collector
    from ..ask import tools as asktools

    saved = os.environ.get("ASK_TOOL_TIMEOUT_S")
    try:
        os.environ["ASK_TOOL_TIMEOUT_S"] = "0.05"

        async def slow(q, a, b, limit):
            await asyncio.sleep(5)
            return {"logs": [], "status": "ok"}

        ctx = {"table": {"[h-1]": {"host": "web-01", "source": "s", "logs": "web-01",
                                   "security": ""}},
               "now": 1786590000, "fetch_logs": slow}
        out = asyncio.run(asktools.run_tool("host_logs", {"host": "[h-1]"}, ctx))
        assert out.get("status") == collector.SOURCE_UNAVAILABLE, out
        assert "중단했다" in (out.get("note") or ""), out
        # "없음" 으로 읽히면 안 된다. 조회를 못 한 것이다.
        assert "근거로 쓰지 마라" in (out.get("note") or ""), out
    finally:
        if saved is None:
            os.environ.pop("ASK_TOOL_TIMEOUT_S", None)
        else:
            os.environ["ASK_TOOL_TIMEOUT_S"] = saved
    return 3




def _metric_batch_checks() -> int:
    """지표를 아이템마다 따로 물어보지 않는가."""
    import asyncio

    from .. import ask
    from ..alerts import collector

    calls = []

    class FakeZbx:
        def __init__(self, source=""):
            pass

        async def call(self, client, method, params):
            calls.append((method, params))
            if method == "host.get":
                return [{"hostid": "10"}]
            if method == "item.get":
                return [{"itemid": "1", "name": "CPU utilization", "key_": "cpu",
                         "value_type": 0, "units": "%", "lastvalue": "5"},
                        {"itemid": "2", "name": "Load average", "key_": "load",
                         "value_type": 0, "units": "", "lastvalue": "1"},
                        {"itemid": "3", "name": "Processes", "key_": "proc",
                         "value_type": 3, "units": "", "lastvalue": "200"}]
            if method == "history.get":
                # 요청한 아이템들의 값을 한 덩어리로 돌려준다.
                ids = params["itemids"]
                ids = ids if isinstance(ids, list) else [ids]
                return [{"itemid": i, "clock": "1786500000", "value": "1"} for i in ids]
            return []

    saved = collector.ZabbixClient
    try:
        collector.ZabbixClient = FakeZbx
        out = asyncio.run(ask.fetch_metrics({"host": "web-01", "source": "s"}, "cpu",
                                            1786500000, 1786500600))
    finally:
        collector.ZabbixClient = saved

    hist = [c for c in calls if c[0] == "history.get"]
    assert len(hist) <= 2, "아이템마다 따로 물었다: %d번" % len(hist)
    # 값 유형이 섞이면 나눠 부른다. 한 번에 두 유형을 넣으면 Zabbix 가 못 받는다.
    for _m, params in hist:
        assert isinstance(params["itemids"], list), params
        assert isinstance(params["history"], int), params
    # 받은 값이 아이템별로 갈려야 한다. 한 덩어리를 그대로 붙이면 남의 값이 섞인다.
    got = {m["name"]: m["sampled_from"] for m in out["metrics"]}
    assert got.get("CPU utilization") == 1, got
    assert got.get("Processes") == 1, got
    return 6




def _no_evidence_checks() -> int:
    """조회가 한 건도 성공하지 않았는데 "없습니다" 로 답하지 않는가."""
    import asyncio

    from .. import ask

    table = {ask.proxy.token_for("host", "web-01"):
             {"host": "web-01", "source": "s", "logs": "web-01", "security": ""}}
    tok = list(table)[0]

    def model(system, messages, tools):
        if len(messages) == 1:
            # 깨진 인자 — 도구가 거부한다.
            return {"stop_reason": "tool_use", "content": [
                {"type": "tool_use", "id": "t1", "name": "host_logs",
                 "input": {"host": tok, "contains": '어제 "로그" {x}'}}]}
        return {"stop_reason": "tool_use", "content": [
            {"type": "tool_use", "id": "t2", "name": "answer",
             "input": {"summary": "그 시간대 로그가 없습니다"}}]}

    r = asyncio.run(ask.run_ask("어제 로그", table=table, model_fn=model))
    assert ask.NO_EVIDENCE in r["text"], r["text"]

    # 성공한 조회가 있으면 붙이지 않는다. 늘 붙으면 사람이 그 문장을 무시한다.
    def ok_model(system, messages, tools):
        if len(messages) == 1:
            return {"stop_reason": "tool_use", "content": [
                {"type": "tool_use", "id": "t1", "name": "list_hosts",
                 "input": {"query": ""}}]}
        return {"stop_reason": "tool_use", "content": [
            {"type": "tool_use", "id": "t2", "name": "answer",
             "input": {"summary": "호스트는 하나다"}}]}

    r2 = asyncio.run(ask.run_ask("호스트 뭐 있어", table=table, model_fn=ok_model))
    assert ask.NO_EVIDENCE not in r2["text"], r2["text"]

    # 답 도구를 안 쓰고 산문으로 끝내도 마찬가지다. 그 길이 열려 있는 한 같은 일이 난다.
    def prose(system, messages, tools):
        if len(messages) == 1:
            return {"stop_reason": "tool_use", "content": [
                {"type": "tool_use", "id": "t1", "name": "host_logs",
                 "input": {"host": tok, "contains": '깨진 "값" {x}'}}]}
        return {"stop_reason": "end_turn",
                "content": [{"type": "text", "text": "그 시간대에는 로그가 없습니다"}]}

    r3 = asyncio.run(ask.run_ask("어제 로그", table=table, model_fn=prose))
    assert ask.NO_EVIDENCE in r3["text"], r3["text"]
    return 4




def _now_context_checks() -> int:
    """모델이 지금이 언제인지 아는가."""
    import asyncio

    from .. import ask

    seen = {}

    def model(system, messages, tools):
        seen["blob"] = str(messages)
        return {"stop_reason": "end_turn", "content": [{"type": "text", "text": "끝"}]}

    table = {ask.proxy.token_for("host", "web-01"):
             {"host": "web-01", "source": "s", "logs": "", "security": ""}}
    asyncio.run(ask.run_ask("어제 로그 보여줘", table=table, model_fn=model,
                            now=1786600000))
    # 지금이 언제인지 UTC 로 적어 준다. 값을 지어내지 않게 형식도 함께 준다.
    assert "2026-08-13" in seen["blob"], seen["blob"][:300]
    assert "UTC" in seen["blob"], seen["blob"][:300]

    asyncio.run(ask.run_ask("이 패널 뭐야", table=table, model_fn=model, now=1786600000,
                            panel={"uid": "u1", "panelId": 2, "title": "t"}))
    assert "2026-08-13" in seen["blob"], "패널 맥락이 지금 시각을 덮어썼다"
    assert "보고 있는 패널" in seen["blob"], seen["blob"][:300]
    return 4




def _event_loop_checks() -> int:
    """느린 저장소가 다른 요청까지 세우지 않는가."""
    import asyncio
    import time

    from .. import app as gw

    async def scenario():
        ticks = {"n": 0}

        async def heartbeat():
            # 루프가 살아 있으면 계속 돈다. 막히면 이 값이 안 는다.
            for _ in range(40):
                await asyncio.sleep(0.005)
                ticks["n"] += 1

        def slow():
            time.sleep(0.12)                       # 늦는 저장소
            return "ok"

        beat = asyncio.ensure_future(heartbeat())
        await gw._off_loop(slow)
        got = ticks["n"]
        beat.cancel()
        return got

    ticked = asyncio.run(scenario())
    assert ticked > 3, "저장소가 도는 동안 이벤트 루프가 멈췄다 (tick=%d)" % ticked
    return 1




def _panel_status_checks() -> int:
    """패널 조회가 실패했을 때 "없다" 로 나가지 않는가."""
    import asyncio

    from .. import ask
    from ..alerts import collector
    from ..integrations import grafana
    from ..ask import tools as asktools

    saved = grafana.list_panels
    try:
        # ① 조회가 실패하면 "없음" 이 아니라 "확인 못 했다" 로 말한다.
        def boom(dash_match="", limit=40):
            raise RuntimeError("grafana down")

        grafana.list_panels = boom
        out = asyncio.run(asktools.run_tool("list_panels", {"dashboard": ""},
                                            {"list_panels": lambda d: ask.fetch_panel_list(
                                                d, ask.proxy.build_masker())}))
        assert out.get("status") == collector.SOURCE_UNAVAILABLE, out
        assert "없" not in (out.get("note") or ""), out

        # ② 주소가 없으면 미배선이다. 그것도 "없음" 이 아니다.
        grafana.list_panels = lambda dash_match="", limit=40: []
        saved_base = grafana._base
        try:
            grafana._base = lambda: ""
            out2 = asyncio.run(asktools.run_tool("list_panels", {"dashboard": ""},
                                                 {"list_panels": lambda d: ask.fetch_panel_list(
                                                     d, ask.proxy.build_masker())}))
        finally:
            grafana._base = saved_base
        assert out2.get("status") == collector.SOURCE_DISABLED, out2

        # ③ 정상 조회는 예전 그대로다.
        def ok(dash_match="", limit=40):
            return [{"uid": "u1", "panel_id": 3, "dashboard": "d", "title": "t"}]

        grafana.list_panels = ok
        ctx = {"list_panels": lambda d: ask.fetch_panel_list(d, ask.proxy.build_masker())}
        out3 = asyncio.run(asktools.run_tool("list_panels", {"dashboard": ""}, ctx))
        assert out3.get("status") == collector.SOURCE_OK and out3["panels"], out3
    finally:
        grafana.list_panels = saved
    return 5




def _session_isolation_checks() -> int:
    """한 사람의 멈춤이 남의 질문을 끊지 않는가."""
    import asyncio

    from .. import ask

    ask.forget_all()
    # ① 사람이 다르면 열쇠도 다르다. 화면이 같은 이름을 보내도 그렇다.
    a, b = ask.session_key("ui", "swoo"), ask.session_key("ui", "kim")
    assert a != b, (a, b)
    assert ask.session_key("ui", "swoo") == a          # 같은 사람은 같은 열쇠

    # ② 한쪽 멈춤이 다른 쪽을 끊지 않는다.
    ask.cancel(a)
    assert ask.cancelled(b, started=0.0) is False, "남의 세션이 함께 멈췄다"
    assert ask.cancelled(a, started=0.0) is True

    # 끝난 뒤 도착한 멈춤은 다음 질문을 죽이지 않는다
    ask.forget_all()
    ask.cancel(a)
    later = ask._now() + 10
    assert ask.cancelled(a, started=later) is False, "지난 취소가 새 질문을 죽였다"

    # ④ 한 번 쓰면 지워진다. 남아 있으면 그다음 질문도 죽는다.
    ask.forget_all()
    ask.cancel(a)
    assert ask.cancelled(a, started=0.0) is True
    assert ask.cancelled(a, started=0.0) is False

    # ⑤ 실경로 — 도는 중에 누르면 다음 라운드에서 멈춘다.
    table = {ask.proxy.token_for("host", "web-01"):
             {"host": "web-01", "source": "s", "logs": "", "security": ""}}

    def model(system, messages, tools):
        # 첫 호출 뒤에 사람이 멈춤을 누른 상황이다.
        ask.cancel(ask.session_key("ui", "swoo"))
        return {"stop_reason": "tool_use", "content": [
            {"type": "tool_use", "id": "t1", "name": "list_hosts", "input": {"query": ""}}]}

    r = asyncio.run(ask.run_ask("뭐 있어", table=table, model_fn=model,
                                sid="ui", user="swoo"))
    assert r["stopped"] == "cancelled", r["stopped"]

    # ⑥ **남의 멈춤은 내 질의를 끊지 않는다.** 화면이 같은 세션 이름을 보내도 그렇다.
    def model2(system, messages, tools):
        ask.cancel(ask.session_key("ui", "kim"))       # 다른 사람이 눌렀다
        return {"stop_reason": "end_turn", "content": [{"type": "text", "text": "끝"}]}

    r2 = asyncio.run(ask.run_ask("뭐 있어", table=table, model_fn=model2,
                                 sid="ui", user="swoo"))
    assert r2["stopped"] == "end_turn", r2["stopped"]
    ask.forget_all()
    return 10




def _prewarm_checks() -> int:
    """기동 예열이 다른 호출과 같은 출구를 지나는가."""
    from .. import ask, egress

    saved = egress.call_raw
    seen = {}
    try:
        def spy(fn, exempt=False, kind="", user=""):
            seen["kind"] = kind
            return {"ok": True, "value": {"content": []}, "reason": "", "elapsed_s": 0.0}

        egress.call_raw = spy
        # 표를 못 만들면 예열은 거기서 끝난다. 상류를 부르는 자리까지 가게 세운다.
        saved_build = ask.build_table

        async def table(*a, **kw):
            return {"[h-1]": {"host": "web-01", "source": "s"}}

        ask.build_table = table
        try:
            msg = ask.prewarm()
        finally:
            ask.build_table = saved_build
        assert "완료" in msg, msg
        assert seen.get("kind") == "ask", seen
    finally:
        egress.call_raw = saved
    return 2




def _log_cap_checks() -> int:
    """로그가 잘렸을 때 그 사실이 **실경로로** 결과에 붙는가."""
    import asyncio

    from ..ask import tools as asktools

    got = {}

    async def logs(q, a, b, limit):
        got["limit"] = limit
        # 상한을 꽉 채워 돌려준다. 최신 쪽만 실렸다는 뜻이다.
        return {"logs": [{"t": 1, "line": "x"}] * limit, "fetched": limit, "status": "ok"}

    ctx = {"table": {"[h-1]": {"host": "web-01", "source": "s", "logs": "web-01",
                               "security": ""}},
           "now": 1786590000, "fetch_logs": logs}
    out = asyncio.run(asktools.run_tool("host_logs", {"host": "[h-1]"}, ctx))
    assert "앞부분은 안 들어왔다" in (out.get("note") or ""), out
    assert got["limit"] == asktools.LOG_LIMIT_DEFAULT, got

    # 잘렸다고 안내했으면 더 달라고 할 길이 있어야 한다
    out3 = asyncio.run(asktools.run_tool("host_logs", {"host": "[h-1]", "limit": 300}, ctx))
    assert got["limit"] == 300, got
    assert "앞부분은 안 들어왔다" in (out3.get("note") or ""), out3
    # 그 상한에도 상한이 있다.
    asyncio.run(asktools.run_tool("host_logs", {"host": "[h-1]", "limit": 99999}, ctx))
    assert got["limit"] == asktools.LOG_LIMIT_MAX, got

    # 상한을 안 채웠으면 붙이지 않는다. 늘 붙으면 사람이 통지를 무시한다.
    async def few(q, a, b, limit):
        return {"logs": [], "fetched": 3, "status": "ok"}

    out2 = asyncio.run(asktools.run_tool("host_logs", {"host": "[h-1]"},
                                         dict(ctx, fetch_logs=few)))
    assert "앞부분은 안 들어왔다" not in (out2.get("note") or ""), out2
    return 7




def _empty_table_checks() -> int:
    """이름 표가 비었을 때 안전한 쪽으로 실패하는가."""
    import asyncio
    import os

    from .. import ask, masking, nametable

    saved, saved_env = dict(nametable._terms), os.environ.get("PROXY_ALLOW_UNMASKED")
    try:
        nametable._terms = {}
        os.environ.pop("PROXY_ALLOW_UNMASKED", None)
        # 앞선 검사가 남긴 세션 토큰이 합쳐지면 마스커가 이름을 들고 있게 된다.
        ask.forget_all()
        # 표가 비면 "가릴 수 없다"로 답한다 — _leaks 는 볼 이름이 없어 통과한다
        assert masking._leaks("아무 문장") is False
        assert masking.cannot_mask() is True

        # ② 이름을 하나도 안 들고 있으면 질의가 나가지 않는다. 사유를 사람에게 말한다.
        def model(system, messages, tools):
            raise AssertionError("가릴 수 없는데 모델을 불렀다")

        r = asyncio.run(ask.run_ask("뭐 있어", table={"[host-1]": {}}, model_fn=model))
        assert r["stopped"] == "rejected", r
        assert "이름" in r["error"], r

        # 대상 표에 이름이 있으면 나간다 — 전역 표가 비었다고 무조건 막지 않는다
        table = {ask.proxy.token_for("host", "web-01"):
                 {"host": "web-01", "source": "s", "logs": "", "security": ""}}
        called = {}

        def model2(system, messages, tools):
            called["yes"] = True
            return {"stop_reason": "end_turn", "content": [{"type": "text", "text": "끝"}]}

        asyncio.run(ask.run_ask("뭐 있어", table=table, model_fn=model2))
        assert called.get("yes"), "가릴 수 있는데 막았다"

        # ③ 운영자가 파일에 적어 둔 배포는 통과한다. 랩이 그 설정이다.
        os.environ["PROXY_ALLOW_UNMASKED"] = "1"
        assert masking.cannot_mask() is False
    finally:
        nametable._terms = saved
        os.environ.pop("PROXY_ALLOW_UNMASKED", None)
        if saved_env is not None:
            os.environ["PROXY_ALLOW_UNMASKED"] = saved_env
    return 8




def _query_masking_checks() -> int:
    """질의 도구 결과에 실명이 남아 모델로 가지 않는가."""
    import asyncio
    import json as _js

    from .. import ask, nametable

    saved = dict(nametable._terms)
    try:
        nametable._terms = {"cust-web-01": "host", "shop.example.co.kr": "host"}
        mk = ask.proxy.build_masker()

        # ① 지표 — 아이템 이름과 키에 실명이 들어 있다.
        items = [{"itemid": "1", "name": "Cert expiry: shop.example.co.kr",
                  "key_": "web.certificate.get[shop.example.co.kr,443]",
                  "units": "s", "lastvalue": "10"}]
        out = ask.metrics_result(items, {"1": []}, mk)
        blob = _js.dumps(out, ensure_ascii=False)
        assert "shop.example.co.kr" not in blob, blob

        # ② 열린 문제 — Zabbix 문제명은 매크로가 풀려 호스트명이 박혀 있다.
        rows = [{"name": "Zabbix agent is not available on cust-web-01",
                 "severity": "4", "clock": "1786590000"}]
        out2 = ask.problems_result(rows, mk)
        assert "cust-web-01" not in _js.dumps(out2, ensure_ascii=False), out2

        # ③ 실경로 — ctx 배선이 빠지면 위 두 검사가 통과해도 원문이 나간다.
        table = {ask.proxy.token_for("host", "cust-web-01"):
                 {"host": "cust-web-01", "source": "zabbix-internal",
                  "logs": "", "security": ""}}
        tok = list(table)[0]
        seen = {}

        def model(system, messages, tools):
            if len(messages) == 1:
                return {"stop_reason": "tool_use", "content": [
                    {"type": "tool_use", "id": "t1", "name": "open_problems",
                     "input": {"host": tok}}]}
            seen["blob"] = str(messages[-1])
            return {"stop_reason": "end_turn", "content": [{"type": "text", "text": "끝"}]}

        # 마스커는 배선이 준 것을 쓴다 — 자기 마스커를 쓰면 배선이 빠져도 통과한다
        saved_fp = ask.fetch_problems
        try:
            async def spy(ent, masker=None):
                seen["masker"] = masker
                return ask.problems_result(rows, masker)

            ask.fetch_problems = spy
            r = asyncio.run(ask.run_ask("문제 뭐 있어", table=table, model_fn=model))
        finally:
            ask.fetch_problems = saved_fp
        assert seen.get("masker") is not None, "배선이 마스커를 안 넘긴다"
        assert "cust-web-01" not in seen.get("blob", ""), seen.get("blob", "")[:200]
        assert r["stopped"] == "end_turn", r
    finally:
        nametable._terms = saved
    return 6




def _ask_dispatch_checks() -> int:
    """도구를 실제로 부를 때 무엇을 막는가."""
    import asyncio
    import json

    from .. import store
    from ..ask import tools as asktools

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

    # 모델은 대괄호를 떼고 넣기도 한다 — 같은 대상으로 본다
    r = asyncio.run(asktools.run_tool("host_logs", {"host": "host-aaa"}, ctx))
    assert not r.get("error"), r

    # 대상을 찾는 규칙은 도구마다 같아야 한다
    async def _j(host, days):
        return {"judgments": [], "status": "ok"}

    async def _p(ent):
        return {"problems": [], "status": "ok"}

    ctx2 = dict(ctx, fetch_judgments=_j, fetch_problems=_p)
    for tool_name in ("past_judgments", "open_problems"):
        r = asyncio.run(asktools.run_tool(tool_name, {"host": "host-aaa"}, ctx2))
        assert not r.get("error"), (tool_name, r)

    # 일수는 분 상한에 걸리면 안 된다 — 30일이 1일이 됐다
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

    from .. import ask, registry
    from ..alerts import collector, incident as inc_mod

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

        # 캐시를 비우고 본다 — 여기서 보려는 것은 캐시가 없을 때다
        ask.forget_tables()
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

    from .. import ask, nametable
    from ..ask import tools as asktools

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

        # 답을 도구로 받는다 — 산문으로 받으면 표시가 글자로 남고 구간이 지어내진다
        def answers(system, messages, tools):
            return {"stop_reason": "tool_use", "content": [
                {"type": "tool_use", "id": "t1", "name": "answer",
                 "input": {"summary": "복제는 정상이다",
                           "findings": ["지연 0초", "IO/SQL 모두 Yes"]}}]}

        r = asyncio.run(ask.run_ask("복제 상태", table=table, model_fn=answers))
        assert "복제는 정상이다" in r["text"], r["text"]
        assert "지연 0초" in r["text"], r["text"]
        assert r["stopped"] == "end_turn", r["stopped"]

        # 없는 그림 표시는 되돌려 고치게 한다 — 예외로 끝내면 사람은 오류를 본다
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

        # 표를 먼저 만들고 질문을 가린다 — 순서가 거꾸로면 안 가려진 채 나간다
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

        # 줄여 쓴 이름도 같은 토큰으로 가린다
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

        # 일부만 적은 이름도 대상으로 푼다
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

        # 이력은 창으로 자르고, 버린 사실을 모델에게 알린다
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

        # 패널 그림은 표시만 준다 — 주소에 대시보드 식별자와 실명이 들어 있다
        shots = []

        def cap5(system, messages, tools):
            shots.append(json.dumps(messages, ensure_ascii=False))
            if len(shots) == 1:
                return {"stop_reason": "tool_use", "content": [
                    {"type": "tool_use", "id": "p1", "name": "panel_image",
                     "input": {"host": list(long_tbl)[0], "match": "CPU"}}]}
            return _text("아래 그림을 보라 img-1")

        async def fake_panel(ent, target, a, b):
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

        # 같은 조회를 두 번 하지 않는다
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

        # 과거 판정의 분석 문장을 싣되 마스킹 누수 검사를 통과할 때만 (prior 와 같은 규칙)
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

        # 실제 토큰 수로 센다 — 호출 횟수만 세면 짧은 질문과 긴 조사가 같다
        import os as _os
        import shutil as _sh
        import tempfile as _tf

        from .. import store as st2

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
            # 열쇠에 신원이 들어가므로 화면이 보내는 이름만으로는 남의 세션을 못 멈춘다
            ask.cancel(ask.session_key("sess-x"))
            return {"stop_reason": "tool_use", "content": [
                {"type": "tool_use", "id": "c1", "name": "list_hosts", "input": {}}]}

        r = asyncio.run(ask.run_ask("멈춤", table=long_tbl, model_fn=keeps_going,
                                    sid="sess-x"))
        assert r["stopped"] == "cancelled", r["stopped"]
        assert len(r["trace"]) <= 1, r["trace"]
        assert r["text"], "멈춰도 사람에게 할 말은 있어야 한다"

        # 보던 패널은 맥락으로만 알린다 — 무조건 붙이면 질문마다 다시 그려진다
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

        # 이력도 가린다 — 화면은 실명으로 되돌린 글을 이력으로 되보낸다
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

        # 한 기계의 세 이름을 모두 가린다 — 패널이 넘기는 것은 Zabbix 이름이다
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

        # 그림 표시는 화면에 글자로 남기지 않는다
        assert ask.strip_handles("아래 [img-6598] 를 보라") == "아래 를 보라"
        assert ask.strip_handles("img-6598 참고") == "참고"
        # 비슷하지만 표시가 아닌 말은 안 건드린다
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
    """LangGraph 엔진이 기존 반복문과 **같은 계약**을 지키는가."""
    import asyncio
    import os

    from .. import ask, nametable
    from ..ask import graph

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

        # 답을 받으면 모델을 더 부르지 않는다 — 질의마다 호출 하나와 5~15초가 더 들었다
        def answering():
            n = {"i": 0}

            def model(system, messages, tools):
                n["i"] += 1
                if n["i"] == 1:
                    return _tool_use("list_hosts", {})
                if n["i"] == 2:
                    return _tool_use("answer", {"summary": "web-01 하나뿐이다"})
                raise AssertionError("답을 받고도 모델을 또 불렀다")
            return model, n

        for engine in ("loop", "graph"):
            m, n = answering()
            r = run(engine, m)
            assert "web-01 하나뿐이다" in r["text"], (engine, r["text"])
            assert n["i"] == 2, (engine, n["i"])

        # 라운드 상한이 그래프에서도 걸린다 — 프레임워크 상한이 먼저 닿으면 예외가 보인다
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
    """사용량이 사용자별로 세어지는가."""
    import os
    import shutil
    import tempfile

    from .. import ask, store

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
        # 열어 둔 채 끝내지 않는다 — store.init() 은 이미 열려 있으면 아무것도 안 한다
        store.close()
        store.PATH = saved_path
        shutil.rmtree(d, ignore_errors=True)
    return 9




def _convo_checks() -> int:
    """대화 이력 — 사용자별로 나뉘고, 목록이 보이고, 만료가 있는가.

    저장소가 죽어도 질의 자체는 돌아야 한다. 대화는 다시 물으면 되지만 조회는 아니다.
    """
    from .. import convo

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

        # 그림도 함께 남긴다 — 답 본문만 저장하면 새로고침에 패널 그림이 사라진다
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
