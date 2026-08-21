"""심층 조사 모드 검사 — 가설표·상태 전이·질의 계약.

설계와 근거는 private/docs/deep_mode_design.md. 여기서 잠그는 것은 그 문서가 FORGE 실패
분류(RF-xx)에 맞춰 정한 규칙들이고, 대부분 코드가 판정하는 것이라 검사로 고정할 수 있다.
"""


def _hypothesis_checks() -> int:
    """가설표 — 사슬 단위·인용 검사·H0 의 예외 지위."""
    from ..deep import hypothesis as H

    recs = {"metrics#1": {"status": "ok"}, "logs#1": {"status": "ok"},
            "security#1": {"status": "unavailable"}, "logs#2": {"status": "unmatched"}}

    # ① 인용은 실재하는 축 기록만 (RF-07 임의 증거 선택 · RF-01 증거 조작)
    ok = H.validate({"id": "H1", "claim": "c", "if_true": "a", "if_false": "b",
                     "supports": ["metrics#1"], "contradicts": []}, recs)
    assert ok[0], ok
    bad = H.validate({"id": "H2", "claim": "c", "if_true": "a", "if_false": "b",
                      "supports": ["metrics#99"], "contradicts": []}, recs)
    assert not bad[0], "없는 기록을 인용한 가설은 폐기한다"
    assert "metrics#99" in bad[1], bad

    # ②-a H0 는 코드가 만든다. 인용이 없어도 폐기되지 않는다.
    h0 = H.null_hypothesis()
    assert h0["id"] == H.NULL_ID
    assert not h0.get("supports") and not h0.get("contradicts")
    assert H.validate(h0, recs)[0], "H0 는 인용 요건의 대상이 아니다"

    # ②-b H0 는 머릿수에도 미결에도 안 든다 — 안 그러면 루프가 안 끝난다
    table = [h0, {"id": "H1", "status": "미결"}]
    assert H.count_real(table) == 1, "둘 이상 강제에 H0 를 세면 안 된다"
    assert H.open_count(table) == 1, "H0 는 미결로 세지 않는다"
    assert not H.enough(table), "실질 가설이 하나면 둘 이상 요건 미달"
    assert H.enough([h0, {"id": "H1", "status": "미결"}, {"id": "H2", "status": "미결"}])

    # ③ 상태 전이 — 조회 실패로는 아무것도 기각 못 한다 (RF-08, G1 확장)
    for rid, allowed in (("metrics#1", True), ("security#1", False), ("logs#2", False)):
        got = H.transition("미결", "기각", rid, recs)
        assert got[0] is allowed, (rid, got)
    assert not H.transition("미결", "기각", "logs#2", recs)[0], \
        "unmatched 는 '그 소스가 이 호스트를 모른다'이지 '없었다'가 아니다"

    # ④ 반증이 있는데 상태가 그대로면 실패 (RF-09 신념 미갱신)
    stale = {"id": "H1", "status": "지지", "supports": ["metrics#1"],
             "contradicts": ["logs#1"]}
    assert H.stale_belief(stale), "반증을 받고도 지지로 남아 있으면 잡아야 한다"
    assert not H.stale_belief({"id": "H1", "status": "미결",
                               "supports": [], "contradicts": ["logs#1"]})

    # ⑤ 종료 사유 셋 — 공동 원인이 있어야 대표 사건이 끝난다
    one = [{"id": "H1", "status": "지지"}, {"id": "H2", "status": "기각"}]
    assert H.done(one, probes_left=True)[0] == "판가름"
    both = [{"id": "H1", "status": "지지"}, {"id": "H2", "status": "지지"}]
    assert H.done(both, probes_left=True)[0] == "공동원인", \
        "둘 다 지지면 복합 원인이다 — 여기서 안 끝나면 대표 사건이 영영 안 끝난다"
    stuck = [{"id": "H1", "status": "미결"}, {"id": "H2", "status": "미결"}]
    assert H.done(stuck, probes_left=False)[0] == "못가름"
    assert H.done(stuck, probes_left=True)[0] == "", "가를 질의가 남았으면 계속한다"

    # ⑥ 전부 기각이면 H0 가 답이다. 덜 기각된 것을 고르면 안 된다.
    allbad = [h0, {"id": "H1", "status": "기각"}, {"id": "H2", "status": "기각"}]
    assert H.done(allbad, probes_left=False)[0] == "판가름"
    assert H.winner(allbad) == H.NULL_ID, "전부 기각이면 '어느 것도 아니다'가 답이다"
    assert H.winner(one) == "H1"
    assert H.winner(both) is None, "공동 원인은 승자가 하나가 아니다"
    return 22


def _probe_checks() -> int:
    """질의 계약 — 가르는 질의만, 중복은 코드가 막는다 (RF-12 반복·정체)."""
    from ..deep import probe as P

    table = [{"id": "H1", "if_true": "iowait 급등", "if_false": "iowait 평상"},
             {"id": "H2", "if_true": "백업 마커 있음", "if_false": "백업 흔적 없음"}]

    # ① 선언한 가설이 실재해야 한다
    ok, why = P.validate({"tool": "host_metrics", "args": {"host": "[host-1]"},
                          "discriminates": ["H1"], "why": "iowait 를 본다"}, table, seen=set())
    assert ok, why
    bad, why = P.validate({"tool": "host_metrics", "args": {}, "discriminates": ["H9"],
                           "why": "x"}, table, seen=set())
    assert not bad and "H9" in why, why

    # ② 아무 가설도 안 가르면 거부한다
    none, why = P.validate({"tool": "host_metrics", "args": {}, "discriminates": [],
                            "why": "그냥 본다"}, table, seen=set())
    assert not none, "무엇을 가르는지 못 적으면 던지지 않는다"

    # ③ 도구는 닫힌 카탈로그에서만 (조회문은 코드가 소유한다)
    off, why = P.validate({"tool": "run_shell", "args": {}, "discriminates": ["H1"],
                           "why": "x"}, table, seen=set())
    assert not off and "run_shell" in why, why

    # ④ **중복 질의 지문 거부** — 이 설계의 출발점인 낭비(같은 지표 4회)를 죽이는 자리
    req = {"tool": "host_metrics", "args": {"host": "[host-1]", "match": "cpu"},
           "discriminates": ["H1"], "why": "x"}
    fp = P.fingerprint(req)
    dup, why = P.validate(req, table, seen={fp})
    assert not dup and "중복" in why, why

    # 인자 순서·공백이 달라도 같은 질의다 — 안 그러면 우회가 된다
    same = {"tool": "host_metrics", "args": {"match": "cpu", "host": "[host-1] "},
            "discriminates": ["H1"], "why": "다르게 적었다"}
    assert P.fingerprint(same) == fp, "인자 순서·공백으로 중복 검출을 피할 수 없어야 한다"
    # 가르는 대상이 달라도 같은 조회면 중복이다 — 지문은 tool·args 만 본다
    other = dict(req, discriminates=["H2"], why="다른 이유")
    assert P.fingerprint(other) == fp
    return 12


def _time_order_checks() -> int:
    """RF-04 시간 역순 — **발단 순서**로 본다. 지속 원인의 겹침은 허용한다."""
    from ..deep import verify as V

    # 백업(원인)은 사건 내내 돌고 지연(결과)은 그 도중에 커진다 — 우리 대표 시나리오
    cause = {"id": "logs#1", "t_first": 1000, "t_last": 1900}
    effect = {"id": "metrics#1", "t_first": 1200, "t_last": 1900}
    assert V.time_ok(cause, effect), \
        "지속 원인이 결과와 겹치는 것은 정상이다 — 막으면 대표 시나리오를 스스로 기각한다"

    # 결과가 먼저 시작했으면 인과 방향이 틀렸다
    assert not V.time_ok({"t_first": 1500, "t_last": 1900},
                         {"t_first": 1200, "t_last": 1900})

    # 시각을 모르면 막지 않는다 — 근거 없이 기각하지 않는다는 이 리포의 규칙
    assert V.time_ok({"t_first": 0, "t_last": 0}, effect)
    assert V.time_ok(cause, {"t_first": 0, "t_last": 0})
    return 4


def _condense_adapter_checks() -> int:
    """축약 어댑터 — 사용량 매핑과 **판단 경로 오염 금지**."""
    import os

    from .. import llm
    from ..deep import condense
    from ..integrations import openai_luna

    # ① 어댑터 계약 — 출구가 읽는 자리를 다 갖췄는가
    ad = openai_luna.LunaAdapter()
    for attr in ("name", "available", "complete", "last_usage", "model"):
        assert hasattr(ad, attr), attr
    assert ad.name != "claude", "이름이 겹치면 사용량 표에서 안 갈린다"

    # ② OpenAI 는 토큰 이름이 다르다. 잘못 매핑하면 **공급자가 조용히 무료로 보인다.**
    got = openai_luna.map_usage({
        "usage": {"prompt_tokens": 100, "completion_tokens": 20,
                  "prompt_tokens_details": {"cached_tokens": 60}},
        "model": "gpt-5.6-luna"})
    assert got["in"] == 100 and got["out"] == 20, got
    assert got["cache_read"] == 60, "cached_tokens 를 캐시 읽기로 옮겨야 한다"
    assert got["cache_write"] == 0, "OpenAI 는 캐시 쓰기 개념이 없다"
    assert got["model"] == "gpt-5.6-luna"
    assert openai_luna.map_usage({}) is None, "사용량이 없으면 추정하지 않는다"

    # ③ ⭐ **판단 경로에 Luna 가 섞이면 안 된다.**
    #    `_adapters()` 는 등록부가 아니라 폴백 체인이라, 넣으면 Claude 가 죽는 순간
    #    트리아지 판단 프롬프트와 월간 리포트가 통째로 OpenAI 로 간다.
    saved = os.environ.get("OPENAI_API_KEY")
    os.environ["OPENAI_API_KEY"] = "sk-검사용"
    try:
        for kind in ("triage", "write"):
            names = [a.name for a in llm._adapters(kind)]
            assert openai_luna.LunaAdapter.name not in names, (
                f"{kind} 체인에 축약 모델이 들어갔다 — 판단이 값싼 모델로 넘어간다")

        # ④ 축약 전용 체인은 Luna 가 앞이고 haiku 가 뒤다(열화 경로)
        chain = [a.name for a in condense.adapters()]
        assert chain and chain[0] == openai_luna.LunaAdapter.name, chain
        assert "claude" in chain, "Luna 가 없거나 죽으면 haiku 로 내려가야 한다"

        # ⑤ 키가 없으면 Luna 는 스스로 빠진다 — 체인이 비지 않는다
        os.environ.pop("OPENAI_API_KEY", None)
        chain2 = [a.name for a in condense.adapters() if a.available()]
        assert openai_luna.LunaAdapter.name not in chain2
    finally:
        if saved is None:
            os.environ.pop("OPENAI_API_KEY", None)
        else:
            os.environ["OPENAI_API_KEY"] = saved
    return 14


def _memory_checks() -> int:
    """구조화 기억 — 누적이 아니라 재구성인가, 그리고 축약이 사건을 못 보는가."""
    from ..deep import memory as M
    from ..deep import state as S

    inc = {"host": "[host-1]", "names": ["복제 지연"], "classes": ["replication"],
           "sev": "SEV2", "verdict": "신규", "statement": "90일 내 처음"}
    st = S.new_state(inc, {})

    # ① 라운드가 늘어도 프롬프트가 선형으로 안 부푼다 — 이게 이 설계의 출발점이다
    for i in range(1, 4):
        st["round"] = i
        M.put_record(st, {"id": "logs#%d" % i, "axis": "logs", "status": "ok",
                          "finding": "오류 급증", "evidence": ["줄 %d" % i],
                          "units": "count", "baseline_status": "ok"})
        M.add_step(st, "%d라운드: 로그를 봤다" % i)
    a = len(M.render(st))
    for i in range(4, 7):
        st["round"] = i
        M.put_record(st, {"id": "logs#%d" % i, "axis": "logs", "status": "ok",
                          "finding": "오류 급증", "evidence": ["줄 %d" % i],
                          "units": "count", "baseline_status": "ok"})
        M.add_step(st, "%d라운드: 로그를 봤다" % i)
    b = len(M.render(st))
    assert b < a * 2.2, "라운드가 두 배인데 프롬프트가 두 배 넘게 늘면 누적이다 (%d→%d)" % (a, b)

    # ② 조회 상태와 평소값 없음이 글에 드러난다 — 모델이 빈 값을 "없었다"로 못 읽게
    st2 = S.new_state(inc, {})
    M.put_record(st2, {"id": "security#1", "axis": "security", "status": "unavailable",
                       "finding": "조회하지 못했다", "baseline_status": "unavailable",
                       "units": "—"})
    txt = M.render(st2)
    assert "unavailable" in txt and "평소값 없음" in txt, txt

    # ③ 감시 인프라에서 온 기록은 그렇게 표시된다 (RF-03 출처 혼동)
    M.put_record(st2, {"id": "logs#1", "axis": "logs", "status": "ok",
                       "origin": "monitoring", "finding": "에이전트가 죽었다",
                       "units": "—", "baseline_status": "ok"})
    assert "감시 인프라" in M.render(st2)

    # ④ ⭐ 축약 입력에는 사건 서사도 다른 축도 가설도 안 실린다
    st2["table"] = [{"id": "H1", "claim": "가설 문장", "status": "미결"}]
    payload = M.condense_input("logs", "평소 대비 무엇이 다른가",
                               {"lines": ["a"]}, {"lines": ["b"]},
                               goal="[host-1] 복제 지연")
    for leak in ("SEV2", "가설 문장", "신규", "security#1"):
        assert leak not in payload, "축약 입력에 %r 이 실렸다" % leak
    assert "incident_window" in payload and "baseline_window" in payload

    # ⑤ ⭐ 무엇을 조사하는지는 준다. 랩 실증에서 축약이 복제 지연·iowait 대신 메모리와
    #    버퍼풀을 남겼다 — 계열이 여럿일 때 무엇을 남길지 고를 근거가 없었다.
    assert "복제 지연" in payload, payload[:200]
    assert "[host-1]" in payload and "vm-" not in payload

    # ⑥ 기록 id 는 축마다 이어서 붙는다
    assert M.next_record_id(st2, "metrics") == "metrics#1"
    assert M.next_record_id(st2, "logs") == "logs#2"

    # ⑦ 조사와 검증이 같은 목표를 넘긴다 — 한쪽만 넘기면 라운드마다 기준이 달라진다
    import inspect

    from ..deep import run as deep_run
    src = inspect.getsource(deep_run)
    assert src.count("goal=goal") >= 2, "조사와 검증 중 한쪽이 목표를 안 넘긴다"
    return 15


def _state_checks() -> int:
    """상태 불변식 — 어긋나면 예외가 아니라 사유를 낸다."""
    from ..deep import state as S

    recs = {"logs#1": {"status": "ok"}}
    st = S.new_state({"host": "h"}, recs)
    assert S.check(st) == ""

    st["stopped"] = "몰라"
    assert "모르는 멈춤" in S.check(st)
    st["stopped"] = "공동원인"
    assert S.check(st) == "", "종료 사유 셋은 정상 값이어야 한다"

    st["table"] = [{"id": "H1"}, {"id": "H1"}]
    assert "두 번" in S.check(st)

    st["table"] = [{"id": "H1", "supports": ["없는#9"], "contradicts": []}]
    assert "없는 기록" in S.check(st)

    st["table"] = [{"id": "H1", "status": "지지",
                    "supports": ["logs#1"], "contradicts": ["logs#1"]}]
    assert "반증을 받고도" in S.check(st), "RF-09 를 상태 검사에서도 잡는다"

    st["table"] = []
    st["seen"] = ["a", "b"]
    st["probes"] = ["a"]
    assert "지문 표" in S.check(st)
    return 8


def _baseline_checks() -> int:
    """정상 구간 — 빈 창을 "평소엔 없었다"로 읽지 않는가."""
    import time

    from ..ask import tools as asktools
    from ..deep import baseline as B

    now = int(time.time())
    inc = (now - 3600, now)

    # ① 같은 요일·시간대로 옮긴다 — 주중/주말과 야간 배치가 섞이면 비교가 무의미하다
    s, e = B.window(*inc)
    assert (inc[0] - s, inc[1] - e) == (B.OFFSET_S, B.OFFSET_S)
    assert (e - s) == (inc[1] - inc[0]), "창 길이가 같아야 비교가 성립한다"

    # ② ⭐ 나이로도 추세 판정을 해야 한다.
    #    use_trend 는 **길이만** 보므로 7일 전 1시간 창은 이력 조회로 가고, 보관이
    #    짧으면 빈 목록이 '조회 성공'으로 온다.
    assert not asktools.use_trend(s, e), "길이 기준으로는 이력 조회로 간다(문제의 전제)"
    assert B.force_trend(s, e), "7일 전 창은 추세로 받아야 한다"
    assert not B.force_trend(inc[0], inc[1]), "사건 창은 그대로 이력으로 본다"

    # ③ 정상 창 상태는 축 상태와 **따로** 싣는다
    assert B.status_of([{"clock": 1, "value": 1}], True) == B.BASELINE_OK
    assert B.status_of([], True) == B.BASELINE_UNAVAILABLE, \
        "조회는 됐지만 값이 없으면 '평소엔 없었다'가 아니라 '평소를 못 봤다'다"
    assert B.status_of([{"clock": 1}], False) == B.BASELINE_UNAVAILABLE

    # ④ 방향성 — 없는 수치를 지어내지 않는다
    assert "배" in B.direction(80, 5)
    assert B.direction(5, 5) == "평소와 비슷"
    assert B.direction(None, 5) == "" and B.direction(80, None) == ""
    assert B.direction(80, "x") == ""
    return 12


def _citation_kind_checks() -> int:
    """근거 자리에 가설 id 를 적었을 때 무엇이 틀렸는지 말해 주는가.

    2026-08-20 랩 실증 단계 3 에서 계획자가 `supports` 에 `H1`·`H3` 를 적어 가설이 전부
    폐기됐다. 그때 사유가 "없는 기록을 인용했다: H1, H3" 여서 **무엇을 대신 써야 하는지가
    안 적혀 있었고**, 다시 시켜도 같은 실수를 반복했다. 관측 기록 id 는 `metrics#1` 처럼
    `#` 를 갖는다 — 모양으로 구분할 수 있다.
    """
    from ..deep import hypothesis as H

    recs = {"metrics#1": {"id": "metrics#1", "status": "ok"}}

    ok, why = H.validate({"id": "H2", "claim": "가설", "supports": ["H1", "H3"]}, recs)
    assert not ok
    assert "가설" in why and "metrics#1" in why, why

    # 모양은 맞는데 없는 기록이면 사유가 다르다 — 섞으면 고칠 방향이 달라진다
    ok, why = H.validate({"id": "H2", "claim": "가설", "supports": ["metrics#9"]}, recs)
    assert not ok and "가설 id" not in why, why

    ok, _ = H.validate({"id": "H2", "claim": "가설", "supports": ["metrics#1"]}, recs)
    assert ok
    return 5


def _tracing_off_checks() -> int:
    """검사를 돌릴 때 추적이 꺼져 있는가.

    셀프테스트는 가짜 모델로 그래프를 돌린다. 추적이 켜져 있으면 그 가짜 실행이 외부 추적
    서비스로 올라간다. 실제로 올라갔다 — 프로젝트 설정 코드는 서비스 기동 때만 도는데
    검사는 그 경로를 안 지나므로 `default` 프로젝트에 86건이 쌓였다(2026-08-21 확인).
    비용·지연 통계가 가짜 값으로 오염되고, 무엇보다 검사 데이터가 외부로 나간다.
    """
    import os

    from .. import tracing

    assert not tracing.enabled(), "검사 중에 추적이 켜져 있다"
    assert os.environ.get("LANGSMITH_TRACING", "").lower() in ("", "0", "false", "off"),         os.environ.get("LANGSMITH_TRACING")
    return 2


def _dry_axis_checks() -> int:
    """같은 대상의 같은 축이 두 번 비면 그만 묻는가.

    중복 검출이 조회 인자까지 넣은 지문으로 도는데, 시간 창만 바꾸면 지문이 달라져 빠져
    나간다. 랩 실증 단계 3 에서 로그를 세 번 물었고 **세 번 다 비었다** — 반복·정체
    실패(RF-12)가 이 경로로 재발했다. 없는 것은 창을 넓혀도 없다.
    """
    from ..deep import probe as P

    st = {"dry": {}}
    req = {"tool": "host_logs", "args": {"host": "[host-1]", "range": "1~2"}}
    assert P.dry_key(req) == ("host_logs", "[host-1]")

    P.note_dry(st, req)
    ok, _ = P.not_dry(st, req)
    assert ok, "한 번 비었다고 막으면 안 된다"

    P.note_dry(st, dict(req, args={"host": "[host-1]", "range": "3~4"}))
    ok, why = P.not_dry(st, dict(req, args={"host": "[host-1]", "range": "5~6"}))
    assert not ok and "비었" in why, why

    # 대상이 다르면 막지 않는다
    ok, _ = P.not_dry(st, dict(req, args={"host": "[host-2]", "range": "1~2"}))
    assert ok
    return 5


def _grounded_verdict_checks() -> int:
    """종합이 아직 안 갈린 가설을 원인으로 내세우면 표시하는가.

    랩 실증 단계 3 에서 종합이 미결 상태인 H1·H3 를 "공동으로 작용했을 가능성이 높습니다"로
    결론에 올렸다. 근거가 없다는 것은 본문에서 스스로 밝혔으나 결론 문장에는 남았다.
    문헌이 권하는 방식은 근거 없는 주장을 되돌리거나 표시하는 쪽이다 — 우리는 답을 버리지
    않고 **코드가 확인한 상태를 덧붙인다.** 사람이 무엇을 믿을지 고를 수 있어야 한다.
    """
    from ..deep import verdict as V

    table = [{"id": "H1", "claim": "갱신 실패", "status": "미결"},
             {"id": "H2", "claim": "계획된 변경", "status": "기각"},
             {"id": "H3", "claim": "검증 로직 변경", "status": "지지"}]

    bad = V.ungrounded("H1과 H3이 공동으로 작용했을 가능성이 높습니다.", table)
    assert bad == ["H1"], bad

    assert V.ungrounded("H3 이 원인이다", table) == []
    assert V.ungrounded("H2 는 기각했다", table) == []      # 기각은 밝혀도 된다
    assert V.ungrounded("원인 미상", table) == []

    # verify 가 실제로 부르는지까지 본다 — 모듈만 있고 안 부르면 검사가 헛돈다
    import inspect

    from ..deep import run as deep_run
    src = inspect.getsource(deep_run.verify)
    assert "ungrounded" in src and "annotate" in src, "verify 가 근거 검사를 안 부른다"

    note = V.annotate("H1이 원인입니다.", ["H1"])
    assert "H1" in note and note.startswith("H1이 원인입니다.")
    assert "미결" in note, note
    return 6


def _hypothesis_survival_checks() -> int:
    """인용 하나가 틀렸다고 이전 라운드의 가설까지 버리지 않는가.

    랩 실증에서 질의가 빈손으로 돌아오자 계획자가 **기대했던 기록 id 를 인용**했고, 그
    한 번의 잘못으로 표가 통째로 비었다(`가설=0`). 그러면 "가설이 둘 미만이라 다시 세우게
    한다"가 매 라운드 반복되고 조사가 앞으로 못 간다.

    이미 선 가설은 이전 모습으로 남기고 이번 갱신만 버린다. 처음 나온 가설이 잘못 인용한
    경우에만 버린다 — 남길 이전 모습이 없기 때문이다.
    """
    from ..deep import graph as G

    recs = {"metrics#1": {"id": "metrics#1", "status": "ok"}}
    H1 = {"id": "H1", "claim": "자원 경합", "status": "지지", "supports": ["metrics#1"],
          "contradicts": []}
    st = {"records": recs, "table": [H1]}

    # 있던 가설이 없는 기록을 인용했다 — 이전 모습으로 남는다
    bad = dict(H1, status="기각", supports=["logs#2"])
    rejected = G.apply_plan(st, {"hypotheses": [bad]})
    kept = [h for h in st["table"] if h.get("id") == "H1"]
    assert kept and kept[0]["status"] == "지지", st["table"]
    assert kept[0]["supports"] == ["metrics#1"], kept[0]
    assert rejected and "H1" in rejected[0]

    # 반증을 받고도 지지로 남기면 그 갱신만 되돌린다 — 조사를 통째로 멈추지 않는다.
    # 랩에서 이것 하나로 5기록·3가설을 쌓은 조사가 invalid_state 로 끝났다(2026-08-21).
    st3 = {"records": recs, "table": [dict(H1, status="미결")]}
    rejected = G.apply_plan(st3, {"hypotheses": [dict(H1, status="지지",
                                                      supports=["metrics#1"],
                                                      contradicts=["metrics#1"])]})
    got = [h for h in st3["table"] if h.get("id") == "H1"][0]
    assert got["status"] != "지지", got
    assert rejected and "반증" in rejected[0], rejected

    # 처음 나온 가설이 잘못 인용하면 버린다 — 남길 이전 모습이 없다
    st2 = {"records": recs, "table": []}
    G.apply_plan(st2, {"hypotheses": [{"id": "H9", "claim": "새 가설",
                                       "supports": ["logs#9"], "contradicts": []}]})
    assert not [h for h in st2["table"] if h.get("id") == "H9"], st2["table"]
    return 5


def _deep_ctx_checks() -> int:
    """계획자에게 준 도구를 심층 맥락이 전부 실행할 수 있는가.

    `open_problems` 를 도구 목록에 넣어 놓고 맥락에 `fetch_problems` 를 안 넣어서 호출이
    통째로 실패했다(2026-08-21 랩). 이웃 목록이 그것에 달려 있었으므로 조사 범위 확장이
    조용히 죽어 있었다. 도구를 늘릴 때마다 같은 실수가 나므로 정적으로 잡는다.
    """
    import inspect
    import re

    from ..ask import tools as asktools
    from ..deep import entry

    names = set(entry.planner_tools())
    assert names, "계획자에게 줄 도구가 없다"
    assert "panel_image" not in names and "list_panels" not in names,         "화면 없는 경로에 패널 도구를 주지 않는다"

    have = set(entry.CTX_KEYS)
    for name in sorted(names):
        fn = (asktools._TOOLS or {}).get(name)
        assert fn, name
        need = set(re.findall(r'ctx\["([a-z_]+)"\]', inspect.getsource(fn)))
        missing = need - have
        assert not missing, "%s 가 쓰는 %s 가 심층 맥락에 없다" % (name, sorted(missing))
    return 3


def _table_merge_checks() -> int:
    """계획자가 다시 안 보낸 가설이 사라지지 않는가.

    가설표는 **우리 상태**이고 모델의 일은 그것을 갱신하는 것이지 매번 전부 다시 적는 것이
    아니다. 그런데 표를 모델 출력으로 통째로 갈아 끼우고 있어서, 모델이 하나만 보내면
    나머지가 거절 기록도 없이 사라졌다. 같은 사건을 돌릴 때마다 가설이 3개였다 1개였다 한
    이유가 이것이다(2026-08-21 랩, 거절 0건인데 표가 줄었다).

    빼는 것은 밝히고 하는 일이어야 한다 — 기각은 상태로 적는다.
    """
    from ..deep import graph as G
    from ..deep import hypothesis as H

    recs = {"metrics#1": {"id": "metrics#1", "status": "ok"}}
    H1 = {"id": "H1", "claim": "자원 경합", "status": "미결", "supports": [],
          "contradicts": []}
    H2 = {"id": "H2", "claim": "DB 고장", "status": "미결", "supports": [],
          "contradicts": []}
    st = {"records": recs, "table": [H1, H2]}

    # 이번 라운드에 H1 만 보냈다 — H2 는 이전 모습으로 남는다
    G.apply_plan(st, {"hypotheses": [dict(H1, status="지지", supports=["metrics#1"])]})
    ids = {h.get("id"): h for h in st["table"]}
    assert "H2" in ids, st["table"]
    assert ids["H2"]["status"] == "미결"
    assert ids["H1"]["status"] == "지지"
    assert H.count_real(st["table"]) == 2

    # 새 가설은 그대로 들어온다
    G.apply_plan(st, {"hypotheses": [{"id": "H3", "claim": "새 것", "status": "미결",
                                      "supports": [], "contradicts": []}]})
    assert H.count_real(st["table"]) == 3

    # 무한정 늘지는 않는다
    for n in range(4, 4 + G.TABLE_MAX):
        G.apply_plan(st, {"hypotheses": [{"id": "H%d" % n, "claim": "x",
                                          "status": "미결", "supports": [],
                                          "contradicts": []}]})
    assert H.count_real(st["table"]) <= G.TABLE_MAX, H.count_real(st["table"])
    return 7


def _neighbor_checks() -> int:
    """다른 대상으로 조사를 넓힐 재료가 있는가.

    랩 실증 단계 3 에서 조사가 사건 호스트를 벗어나지 못했다. 원인이 프롬프트만은 아니었다 —
    **열린 문제 목록이 호스트 이름을 안 실어서** 전체를 조회해도 어느 대상의 문제인지 알 수
    없었다. 원인과 증상이 다른 호스트에 있는 사건에서는 그 목록이 유일한 연결 고리다.

    조사 범위를 모델의 자유 탐색에 맡기지 않는다. 문헌이 권하는 방식은 후보를 명시적으로
    주는 쪽이다(의존 관계를 안 주면 모델이 지어낸다). 그래서 코드가 목록을 만들어 기억에
    싣고, 프롬프트는 그 목록 안에서 고르라고만 말한다.
    """
    from ..ask.fetch import zabbix as fz
    from ..deep import memory as M
    from ..deep import state as S

    # problem.get 은 selectHosts 를 안 받는다(공식 문서: acknowledges·tags·suppressionData
    # 뿐). 호스트는 objectid 로 트리거를 한 번 더 조회해 붙인다.
    import inspect

    src = inspect.getsource(fz.fetch_problems)
    assert "selectHosts" not in src, "problem.get 에 selectHosts 를 주면 Invalid params 다"
    assert "_attach_hosts" in src, "문제에 호스트를 안 붙인다"

    rows = [{"name": "MySQL: Service is down", "severity": "4", "clock": "100",
             "hosts": [{"host": "web-01"}]}]
    got = fz.problems_result(rows)
    assert got["problems"][0].get("host") == "web-01", got["problems"][0]

    # 이름은 다른 값과 같은 규칙으로 가린다
    class _M:
        def mask(self, x):
            return "[host-9]" if x == "web-01" else x

    got = fz.problems_result(rows, _M())
    assert got["problems"][0]["host"] == "[host-9]", got["problems"][0]

    # 기억이 이웃을 보여 준다 — 사건 호스트 자신은 빼고
    st = S.new_state({"host": "[host-1]"}, {})
    st["neighbors"] = [{"host": "[host-2]", "name": "웹 접속 실패", "sev": "4"}]
    txt = M.render(st)
    assert "[host-2]" in txt and "웹 접속 실패" in txt, txt
    assert M.render(S.new_state({"host": "[host-1]"}, {})).count("다른 대상") == 0
    return 5


def _premature_checks() -> int:
    """질의를 한 번도 안 던지고 '못 가름'으로 끝내지 않는가.

    랩 첫 실행(2026-08-20)이 정확히 그렇게 끝났다 — 축 기록 넷과 미결 가설 둘을 손에 쥐고
    질의 0개로 1라운드에 종료했다. 이 설계가 막으려던 조기 종결을 설계 자신이 한 것이다.
    """
    import asyncio
    import os

    from ..deep import graph as G
    from ..deep import memory
    from ..deep import state as S

    recs = {"metrics#1": {"id": "metrics#1", "axis": "metrics", "status": "ok",
                          "finding": "iowait 80%", "units": "%",
                          "baseline_status": "ok", "t_first": 100, "t_last": 900}}

    # ③ 인용할 수 있는 기록 id 를 대 놓고 알려 준다. **langgraph 유무와 무관하게 돈다** —
    # 랩에서만 도는 검사는 개발 PC 에서 통째로 건너뛰어 검사 구실을 못 한다.
    txt = memory.render(S.new_state({"host": "[host-1]"}, dict(recs)))
    assert "metrics#1" in txt.split("[관측]")[1].splitlines()[0], txt

    try:
        import langgraph  # noqa: F401
    except ImportError:
        return 1

    H1 = {"id": "H1", "claim": "자원 경합", "if_true": "iowait 급등",
          "if_false": "iowait 평상", "status": "미결", "supports": [], "contradicts": []}
    H2 = {"id": "H2", "claim": "DB 고장", "if_true": "SQL 정지",
          "if_false": "IO/SQL 정상", "status": "미결", "supports": [], "contradicts": []}

    tries = []

    async def model(system, user, specs):
        tries.append(user)
        return {"content": [{"type": "tool_use", "name": "plan",
                             "input": {"hypotheses": [H1, H2], "probe_discriminates": [],
                                       "probe_why": "", "note": ""}}]}

    async def probe(req):
        raise AssertionError("질의를 안 냈는데 조회가 돌았다")

    saved = os.environ.get("DEEP_LOOP")
    os.environ["DEEP_LOOP"] = "hypothesis"
    try:
        out = asyncio.run(G.build(model, probe, lambda: "", system="s")
                          .ainvoke(S.new_state({"host": "[host-1]"}, dict(recs)),
                                   {"recursion_limit": 30}))
        # ① 1라운드 '못가름'을 금지한다 — 세는 상한까지 다시 시켜 본다
        assert out.get("stopped") == "rounds", out.get("stopped")
        assert int(out.get("round") or 0) == G.MAX_ROUNDS, out.get("round")
        # ② 다시 시킬 때 무엇을 안 했는지 알려 준다
        assert any("질의를 하나" in t for t in tries[1:]), tries[-1][-200:]
    finally:
        if saved is None:
            os.environ.pop("DEEP_LOOP", None)
        else:
            os.environ["DEEP_LOOP"] = saved
    return 4


def _loop_checks() -> int:
    """반복문 — 가르는 질의만 돌고, 판가름이 나면 멈추는가. 유료 호출 없이 돈다."""
    import asyncio
    import os

    try:
        import langgraph  # noqa: F401
    except ImportError:
        return 0        # 개발 PC 에 없으면 건너뛴다(랩에서 돈다)

    from ..deep import graph as G
    from ..deep import state as S

    recs = {"metrics#1": {"id": "metrics#1", "axis": "metrics", "status": "ok",
                          "finding": "iowait 80%", "units": "%",
                          "baseline_status": "ok", "t_first": 100, "t_last": 900},
            "logs#1": {"id": "logs#1", "axis": "logs", "status": "ok",
                       "finding": "백업 마커", "units": "count",
                       "baseline_status": "ok", "t_first": 50, "t_last": 900}}

    def _plan(hyps, disc, tool="host_metrics", args=None):
        calls = [{"type": "tool_use", "name": "plan",
                  "input": {"hypotheses": hyps, "probe_discriminates": disc,
                            "probe_why": "가른다", "note": ""}}]
        if tool:
            calls.append({"type": "tool_use", "name": tool,
                          "input": args or {"host": "[host-1]"}})
        return {"content": calls}

    H1 = {"id": "H1", "claim": "자원 경합", "if_true": "iowait 급등",
          "if_false": "iowait 평상", "status": "미결", "supports": [], "contradicts": []}
    H2 = {"id": "H2", "claim": "DB 고장", "if_true": "SQL 스레드 정지",
          "if_false": "IO/SQL 정상", "status": "미결", "supports": [], "contradicts": []}

    seq = []

    async def model(system, user, specs):
        seq.append(user)
        n = len(seq)
        if n == 1:
            return _plan([H1, H2], ["H1", "H2"])
        # 2회차: 근거를 받아 판가름을 낸다
        return _plan([dict(H1, status="지지", supports=["metrics#1"]),
                      dict(H2, status="기각", contradicts=["metrics#1"])],
                     ["H1", "H2"], tool=None)

    async def probe(req):
        return {"id": "metrics#2", "axis": "metrics", "status": "ok",
                "finding": "iowait 확인", "units": "%", "baseline_status": "ok",
                "evidence": ["iowait 80"], "t_first": 100, "t_last": 900}, ""

    saved = os.environ.get("DEEP_LOOP")
    os.environ["DEEP_LOOP"] = "hypothesis"
    try:
        st = S.new_state({"host": "[host-1]"}, dict(recs))
        app = G.build(model, probe, lambda: "", system="s")
        out = asyncio.run(app.ainvoke(st, {"recursion_limit": 20}))

        # ① 판가름이 나면 멈춘다 — 세는 상한이 아니라 의미로 끝나야 한다
        assert out.get("stopped") == "판가름", out.get("stopped")
        assert int(out.get("round") or 0) <= 2, out.get("round")

        # ② H0 가 코드로 붙어 있다 (모델이 안 냈는데도)
        ids = [h.get("id") for h in (out.get("table") or [])]
        assert "H0" in ids, ids

        # ③ ⭐ 프롬프트가 **누적이 아니라 재구성**이다.
        #    2회차가 1회차를 통째로 품고 있으면 이어 붙인 것이다 — 우리가 실측한
        #    0.4K→29.9K 가 그 모양이었다. 크기 비율은 라운드가 적을 때 의미가 없으므로
        #    (첫 회차는 가설도 기록도 비어 있다) 포함 여부로 본다.
        assert len(seq) >= 2, seq
        assert seq[0] not in seq[1], "이전 프롬프트를 그대로 품고 있다 — 누적이다"
        assert "[가설]" in seq[1] and "[지금까지]" in seq[1], "재구성한 칸이 보여야 한다"

        # ④ ⭐ 중복 질의는 두 번 안 돈다
        async def same(system, user, specs):
            return _plan([H1, H2], ["H1", "H2"], args={"host": "[host-1]"})

        st2 = S.new_state({"host": "[host-1]"}, dict(recs))
        out2 = asyncio.run(G.build(same, probe, lambda: "", system="s")
                           .ainvoke(st2, {"recursion_limit": 20}))
        assert len(out2.get("probes") or []) == 1, \
            "같은 조회를 라운드마다 다시 던지면 안 된다 — 우리가 실측한 낭비가 그것이다"
        assert out2.get("stopped") in ("못가름", "rounds"), out2.get("stopped")

        # ⑤ 근거 없는 상태 변경은 되돌려진다 (조회 실패로는 기각 못 한다)
        st3 = S.new_state({"host": "[host-1]"},
                          {"logs#9": {"id": "logs#9", "status": "unavailable"}})
        rej = G.apply_plan(st3, {"hypotheses": [
            dict(H1, status="기각", contradicts=["logs#9"])]})
        assert rej and "근거가 없다" in rej[0], rej
        assert st3["table"][0]["status"] == "미결", st3["table"]
    finally:
        if saved is None:
            os.environ.pop("DEEP_LOOP", None)
        else:
            os.environ["DEEP_LOOP"] = saved
    return 10


def _deep_budget_checks() -> int:
    """심층 전용 시간당 상한 — 트리아지 예산을 먹지 않는가."""
    from .. import egress

    class _Ok:
        name = "fake"

        def __init__(self):
            self.last_usage = None

        def available(self):
            return True

        def complete(self, _s, _u):
            return "ok"

    saved = (egress.MAX_PER_HOUR, list(egress._calls))
    try:
        egress.MAX_PER_HOUR = 100
        egress._calls.clear(); egress._calls_kind.clear()
        # ① 심층 상한이 전역보다 낮으면 그쪽이 먼저 걸린다
        for _ in range(3):
            egress.call([_Ok()], "s", "u", kind="deep", max_per_hour=3)
        got = egress.call([_Ok()], "s", "u", kind="deep", max_per_hour=3)
        assert got["degraded"] and got["reason"] == egress.BLOCKED_HOUR, got
        # ② 그런데 전역 예산은 아직 남아 있어 트리아지는 돈다 — 이게 상한을 나눈 이유다
        ok = egress.call([_Ok()], "s", "u", kind="triage")
        assert not ok["degraded"], ok

        # ③ ⭐ **전용 상한은 그 용도만 센다.** 전체를 세면 남의 트래픽에 먼저 소진돼
        #    첫 호출부터 막힌다 — 랩에서 실제로 그랬다(hour_limit, 라운드 0).
        egress._calls.clear(); egress._calls_kind.clear()
        for _ in range(10):
            egress.call([_Ok()], "s", "u", kind="triage")      # 남의 트래픽
        got2 = egress.call([_Ok()], "s", "u", kind="deep", max_per_hour=3)
        assert not got2["degraded"],             "전용 상한이 전체 호출을 센다 — 심층이 남의 트래픽에 굶는다"

        # ④ call_raw 도 같은 인자를 받는다(계획자가 이쪽을 쓴다)
        egress._calls.clear(); egress._calls_kind.clear()
        for _ in range(2):
            egress.call_raw(lambda: {"content": []}, kind="deep", max_per_hour=2)
        raw = egress.call_raw(lambda: {"content": []}, kind="deep", max_per_hour=2)
        assert not raw["ok"] and raw["reason"] == egress.BLOCKED_HOUR, raw
    finally:
        egress.MAX_PER_HOUR = saved[0]
        egress._calls.clear(); egress._calls_kind.clear()
        egress._calls.extend(saved[1])
    return 7


def _deep_record_checks() -> int:
    """심층 결과 기록 — 실패도 남고, **사람 라벨을 오염시키지 않는가.**"""
    import os
    import tempfile

    from .. import store
    from ..alerts import quality, triage

    # ① 기계가 남기는 축이 사람 라벨 축과 섞이면 안 된다.
    #    섞이면 심층 조사 성공률이 판정 정확도로 둔갑해 슬라이드에 실린다.
    assert "deep" not in quality.AXES, \
        "심층 축을 품질 지표 축에 넣으면 기계 기록이 사람 라벨로 세어진다"

    d = tempfile.mkdtemp(prefix="deep-note-")
    saved = store.PATH
    try:
        store.PATH = os.path.join(d, "n.db")
        store.close()
        store.init()
        jid = store.record_judgment({"fingerprint": "fp1", "host": "h",
                                     "source": "zabbix-internal"})
        assert jid

        # ② 실패가 남는다 — 예전에는 로그 한 줄로 끝났다
        triage._note_deep(jid, {"ok": 0, "stopped": "no_evidence", "error": "축 0건"})
        # ③ 성공도 남는다
        triage._note_deep(jid, {"ok": 1, "stopped": "판가름", "rounds": 2,
                                "winner": "H1"})
        rows = store._exec("SELECT axis, ok, note FROM feedback WHERE judgment_id = ?",
                           (jid,), fetch="all") or []
        assert len(rows) == 2, rows
        assert {r[0] for r in rows} == {"deep"}, rows
        assert {r[1] for r in rows} == {0, 1}, rows
        assert any("no_evidence" in (r[2] or "") for r in rows), rows
        assert any("H1" in (r[2] or "") for r in rows), rows

        # ④ 품질 지표는 이 행들을 안 센다
        lab = store.labels_for([jid]).get(jid) or {}
        assert not (set(lab) & set(quality.AXES)), lab
    finally:
        store.close()
        store.PATH = saved
    return 9


def _survey_parallel_checks() -> int:
    """조사가 축을 **동시에** 훑는가.

    순차로 두면 축 넷이 그대로 더해진다 — 계획서가 아키텍처 변경으로 꼽은 자리다.
    """
    import asyncio
    import time

    from ..deep import run as deep_run

    DELAY = 0.15

    async def slow_tool(name, args):
        await asyncio.sleep(DELAY)
        return {"status": "ok"}, 10

    async def slow_condense(system, user):
        await asyncio.sleep(DELAY)
        return {"ok": True, "text": '{"status":"ok","finding":"본 것","units":"—",'
                                    '"baseline_status":"ok","evidence":["x"]}'}

    class _Mk:
        _fwd = {"h": "[host-1]"}

        def mask(self, x):
            return x

        def unmask(self, x):
            return x

    async def go():
        st = {"records": {}, "steps": []}
        t0 = time.monotonic()
        await deep_run.survey(st, {"host": "[host-1]"}, slow_tool, slow_condense,
                              now=1787000000)
        return time.monotonic() - t0, st

    took, st = asyncio.run(go())

    # 축 4개 × (조회 2 + 축약 1) = 12번. 순차면 12*DELAY, 병렬이면 2~3 단계면 끝난다.
    assert len(st["records"]) == 4, st["records"].keys()
    assert took < DELAY * 7, (
        "조사가 순차로 돈다(%0.2fs) — 축을 동시에 훑어야 한다" % took)
    return 2


def _deadline_checks() -> int:
    """마감이 화면 앞단 시한보다 낮은가.

    넘으면 게이트웨이가 멀쩡히 조사하는 중에 사람은 502 를 본다. 어제 감사에서 질의
    경로가 같은 모양으로 한 번 걸렸다(프록시 기본 30초 → 180초로 올린 자리다).
    """
    from ..deep import graph as G

    PROXY_TIMEOUT_S = 180      # lab/docker-compose.yml GF_DATAPROXY_TIMEOUT
    assert G.DEADLINE_S < PROXY_TIMEOUT_S, (
        "심층 마감(%s초)이 화면 앞단 시한(%s초)보다 크다 — 사람은 502 를 본다"
        % (G.DEADLINE_S, PROXY_TIMEOUT_S))
    # ⭐ 시간당 상한이 조사 한 번을 담아야 한다. 한 번이 축약을 CONDENSE_MAX 번까지
    #    부르므로, 상한이 그보다 작으면 **한 번도 못 끝낸다** — 랩에서 그렇게 막혔다.
    from ..deep import entry as _entry
    assert _entry.MAX_PER_HOUR >= G.CONDENSE_MAX * 2, (
        "시간당 상한(%s)이 조사 한 번의 축약(%s)을 두 번도 못 담는다"
        % (_entry.MAX_PER_HOUR, G.CONDENSE_MAX))

    # 라운드 상한과도 앞뒤가 맞아야 한다. 라운드마다 최소 한 번은 모델을 부른다.
    assert G.MAX_ROUNDS * 10 < G.DEADLINE_S, \
        "라운드 상한이 마감 안에 못 들어간다 — 마감으로만 끝나면 조사가 늘 잘린다"
    return 3


def _entry_wiring_checks() -> int:
    """배선 — 진입점이 실제로 부르는 함수와 인자가 맞는가.

    골격을 가짜로만 검사하면 **배선이 틀려도 전부 통과한다.** 실제로 첫 랩 실행이
    `claude_tools() got an unexpected keyword argument 'kind'` 로 5초 만에 죽었다.
    """
    import inspect

    from .. import egress, llm
    from ..deep import condense, entry

    # ① 계획자·종합이 부르는 함수의 인자가 실제 시그니처에 있는가
    p = inspect.signature(llm.claude_tools).parameters
    for need in ("system", "messages", "tools", "model"):
        assert need in p, "claude_tools 에 %s 가 없다" % need
    assert "kind" not in p, "kind 를 받는다면 entry 가 그것을 써야 한다"

    # ② 출구가 심층 전용 상한을 받는가 (entry 가 넘긴다)
    for fn in (egress.call, egress.call_raw):
        assert "max_per_hour" in inspect.signature(fn).parameters, fn.__name__

    # ③ 축약 체인이 출구가 아는 어댑터 계약을 지키는가
    for ad in condense.adapters():
        for attr in ("name", "available", "complete"):
            assert hasattr(ad, attr), (ad, attr)

    # ④ 진입점이 조사에 넘기는 도구 이름이 닫힌 카탈로그 안에 있는가 —
    #    없는 도구를 부르면 조사가 통째로 빈다
    from ..ask import tools as asktools
    from ..deep import probe as P
    from ..deep import run as deep_run

    names = {t.get("name") for t in (asktools.TOOL_SPECS or [])}
    for axis, tool in deep_run.SURVEY:
        assert tool in names, "조사가 없는 도구를 부른다: %s" % tool
        assert tool in P.catalog(), tool
    assert entry.enabled() in (True, False)
    return 12


def _ask_target_checks() -> int:
    """질의 심층 — **질문에서 대상을 찾아내는가.**

    알림은 사건에 호스트가 들어 있지만 질의는 질문 안에 있다. 안 풀면 조사가 빈 대상으로
    나가 네 축이 통째로 실패한다 — 랩 첫 실행이 그렇게 "구분할 수 없다"로 끝났다.
    """
    from ..deep import entry, run as deep_run

    table = {"[host-1]": {"host": "vm-p3-target-002.novalocal",
                          "logs": "vm-p3-target-002.novalocal", "security": ""},
             "[host-2]": {"host": "lab-db-agent", "logs": "lab-db-agent",
                          "security": ""}}

    q = "vm-p3-target-002.novalocal 의 복제 지연이 심각합니다"
    assert entry.host_from_question(q, table) == "[host-1]", \
        entry.host_from_question(q, table)
    assert entry.host_from_question("복제가 느립니다", table) == "", "대상이 없으면 빈 값"

    class _Mk:
        _fwd = {"x": "y"}

        def mask(self, v):
            return "가려짐"

        def unmask(self, v):
            return v

        def register(self, *a, **kw):
            return ""

    # 이미 토큰인 값을 또 가리면 표에 없는 값이 되어 조회가 전부 실패한다
    inc = deep_run.prepare({"incident": {"host": "[host-1]"}, "alerts": [], "host": {}},
                           _Mk())
    assert inc["host"] == "[host-1]", inc["host"]
    inc2 = deep_run.prepare({"incident": {"host": "실명"}, "alerts": [], "host": {}},
                            _Mk())
    assert inc2["host"] == "가려짐", inc2["host"]
    return 4


def _survey_args_checks() -> int:
    """조사 인자 — 조회 계층이 **실제로 읽는 형태**인가.

    랩 첫 실행이 1초 만에 "네 축에서 아무 기록도 못 만들었다"로 끝났다. 구간을
    `시작-끝` 으로 적었는데 구분자가 `~`·`..`·`to` 다(하이픈은 ISO 날짜와 부딪힌다).
    골격 검사만으로는 이런 것이 안 잡힌다.
    """
    import time

    from ..ask import tools as asktools
    from ..deep import run as deep_run

    now = int(time.time())
    span = (now - 3600, now)

    for axis, tool in deep_run.SURVEY:
        args = deep_run.tool_args(tool, "[host-1]", span)
        assert args.get("host") == "[host-1]", (tool, args)
        props = set()
        for sp in (asktools.TOOL_SPECS or []):
            if sp.get("name") == tool:
                props = set((sp.get("input_schema") or {}).get("properties") or {})
        # 그 도구가 안 받는 인자를 보내면 조용히 무시돼 엉뚱한 구간을 본다
        assert set(args) <= props, (tool, set(args) - props)

        if "range" in args:
            a, b = asktools.span_of(args)
            assert (a, b) == span, ("구간을 못 읽는다", tool, args, (a, b))
        else:
            assert args.get("days", 0) >= 1, (tool, args)
    return 12
