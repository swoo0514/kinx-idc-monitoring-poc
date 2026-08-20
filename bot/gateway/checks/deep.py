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
