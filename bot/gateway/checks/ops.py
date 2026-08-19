"""운영 검사 — 생존 신호·대기 파일·명부·동시 호출."""

import logging
import asyncio
import importlib
import io
import json
import os
import re
import socket
import tempfile
import threading
import time
import shutil

from .. import egress, heartbeat, llm, registry
from ..alerts import incident, pending
log = logging.getLogger("gateway.selftest")




def _pending_checks() -> int:
    """대기 알림 기록 — 창이 닫히기 전에 죽어도 알림이 남아 있는지."""
    import os
    import tempfile

    from ..alerts import pending

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

        # 동시성 — 사건 마감(drop)과 새 알림 도착(append)이 겹치면 200 을 준 알림이 사라진다
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




def _heartbeat_checks() -> int:
    """생존 신호 — 프로토콜이 실제로 통하는지, 안 켰을 때 조용한지."""
    import json
    import os
    import socket
    import struct
    import threading

    from .. import heartbeat

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
    # 배포 서버에 든 값을 지우고 검사한다 — 안 그러면 설정 탓인지 코드 탓인지 모른다
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

    # Zabbix 는 아이템이 없어도 response=success 를 준다 — failed 를 세야 한다
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
    """정상 종료 시 마감 — 대기 중인 사건이 버려지지 않는지."""
    import asyncio
    import time

    from ..alerts import incident

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
    # 마감 건수에 안 잡혀야 한다 — 대기 파일이 갖고 있어 재기동 후 다시 처리된다
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
    """LLM 동시 호출 상한 — 상한이 실제로 걸리는지, 대기를 포기하면 열화로 내려가는지."""
    import io
    import os
    import threading
    import time

    from .. import egress, llm

    ctx = {"prejudge": {"verdict": "신규", "statement": "처음"}, "sources": {}}

    class _Slow:
        name = "fake"

        def __init__(self, *a, **kw):     # 실제 어댑터가 용도·모델을 받는다
            pass

        def available(self):
            return True

        def complete(self, _sys, _user):
            time.sleep(0.3)
            return "분석 결과"

    class _Absent:
        name = "absent"

        def __init__(self, *a, **kw):
            pass

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
        # 절대값이 아니라 증가분으로 본다 — 앞선 검사가 같은 계수기를 쓰면 순서에 깨진다
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

        # 앞선 8건은 실제로 나갔다 — "안 나간 호출"만 보려면 창을 비우고 시작한다
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
        # 나가지도 않은 호출이 시간당 예산을 먹으면 안 된다
        assert egress.calls_last_hour() == 0, \
            f"대기 포기가 예산을 먹었다: {egress.calls_last_hour()}건"
        assert egress.kind_counts() == {}, egress.kind_counts()
        # 어댑터가 전멸해도 마찬가지다
        egress._sem = threading.BoundedSemaphore(2)

        class _Dead:
            name = "dead"

            def __init__(self, *a, **kw):     # 실제 어댑터가 용도·모델을 받는다
                pass

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

        # 시간당 총량 — 게이트가 아니라 여기서 세므로 게이트 규칙이 몇 개든 구멍이 안 생긴다
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

        # 월간 리포트도 같은 출구를 지나야 한다 — 나가는 길이 하나라는 것은 검사로 붙든다
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

        # 출구를 우회하는 코드가 어디에도 없어야 한다 — 못 옮긴 것은 예외 목록에 이유와 함께 적는다
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
        # 공급자에 직접 말을 거는 것은 어댑터가 사는 곳만 한다
        # Slack 은 chat.postMessage 라 /api/chat 로 잡으면 오검출된다
        TALKS_PROVIDER = [(r"/api/chat(?![.\w])", "채팅 API"),
                          (r"/v1/messages", "Anthropic 메시지 API"),
                          (r"\banthropic\.", "Anthropic SDK")]
        # gateway/ 아래 전부와 bot/ 스크립트를 본다 — 검사 파일은 뺀다(주소가 문자열로 들어 있다)
        gw = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        bot = os.path.dirname(gw)
        files = sorted(glob.glob(os.path.join(gw, "**", "*.py"), recursive=True))
        files += sorted(glob.glob(os.path.join(bot, "*.py")))
        for f in files:
            base = os.path.basename(f)
            if base == "selftest.py" or os.sep + "checks" + os.sep in f:
                continue
            src = io.open(f, encoding="utf-8").read()
            hits = []
            if base != "egress.py":
                hits += [w for p, w in CALLS_ADAPTER if re.search(p, src, re.M)]
            # 어댑터가 사는 곳 둘(llm.py·holmes.py)과 중계(proxy.py)만 공급자 주소를 쓴다
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




def _llm_usage_checks() -> int:
    """나가는 호출이 전부 사용량 표에 남는가.

    질의 경로만 기록하면 실환경 비용을 낼 수 없다. 알림 분석이 질의보다 잦고 입력도
    크다. 근거는 GATEWAY_GUIDE §29.
    """
    import os
    import tempfile

    from .. import egress, llm, store

    class _WithUsage:
        name = "fake"

        def __init__(self):
            self.last_usage = None

        def available(self):
            return True

        def complete(self, _s, _u):
            self.last_usage = {"in": 11, "out": 22, "cache_write": 33,
                               "cache_read": 44, "model": "m1"}
            return "분석"

    class _NoUsage:
        name = "holmes"

        def available(self):
            return True

        def complete(self, _s, _u):
            return "조사 결과"

    class _Dead:
        name = "dead"

        def available(self):
            return True

        def complete(self, _s, _u):
            raise RuntimeError("죽음")

    d = tempfile.mkdtemp(prefix="usage-")
    saved = store.PATH
    try:
        store.PATH = os.path.join(d, "u.db")
        store.close()
        store.init()

        # ① 어댑터가 낸 사용량이 그대로 남는다. 용도도 함께 남아야 질의와 갈린다.
        egress.call([_WithUsage()], "sys", "user", exempt=True, kind="triage")
        got = store.tokens_since(3600, kind="triage")
        assert got["in"] == 11 and got["out"] == 22, got
        assert got["cache_write"] == 33 and got["cache_read"] == 44, got
        assert store.tokens_since(3600, kind="ask")["in"] == 0, "용도가 섞이면 안 된다"

        # ② 못 재는 경로(심층조사)는 0 으로 남기되 그 사실이 드러나야 한다.
        #    0 을 그냥 두면 "공짜"로 읽힌다 — 이 리포에서 반복해서 겪은 실패 모양이다.
        egress.call([_NoUsage()], "sys", "user", exempt=True, kind="holmes")
        rows = store._exec("SELECT in_tok, out_tok, model FROM usage WHERE kind = ?",
                           ("holmes",), fetch="all") or []
        assert len(rows) == 1, rows
        assert rows[0][0] == 0 and rows[0][1] == 0, rows
        assert "계측" in (rows[0][2] or ""), "잴 수 없다는 사실이 모델 자리에 남아야 한다"

        # ③ 실패한 호출은 기록하지 않는다. 안 나간 것을 쓴 것으로 세면 안 된다.
        egress.call([_Dead()], "sys", "user", exempt=True, kind="write")
        assert store.tokens_since(3600, kind="write")["in"] == 0
        assert not (store._exec("SELECT 1 FROM usage WHERE kind = ?",
                                ("write",), fetch="all") or [])

        # ④ 실제 어댑터에도 자리가 있어야 한다. 없으면 위 계약이 가짜에만 맞는 것이다.
        assert hasattr(llm.ClaudeAdapter(), "last_usage")
        assert hasattr(llm.OllamaAdapter(), "last_usage")

        # ⑤ **다른 출구(call_raw)도 기록한다.** 질의 경로는 이쪽을 쓰는데, 예열과
        #    마무리 호출은 반복문 밖이라 안에서 적던 방식으로는 빠진다.
        def _raw():
            return {"usage": {"input_tokens": 7, "output_tokens": 3,
                              "cache_creation_input_tokens": 1,
                              "cache_read_input_tokens": 2},
                    "model": "m2", "content": []}

        egress.call_raw(_raw, exempt=True, kind="ask", user="사람1")
        got = store.tokens_since(3600, kind="ask")
        assert got["in"] == 7 and got["out"] == 3, got
        assert got["cache_write"] == 1 and got["cache_read"] == 2, got
        rows = store._exec("SELECT user, model FROM usage WHERE kind = ?",
                           ("ask",), fetch="all") or []
        assert len(rows) == 1, "한 번 부르면 한 행 — 두 곳에서 적으면 두 배로 센다"
        assert rows[0][0] == "사람1", "사람별 사용량의 근거라 이름이 남아야 한다"
        assert rows[0][1] == "m2"

        # ⑥ 사용량을 안 실어 보내는 응답이면 행을 만들지 않는다(추정하지 않는다).
        egress.call_raw(lambda: {"content": []}, exempt=True, kind="route")
        assert not (store._exec("SELECT 1 FROM usage WHERE kind = ?",
                                ("route",), fetch="all") or [])
    finally:
        store.close()
        store.PATH = saved
    return 17


def _registry_checks() -> int:
    """호스트 명부 — 한 호스트의 사실이 한 곳에서 읽히는지."""
    import importlib
    import os
    import tempfile

    from .. import registry

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

        from ..alerts import collector as _c
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

        # 생존 신호도 서버마다 따로 센다 — 한 곳만 세면 다른 서버의 끊김을 못 잡는다
        from .. import heartbeat as _hb
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
            # 명부에 있는데 토큰이 비면 조회하지 않는다 — 전역 토큰이면 남의 수치를 그 서버 것으로 쓴다
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
