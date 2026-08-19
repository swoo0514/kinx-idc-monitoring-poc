"""판정 이력 저장소와 그것을 쓰는 기능 검사."""

import logging
import asyncio
import importlib
import io
import json
import os
import shutil
import sqlite3
import tempfile

from .common import _FakeHttpx
from .. import llm, masking, nametable, store
from ..alerts import collector, pending, prior, quality, triage
from ..integrations import grafana, keep, slack
log = logging.getLogger("gateway.selftest")




def _store_checks() -> int:
    """판정 이력 저장소 — 남기고, 세고, 재기동을 견디는가 (§24)."""
    import os
    import shutil
    import tempfile

    from .. import store

    d = tempfile.mkdtemp(prefix="store-test-")
    saved = store.PATH
    try:
        store.PATH = os.path.join(d, "hist.db")
        store.init()

        # ① 판정 한 건을 남기고 되읽는다
        store.record_judgment({
            "fingerprint": "fp1", "host": "h1", "realm": "internal",
            "source": "zabbix-internal", "classes": "disk_space", "alert_count": 2,
            "sev": "SEV2", "verdict": "만성", "gate_fired": 1,
            "gate_reason": "2건 병합", "sources": "logs:ok,security:ok",
            "provider": "claude", "degraded": 0, "total_s": 21.4,
        }, now=1000.0)
        rows = store.judgments(since=0, now=2000.0)
        assert len(rows) == 1, rows
        assert rows[0]["fingerprint"] == "fp1" and rows[0]["verdict"] == "만성", rows[0]

        # ② 중복 판정 — 같은 키는 한 번만 통과하고 창이 지나면 다시 통과
        assert store.seen_once("k1", ttl_s=3600, now=1000.0) is True
        assert store.seen_once("k1", ttl_s=3600, now=1100.0) is False
        assert store.seen_once("k1", ttl_s=3600, now=1000.0 + 3601) is True

        # ③ 호출 창 — 시간이 지나면 빠진다
        for i in range(5):
            store.record_call("triage", now=1000.0 + i)
        assert store.calls_since(3600, now=1010.0) == 5
        assert store.calls_since(3600, now=1000.0 + 3700) == 0
        assert store.calls_since(3600, now=1010.0, kind="triage") == 5
        assert store.calls_since(3600, now=1010.0, kind="monthly") == 0

        # ④ 재기동을 견딘다 — 이게 이 저장소의 존재 이유다
        store.close()
        store.init()
        assert store.calls_since(3600, now=1010.0) == 5, "재기동에 호출 창이 사라졌다"
        assert store.seen_once("k1", ttl_s=3600, now=1100.0) is False,             "재기동에 중복 판정 창이 사라졌다"
        assert len(store.judgments(since=0, now=2000.0)) == 1

        # ⑤ 저장소를 못 쓰면 조용히 멈추지 않는다
        store.close()
        # 없는 디렉토리는 코드가 만들어 주므로 실패가 아니다. 디렉토리 자체를 지정한다.
        store.PATH = d
        assert store.init() is False, "쓸 수 없는 경로인데 성공으로 봤다"
        assert store.record_judgment({"fingerprint": "fp2"}) is None
        assert store.seen_once("k2", ttl_s=10) is True, "저장소가 죽어도 알림은 흘러야"

        # ⑥ 배선 — 사건을 마감하면 이력이 남는가. 함수가 아니라 경로를 본다.
        import asyncio
        import time as _t

        from ..alerts import incident as inc_mod, triage

        store.PATH = os.path.join(d, "wire.db")
        store.close()
        store.init()
        inc = inc_mod.Incident(
            key=("internal", "h9", "disk_space"), host="h9",
            alerts=[inc_mod.Alert(source="zabbix-internal", event_id="e9",
                                  trigger_id="", host="h9", alert_name="n",
                                  sev="SEV3", incident_class="disk_space",
                                  recv=_t.monotonic())],
            opened_at=_t.monotonic(), last_at=_t.monotonic())

        class _DeadZbx:
            source = "zabbix-internal"

            async def call(self, *a, **kw):
                raise RuntimeError("down")

        saved_keep = os.environ.pop("KEEP_URL", None)
        saved_slack = os.environ.pop("SLACK_BOT_TOKEN", None)
        try:
            asyncio.run(triage.run_incident(inc))
        finally:
            if saved_keep is not None:
                os.environ["KEEP_URL"] = saved_keep
            if saved_slack is not None:
                os.environ["SLACK_BOT_TOKEN"] = saved_slack
        rows = store.judgments(since=0)
        assert rows, "사건을 마감했는데 이력이 안 남았다"
        assert rows[0]["fingerprint"] == inc.fingerprint(), rows[0]
        assert rows[0]["gate_reason"], rows[0]
        return 20
    finally:
        store.close()
        store.PATH = saved
        shutil.rmtree(d, ignore_errors=True)




def _store_schema_checks() -> int:
    """스키마 판올림과 판정 식별자 (§24-4)."""
    import os
    import shutil
    import sqlite3
    import tempfile
    import time as _time

    from .. import store

    d = tempfile.mkdtemp(prefix="store-v1-")
    saved = store.PATH
    try:
        # ⓪ 물결표를 편다. 안 펴면 작업 디렉토리 밑 `~` 폴더에 조용히 쌓인다.
        import importlib
        saved_env = os.environ.get("GATEWAY_STORE_FILE")
        os.environ["GATEWAY_STORE_FILE"] = "~/.kinx-gateway/history.db"
        try:
            got = importlib.reload(store).PATH
            assert "~" not in got, got
        finally:
            if saved_env is None:
                os.environ.pop("GATEWAY_STORE_FILE", None)
            else:
                os.environ["GATEWAY_STORE_FILE"] = saved_env
            importlib.reload(store)

        # ① 구스키마 파일 — 판올림이 컬럼을 만들고 기존 행을 보존한다
        p = os.path.join(d, "old.db")
        c = sqlite3.connect(p)
        c.executescript(
            "CREATE TABLE judgment (ts REAL NOT NULL, fingerprint TEXT, host TEXT,"
            " realm TEXT, source TEXT, classes TEXT, alert_count INTEGER, sev TEXT,"
            " verdict TEXT, gate_fired INTEGER, gate_reason TEXT, sources TEXT,"
            " provider TEXT, degraded INTEGER, total_s REAL);"
            "CREATE TABLE seen (key TEXT PRIMARY KEY, ts REAL NOT NULL);"
            "CREATE TABLE call (ts REAL NOT NULL, kind TEXT);")
        c.execute("INSERT INTO judgment (ts,fingerprint,host) VALUES (?,?,?)",
                  (500.0, "old-fp", "old-host"))
        c.commit()
        c.close()

        store.PATH = p
        store.close()
        assert store.init() is True, "구스키마를 판올림하지 못했다"
        rows = store.judgments(since=0, now=9e9)
        assert len(rows) == 1 and rows[0]["fingerprint"] == "old-fp", rows
        assert rows[0]["id"], "판올림 뒤 옛 행에 식별자가 없다"
        for col in ("event_ts", "ikey", "origin", "summary", "change",
                    "prior_used", "annotation_id"):
            assert col in rows[0], col

        # ② 두 번 열어도 예외가 없다 — mark CLI 가 같은 파일을 따로 연다
        store.close()
        assert store.init() is True, "두 번째 판올림이 실패했다"

        # ③ 식별자는 재사용되지 않는다
        j1 = store.record_judgment({"fingerprint": "a", "host": "h"}, now=1000.0)
        j2 = store.record_judgment({"fingerprint": "b", "host": "h"}, now=1001.0)
        assert isinstance(j1, int) and j2 > j1, (j1, j2)
        store._exec("DELETE FROM judgment")
        j3 = store.record_judgment({"fingerprint": "c", "host": "h"}, now=1002.0)
        assert j3 > j2, "표를 비웠더니 식별자가 되돌아갔다 — 옛 카드가 남의 판정을 가리킨다"

        # ④ finish 는 해당 행만 갱신하고 없는 식별자는 무시한다
        j4 = store.record_judgment({"fingerprint": "d", "host": "h"}, now=1003.0)
        store.finish(j4, {"provider": "claude", "total_s": 12.5, "summary": "결론"})
        store.finish(999999, {"provider": "x"})
        rows = {r["id"]: r for r in store.judgments(since=0, now=9e9)}
        assert rows[j4]["provider"] == "claude" and rows[j4]["total_s"] == 12.5
        assert rows[j4]["summary"] == "결론"
        assert rows[j3]["provider"] in (None, ""), rows[j3]

        # ⑤ 라벨 — 같은 판정·같은 축에 둘이면 나중 것이 이긴다
        store.record_feedback(j4, "overall", ok=False, who="t", now=2000.0)
        store.record_feedback(j4, "overall", ok=True, who="t", now=2100.0)
        labels = store.labels_for([j4])
        assert labels[j4]["overall"]["ok"] == 1, labels

        # ⑥ 라우팅 기록 — 중복으로 걸린 것도 분모에 남는다
        store.record_route({"source": "zabbix-internal", "host": "h", "sev": "SEV3",
                            "cls": "disk_space", "route": "triage", "dup": 0},
                           now=3000.0)
        store.record_route({"source": "zabbix-internal", "host": "h", "sev": "SEV3",
                            "cls": "disk_space", "route": "triage", "dup": 1},
                           now=3001.0)
        rt = store.routes(since=0, now=9e9)
        assert len(rt) == 2 and sum(r["dup"] for r in rt) == 1, rt

        # ⑦ 서술만 먼저 지운다 — 행은 남고 지표는 그대로 산출된다
        store.prune(now=1003.0 + store.SUMMARY_DAYS * 86400 + 10)
        rows = {r["id"]: r for r in store.judgments(since=0, now=9e9)}
        assert j4 in rows, "보관 기한이 남았는데 행이 사라졌다"
        assert not rows[j4]["summary"], "서술 보관 기한이 지났는데 남아 있다"

        # ⑧ 주기 정리가 실제로 돈다 — 기동 때 한 번뿐이면 보관 기한을 못 지킨다
        old = _time.time() - (store.SUMMARY_DAYS + 10) * 86400
        jp = store.record_judgment({"fingerprint": "p", "host": "h",
                                    "summary": "옛 서술"}, now=old)
        pr = store.Pruner(interval_s=0.05)
        pr.start()
        try:
            for _ in range(40):
                _time.sleep(0.05)
                if not store.get_judgment(jp).get("summary"):
                    break
        finally:
            pr.stop()
        row = store.get_judgment(jp)
        assert row, "보관 기한이 남은 행을 주기 정리가 지웠다"
        assert not row.get("summary"), "주기 정리가 안 돌았다"
        return 19
    finally:
        store.close()
        store.PATH = saved
        shutil.rmtree(d, ignore_errors=True)




def _judgment_wiring_checks() -> int:
    """판정 행이 카드보다 먼저 생기는가 — 정정 버튼이 가리킬 대상 (§25-1)."""
    import asyncio
    import os
    import shutil
    import tempfile
    import time as _t

    from .. import llm, store
    from ..alerts import collector, incident as inc_mod, triage
    from ..integrations import keep

    d = tempfile.mkdtemp(prefix="wire-")
    saved_path, saved_push, saved_llm = store.PATH, keep.push_alert, llm.triage_reply
    saved_zbx, saved_ctx = collector.ZabbixClient, collector.collect_incident_context
    saved_keep = os.environ.pop("KEEP_URL", None)
    saved_slack = os.environ.pop("SLACK_BOT_TOKEN", None)
    cards = []

    def _fake_push(*a, **kw):
        cards.append(kw)
        return {"ok": True}

    def _fake_llm(context, sev):
        return {"text": "원인은 백업 부하다", "provider": "claude", "degraded": False,
                "change": "이전과 동일", "reason": ""}

    class _Zbx:
        def __init__(self, *a, **kw):
            self.source = "zabbix-internal"

    async def _fake_ctx(zbx, inc):
        # 조회는 전부 성공했고 교차 신호만 없는 상태 — 게이트가 정상적으로 건너뛴다
        return {"incident": {"host": inc.host, "classes": sorted(inc.classes()),
                             "alert_count": len(inc.alerts),
                             "fingerprint": inc.fingerprint()},
                "host": {}, "logs": [], "security": [], "open_problems": [],
                "alerts": [{"name": a.alert_name, "source": a.source, "sev": a.sev,
                            "class": a.incident_class,
                            "prejudge": {"verdict": "만성"}} for a in inc.alerts],
                "sources": {"logs": "ok", "security": "ok", "metrics": "ok",
                            "open_problems": "ok"}}

    def _mk(cls="disk_space", clock=1700000000.0):
        return inc_mod.Incident(
            key=("internal", "h7", cls), host="h7",
            alerts=[inc_mod.Alert(source="zabbix-internal", event_id="e7",
                                  trigger_id="t7", host="h7", alert_name="디스크",
                                  sev="SEV2", incident_class=cls,
                                  recv=_t.monotonic(), clock=clock)],
            opened_at=_t.monotonic(), last_at=_t.monotonic())

    try:
        store.PATH = os.path.join(d, "w.db")
        store.close()
        store.init()
        keep.push_alert = _fake_push
        llm.triage_reply = _fake_llm
        collector.ZabbixClient = _Zbx
        collector.collect_incident_context = _fake_ctx

        # ① 게이트 스킵 — 카드에 판정 식별자가 실리고 DB 행과 같다
        inc = _mk()
        asyncio.run(triage.run_incident(inc))
        rows = store.judgments(since=0, now=9e9)
        assert len(rows) == 1 and rows[0]["gate_fired"] == 0, rows
        assert cards and cards[-1].get("extra", {}).get("judgment_id") == rows[0]["id"], cards[-1]
        assert rows[0]["origin"] == "auto", rows[0]
        assert rows[0]["event_ts"] == 1700000000.0, "사건 발생 시각이 안 들어왔다"
        assert rows[0]["ikey"], "폴백 키가 비었다"

        # ② 사람이 강제한 재분석 — 분모에서 빼야 하므로 표시가 남는다
        cards.clear()
        inc2 = _mk()
        asyncio.run(triage.run_incident(inc2, force=True))
        rows = [r for r in store.judgments(since=0, now=9e9) if r["origin"] == "forced"]
        assert len(rows) == 1, "강제 재분석이 auto 와 구분되지 않는다"
        assert rows[0]["gate_fired"] == 1 and rows[0]["provider"] == "claude", rows[0]
        assert rows[0]["summary"] == "원인은 백업 부하다", "분석 결론이 안 남았다"
        assert rows[0]["change"] == "이전과 동일", rows[0]
        assert rows[0]["total_s"] is not None, "finish 가 안 불렸다"
        assert cards and cards[-1].get("extra", {}).get("judgment_id") == rows[0]["id"]

        # ③ 저장소가 죽어도 카드는 나가고 흐름이 안 깨진다
        store.close()
        store.PATH = d
        store.init()
        cards.clear()
        asyncio.run(triage.run_incident(_mk()))
        assert cards, "저장소가 죽자 카드까지 멈췄다"
        assert not cards[-1].get("extra", {}).get("judgment_id")
        return 14
    finally:
        store.close()
        store.PATH, keep.push_alert, llm.triage_reply = saved_path, saved_push, saved_llm
        collector.ZabbixClient, collector.collect_incident_context = saved_zbx, saved_ctx
        if saved_keep is not None:
            os.environ["KEEP_URL"] = saved_keep
        if saved_slack is not None:
            os.environ["SLACK_BOT_TOKEN"] = saved_slack
        shutil.rmtree(d, ignore_errors=True)




def _feedback_checks() -> int:
    """사람이 남기는 판정 라벨 — 틀린 대상에 붙지 않고, 실패가 성공으로 안 보이는가 (§25-2)."""
    import os
    import shutil
    import sys
    import tempfile

    from .. import store

    # 도구 스크립트는 bot/tools/ 에 있다. 검사 파일에서 두 단계 위가 bot/ 이다.
    _bot = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    sys.path.insert(0, os.path.join(_bot, "tools"))
    import mark_judgment

    d = tempfile.mkdtemp(prefix="mark-")
    saved = store.PATH
    try:
        store.PATH = os.path.join(d, "m.db")
        store.close()
        store.init()
        jid = store.record_judgment({"fingerprint": "fp-a", "host": "h1"}, now=1000.0)

        # 워크플로는 종료코드로만 성패를 안다 — 0 을 돌려주면 사람은 정정이 된 줄 안다
        assert mark_judgment.run(jid=999999, fingerprint="fp-a", ok=False) != 0
        assert mark_judgment.run(jid=jid, fingerprint="다른지문", ok=False) != 0
        assert mark_judgment.run(jid=jid, fingerprint="fp-a", ok=False, axis="없는축") != 0
        assert not store.labels_for([jid]), "실패한 요청이 라벨을 남겼다"

        # ② 정상 정정
        assert mark_judgment.run(jid=jid, fingerprint="fp-a", ok=False,
                                 note="봤어야 했다", who="tester") == 0
        lab = store.labels_for([jid])
        assert lab[jid]["overall"]["ok"] == 0 and lab[jid]["overall"]["who"] == "tester"

        # ③ 지문 없이도 식별자만으로 되지만, 그건 사람이 직접 부를 때다
        assert mark_judgment.run(jid=jid, fingerprint="", ok=True) == 0
        assert store.labels_for([jid])[jid]["overall"]["ok"] == 1, "나중 라벨이 안 이겼다"

        # ④ 저장소를 못 쓰면 실패로 끝낸다 — 아무도 안 읽는 파일에 쌓이면 안 된다
        store.close()
        store.PATH = d
        assert mark_judgment.run(jid=1, fingerprint="", ok=True) != 0

        # ⑤ 사람이 재분석을 누른 것 자체가 게이트 판정에 대한 음성 라벨이다
        import analyze_now
        store.close()
        store.PATH = os.path.join(d, "m.db")
        store.init()
        n = analyze_now.label_previous("fp-a")
        assert n == 1, "직전 판정에 라벨이 안 붙었다"
        lab = store.labels_for([jid])
        assert lab[jid]["gate"]["ok"] == 0, lab
        assert lab[jid]["gate"]["who"] == "workflow:analyze-now", lab
        assert analyze_now.label_previous("없는지문") == 0
        return 12
    finally:
        store.close()
        store.PATH = saved
        shutil.rmtree(d, ignore_errors=True)




def _route_record_checks() -> int:
    """라우팅 판정이 남는가 — 판정 이력만 보면 triage 경로밖에 안 보인다 (§25-3)."""
    import os
    import shutil
    import tempfile

    from .. import app as app_mod, store
    from ..alerts import pending

    d = tempfile.mkdtemp(prefix="route-")
    saved_path, saved_pending = store.PATH, pending.PATH
    saved_tok = os.environ.get("GATEWAY_TOKEN")
    os.environ["GATEWAY_TOKEN"] = "t-route"

    class _FakeBg:
        def add_task(self, fn, *a, **kw):
            pass

    try:
        store.PATH = os.path.join(d, "r.db")
        pending.PATH = os.path.join(d, "pending.jsonl")
        store.close()
        store.init()

        def _ev(eid, nsev):
            return app_mod.ZabbixEvent(source="zabbix-internal", event_id=eid,
                                       trigger_id="t1", nseverity=nsev, host="h1",
                                       event_name="Disk space is low")

        r1 = app_mod.webhook_zabbix(_ev("e1", 4), _FakeBg(), "t-route")
        r2 = app_mod.webhook_zabbix(_ev("e1", 4), _FakeBg(), "t-route")   # 같은 알림
        app_mod.webhook_zabbix(_ev("e2", 1), _FakeBg(), "t-route")        # 낮은 심각도
        assert r1["status"] == "accepted" and r2["status"] == "duplicate"

        rows = store.routes(since=0, now=9e9)
        assert len(rows) == 3, "중복이 분모에서 조용히 빠졌다: %s" % rows
        dups = [r for r in rows if r["dup"]]
        assert len(dups) == 1 and dups[0]["route"], "중복 행에 경로가 안 실렸다"
        assert {r["route"] for r in rows} == {"triage", "dashboard_only"}, rows
        assert all(r["cls"] == "disk_space" for r in rows), rows
        assert all(r["host"] == "h1" and r["source"] == "zabbix-internal" for r in rows)
        return 8
    finally:
        store.close()
        store.PATH, pending.PATH = saved_path, saved_pending
        if saved_tok is None:
            os.environ.pop("GATEWAY_TOKEN", None)
        else:
            os.environ["GATEWAY_TOKEN"] = saved_tok
        shutil.rmtree(d, ignore_errors=True)




def _annotation_checks() -> int:
    """판정 주석 — 지표 스파이크와 같은 자리에 찍히는가, 실패가 조용한가 (§25-4)."""
    import os

    from ..integrations import grafana

    saved_env = {k: os.environ.get(k) for k in
                 ("GATEWAY_GRAFANA_URL", "GRAFANA_INTERNAL_URL", "GRAFANA_TOKEN")}
    saved_httpx = grafana.httpx
    sent = []

    class _Resp:
        def __init__(self, code, payload):
            self.status_code, self._p, self.text = code, payload, str(payload)

        def json(self):
            return self._p

    class _FakeHttpx:
        def __init__(self, code=200, payload=None, boom=False):
            self.code, self.payload, self.boom = code, payload or {"id": 77}, boom

        def post(self, url, **kw):
            sent.append((url, kw))
            if self.boom:
                raise RuntimeError("연결 거부")
            return _Resp(self.code, self.payload)

        def get(self, url, **kw):
            sent.append((url, kw))
            return _Resp(self.code, self.payload)

    try:
        for k in saved_env:
            os.environ.pop(k, None)

        # ① 주소·토큰이 없으면 발행하지 않는다. 예외도 아니다.
        grafana.httpx = _FakeHttpx()
        assert grafana.annotate("x", 1700000000.0) is None
        assert not sent, "주소가 없는데 어딘가로 보냈다"

        os.environ["GATEWAY_GRAFANA_URL"] = "http://grafana.local:3000"
        assert grafana.annotate("x", 1700000000.0) is None, "토큰 없이 보냈다"

        # ② 정상 발행 — 시각은 밀리초이고 사건 발생 시각이다
        os.environ["GRAFANA_TOKEN"] = "tok"
        sent.clear()
        aid = grafana.annotate("복제 지연 · SEV2", 1700000000.0,
                               tags=["kinx-bot", "SEV2"])
        assert aid == 77, aid
        url, kw = sent[-1]
        assert url.endswith("/api/annotations"), url
        body = kw["json"]
        assert body["time"] == 1700000000000, \
            "초로 보내면 1970년에 찍히고 화면에서 조용히 사라진다: %s" % body["time"]
        assert "timeEnd" not in body, "해소 시각을 모르는데 구간으로 찍었다"
        assert body["tags"] == ["kinx-bot", "SEV2"] and body["text"]
        assert kw["headers"]["Authorization"] == "Bearer tok"

        # ③ 실패는 조용히 넘어간다 — 트리아지를 막지 않는다
        grafana.httpx = _FakeHttpx(boom=True)
        assert grafana.annotate("x", 1700000000.0) is None
        grafana.httpx = _FakeHttpx(code=401, payload={"message": "unauthorized"})
        assert grafana.annotate("x", 1700000000.0) is None

        # ④ 사건 시각을 모르면(0) 발행하지 않는다 — 1970년 주석을 만들지 않는다
        grafana.httpx = _FakeHttpx()
        assert grafana.annotate("x", 0) is None

        # 주석은 판정 행의 사건 시각을 그대로 쓴다 — 다시 계산하면 분석에 걸린 만큼 밀린다
        import asyncio
        import time as _t

        from ..alerts import incident as inc_mod, triage

        sent.clear()
        grafana.httpx = _FakeHttpx()
        inc = inc_mod.Incident(
            key=("internal", "h1", "other"), host="h1",
            alerts=[inc_mod.Alert(source="zabbix-internal", event_id="e1",
                                  trigger_id="", host="h1", alert_name="n",
                                  sev="SEV1", incident_class="other",
                                  recv=_t.monotonic())],   # clock 없음 = 발행 측 미제공
            opened_at=_t.monotonic(), last_at=_t.monotonic())
        asyncio.run(triage._annotate(None, inc, "SEV1", "헤드", "단일", "본문",
                                     event_ts=1700000000.0))
        assert sent and sent[-1][1]["json"]["time"] == 1700000000000, sent[-1][1]["json"]
        # 사건 유형이 태그에 실려야 패널이 자기가 다루는 것만 골라 갈 수 있다
        assert "other" in sent[-1][1]["json"]["tags"], sent[-1][1]["json"]["tags"]
        return 15
    finally:
        grafana.httpx = saved_httpx
        for k, v in saved_env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v




def _quality_checks() -> int:
    """판정 정확도 산출 — 라벨이 없을 때 숫자를 지어내지 않는가 (§25-5)."""
    import os
    import shutil
    import tempfile

    from .. import store
    from ..alerts import quality

    d = tempfile.mkdtemp(prefix="quality-")
    saved = store.PATH
    T = 1700000000.0
    try:
        store.PATH = os.path.join(d, "q.db")
        store.close()
        store.init()

        ids = []
        for i in range(10):
            ids.append(store.record_judgment({
                "fingerprint": "fp%d" % i, "ikey": "internal|h1|bridge1",
                "host": "h1", "realm": "internal", "classes": "disk_space",
                "alert_count": 1 + (i % 3), "sev": "SEV2", "verdict": "만성",
                "gate_fired": 1 if i < 6 else 0, "origin": "auto",
                "event_ts": T - 3600 + i, "provider": "claude", "degraded": i == 0,
                "total_s": None if i < 2 else 10.0 + i,
                "change": "이전과 동일" if i < 5 else "새 증상",
                "annotation_id": 5 if i < 4 else None,
                "sources": "logs:ok,security:unavailable"}, now=T - 3600 + i))
        store.record_judgment({"fingerprint": "fpF", "host": "h1", "origin": "forced",
                               "gate_fired": 1, "event_ts": T - 100,
                               "total_s": 99.0}, now=T - 100)

        # 라벨이 하나도 없으면 정확도 칸에 백분율이 없어야 한다 — 각주는 슬라이드에서 떨어진다
        m = quality.collect(days=30, now=T)
        acc = quality.render_accuracy(m)
        assert "%" not in acc, "라벨 0건인데 백분율을 만들었다:\n%s" % acc
        assert "판정 불가" in acc and "0/10" in acc, acc

        # ② 강제 재분석은 분모에서 빠진다
        assert m["judgments"] == 10 and m["forced"] == 1, m
        assert abs(m["gate_fire_rate"] - 0.6) < 1e-9, m

        # ③ 응답시간은 값이 없는 행을 빼고, 뺀 건수를 함께 낸다
        assert m["latency"]["n"] == 8 and m["latency"]["excluded"] == 2, m["latency"]
        assert "%.1f" % m["latency"]["p50"] not in ("0.0",), m["latency"]

        # ④ 라벨이 임계 미만이면 점추정을 만들지 않는다
        for i in range(3):
            store.record_feedback(ids[i], "overall", ok=True, who="t", now=T)
        m = quality.collect(days=30, now=T)
        acc = quality.render_accuracy(m)
        assert "%" not in acc and "3/10" in acc, acc

        # ⑤ 임계를 넘으면 점추정과 신뢰구간이 함께 나온다
        saved_min = quality.MIN_LABELS
        quality.MIN_LABELS = 3
        try:
            m = quality.collect(days=30, now=T)
            acc = quality.render_accuracy(m)
            assert "100.0%" in acc and "95% CI" in acc, acc
            lo, hi = m["accuracy"]["overall"]["ci"]
            assert 0.0 < lo < 1.0 and abs(hi - 1.0) < 1e-9, (lo, hi)
        finally:
            quality.MIN_LABELS = saved_min

        # ⑥ 조치 성공률은 지어내지 않고 사유를 남긴다
        assert "미확인" in quality.render(m), quality.render(m)

        # ⑦ 라벨 없이 재는 병합 축 — 같은 호스트에서 창 안에 갈라진 사건
        assert m["split_incidents"] >= 1, m

        # ⑧ 측정 조건이 헤더에 박힌다
        head = quality.render(m)
        assert "창 30일" in head and "판정 10건" in head, head

        # ⑨ 보낼 키와 받을 아이템이 문자 단위로 같다. 어긋나면 전송은 성공인데 화면만 빈다.
        import io
        import re as _re
        # checks/store.py → checks → gateway → bot → 리포 뿌리
        root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(
            os.path.abspath(__file__)))))
        with io.open(os.path.join(root, "ansible", "quality_metrics.yml"),
                     encoding="utf-8") as f:
            declared = set(_re.findall(r'key:\s*"(quality\.[a-z0-9_]+)"', f.read()))
        sending = set(quality.trapper_values(m))
        assert sending == declared, "키 불일치: 보냄-선언 %s / 선언-보냄 %s" % (
            sorted(sending - declared), sorted(declared - sending))

        # ⑩ 산출 안 된 정확도는 0 이 아니라 -1 로 간다 — 0 은 "정확도 0%" 로 읽힌다
        assert quality.trapper_values(m)["quality.acc_gate"] == -1, "미산출을 0 으로 보냈다"
        return 19
    finally:
        store.close()
        store.PATH = saved
        shutil.rmtree(d, ignore_errors=True)




def _prior_checks() -> int:
    """과거 결론 연계 — 무엇을 고르고, 무엇을 절대 안 싣는가 (§25-6)."""
    import json
    import os
    import shutil
    import tempfile
    import time as _t

    from .. import masking, nametable, store
    from ..alerts import incident as inc_mod, prior

    d = tempfile.mkdtemp(prefix="prior-")
    saved_path, saved_terms = store.PATH, dict(nametable._terms)
    saved_mode = prior.MODE
    T = 1700000000.0

    def _inc(host="db01", cls="replication"):
        return inc_mod.Incident(
            key=("internal", host, "bridge1"), host=host,
            alerts=[inc_mod.Alert(source="zabbix-internal", event_id="e1",
                                  trigger_id="t1", host=host, alert_name="복제 지연",
                                  sev="SEV2", incident_class=cls,
                                  recv=_t.monotonic(), clock=T)],
            opened_at=_t.monotonic(), last_at=_t.monotonic())

    try:
        store.PATH = os.path.join(d, "p.db")
        store.close()
        store.init()
        inc = _inc()
        fp, ikey = inc.fingerprint(), "|".join(str(x) for x in inc.key)

        def _add(fingerprint, ikey_, host, ts, summary, classes="replication"):
            return store.record_judgment({
                "fingerprint": fingerprint, "ikey": ikey_, "host": host,
                "realm": "internal", "classes": classes, "sev": "SEV2",
                "verdict": "만성", "gate_fired": 1, "origin": "auto",
                "event_ts": ts, "summary": summary, "prior_used": 0}, now=ts)

        old = _add(fp, ikey, "db01", T - 20 * 86400, "20일 전 결론: 백업 I/O 경합")
        recent = _add(fp, ikey, "db01", T - 2 * 86400,
                      "2일 전 결론: sw-core-01 상류에서 지연")
        _add("다른지문", ikey, "db01", T - 5 * 86400, "유형만 같은 결론")
        _add("또다른", "internal|db01|bridge9", "db01", T - 6 * 86400, "호스트만 같은 결론")
        me = _add(fp, ikey, "db01", T, "지금 사건")

        # ① 자기 자신은 안 고른다. 시각 역순이고 상한을 지킨다.
        got = prior.select(inc, me, now=T)
        assert all(p["id"] != me for p in got), got
        assert len(got) <= prior.MAX_ITEMS, got
        assert got[0]["match"] == "동일 사건", got[0]

        # ② 폴백 3단 — 지문이 갈려도 유형·호스트로 찾아낸다
        inc2 = _inc()
        store._exec("DELETE FROM judgment WHERE fingerprint=?", (fp,))
        g2 = prior.select(inc2, None, now=T)
        assert g2 and g2[0]["match"] == "같은 유형", g2
        store._exec("DELETE FROM judgment WHERE ikey=?", (ikey,))
        g3 = prior.select(inc2, None, now=T)
        assert g3 and g3[0]["match"] == "같은 호스트", g3

        # ③ 본문은 사람이 확인한 결론에만 붙는다. 기본은 구조화만이다.
        store.close()
        store.PATH = os.path.join(d, "p2.db")
        store.init()
        old = _add(fp, ikey, "db01", T - 20 * 86400, "20일 전 결론: 백업 I/O 경합")
        recent = _add(fp, ikey, "db01", T - 2 * 86400,
                      "2일 전 결론: sw-core-01 상류에서 지연")
        nametable._terms = {"db01": "host", "sw-core-01": "host"}
        store.record_feedback(recent, "cause", ok=True, who="t", now=T)
        got = prior.select(inc, None, now=T)
        assert all(not p["summary"] for p in got), \
            "기본 모드인데 본문이 실렸다 — 확인된 결론이라도 기본은 구조화만이다"
        assert [p for p in got if p["confirmed"]], got

        prior.MODE = "full"
        got = prior.select(inc, None, now=T)
        body = [p for p in got if p["summary"]]
        assert len(body) == 1 and body[0]["id"] == recent, got

        # ④ 오답 표시된 결론은 본문 없이 개수만 — 모델은 틀린 문장도 베낀다
        store.record_feedback(old, "cause", ok=False, who="t", now=T)
        got = prior.select(inc, None, now=T)
        wrong = [p for p in got if p["confirmed"] is False and p.get("wrong")]
        assert wrong and not wrong[0]["summary"], got

        # ⑤ 프롬프트로 나가는 전문에 다른 호스트 실명이 남지 않는다
        ctx = {"incident": {"host": "db01", "classes": ["replication"],
                            "alert_count": 1, "merge_reason": "단일"},
               "host": {"host": "db01"}, "alerts": [], "logs": [], "security": [],
               "sources": {"logs": "ok"}, "prior": got}
        out = masking.build_llm_context(ctx, "SEV2", masking.Masker())
        blob = json.dumps(out, ensure_ascii=False)
        assert "sw-core-01" not in blob, "표에 있는 다른 호스트명이 그대로 나갔다"
        assert "db01" not in blob, blob[:200]
        assert out["prior"] and out["prior"][0]["match"], out["prior"]

        # ⑥ 이름 표가 비면 본문을 아예 안 싣는다 — 가릴 대상을 모르는 상태다
        nametable._terms = {}
        out = masking.build_llm_context(ctx, "SEV2", masking.Masker())
        assert all(not p.get("summary") for p in out["prior"]), out["prior"]

        # ⑦ 길이 상한 — 과거 결론이 길어도 프롬프트가 그만큼 늘지 않는다
        nametable._terms = {"db01": "host"}
        big = dict(got[0], summary="가" * 10000, confirmed=True)
        out = masking.build_llm_context(dict(ctx, prior=[big]), "SEV2", masking.Masker())
        assert len(out["prior"][0]["summary"]) <= prior.MAX_BODY_CHARS + 10, \
            len(out["prior"][0]["summary"])

        # ⑧ 과거 결론이 붙을 때만 변화 판정을 요구하고, 그 줄을 코드가 읽는다
        from .. import llm
        assert llm.PRIOR_INSTRUCTION not in llm.build_user_prompt({"prior": []})
        assert llm.PRIOR_INSTRUCTION in llm.build_user_prompt({"prior": [{"match": "x"}]})
        assert llm.extract_change("본문\n변화: 달라짐 — 이번엔 백업이 아니다") \
            == "달라짐 — 이번엔 백업이 아니다"
        assert llm.extract_change("변화 판정 줄이 없는 회신") == ""

        # ⑨ 꺼 두면 아무것도 안 고른다
        prior.MODE = "off"
        assert prior.select(inc, None, now=T) == []
        return 22
    finally:
        prior.MODE = saved_mode
        nametable._terms = saved_terms
        store.close()
        store.PATH = saved_path
        shutil.rmtree(d, ignore_errors=True)




def _dashboard_annotation_checks() -> int:
    """주석이 어느 패널에 서는가 — 번호가 어긋난 채 커밋되는 것을 잡는다 (§25-4)."""
    import io
    import json
    import os
    import sys

    # gateway/selftest.py → gateway → bot → 리포 뿌리
    here = os.path.abspath(__file__)
    root = os.path.dirname(os.path.dirname(os.path.dirname(here)))
    if not os.path.isdir(os.path.join(root, ".git")):
        root = os.path.dirname(root)
    sys.path.insert(0, os.path.join(root, "tools"))
    import set_judgment_annotation as sja

    from ..alerts import incident as inc_mod

    n = 0
    for uid, spec in sja.SPEC.items():
        path = os.path.join(root, "lab", "grafana", "provisioning", "dashboards",
                            "json", uid + ".json")
        dash = json.load(io.open(path, encoding="utf-8"))
        qs = [a for a in (dash.get("annotations") or {}).get("list") or []
              if (a.get("name") or "").startswith(sja.QUERY_NAME)]
        assert qs, "%s: 판정 주석 질의가 없다 — set_judgment_annotation.py 를 돌린다" % uid
        assert qs == sja.queries(dash, spec), (
            "%s: 주석 질의가 선언과 어긋난다. set_judgment_annotation.py 를 다시 돌린다" % uid)
        by_id = {p.get("id"): p for p in dash.get("panels", [])}
        for q in qs:
            ids = (q.get("filter") or {}).get("ids")
            # 범위를 안 좁히면 통계 숫자 패널 옆까지 세로선이 선다
            assert ids, "%s: 표시 패널을 안 좁혔다" % uid
            for pid in ids:
                assert pid in by_id, "%s: 없는 패널 번호 %s" % (uid, pid)
                assert by_id[pid].get("type") in ("timeseries", "graph"), (
                    "%s: 주석이 안 그려지는 패널을 골랐다 — %s" % (uid, by_id[pid].get("type")))
            # 태그 조건은 AND 다. 봇이 안 다는 유형을 적으면 그 질의는 영원히 빈다.
            for tag in q["target"]["tags"][1:]:
                assert tag in inc_mod._KNOWN_CLASSES, (
                    "%s: 봇이 달지 않는 유형이다 — %s" % (uid, tag))
            assert q["target"]["tags"][0] == sja.TAG, q["target"]
        n += 5
    return n




def _select_invariant_checks() -> int:
    """무작위·극단 입력으로 불변 조건을 흔든다."""
    import random

    from ..alerts import collector as c

    rnd = random.Random(20260813)
    shapes = ["INFO request completed status=200 dur=%dms path=/v1/pay/%d",
              "ERROR connection reset by peer upstream=db-pool-%d retry=%d",
              "WARN pool wait %dms queue=%d",
              "kernel: Out of memory: Killed process %d (app%d)",
              "2026/08/13 01:58:%02d.6661 [Mysql] Cannot fetch data: Error %d"]
    n = 0
    for _ in range(300):
        size = rnd.choice([0, 1, 39, 40, 41, 120, 300, 900])
        recs = []
        for i in range(size):
            # 시각이 겹치는 경우를 일부러 만든다 — 나노초를 초로 바꾸면 실제로 겹친다
            t = float(rnd.choice([1000, 1000, 1001, 1002 + i // 7]))
            recs.append({"t": t, "line": rnd.choice(shapes)
                         % (rnd.randint(0, 3), rnd.randint(0, 3))})
        out = c.select_logs(recs)
        body = [r for r in out if "line" in r]
        gaps = [r for r in out if "gap" in r]

        assert len(body) <= c.LOKI_SEND_LIMIT, (size, len(body))
        assert sum(g["gap"] for g in gaps) + len(body) == len(recs), (size, len(body))
        assert all(r.get("why") for r in body), body[:1]
        assert all(g["gap"] > 0 and g["to"] >= g["t"] for g in gaps), gaps[:1]
        assert [r["t"] for r in out] == sorted(r["t"] for r in out), "시각순이 아니다"
        # 같은 형태가 상한을 넘지 않는다. 단 창이 작아 전부 실린 경우는 접지 않는다.
        if len(recs) > c.LOKI_SEND_LIMIT:
            per = {}
            for r in body:
                s = c.log_shape(r["line"])
                per[s] = per.get(s, 0) + 1
            assert max(per.values(), default=0) <= c.SAME_SHAPE_MAX, per
        n += 0
    return 6




def _evidence_checks() -> int:
    """원문으로 되짚을 재료를 남기는가 — 사람용이고 모델에는 안 간다 (§25-7)."""
    import json
    import os
    import shutil
    import tempfile

    from .. import masking, store
    from ..alerts import prior
    from ..integrations import slack

    # ① 조회 참조가 컨텍스트에 있어도 전송 형태에는 없다. 모델의 분석 재료가 아니다.
    ctx = {"incident": {"host": "h1", "classes": ["disk_space"], "alert_count": 1},
           "host": {}, "alerts": [], "security": [], "sources": {"logs": "ok"},
           "logs": [{"t": 1.0, "line": "a", "why": "recent"}],
           "logs_query": '{host="h1"}', "logs_from": 1700000000,
           "logs_to": 1700000900}
    out = masking.build_llm_context(ctx, "SEV2", masking.Masker())
    blob = json.dumps(out, ensure_ascii=False)
    assert "logs_query" not in blob and 'host="h1"' not in blob, blob[:200]

    # Loki 보존이 31일인데 판정 행은 90일이라 오래된 참조는 0건이 "없었다"로 읽힌다
    d = tempfile.mkdtemp(prefix="evi-")
    saved = store.PATH
    try:
        store.PATH = os.path.join(d, "e.db")
        store.close()
        store.init()
        jid = store.record_judgment({"fingerprint": "fp", "host": "h1",
                                     "summary": "결론", "evidence": '{"q":"x"}'},
                                    now=1000.0)
        assert store.get_judgment(jid)["evidence"], "증거가 안 남았다"
        store.prune(now=1000.0 + store.SUMMARY_DAYS * 86400 + 10)
        row = store.get_judgment(jid)
        assert row and not row["summary"], "서술이 안 지워졌다"
        assert not row["evidence"], "증거가 서술보다 오래 남았다"

        # ③ 과거 결론 경로에 새 컬럼이 안 섞인다
        got = prior.select.__doc__ is not None
        assert got
        item = masking._prior_item({"summary": "", "match": "동일 사건"}, lambda x: x)
        assert "evidence" not in item and "logs_query" not in item, item
    finally:
        store.close()
        store.PATH = saved
        shutil.rmtree(d, ignore_errors=True)

    # Grafana 링크는 사건 시각 기준 절대 창 — 상대 창이면 재투입 때 엉뚱한 구간이 열린다
    saved_url = os.environ.get("GRAFANA_URL")
    os.environ["GRAFANA_URL"] = "http://g.local"
    try:
        link = slack._grafana_link("h1", event_ts=1700000000)
        assert "from=now-" not in link, link
        assert "1699999" in link or "1700000" in link, link
    finally:
        if saved_url is None:
            os.environ.pop("GRAFANA_URL", None)
        else:
            os.environ["GRAFANA_URL"] = saved_url
    return 11
