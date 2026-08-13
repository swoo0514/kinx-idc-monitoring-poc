"""판정 이력 저장소. 설계는 bot/GATEWAY_GUIDE.md §24."""

import logging
import os
import sqlite3
import threading
import time

log = logging.getLogger("gateway.store")

# 환경변수로 들어온 값에도 물결표를 편다. 안 펴면 작업 디렉토리 밑에 `~` 폴더가 생기고,
# 파일은 열리므로 아무 오류 없이 다른 곳에 쌓인다 (§24-1).
PATH = os.path.expanduser(os.environ.get("GATEWAY_STORE_FILE",
                                         "~/.kinx-gateway/history.db"))
KEEP_DAYS = int(os.environ.get("GATEWAY_STORE_KEEP_DAYS", "90"))
SUMMARY_DAYS = int(os.environ.get("GATEWAY_STORE_SUMMARY_DAYS", "30"))

_lock = threading.Lock()
_conn = None
_error = ""

# 판정 행이 담는 값. ts 는 기록 시각이고 event_ts 가 사건 발생 시각이다.
JUDGMENT_COLS = (
    "fingerprint", "ikey", "host", "realm", "source", "classes", "alert_count",
    "sev", "verdict", "gate_fired", "gate_reason", "sources", "origin",
    "event_ts", "provider", "degraded", "total_s", "summary", "change",
    "prior_used", "annotation_id", "evidence")

_JUDGMENT_DDL = """
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL NOT NULL,
  fingerprint TEXT, ikey TEXT, host TEXT, realm TEXT, source TEXT,
  classes TEXT, alert_count INTEGER, sev TEXT, verdict TEXT,
  gate_fired INTEGER, gate_reason TEXT, sources TEXT, origin TEXT,
  event_ts REAL, provider TEXT, degraded INTEGER, total_s REAL,
  summary TEXT, change TEXT, prior_used INTEGER, annotation_id INTEGER,
  evidence TEXT"""

_SCHEMA = """
CREATE TABLE IF NOT EXISTS judgment (%s);
CREATE INDEX IF NOT EXISTS judgment_ts ON judgment(ts);""" % _JUDGMENT_DDL + """
CREATE INDEX IF NOT EXISTS judgment_fp ON judgment(fingerprint);
CREATE INDEX IF NOT EXISTS judgment_ikey ON judgment(ikey);
CREATE TABLE IF NOT EXISTS feedback (
  ts REAL NOT NULL, judgment_id INTEGER, axis TEXT, ok INTEGER,
  note TEXT, who TEXT);
CREATE INDEX IF NOT EXISTS feedback_jid ON feedback(judgment_id);
CREATE TABLE IF NOT EXISTS route (
  ts REAL NOT NULL, source TEXT, host TEXT, sev TEXT, cls TEXT,
  route TEXT, dup INTEGER);
CREATE INDEX IF NOT EXISTS route_ts ON route(ts);
CREATE TABLE IF NOT EXISTS seen (key TEXT PRIMARY KEY, ts REAL NOT NULL);
CREATE TABLE IF NOT EXISTS call (ts REAL NOT NULL, kind TEXT);
CREATE INDEX IF NOT EXISTS call_ts ON call(ts);
"""


def status() -> dict:
    with _lock:
        return {"path": PATH, "open": _conn is not None, "error": _error}


def _columns(c, table: str) -> list:
    return [r[1] for r in c.execute("PRAGMA table_info(%s)" % table).fetchall()]


def _migrate(c) -> None:
    """구스키마를 판올림한다. 근거는 가이드 §24-4.

    판정 식별자는 ALTER 로 붙일 수 없으므로(SQLite 제약) 표를 한 번 다시 만든다.
    ALTER 는 다른 프로세스가 같은 파일에 먼저 붙였을 수 있어 중복 오류를 흡수한다.
    """
    old = _columns(c, "judgment")
    if old and "id" not in old:
        keep = [x for x in ("ts",) + JUDGMENT_COLS if x in old]
        cols = ",".join(keep)
        c.execute("CREATE TABLE judgment_v2 (%s)" % _JUDGMENT_DDL)
        c.execute("INSERT INTO judgment_v2 (%s) SELECT %s FROM judgment" % (cols, cols))
        c.execute("DROP TABLE judgment")
        c.execute("ALTER TABLE judgment_v2 RENAME TO judgment")
        log.info("판정 이력 스키마를 판올림했다 — 행 %d개 보존",
                 c.execute("SELECT COUNT(*) FROM judgment").fetchone()[0])
    c.executescript(_SCHEMA)
    have = _columns(c, "judgment")
    for name in JUDGMENT_COLS:
        if name in have:
            continue
        try:
            c.execute("ALTER TABLE judgment ADD COLUMN %s" % name)
        except sqlite3.OperationalError as e:
            if "duplicate column" not in str(e).lower():
                raise


def init() -> bool:
    global _conn, _error
    with _lock:
        if _conn is not None:
            return True
        try:
            d = os.path.dirname(PATH)
            if d:
                os.makedirs(d, exist_ok=True)
                os.chmod(d, 0o700)
            c = sqlite3.connect(PATH, check_same_thread=False, timeout=5)
            c.row_factory = sqlite3.Row
            c.execute("PRAGMA journal_mode=WAL")
            _migrate(c)
            c.commit()
            # 서술이 담기므로 같은 기계의 다른 사용자에게 열어 두지 않는다 (§24-6).
            for suffix in ("", "-wal", "-shm"):
                try:
                    os.chmod(PATH + suffix, 0o600)
                except OSError:
                    pass
            _conn, _error = c, ""
            return True
        except Exception as e:
            _error = str(e)
            log.error("판정 이력 저장소를 열지 못했다 %s: %s — 메모리로 동작한다", PATH, e)
            return False


def close() -> None:
    global _conn
    with _lock:
        if _conn is not None:
            try:
                _conn.close()
            except Exception:
                pass
            _conn = None


def _exec(sql: str, args=(), fetch: str = ""):
    with _lock:
        if _conn is None:
            return None
        try:
            cur = _conn.execute(sql, args)
            if fetch == "one":
                return cur.fetchone()
            if fetch == "all":
                return cur.fetchall()
            _conn.commit()
            return True
        except Exception as e:
            log.warning("저장소 질의 실패: %s", e)
            return None


def record_judgment(row: dict, now: float = None):
    """판정 행을 남기고 식별자를 돌려준다. 저장소를 못 쓰면 None."""
    cols = JUDGMENT_COLS
    vals = [time.time() if now is None else now] + [row.get(c) for c in cols]
    with _lock:
        if _conn is None:
            return None
        try:
            cur = _conn.execute(
                "INSERT INTO judgment (ts,%s) VALUES (%s)"
                % (",".join(cols), ",".join("?" * (len(cols) + 1))), vals)
            _conn.commit()
            return cur.lastrowid
        except Exception as e:
            log.warning("판정 기록 실패: %s", e)
            return None


def finish(judgment_id, fields: dict) -> bool:
    """분석이 끝난 뒤 채워지는 값. 없는 식별자는 조용히 넘어간다."""
    cols = [c for c in fields if c in JUDGMENT_COLS]
    if not judgment_id or not cols:
        return False
    sql = "UPDATE judgment SET %s WHERE id=?" % ",".join("%s=?" % c for c in cols)
    return _exec(sql, [fields[c] for c in cols] + [judgment_id]) is True


def get_judgment(judgment_id) -> dict:
    r = _exec("SELECT * FROM judgment WHERE id=?", (judgment_id,), fetch="one")
    return dict(r) if r else {}


def latest_judgment(fingerprint: str) -> dict:
    r = _exec("SELECT * FROM judgment WHERE fingerprint=? ORDER BY ts DESC LIMIT 1",
              (fingerprint,), fetch="one")
    return dict(r) if r else {}


def record_feedback(judgment_id, axis: str, ok: bool, note: str = "",
                    who: str = "", now: float = None) -> bool:
    """사람이 남긴 판정 확인·정정. 같은 축에 여러 번 남을 수 있고 나중 것이 유효하다."""
    now = time.time() if now is None else now
    return _exec("INSERT INTO feedback (ts,judgment_id,axis,ok,note,who)"
                 " VALUES (?,?,?,?,?,?)",
                 (now, judgment_id, axis, 1 if ok else 0, note, who)) is True


def labels_for(ids) -> dict:
    """판정별 축별 최신 라벨. {판정 id: {축: {ok, ts, who, note}}}"""
    ids = [int(i) for i in ids if i]
    if not ids:
        return {}
    rows = _exec("SELECT * FROM feedback WHERE judgment_id IN (%s) ORDER BY ts ASC"
                 % ",".join("?" * len(ids)), tuple(ids), fetch="all") or []
    out = {}
    for r in rows:                      # 시간 오름차순이라 나중 것이 앞을 덮는다
        out.setdefault(r["judgment_id"], {})[r["axis"]] = {
            "ok": r["ok"], "ts": r["ts"], "who": r["who"], "note": r["note"]}
    return out


def record_route(row: dict, now: float = None) -> bool:
    """알림 1건의 라우팅 판정. 중복으로 걸린 것도 남긴다 — 안 남기면 분모에서 빠진다."""
    now = time.time() if now is None else now
    cols = ("source", "host", "sev", "cls", "route", "dup")
    return _exec("INSERT INTO route (ts,%s) VALUES (?,?,?,?,?,?,?)" % ",".join(cols),
                 [now] + [row.get(c) for c in cols]) is True


def routes(since: float = 0, now: float = None, limit: int = 100000) -> list:
    now = time.time() if now is None else now
    rows = _exec("SELECT * FROM route WHERE ts>=? AND ts<=? ORDER BY ts DESC LIMIT ?",
                 (since, now, limit), fetch="all")
    return [dict(r) for r in (rows or [])]


def judgments(since: float = 0, now: float = None, limit: int = 1000) -> list:
    now = time.time() if now is None else now
    rows = _exec("SELECT * FROM judgment WHERE ts>=? AND ts<=? ORDER BY ts DESC LIMIT ?",
                 (since, now, limit), fetch="all")
    return [dict(r) for r in (rows or [])]


def judgments_in_realms(realms, since: float = 0, now: float = None,
                        host: str = "", limit: int = 20) -> list:
    """허용된 감시 영역의 판정만. 대화형 질의가 남의 영역을 못 읽게 하는 자리다.

    `judgments()` 에 조건을 얹지 않고 따로 둔다. 그 함수는 품질 지표와 월간 리포트가
    분모로 쓰고 있어, 조건이 붙으면 그 수치가 조용히 바뀐다.

    **허용 영역이 비면 아무것도 주지 않는다.** 빈 목록을 "제한 없음" 으로 읽으면
    설정을 빠뜨린 사람이 전부를 보게 된다.
    """
    names = [str(r) for r in (realms or []) if str(r)]
    if not names:
        return []
    now = time.time() if now is None else now
    sql = ("SELECT * FROM judgment WHERE ts>=? AND ts<=? AND realm IN (%s)"
           % ",".join("?" for _ in names))
    args = [since, now] + names
    if host:
        sql += " AND host=?"
        args.append(host)
    rows = _exec(sql + " ORDER BY ts DESC LIMIT ?", tuple(args + [limit]), fetch="all")
    return [dict(r) for r in (rows or [])]


def seen_once(key: str, ttl_s: float, now: float = None) -> bool:
    """처음 보는 키면 True. 저장소를 못 쓰면 True — 알림을 막지 않는다 (§24-3)."""
    now = time.time() if now is None else now
    with _lock:
        if _conn is None:
            return True
        try:
            _conn.execute("DELETE FROM seen WHERE ts < ?", (now - ttl_s,))
            r = _conn.execute("SELECT ts FROM seen WHERE key=?", (key,)).fetchone()
            if r is not None:
                _conn.commit()
                return False
            _conn.execute("INSERT OR REPLACE INTO seen (key,ts) VALUES (?,?)", (key, now))
            _conn.commit()
            return True
        except Exception as e:
            log.warning("중복 판정 조회 실패: %s", e)
            return True


def record_call(kind: str, now: float = None) -> bool:
    now = time.time() if now is None else now
    return _exec("INSERT INTO call (ts,kind) VALUES (?,?)", (now, kind)) is True


def calls_since(window_s: float, now: float = None, kind: str = "") -> int:
    now = time.time() if now is None else now
    sql = "SELECT COUNT(*) AS n FROM call WHERE ts>=? AND ts<=?"
    args = [now - window_s, now]
    if kind:
        sql += " AND kind=?"
        args.append(kind)
    r = _exec(sql, tuple(args), fetch="one")
    return int(r["n"]) if r else 0


def kind_counts(window_s: float, now: float = None) -> dict:
    now = time.time() if now is None else now
    rows = _exec("SELECT kind, COUNT(*) AS n FROM call WHERE ts>=? AND ts<=? GROUP BY kind",
                 (now - window_s, now), fetch="all")
    return {r["kind"]: int(r["n"]) for r in (rows or []) if r["kind"]}


class Pruner:
    """보관 기한을 실제로 지키는 주기 정리.

    기동 때 한 번만 지우면 오래 떠 있는 프로세스는 영원히 안 지운다. 서술을 담기
    시작한 뒤로는 그게 못 지키는 보관 약속이 된다.
    """

    def __init__(self, interval_s: float = None):
        self.interval_s = float(interval_s if interval_s is not None
                                else os.environ.get("GATEWAY_STORE_PRUNE_S", "21600"))
        self._stop = threading.Event()
        self._thread = None

    def start(self):
        if self._thread and self._thread.is_alive():
            return True
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name="store-prune",
                                        daemon=True)
        self._thread.start()
        return True

    def stop(self):
        self._stop.set()

    def _loop(self):
        while not self._stop.wait(self.interval_s):
            try:
                prune()
            except Exception as e:
                log.warning("주기 정리 실패: %s", e)


def prune(now: float = None) -> None:
    """행보다 서술을 먼저 지운다 — 지표는 구조화 값만으로 산출된다 (§24-6)."""
    now = time.time() if now is None else now
    cut = now - KEEP_DAYS * 86400
    # 증거 참조도 서술과 같이 지운다. Loki 보존이 31일인데 판정 행은 90일이라,
    # 오래된 조회문을 눌러 0건이 나오면 "로그가 없었다"로 읽힌다.
    _exec("UPDATE judgment SET summary=NULL, evidence=NULL"
          " WHERE ts < ? AND (summary IS NOT NULL OR evidence IS NOT NULL)",
          (now - SUMMARY_DAYS * 86400,))
    _exec("DELETE FROM judgment WHERE ts < ?", (cut,))
    _exec("DELETE FROM feedback WHERE judgment_id NOT IN (SELECT id FROM judgment)")
    _exec("DELETE FROM route WHERE ts < ?", (cut,))
    _exec("DELETE FROM call WHERE ts < ?", (now - 2 * 86400,))
