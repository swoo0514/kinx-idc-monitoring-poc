"""판정 이력 저장소. 설계는 bot/GATEWAY_GUIDE.md §24."""

import logging
import os
import sqlite3
import threading
import time

log = logging.getLogger("gateway.store")

PATH = os.environ.get("GATEWAY_STORE_FILE",
                      os.path.expanduser("~/.kinx-gateway/history.db"))
KEEP_DAYS = int(os.environ.get("GATEWAY_STORE_KEEP_DAYS", "90"))

_lock = threading.Lock()
_conn = None
_error = ""

_SCHEMA = """
CREATE TABLE IF NOT EXISTS judgment (
  ts REAL NOT NULL, fingerprint TEXT, host TEXT, realm TEXT, source TEXT,
  classes TEXT, alert_count INTEGER, sev TEXT, verdict TEXT,
  gate_fired INTEGER, gate_reason TEXT, sources TEXT,
  provider TEXT, degraded INTEGER, total_s REAL);
CREATE INDEX IF NOT EXISTS judgment_ts ON judgment(ts);
CREATE INDEX IF NOT EXISTS judgment_fp ON judgment(fingerprint);
CREATE TABLE IF NOT EXISTS seen (key TEXT PRIMARY KEY, ts REAL NOT NULL);
CREATE TABLE IF NOT EXISTS call (ts REAL NOT NULL, kind TEXT);
CREATE INDEX IF NOT EXISTS call_ts ON call(ts);
"""


def status() -> dict:
    with _lock:
        return {"path": PATH, "open": _conn is not None, "error": _error}


def init() -> bool:
    global _conn, _error
    with _lock:
        if _conn is not None:
            return True
        try:
            d = os.path.dirname(PATH)
            if d:
                os.makedirs(d, exist_ok=True)
            c = sqlite3.connect(PATH, check_same_thread=False, timeout=5)
            c.row_factory = sqlite3.Row
            c.execute("PRAGMA journal_mode=WAL")
            c.executescript(_SCHEMA)
            c.commit()
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


def record_judgment(row: dict, now: float = None) -> bool:
    cols = ("fingerprint", "host", "realm", "source", "classes", "alert_count",
            "sev", "verdict", "gate_fired", "gate_reason", "sources",
            "provider", "degraded", "total_s")
    vals = [time.time() if now is None else now] + [row.get(c) for c in cols]
    ok = _exec("INSERT INTO judgment (ts,%s) VALUES (%s)"
               % (",".join(cols), ",".join("?" * (len(cols) + 1))), vals)
    return ok is True


def judgments(since: float = 0, now: float = None, limit: int = 1000) -> list:
    now = time.time() if now is None else now
    rows = _exec("SELECT * FROM judgment WHERE ts>=? AND ts<=? ORDER BY ts DESC LIMIT ?",
                 (since, now, limit), fetch="all")
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


def prune(now: float = None) -> None:
    now = time.time() if now is None else now
    cut = now - KEEP_DAYS * 86400
    _exec("DELETE FROM judgment WHERE ts < ?", (cut,))
    _exec("DELETE FROM call WHERE ts < ?", (now - 2 * 86400,))
