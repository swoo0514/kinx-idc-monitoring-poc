"""외부 LLM 으로 나가는 유일한 출구."""

import contextlib
import logging
import os
import threading
import time

from . import store

log = logging.getLogger("gateway.egress")

# 동시에 나가는 호출 수 — 게이트 조건으로는 못 막는다. 조건은 몇 개가 나가는지 안 본다
MAX_CONCURRENCY = int(os.environ.get("LLM_MAX_CONCURRENCY", "3"))
# 자리를 기다리는 상한 — 무한정 기다리면 Slack 게시 같은 다른 일까지 멈춘다
QUEUE_WAIT_S = float(os.environ.get("LLM_QUEUE_WAIT_S", "60"))
# 시간당 총량. 동시 수를 눌러도 장애가 길게 이어지면 총량은 계속 는다.
MAX_PER_HOUR = int(os.environ.get("LLM_MAX_PER_HOUR", "200"))

_sem = threading.BoundedSemaphore(MAX_CONCURRENCY)
_calls: list = []          # 최근 1시간 호출 시각
_lock = threading.Lock()
_stats = {"inflight": 0, "peak_inflight": 0, "queue_timeouts": 0, "hour_blocked": 0}
_peaks: list = []          # (시각, 그때 동시 수) — 누적 최고만 두면 언제 찍혔는지 모른다
_by_kind: dict = {}        # 용도별 호출 시각 — 무엇이 예산을 쓰는지 봐야 조정이 된다

# 열화 사유. 부르는 쪽이 문구를 만들 때 쓴다.
BLOCKED_HOUR = "hour_limit"
BLOCKED_QUEUE = "queue_timeout"
BLOCKED_NONE = "adapters_failed"


def stats() -> dict:
    with _lock:
        return dict(_stats)


def calls_last_hour(now: float = None, kind: str = "") -> int:
    """최근 1시간 호출 수. kind 를 주면 그 용도만."""
    now = time.time() if now is None else now
    with _lock:
        _calls[:] = [t for t in _calls if now - t <= 3600]
        if not kind:
            return len(_calls)
        q = _by_kind.setdefault(kind, [])
        q[:] = [t for t in q if now - t <= 3600]
        return len(q)


def kind_counts(now: float = None) -> dict:
    now = time.time() if now is None else now
    with _lock:
        out = {}
        for k, q in _by_kind.items():
            q[:] = [t for t in q if now - t <= 3600]
            out[k] = len(q)
        return out


def _hour_ok(exempt: bool, now: float = None, cap: int = None) -> bool:
    """시간당 총량이 남았는지 본다. **세지는 않는다.**"""
    now = time.time() if now is None else now
    if store.status()["open"]:
        used = store.calls_since(3600, now)
        if not exempt and used >= (MAX_PER_HOUR if cap is None else cap):
            with _lock:
                _stats["hour_blocked"] += 1
            return False
        return True
    with _lock:
        _calls[:] = [t for t in _calls if now - t <= 3600]
        if not exempt and len(_calls) >= (MAX_PER_HOUR if cap is None else cap):
            _stats["hour_blocked"] += 1
            return False
        return True


def _record(kind: str, now: float = None, user: str = "") -> None:
    """실제로 나가기 직전에 센다."""
    now = time.time() if now is None else now
    store.record_call(kind or "?", now, user=user)
    with _lock:
        _calls[:] = [t for t in _calls if now - t <= 3600]
        _calls.append(now)
        q = _by_kind.setdefault(kind or "?", [])
        q[:] = [t for t in q if now - t <= 3600]
        q.append(now)


def peak_last_hour(now: float = None) -> int:
    """최근 1시간 최고 동시 호출 수."""
    now = time.time() if now is None else now
    with _lock:
        _peaks[:] = [p for p in _peaks if now - p[0] <= 3600]
        return max((p[1] for p in _peaks), default=0)


def _enter(now: float = None):
    now = time.time() if now is None else now
    with _lock:
        _stats["inflight"] += 1
        _stats["peak_inflight"] = max(_stats["peak_inflight"], _stats["inflight"])
        _peaks.append((now, _stats["inflight"]))
        _peaks[:] = [p for p in _peaks if now - p[0] <= 3600]


def _leave():
    with _lock:
        _stats["inflight"] -= 1


class Blocked(Exception):
    """제한에 걸려 나가지 못했다. reason 은 BLOCKED_* 중 하나."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


@contextlib.contextmanager
def guard(kind: str = "", exempt: bool = False, max_per_hour: int = None,
          user: str = ""):
    """동시 수·시간당 총량을 걸고 실제 발신 직전에 센다 (§21-2)."""
    if not _hour_ok(exempt, cap=max_per_hour):
        log.warning("시간당 상한 도달 — %d건/1h (용도 %s)",
                    max_per_hour or MAX_PER_HOUR, kind or "?")
        raise Blocked(BLOCKED_HOUR)
    if not _sem.acquire(timeout=QUEUE_WAIT_S):
        with _lock:
            _stats["queue_timeouts"] += 1
        log.warning("동시 호출 대기 초과 — 상한 %d, 대기 %.0fs (용도 %s)",
                    MAX_CONCURRENCY, QUEUE_WAIT_S, kind or "?")
        raise Blocked(BLOCKED_QUEUE)
    _enter()
    try:
        yield lambda: _record(kind, user=user)
    finally:
        _leave()
        _sem.release()


def call(adapters, system: str, user: str, exempt: bool = False,
         kind: str = "") -> dict:
    """외부 LLM 호출. 예외를 던지지 않는다."""
    t0 = time.monotonic()

    def _out(text, provider, degraded, reason=""):
        return {"text": text, "provider": provider, "degraded": degraded,
                "reason": reason, "elapsed_s": round(time.monotonic() - t0, 2)}

    try:
        with guard(kind, exempt) as record:
            for adapter in adapters:
                if not adapter.available():
                    continue
                record()           # 이 어댑터로 실제로 나간다 — 여기서 센다
                try:
                    text = adapter.complete(system, user)
                    return _out(text, adapter.name, False)
                except Exception as e:  # 타임아웃·429·529 포함 — 다음 어댑터로 폴백
                    log.warning("adapter %s failed (%s): %s", adapter.name, kind or "?", e)
    except Blocked as b:
        return _out("", "none", True, b.reason)
    # 어댑터가 하나도 안 붙었거나 전부 실패. 붙을 어댑터가 없었으면 아무것도 안 셌다.
    return _out("", "none", True, BLOCKED_NONE)


def call_raw(fn, exempt: bool = False, kind: str = "", user: str = "") -> dict:
    """형태가 다른 호출(도구 사용 등)도 같은 출구를 지나게 한다."""
    t0 = time.monotonic()

    def _out(ok, value=None, reason=""):
        return {"ok": ok, "value": value, "reason": reason,
                "elapsed_s": round(time.monotonic() - t0, 2)}

    try:
        with guard(kind, exempt, user=user) as record:
            record()
            return _out(True, fn())
    except Blocked as b:
        return _out(False, reason=b.reason)
    except Exception as e:
        log.warning("call_raw 실패 (%s): %s", kind or "?", e)
        return _out(False, reason="%s: %s" % (type(e).__name__, e))
