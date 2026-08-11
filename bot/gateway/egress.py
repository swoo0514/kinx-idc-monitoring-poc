"""외부 LLM 으로 나가는 유일한 출구.

전에는 나가는 길이 여러 개였다. 트리아지(`llm.triage_reply`)와 월간 리포트
(`llm.monthly_reply`)가 각자 어댑터를 부르고, 심층조사(HolmesGPT)는 아예 다른
프로세스에서 자기 키로 나갔다. 어댑터 체인도 두 벌로 복제돼 있었다.

길이 여러 개면 보호도 여러 벌이 필요하고, 새 길이 생길 때 보호를 빠뜨려도 아무
신호가 없다. 실제로 동시 호출 상한을 트리아지에만 걸었더니 월간 리포트가 상한
밖에 남았는데, 그 사실이 코드를 읽기 전까지 드러나지 않았다.

그래서 나가는 지점을 하나로 만든다. 이 모듈을 거치지 않고 외부 LLM 을 부르는
코드는 없어야 한다. 여기서 동시 호출 수와 시간당 총량을 보고, 얼마나 썼는지를
센다. 마스킹은 부르는 쪽에 남는다 — 무엇을 가려야 하는지는 그 요청의 맥락을
아는 쪽만 판단할 수 있다.

설정·근거는 bot/GATEWAY_GUIDE.md §21.
"""

import logging
import os
import threading
import time

log = logging.getLogger("gateway.egress")

# 동시에 나가는 호출 수. 여러 호스트가 한꺼번에 무너지면 대기 창도 비슷한 시각에
# 닫혀 호출이 몰린다. 게이트의 발동 조건으로는 이것을 막을 수 없다 — 조건은
# "볼 만한 사건인가"를 판단할 뿐 몇 개가 동시에 나가는지는 보지 않는다.
MAX_CONCURRENCY = int(os.environ.get("LLM_MAX_CONCURRENCY", "3"))
# 자리를 기다리는 상한. 무한정 기다리면 스레드가 대기로 가득 차 Slack 게시 같은
# 다른 일까지 멈춘다. 넘기면 기다리지 않고 열화로 내려간다.
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


def _take_hour(exempt: bool, kind: str, now: float = None) -> bool:
    """시간당 총량에서 한 칸 쓴다. 남았으면 True.

    exempt 는 위중한 사건이다. 총량과 무관하게 통과시킨다 — 폭주 때 정작 위중한
    것이 막히면 상한이 사고를 키운다. 대신 쓴 것은 똑같이 센다.
    """
    now = time.time() if now is None else now
    with _lock:
        _calls[:] = [t for t in _calls if now - t <= 3600]
        if not exempt and len(_calls) >= MAX_PER_HOUR:
            _stats["hour_blocked"] += 1
            return False
        _calls.append(now)
        q = _by_kind.setdefault(kind or "?", [])
        q[:] = [t for t in q if now - t <= 3600]
        q.append(now)
        return True


def peak_last_hour(now: float = None) -> int:
    """최근 1시간 최고 동시 호출 수.

    누적 최고(`peak_inflight`)는 한 번 찍히면 영원히 남아 지금이 한가한지 붐비는지를
    말해 주지 않는다. 상한을 올릴지 판단하려면 최근 값이 필요하다.
    """
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


def call(adapters, system: str, user: str, exempt: bool = False,
         kind: str = "") -> dict:
    """외부 LLM 호출. 예외를 던지지 않는다.

    반환: {"text", "provider", "elapsed_s", "degraded", "reason"}
    실패해도 부르는 쪽 흐름은 이어져야 하므로 모든 실패를 dict 로 돌려준다.
    회신 문구는 부르는 쪽이 만든다 — 트리아지와 월간 리포트는 열화 시 남길 내용이
    다르기 때문이다.
    """
    t0 = time.monotonic()

    def _out(text, provider, degraded, reason=""):
        return {"text": text, "provider": provider, "degraded": degraded,
                "reason": reason, "elapsed_s": round(time.monotonic() - t0, 2)}

    # 총량을 먼저 본다. 총량에 걸린 건은 자리를 기다릴 이유가 없다.
    if not _take_hour(exempt, kind):
        log.warning("시간당 상한 도달 — %d건/1h (용도 %s). 열화로 회신한다",
                    MAX_PER_HOUR, kind or "?")
        return _out("", "none", True, BLOCKED_HOUR)

    if not _sem.acquire(timeout=QUEUE_WAIT_S):
        with _lock:
            _stats["queue_timeouts"] += 1
        log.warning("동시 호출 대기 초과 — 상한 %d, 대기 %.0fs (용도 %s)",
                    MAX_CONCURRENCY, QUEUE_WAIT_S, kind or "?")
        return _out("", "none", True, BLOCKED_QUEUE)

    _enter()
    try:
        for adapter in adapters:
            if not adapter.available():
                continue
            try:
                text = adapter.complete(system, user)
                return _out(text, adapter.name, False)
            except Exception as e:  # 타임아웃·429·529 포함 — 다음 어댑터로 폴백
                log.warning("adapter %s failed (%s): %s", adapter.name, kind or "?", e)
    finally:
        _leave()
        _sem.release()
    return _out("", "none", True, BLOCKED_NONE)
