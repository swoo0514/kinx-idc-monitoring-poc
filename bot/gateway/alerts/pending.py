"""대기 중 알림 기록 — 창이 닫히기를 기다리는 동안 프로세스가 죽어도 알림을 잃지 않는다."""

import json
import logging
import os
import tempfile
import threading

log = logging.getLogger("gateway.pending")

# 이 파일을 만지는 동작을 한 줄로 세운다 — drop 이 통째로 다시 쓰므로 겹치면 알림이 사라진다
# RLock 인 이유는 drop·take_for_replay 가 잠근 채 _rewrite 를 부르기 때문이다
_lock = threading.RLock()

PATH = os.environ.get("GATEWAY_PENDING_FILE",
                      os.path.expanduser("~/.kinx-gateway/pending.jsonl"))
MAX_REPLAY = int(os.environ.get("GATEWAY_PENDING_MAX_REPLAY", "3"))


def _key(rec: dict) -> tuple:
    return (rec.get("source", ""), rec.get("event_id", ""))


def append(rec: dict) -> bool:
    """한 줄 추가. 디스크에 닿은 것을 확인하고 나서 참을 돌려준다.

    fsync 까지 하는 이유는 기록했다고 응답한 뒤 전원이 나가면 같은 유실이 나기 때문이다.
    """
    with _lock:
        try:
            os.makedirs(os.path.dirname(PATH) or ".", exist_ok=True)
            with open(PATH, "a", encoding="utf-8") as f:
                f.write(json.dumps(rec, ensure_ascii=False) + "\n")
                f.flush()
                os.fsync(f.fileno())
            return True
        except Exception as e:
            log.error("대기 알림 기록 실패 %s: %s", PATH, e)
            return False


def load() -> list:
    """재기동 시 남아 있는 알림. 깨진 줄은 건너뛴다 — 한 줄 때문에 전부 버리지 않는다."""
    with _lock:
        if not os.path.exists(PATH):
            return []
        out = []
        try:
            with open(PATH, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        out.append(json.loads(line))
                    except ValueError:
                        log.warning("대기 알림 한 줄을 읽지 못해 건너뛴다: %.80s", line)
        except Exception as e:
            log.error("대기 알림 읽기 실패 %s: %s", PATH, e)
        return out


def drop(recs) -> None:
    """처리를 마친 알림을 목록에서 뺀다. 남은 것만 새 파일로 바꿔 쓴다."""
    with _lock:
        gone = {_key(r) for r in recs}
        if not gone:
            return
        keep = [r for r in load() if _key(r) not in gone]
        _rewrite(keep)


def _rewrite(recs: list) -> None:
    with _lock:
        try:
            os.makedirs(os.path.dirname(PATH) or ".", exist_ok=True)
            d = os.path.dirname(PATH) or "."
            fd, tmp = tempfile.mkstemp(dir=d, prefix=".pending-", suffix=".tmp")
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                for r in recs:
                    f.write(json.dumps(r, ensure_ascii=False) + "\n")
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, PATH)   # 바꿔치기라 중간 상태의 파일이 남지 않는다
        except Exception as e:
            log.error("대기 알림 정리 실패 %s: %s", PATH, e)


def take_for_replay() -> list:
    """재기동 후 다시 처리할 알림. 시도 횟수를 올리고 한도를 넘은 것은 버린다."""
    with _lock:
        recs = load()
        if not recs:
            return []
        live, dead = [], []
        for r in recs:
            r["replays"] = int(r.get("replays", 0)) + 1
            (dead if r["replays"] > MAX_REPLAY else live).append(r)
        for r in dead:
            log.error("대기 알림 %s/%s 를 %d회 재시도 후 버린다 — 분석 단계에서 반복해 죽는지 확인",
                      r.get("source"), r.get("event_id"), MAX_REPLAY)
        _rewrite(live)
        return live
