"""대화 이력 — 사용자별 대화방. 설계는 bot/GATEWAY_GUIDE.md §27-2.

**저장소는 Redis 다.** 담는 것이 키로 빠르게 읽고 만료가 필요한 상태이고, 게이트웨이를
프로세스 여럿으로 늘리는 순간 공유되어야 하기 때문이다. 판정 이력과 증거는 여기 두지
않는다 — 그건 재현과 감사를 위한 것이라 영속 저장소가 맞다.

**Redis 가 죽어도 질의는 돈다.** 대화 이력과 목록만 포기한다. 대화는 다시 물으면 되지만
관측 조회는 그렇지 않다. 알림 경로에서 저장소가 죽어도 알림을 흘려보내는 것과 같은 판단이다.

키 구조
    ask:convo:{id}          대화 본문(리스트). TTL 은 마지막 사용에서 30일
    ask:convo-meta:{id}     제목·주인·시각(해시)
    ask:convo-list:{user}   그 사람의 대화 목록(정렬 집합, 점수=마지막 시각)
"""

import json
import logging
import os
import time
import uuid

log = logging.getLogger("gateway.convo")

TTL_S = int(os.environ.get("ASK_CONVO_TTL_S", str(30 * 86400)))
MAX_MESSAGES = int(os.environ.get("ASK_CONVO_MAX_MSGS", "200"))
TITLE_MAX = 60

_backend = None          # None 이면 대화를 저장하지 않는다(열화)
_mem = {"convo": {}, "meta": {}, "list": {}}


def use_redis(url: str = "") -> bool:
    """Redis 를 연결한다. 실패하면 False 이고 대화 없이 돈다."""
    global _backend
    url = url or os.environ.get("REDIS_URL", "")
    if not url:
        _backend = None
        return False
    try:
        import redis
        c = redis.Redis.from_url(url, decode_responses=True, socket_timeout=2)
        c.ping()
        _backend = c
        return True
    except Exception as e:
        log.warning("Redis 에 못 붙었다(%s) — 대화 이력 없이 돈다", e)
        _backend = None
        return False


def use_memory() -> None:
    """검사·단일 프로세스용. 재기동하면 사라진다."""
    global _backend
    _backend = "mem"
    _mem["convo"].clear()
    _mem["meta"].clear()
    _mem["list"].clear()


def use_none() -> None:
    global _backend
    _backend = None


def status() -> dict:
    return {"backend": "redis" if _backend not in (None, "mem") else
            ("memory" if _backend == "mem" else "none")}


def _title_of(text: str) -> str:
    t = " ".join(str(text or "").split())[:TITLE_MAX]
    return t or "새 대화"


def create(user: str, first_text: str = "") -> str:
    """대화방 하나. 반환은 식별자, 저장소가 없으면 빈 문자열."""
    if _backend is None:
        return ""
    cid = uuid.uuid4().hex[:16]
    now = time.time()
    meta = {"id": cid, "user": user, "title": _title_of(first_text), "at": now}
    if _backend == "mem":
        _mem["meta"][cid] = meta
        _mem["convo"][cid] = []
        _mem["list"].setdefault(user, {})[cid] = now
        return cid
    try:
        _backend.hset("ask:convo-meta:" + cid, mapping={k: str(v) for k, v in meta.items()})
        _backend.expire("ask:convo-meta:" + cid, TTL_S)
        _backend.zadd("ask:convo-list:" + user, {cid: now})
        _backend.expire("ask:convo-list:" + user, TTL_S)
        return cid
    except Exception as e:
        log.warning("대화 만들기 실패: %s", e)
        return ""


def _owner(cid: str) -> str:
    if _backend == "mem":
        return (_mem["meta"].get(cid) or {}).get("user", "")
    try:
        return _backend.hget("ask:convo-meta:" + cid, "user") or ""
    except Exception:
        return ""


def append(cid: str, user: str, role: str, text: str, images: list = None) -> bool:
    """한 줄 더한다. **주인이 아니면 아무것도 하지 않는다.**

    답에 붙었던 그림도 함께 남긴다. 본문만 저장하면 새로고침한 순간 화면에서 그림이
    사라진다(2026-08-18 실측). 그림은 바이트가 아니라 주소라서 부피는 작다.
    """
    if _backend is None or not cid or _owner(cid) != user:
        return False
    body = {"role": role, "content": text, "at": time.time()}
    if images:
        body["images"] = images
    row = json.dumps(body, ensure_ascii=False)
    now = time.time()
    if _backend == "mem":
        _mem["convo"].setdefault(cid, []).append(row)
        _mem["convo"][cid] = _mem["convo"][cid][-MAX_MESSAGES:]
        _mem["list"].setdefault(user, {})[cid] = now
        return True
    try:
        key = "ask:convo:" + cid
        _backend.rpush(key, row)
        _backend.ltrim(key, -MAX_MESSAGES, -1)
        # 쓸 때마다 수명을 늘린다 — 쓰는 대화는 살아 있고 안 쓰면 저절로 사라진다.
        for k in (key, "ask:convo-meta:" + cid, "ask:convo-list:" + user):
            _backend.expire(k, TTL_S)
        _backend.zadd("ask:convo-list:" + user, {cid: now})
        return True
    except Exception as e:
        log.warning("대화 기록 실패: %s", e)
        return False


def load(cid: str, user: str) -> list:
    """대화 본문. **주인이 아니면 빈 목록.**"""
    if _backend is None or not cid or _owner(cid) != user:
        return []
    try:
        rows = (_mem["convo"].get(cid, []) if _backend == "mem"
                else _backend.lrange("ask:convo:" + cid, 0, -1))
        return [json.loads(r) for r in rows]
    except Exception as e:
        log.warning("대화 읽기 실패: %s", e)
        return []


def listing(user: str, limit: int = 50) -> list:
    """그 사람의 대화 목록. 최근 것이 위다."""
    if _backend is None:
        return []
    try:
        if _backend == "mem":
            ids = sorted((_mem["list"].get(user) or {}).items(),
                         key=lambda kv: kv[1], reverse=True)[:limit]
            metas = [_mem["meta"].get(i) for i, _ in ids]
        else:
            ids = _backend.zrevrange("ask:convo-list:" + user, 0, limit - 1)
            metas = [_backend.hgetall("ask:convo-meta:" + i) for i in ids]
        return [{"id": m.get("id"), "title": m.get("title"), "at": float(m.get("at") or 0)}
                for m in metas if m]
    except Exception as e:
        log.warning("대화 목록 실패: %s", e)
        return []


def rename(cid: str, user: str, title: str) -> bool:
    if _backend is None or _owner(cid) != user:
        return False
    t = _title_of(title)
    if _backend == "mem":
        _mem["meta"][cid]["title"] = t
        return True
    try:
        _backend.hset("ask:convo-meta:" + cid, "title", t)
        return True
    except Exception as e:
        log.warning("대화 이름 바꾸기 실패: %s", e)
        return False


def remove(cid: str, user: str) -> bool:
    if _backend is None or _owner(cid) != user:
        return False
    if _backend == "mem":
        _mem["convo"].pop(cid, None)
        _mem["meta"].pop(cid, None)
        (_mem["list"].get(user) or {}).pop(cid, None)
        return True
    try:
        _backend.delete("ask:convo:" + cid, "ask:convo-meta:" + cid)
        _backend.zrem("ask:convo-list:" + user, cid)
        return True
    except Exception as e:
        log.warning("대화 지우기 실패: %s", e)
        return False
