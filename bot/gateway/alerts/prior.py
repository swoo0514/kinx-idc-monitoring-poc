"""과거 분석 결론 연계. 선택 기준과 안 싣는 이유는 bot/GATEWAY_GUIDE.md §25-6."""

import logging
import os

from .. import store

log = logging.getLogger("gateway.prior")

# structured = 구조화 필드만 / full = 사람이 확인한 결론은 본문까지 / off = 안 씀
MODE = os.environ.get("GATEWAY_PRIOR_MODE", "structured")
MAX_ITEMS = int(os.environ.get("GATEWAY_PRIOR_MAX", "2"))
MAX_BODY_CHARS = int(os.environ.get("GATEWAY_PRIOR_BODY_CHARS", "600"))
LOOKBACK_DAYS = int(os.environ.get("GATEWAY_PRIOR_LOOKBACK_DAYS", "180"))

MATCH_SAME = "동일 사건"
MATCH_KIND = "같은 유형"
MATCH_HOST = "같은 호스트"


def _rows(sql: str, args: tuple) -> list:
    rows = store._exec(sql, args, fetch="all") or []
    return [dict(r) for r in rows]


def _candidates(inc, now: float) -> list:
    """지문 → 유형 → 호스트 순으로 찾는다."""
    since = now - LOOKBACK_DAYS * 86400
    ikey = "|".join(str(x) for x in (inc.key or ()))
    base = ("SELECT * FROM judgment WHERE gate_fired=1 AND ts>=? AND ts<=? AND %s"
            " ORDER BY ts DESC LIMIT 20")
    for cond, args, grade in (
            ("fingerprint=?", (inc.fingerprint(),), MATCH_SAME),
            ("ikey=?", (ikey,), MATCH_KIND),
            ("host=? AND realm=?", (inc.host, inc.key[0] if inc.key else ""), MATCH_HOST)):
        got = _rows(base % cond, (since, now) + args)
        if got:
            return [dict(r, match=grade) for r in got]
    return []


def select(inc, current_id=None, now: float = None) -> list:
    """이 사건에 붙일 과거 결론. 본문은 사람이 확인한 것에만 붙는다."""
    import time
    now = time.time() if now is None else now
    if MODE == "off" or not store.status()["open"]:
        return []
    rows = [r for r in _candidates(inc, now) if r["id"] != current_id]
    if not rows:
        return []
    labels = store.labels_for([r["id"] for r in rows])

    def _verdict(rid):
        lab = labels.get(rid) or {}
        for axis in ("cause", "overall"):
            if axis in lab:
                return bool(lab[axis]["ok"])
        return None

    out = []
    for r in rows:
        v = _verdict(r["id"])
        # 오답 표시된 결론은 본문을 안 싣는다 — 모델이 그 문장에 기대어 새 가설을 쓴다
        body = ""
        if MODE == "full" and v is True:
            body = (r.get("summary") or "")[:MAX_BODY_CHARS]
        out.append({
            "id": r["id"], "match": r["match"], "verdict": r.get("verdict") or "",
            "classes": r.get("classes") or "", "sev": r.get("sev") or "",
            "gate_reason": r.get("gate_reason") or "",
            "days_ago": round((now - (r.get("event_ts") or r["ts"])) / 86400.0, 1),
            "confirmed": v is True, "wrong": v is False,
            "prior_used": bool(r.get("prior_used")),
            "summary": body,
        })
    # 오염 안 된 원본을 먼저 쓴다 — 주입받아 나온 결론을 다시 넣으면 자기 문장을 읽는다
    out.sort(key=lambda p: (p["prior_used"], -1 if p["confirmed"] else 0))
    return out[:MAX_ITEMS]
