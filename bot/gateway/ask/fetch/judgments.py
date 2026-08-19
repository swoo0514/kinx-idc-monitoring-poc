"""과거 판정 조회. 본문 전송 조건은 §25-6."""

import logging
import time
import os
from ... import masking

from ..policy import allowed_realms
log = logging.getLogger("gateway.ask")


def judgment_body(row: dict, mk: masking.Masker) -> str:
    """과거 판정의 분석 문장. 실을 수 없으면 빈 문자열."""
    raw = str(row.get("summary") or "")[:600]
    if not raw:
        return ""
    masked = mk.mask(raw)
    return "" if masking._leaks(masked) else masked


async def fetch_judgments(host: str, days: int, masker: masking.Masker,
                          now: float = None) -> dict:
    from ... import store
    from ...alerts import collector
    if not store.status()["open"]:
        return {"judgments": [], "status": collector.SOURCE_UNAVAILABLE,
                "note": "판정 이력 저장소를 열지 못했다"}
    now = time.time() if now is None else now
    rows = store.judgments_in_realms(allowed_realms(), since=now - days * 86400,
                                     now=now, host=host)
    out = []
    for r in rows:
        item = {"ts": int(r.get("ts") or 0),
                "host": masker.mask(r.get("host") or ""),
                "classes": r.get("classes") or "",
                "sev": r.get("sev") or "",
                "verdict": r.get("verdict") or ""}
        body = judgment_body(r, masker)
        if body:
            item["summary"] = body
        else:
            # 서술은 30일이면 지워진다(보관 정책). 없는 것과 못 실은 것을 구분한다.
            item["summary_note"] = "본문 없음(보관 기간 경과 또는 가림 실패)"
        out.append(item)
    return {"judgments": out, "status": collector.SOURCE_OK}
