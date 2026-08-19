"""과거 판정 조회. 본문 전송 조건은 §25-6.

원본은 한 파일(`ask.py`, 1,289줄)이었다. 2026-08-19 에 옮기기만 했고
기능은 바꾸지 않았다.
"""

import logging
import time
import os
from ... import masking

from ..policy import allowed_realms
log = logging.getLogger("gateway.ask")


def judgment_body(row: dict, mk: masking.Masker) -> str:
    """과거 판정의 분석 문장. 실을 수 없으면 빈 문자열.

    시각과 유형만 주면 "예전에도 있었다" 까지밖에 못 말한다. **무엇이라고 판단했는지가
    값이다.** 다만 그 문장에는 호스트명이 섞이므로 가린 뒤 누수 검사를 통과할 때만
    싣는다. 못 실어도 구조화 값은 그대로 가므로 판정 자체는 보인다(prior 와 같은 규칙).
    """
    raw = str(row.get("summary") or "")[:600]
    if not raw:
        return ""
    masked = mk.mask(raw)
    return "" if masking._leaks(masked) else masked


async def fetch_judgments(host: str, days: int, masker: masking.Masker,
                          now: float = None) -> dict:
    from ... import collector, store
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
