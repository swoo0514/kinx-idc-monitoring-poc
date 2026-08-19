"""로그 조회(Loki).

원본은 한 파일(`ask.py`, 1,289줄)이었다. 2026-08-19 에 옮기기만 했고
기능은 바꾸지 않았다.
"""

import logging
import os
from ... import masking

log = logging.getLogger("gateway.ask")


# ---------------------------------------------------------------------------
# 실제 조회. 질의문은 asktools 가 만들고 여기서는 보내기만 한다.
#
# 반환에 항상 status 를 싣는다. 빈 결과가 "없었다" 인지 "못 봤다" 인지 구분되지 않으면
# 모델이 없음을 근거로 단언한다. 알림 경로에서 이미 겪은 문제다(조회 상태 계약).
# ---------------------------------------------------------------------------

async def fetch_logs(logql: str, start: int, end: int, limit: int,
                     masker: masking.Masker) -> dict:
    import httpx

    from ...alerts import collector
    url = os.environ.get("LOKI_URL", "").rstrip("/")
    if not url:
        return {"logs": [], "status": collector.SOURCE_DISABLED,
                "note": "로그 저장소가 연결돼 있지 않다"}
    try:
        async with httpx.AsyncClient() as c:
            r = await c.get(f"{url}/loki/api/v1/query_range", params={
                "query": logql,
                "start": str(int(start) * 1_000_000_000),
                "end": str(int(end) * 1_000_000_000),
                "limit": min(int(limit), collector.LOKI_FETCH_LIMIT),
                "direction": "backward"}, timeout=collector.TIMEOUT_S)
            r.raise_for_status()
            recs = [{"t": collector._loki_ts(ts),
                     "line": line[:collector.LOKI_LINE_MAX]}
                    for st in r.json().get("data", {}).get("result", [])
                    for ts, line in st.get("values", [])]
    except Exception as e:
        log.warning("로그 조회 실패: %s", e)
        return {"logs": [], "status": collector.SOURCE_UNAVAILABLE,
                "note": "조회하지 못했다. 이 결과를 '없음'으로 읽지 마라"}
    picked = collector.select_logs(sorted(recs, key=lambda r: r["t"]))
    return {"logs": [masking._log_item(x, masker.mask) for x in picked],
            "fetched": len(recs), "status": collector.SOURCE_OK}
