"""보안 경보 조회(Wazuh 인덱서)."""

import logging
import os
from ... import masking

log = logging.getLogger("gateway.ask")


async def fetch_security(body: dict, masker: masking.Masker) -> dict:
    import httpx

    from ...alerts import collector
    url = os.environ.get("WAZUH_INDEXER_URL", "").rstrip("/")
    if not url:
        return {"alerts": [], "status": collector.SOURCE_DISABLED,
                "note": "보안 저장소가 연결돼 있지 않다"}
    auth = (os.environ.get("WAZUH_INDEXER_USER", ""),
            os.environ.get("WAZUH_INDEXER_PASSWORD", ""))
    try:
        # 랩 인덱서가 자체 서명이라 검증을 끈다(알림 경로와 같은 조건).
        async with httpx.AsyncClient(verify=False) as c:
            r = await c.post(f"{url}/wazuh-alerts-*/_search", json=body, auth=auth,
                             timeout=collector.TIMEOUT_S)
            r.raise_for_status()
            body_json = r.json()
            hits = body_json.get("hits", {}).get("hits", [])
            total = (body_json.get("hits", {}).get("total") or {}).get("value")
    except Exception as e:
        log.warning("보안 조회 실패: %s", e)
        return {"alerts": [], "status": collector.SOURCE_UNAVAILABLE,
                "note": "조회하지 못했다. 이 결과를 '없음'으로 읽지 마라"}
    out = {"alerts": [masking._security_item(
                          collector.flatten_alert(h.get("_source") or {}), masker.mask)
                      for h in hits],
           "status": collector.SOURCE_OK}
    if total is not None:
        # **구간의 총 건수를 함께 준다.** 실린 것만 세면 50건을 넘을 때 조용히 적게 센다.
        out["total"] = int(total)
        if int(total) > len(hits):
            out["note"] = ("이 구간의 경보는 모두 %d건인데 최근 %d건만 실렸다. 건수는 "
                           "total 을 쓰고, 종류별로 세는 것은 실린 범위 안에서만 하라."
                           % (int(total), len(hits)))
    return out
