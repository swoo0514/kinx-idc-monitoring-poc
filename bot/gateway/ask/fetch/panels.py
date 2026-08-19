"""관측 화면 목록과 그림 주소(Grafana)."""

import logging
from ... import masking
from .. import config

from ..config import PANELS_TTL_S
from ..session import _lock, _now
log = logging.getLogger("gateway.ask")


def var_host_of(entry: dict, panel: dict) -> str:
    """대시보드 변수에 넣을 호스트 값. 화면이 준 값이 먼저다."""
    return str((panel or {}).get("host") or "") or (entry or {}).get("host", "")


async def fetch_panel(entry: dict, target, start: int, end: int,
                      panel: dict = None) -> dict:
    """관측 화면 한 장. 모델에는 표시만 가고 주소는 화면으로만 간다."""
    from ...integrations import grafana
    from .. import tools as asktools
    if target:
        uid, panel_id, title = target
        note = "사람이 보고 있는 패널이 아니라 목록에서 고른 패널이다"
    else:
        uid, panel_id = asktools.panel_pick(panel)
        title, note = str((panel or {}).get("title") or ""), ""
    if not uid:
        return {"error": "어느 패널인지 모른다. list_panels 로 목록을 받아 ref 를 골라 "
                         "panel_ref 에 넣어라"}
    out = {"id": "img-%d" % (abs(hash((uid, panel_id, start))) % 9000 + 1000),
           "title": title,
           "url": grafana.panel_url(uid, panel_id, var_host_of(entry, panel), start, end)}
    if note:
        out["note"] = note
    return out


_panel_lists: dict = {}      # 대시보드 조건 -> (만든 시각, 목록)


def forget_panels() -> None:
    """패널 목록 캐시를 버린다. 대상 표를 버릴 때 같이 부른다."""
    with _lock:
        _panel_lists.clear()


async def fetch_panel_list(dash: str, masker: masking.Masker) -> tuple:
    """볼 수 있는 패널 목록과 조회 상태. 표시는 부르는 쪽이 붙인다.

    제목에 고객사명이나 호스트명이 들어 있을 수 있으므로 이름 표를 거쳐 내보낸다.
    """
    import asyncio

    from ...integrations import grafana
    from ...alerts import collector
    # 조회 실패와 "없음"을 구분한다 (§12) — 이 축만 빠져 Grafana 가 죽어도 "없다"로 나갔다
    key = str(dash or "")
    with _lock:
        made, cached = _panel_lists.get(key, (0.0, None))
    if cached is not None and _now() - made < PANELS_TTL_S:
        items = cached
    else:
        try:
            items = await asyncio.to_thread(grafana.list_panels, dash)
        except Exception as e:
            log.warning("패널 목록 조회 실패: %s", e)
            return [], collector.SOURCE_UNAVAILABLE
        # 빈 목록은 캐시하지 않는다. 미배선 상태를 60초 붙들 이유가 없다.
        if items:
            with _lock:
                _panel_lists[key] = (_now(), list(items))
    # 빈 목록일 때만 설정을 본다 — 먼저 보면 조회를 건너뛰어 검사가 지나간다
    if not items and not grafana._base():
        return [], collector.SOURCE_DISABLED
    # 질의문에는 호스트명이 그대로 들어 있는 일이 있다. 이름 표를 거쳐 내보낸다.
    return [dict(it, title=masker.mask(str(it.get("title") or "")),
                 dashboard=masker.mask(str(it.get("dashboard") or "")),
                 query=masker.mask(str(it.get("query") or "")))
            for it in items], collector.SOURCE_OK
