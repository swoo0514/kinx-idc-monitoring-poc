"""판정 주석 발행. 설계·운영은 bot/GATEWAY_GUIDE.md §25-4."""

import base64
import logging
import os

import httpx

log = logging.getLogger("gateway.grafana")

TIMEOUT_S = float(os.environ.get("GRAFANA_TIMEOUT_S", "5"))
_warned = set()


def _base() -> str:
    return (os.environ.get("GATEWAY_GRAFANA_URL")
            or os.environ.get("GRAFANA_INTERNAL_URL", "")).rstrip("/")


def _auth() -> dict:
    tok = os.environ.get("GRAFANA_TOKEN", "")
    if tok:
        return {"Authorization": "Bearer " + tok}
    user = os.environ.get("GRAFANA_USER", "")
    pw = (os.environ.get("GRAFANA_ADMIN_PASSWORD", "")
          or os.environ.get("GRAFANA_PASSWORD", ""))
    if user and pw:
        raw = base64.b64encode(("%s:%s" % (user, pw)).encode()).decode()
        return {"Authorization": "Basic " + raw}
    return {}


def _warn_once(key: str, msg: str, *a) -> None:
    """사건마다 같은 경고를 찍지 않는다 — 그러면 진짜 경고가 안 보인다."""
    if key not in _warned:
        _warned.add(key)
        log.warning(msg, *a)


def status() -> dict:
    """기동 시 한 번 확인한다. 안 되고 있다는 걸 아무도 모르는 상태를 막는다."""
    base = _base()
    if not base:
        return {"configured": False, "ok": False, "error": "주소 미설정"}
    auth = _auth()
    if not auth:
        return {"configured": False, "ok": False, "error": "자격 증명 미설정"}
    try:
        r = httpx.get(base + "/api/health", headers=auth, timeout=TIMEOUT_S)
        return {"configured": True, "ok": r.status_code < 300,
                "error": "" if r.status_code < 300 else "HTTP %d" % r.status_code}
    except Exception as e:
        return {"configured": True, "ok": False, "error": str(e)[:120]}


def annotate(text: str, event_ts: float, tags=()) -> int:
    """조직 수준 주석을 남기고 식별자를 돌려준다. 실패하면 None.

    dashboardUID 를 안 넘기면 모든 대시보드에서 보인다. 시각은 밀리초이고, 분석 시각이
    아니라 사건 발생 시각을 쓴다 — 디바운스와 분석 시간만큼 밀리면 지표 스파이크 옆에
    있지 않아 쓸모가 없다.
    """
    base = _base()
    if not base:
        return None
    auth = _auth()
    if not auth:
        _warn_once("auth", "Grafana 자격 증명이 없어 판정 주석을 발행하지 않는다")
        return None
    if not event_ts:
        _warn_once("clock", "사건 발생 시각을 몰라 주석을 건너뛴다 — 1970년에 찍힌다")
        return None
    body = {"time": int(float(event_ts) * 1000), "text": text,
            "tags": [str(t) for t in tags]}
    try:
        r = httpx.post(base + "/api/annotations", json=body,
                       headers=dict(auth, **{"Content-Type": "application/json"}),
                       timeout=TIMEOUT_S)
        if r.status_code >= 300:
            _warn_once("http%d" % r.status_code, "판정 주석 발행 실패: HTTP %d %s",
                       r.status_code, r.text[:120])
            return None
        return (r.json() or {}).get("id")
    except Exception as e:
        _warn_once("exc", "판정 주석 발행 실패: %s", e)
        return None


SEARCH_LIMIT = 50


def _flatten(panels):
    """행(row) 안에 접힌 패널까지 펼친다.

    Grafana 는 접힌 row 의 자식 패널을 `panel["panels"]` 에 중첩해 넣는다. 최상위만
    보면 사람이 펼쳐 보던 패널을 "없다" 고 답한다.
    """
    out = []
    for p in (panels or []):
        out.append(p)
        out.extend(_flatten(p.get("panels")))
    return out






PANEL_TYPES = ("timeseries", "graph", "table", "logs", "stat", "barchart", "piechart")


def list_panels(dash_match: str = "", limit: int = 40) -> list:
    """패널 목록. `[{uid, panel_id, dashboard, title}]`. 못 읽으면 빈 목록.

    **제목으로 찾지 않고 번호로 그리기 위한 목록이다.** 제목 검색은 이름이 비슷한 옆
    패널을 집는다. 목록을 주고 그중 하나를 번호로 가리키게 하면 그 종류의 실수가
    구조적으로 사라진다(2026-08-18 실측: 제목으로 찾다가 남의 대시보드 패널을 붙였고,
    이름이 안 맞자 "그 대시보드에는 없다" 고 답했다).
    """
    base, want = _base(), str(dash_match or "").strip().lower()
    if not base:
        return []
    out = []
    try:
        with httpx.Client(timeout=TIMEOUT_S) as c:
            r = c.get(base + "/api/search", params={"type": "dash-db", "limit": SEARCH_LIMIT},
                      headers=_auth())
            r.raise_for_status()
            for d in r.json():
                dash = str(d.get("title") or "")
                if want and want not in dash.lower():
                    continue
                dr = c.get(base + "/api/dashboards/uid/" + str(d.get("uid") or ""),
                           headers=_auth())
                if dr.status_code != 200:
                    continue
                for p in _flatten((dr.json().get("dashboard") or {}).get("panels")):
                    title = str(p.get("title") or "")
                    if not title or p.get("type") not in PANEL_TYPES:
                        continue
                    out.append({"uid": d.get("uid"), "panel_id": p.get("id"),
                                "dashboard": dash, "title": title})
                    if len(out) >= limit:
                        return out
    except Exception as e:
        log.warning("패널 목록 조회 실패: %s", e)
    return out


def panel_url(uid: str, panel_id, host: str, start: int, end: int) -> str:
    """브라우저가 그림을 받아 갈 주소.

    **이 주소는 모델에 주지 않는다.** 대시보드 식별자와 호스트 실명이 들어 있다.
    화면이 사용자 세션으로 직접 받아 그린다.
    """
    from urllib.parse import urlencode
    q = urlencode({"panelId": panel_id, "var-host": host, "orgId": 1,
                   "from": int(start) * 1000, "to": int(end) * 1000,
                   "width": 1000, "height": 320, "theme": "dark"})
    return "/render/d-solo/%s/x?%s" % (uid, q)
