"""호스트 명부 — 한 호스트에 관한 사실을 한 곳에 모은다.

전에는 같은 종류의 사실이 환경변수 네 개에 흩어져 있었다. 어느 Loki 라벨을 쓰는지,
로그가 없는 것이 정상인지, 보안 에이전트가 있는지, 어느 감시 영역인지가 각각 다른
형식으로 적혀 있어서 호스트가 하나 늘 때마다 네 군데를 고쳐야 했다.

식별은 명부가 하지 않는다. Zabbix 는 호스트명이 그 서버 안에서 유일하도록 강제하므로
`(감시 서버, 호스트명)` 이 이미 유일한 식별자다(공식 문서 확인). 명부는 그 호스트에
딸린 **성질**을 담는다. 그래서 명부에 없는 호스트도 정상 동작해야 하고, 실제로 그렇다.

`id` 칸은 비워 둔다. 이름이 바뀌어도 이력을 잇는 용도인데, 그러려면 봇이 쓰는 저장소가
먼저 있어야 한다(인수인계 §2-1-1). 지금 채워도 읽는 곳이 없다.

설정·형식은 bot/GATEWAY_GUIDE.md §8-1-2.
"""

import logging
import os

log = logging.getLogger("gateway.registry")

PATH = os.environ.get("HOST_REGISTRY_FILE", "")

_ENTRIES: list = []
_SOURCES: list = []
_ALLOW: list = []
_LOAD_ERROR = ""


def _load():
    global _ENTRIES, _SOURCES, _ALLOW, _LOAD_ERROR
    _ENTRIES, _SOURCES, _ALLOW, _LOAD_ERROR = [], [], [], ""
    if not PATH:
        return
    try:
        import yaml
    except ImportError:
        _LOAD_ERROR = "pyyaml 미설치"
        log.error("호스트 명부를 못 읽는다(%s) — 환경변수 설정으로 동작한다. "
                  "pip install pyyaml 후 재기동한다", _LOAD_ERROR)
        return
    try:
        with open(PATH, encoding="utf-8") as f:
            doc = yaml.safe_load(f) or {}
        rows = doc.get("hosts") or []
        _ENTRIES = [r for r in rows if isinstance(r, dict) and r.get("name")]
        _ALLOW = list(doc.get("allow") or [])
        srcs = doc.get("sources") or []
        _SOURCES = [r for r in srcs if isinstance(r, dict) and r.get("name")]
        log.info("호스트 명부 %s 에서 호스트 %d건 / 감시 서버 %d건 로드",
                 PATH, len(_ENTRIES), len(_SOURCES))
        if len(_ENTRIES) != len(rows):
            log.warning("명부에서 이름 없는 항목 %d건을 건너뛰었다", len(rows) - len(_ENTRIES))
        dup = duplicates()
        if dup:
            log.warning("명부에 같은 이름이 두 번 적힌 항목 %d건 — 앞줄이 이긴다: %s",
                        len(dup), ", ".join("%s/%s" % (s or "-", n) for s, n in dup))
    except Exception as e:
        _LOAD_ERROR = str(e)
        # 조용히 비우면 명부에 적어 둔 성질이 통째로 무시되고 아무도 모른다.
        log.error("호스트 명부 로드 실패 %s: %s — 환경변수 설정으로 동작한다", PATH, e)



def status() -> dict:
    """진단용. 명부를 실제로 읽었는지 사람이 확인할 수 있어야 한다."""
    return {"path": PATH, "entries": len(_ENTRIES), "sources": len(_SOURCES),
            "allow": len(_ALLOW), "error": _LOAD_ERROR}


def source_conf(name: str) -> dict:
    """그 감시 서버의 접속 정보. 없으면 빈 dict.

    토큰은 파일에 넣지 않는다 — 명부는 깃에 올라가고 크리덴셜은 올라가면 안 된다.
    파일에는 **어느 환경변수에 들어 있는지**만 적고 값은 실행 환경에서 읽는다.
    """
    for s in _SOURCES:
        if s.get("name") == name:
            return s
    return {}


def entries() -> list:
    """명부에 적힌 호스트 항목 전체. 전역 이름 표가 이 목록을 쓴다."""
    return list(_ENTRIES)


def allow_terms() -> list:
    """마스킹에서 **빼야 할** 낱말. 호스트명과 겹치는 흔한 단어를 여기 적는다.

    형식: 파일 최상위에 `allow: [ ... ]`. 오탐이 실제로 났을 때만 적는다 — 여기 적힌
    이름은 원문 그대로 나가므로, 미리 넣어 두는 것이 아니라 확인 후 넣는다.
    """
    return [str(x) for x in _ALLOW if x]


def source_names() -> list:
    """명부에 적힌 감시 서버 이름들. 안 적었으면 빈 목록(=단일 서버 환경)."""
    return [str(s["name"]) for s in _SOURCES]


def source_realm(name: str) -> str:
    """감시 서버 절에 적힌 영역. 없으면 빈 문자열."""
    return str(source_conf(name).get("realm") or "")


def entry(source: str, host: str) -> dict:
    """그 호스트의 명부 항목. 없으면 빈 dict.

    `source` 를 적은 항목이 먼저다. 호스트명은 감시 서버 안에서만 유일하므로,
    감시 서버가 둘이면 같은 이름이 두 기계일 수 있다. 그때는 source 로 갈라야 한다.
    source 를 안 적은 항목은 감시 서버가 하나인 환경을 위한 편의다.
    """
    if not host:
        return {}
    exact = [e for e in _ENTRIES if e.get("name") == host and e.get("source") == source]
    if exact:
        return exact[0]
    loose = [e for e in _ENTRIES if e.get("name") == host and not e.get("source")]
    return loose[0] if loose else {}


def realm(source: str, host: str, env_map: dict) -> str:
    """이 알림이 어느 감시 영역인가.

    명부 → 환경변수 매핑 → **소스 그대로** 순이다. 마지막이 중요하다. 아무것도 안 적으면
    소스마다 다른 영역이 되어 사내 db01 과 고객사 db01 이 자동으로 갈라진다. 예전에는
    전부 한 영역이라 설정을 안 한 사람이 가장 위험했다.
    """
    e = entry(source, host)
    if e.get("realm"):
        return str(e["realm"])
    # 감시 서버 절에 적힌 영역이 그다음이다 — 호스트마다 안 적어도 서버 단위로 정해진다.
    sr = source_realm(source)
    if sr:
        return sr
    if source in env_map:
        return env_map[source]
    return source or ""


def duplicates() -> list:
    """같은 `(source, name)` 이 두 줄 이상인 것. 반환 `[(source, name), ...]`.

    지금은 뒷줄이 조용히 무시된다. 배포가 명부 조각을 자동으로 남기기 시작하면 손으로
    적은 줄과 겹칠 수 있고, 그때 어느 쪽이 이겼는지 아무도 모르면 안 된다.
    """
    seen, dup = set(), []
    for e in _ENTRIES:
        key = (str(e.get("source") or ""), str(e.get("name") or ""))
        if key in seen and key not in dup:
            dup.append(key)
        seen.add(key)
    return dup


def label(source: str, host: str, axis: str) -> str:
    """그 축에서 이 호스트를 부르는 이름. 명부에 없으면 빈 문자열."""
    key = {"logs": "loki", "security": "wazuh"}.get(axis, "")
    return str(entry(source, host).get(key) or "") if key else ""


def axis_on(source: str, host: str, axis: str):
    """이 호스트에 그 축이 있는가. 명부에 안 적혔으면 None(모름 → 기존 규칙)."""
    v = entry(source, host).get(axis)
    return None if v is None else bool(v)


# **적재는 파일 끝에서 한다.** 위쪽에 두면 아직 정의되지 않은 함수를 부르게 되고,
# 그 실패는 try 안에서 잡혀 "명부 로드 실패" 한 줄로만 지나간다(2026-08-18 실측).
_load()
