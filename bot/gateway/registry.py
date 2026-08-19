"""호스트 명부 — 한 호스트에 관한 사실을 한 곳에 모은다."""

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
    """그 감시 서버의 접속 정보. 없으면 빈 dict."""
    for s in _SOURCES:
        if s.get("name") == name:
            return s
    return {}


def entries() -> list:
    """명부에 적힌 호스트 항목 전체. 전역 이름 표가 이 목록을 쓴다."""
    return list(_ENTRIES)


def allow_terms() -> list:
    """마스킹에서 **빼야 할** 낱말. 호스트명과 겹치는 흔한 단어를 여기 적는다."""
    return [str(x) for x in _ALLOW if x]


def source_names() -> list:
    """명부에 적힌 감시 서버 이름들. 안 적었으면 빈 목록(=단일 서버 환경)."""
    return [str(s["name"]) for s in _SOURCES]


def source_realm(name: str) -> str:
    """감시 서버 절에 적힌 영역. 없으면 빈 문자열."""
    return str(source_conf(name).get("realm") or "")


def entry(source: str, host: str) -> dict:
    """그 호스트의 명부 항목. 없으면 빈 dict."""
    if not host:
        return {}
    exact = [e for e in _ENTRIES if e.get("name") == host and e.get("source") == source]
    if exact:
        return exact[0]
    loose = [e for e in _ENTRIES if e.get("name") == host and not e.get("source")]
    return loose[0] if loose else {}


def realm(source: str, host: str, env_map: dict) -> str:
    """이 알림이 어느 감시 영역인가."""
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
    """같은 `(source, name)` 이 두 줄 이상인 것. 반환 `[(source, name), ...]`."""
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


# 적재는 파일 끝에서 한다 — 위쪽이면 미정의 함수를 부르고 그 실패가 try 에 묻힌다
_load()
