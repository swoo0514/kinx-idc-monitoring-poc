"""전역 이름 표 — 이 환경의 호스트 이름을 모아 마스킹의 마지막 그물로 쓴다.

감시 서버·로그·보안에서 코드가 읽어 만들고 주기 갱신한다. 명부 파일은 캐시이자 예외
지정용이다. 설계 근거·검증 결과는 bot/GATEWAY_GUIDE.md §22.
"""

import json
import logging
import os
import re
import tempfile
import threading
import time

import httpx

from . import registry

log = logging.getLogger("gateway.nametable")

CACHE_FILE = os.environ.get("NAMETABLE_CACHE_FILE",
                            os.path.expanduser("~/.kinx-gateway/nametable.json"))
REFRESH_S = float(os.environ.get("NAMETABLE_REFRESH_S", "3600"))
TIMEOUT_S = 10
RISKY_MAX_LEN = int(os.environ.get("NAMETABLE_RISKY_LEN", "3"))

_lock = threading.Lock()
_terms: dict = {}      # 원문 -> kind ("host" | "group")
_by_source: dict = {}  # 출처 -> 건수
_error = ""
_built_at = 0.0


def status() -> dict:
    with _lock:
        return {"terms": len(_terms), "by_source": dict(_by_source),
                "built_at": _built_at, "error": _error, "cache": CACHE_FILE}


def terms() -> list:
    """치환 대상 (원문, kind). 긴 것부터 (§22)."""
    with _lock:
        items = list(_terms.items())
    return sorted(items, key=lambda kv: len(kv[0]), reverse=True)


def risky() -> list:
    """오탐이 날 만한 항목과 사유 (§22)."""
    with _lock:
        names = list(_terms)
    out = []
    for n in names:
        why = []
        if len(n) <= RISKY_MAX_LEN:
            why.append("%d자 이하" % RISKY_MAX_LEN)
        if re.fullmatch(r"[a-z]+", n):
            why.append("영문 소문자 낱말")
        if any(n != o and n.lower() in o.lower() for o in names):
            why.append("다른 이름의 일부")
        if why:
            out.append({"name": n, "why": why})
    return out


def apply_to(masker) -> int:
    """마스커에 표를 등록한다. 맥락 기반 등록 뒤에 부른다 (§22)."""
    n = 0
    for name, kind in terms():
        if name not in masker._fwd:
            masker.register(kind, name)
            n += 1
    return n


def _zabbix_names(client, url: str, token: str) -> set:
    r = client.post(url.rstrip("/") + "/api_jsonrpc.php", timeout=TIMEOUT_S,
                    headers={"Authorization": "Bearer " + token,
                             "Content-Type": "application/json-rpc"},
                    json={"jsonrpc": "2.0", "id": 1, "method": "host.get",
                          "params": {"output": ["host", "name"],
                                     "selectInterfaces": ["dns"],
                                     "selectHostGroups": ["name"]}})
    r.raise_for_status()
    out = set()
    for h in r.json().get("result", []):
        for k in ("host", "name"):
            if h.get(k):
                out.add(("host", h[k]))
        for i in (h.get("interfaces") or []):
            if i.get("dns"):
                out.add(("host", i["dns"]))
        for g in (h.get("hostgroups") or []):
            if g.get("name"):
                out.add(("group", g["name"]))
    return out


def _loki_names(client, url: str) -> set:
    """라벨 값 목록."""
    label = os.environ.get("LOKI_HOST_LABEL", "host")
    now = int(time.time())
    r = client.get("%s/loki/api/v1/label/%s/values" % (url.rstrip("/"), label),
                   params={"start": str((now - 7 * 86400) * 1_000_000_000),
                           "end": str(now * 1_000_000_000)}, timeout=TIMEOUT_S)
    r.raise_for_status()
    return {("host", v) for v in (r.json().get("data") or []) if v}


def _wazuh_names(client, url: str, user: str, pw: str) -> set:
    """에이전트 이름 목록. 집계 1회로 받는다 (호스트당 1요청을 피한다)."""
    body = {"size": 0, "aggs": {"agents": {"terms": {"field": "agent.name",
                                                     "size": 1000}}},
            "query": {"range": {"@timestamp": {"gte": "now-7d"}}}}
    r = client.post(url.rstrip("/") + "/wazuh-alerts-*/_search", json=body,
                    auth=(user, pw), timeout=TIMEOUT_S)
    r.raise_for_status()
    buckets = (((r.json().get("aggregations") or {}).get("agents") or {})
               .get("buckets") or [])
    return {("host", b["key"]) for b in buckets if b.get("key")}


def build(now: float = None) -> dict:
    """출처에서 이름을 모아 표를 새로 만든다. 예외를 던지지 않는다 (§22)."""
    now = time.time() if now is None else now
    found, per, errs = set(), {}, []

    srcs = [(n, registry.source_conf(n)) for n in registry.source_names()]
    if not srcs:
        srcs = [("", {})]
    for name, conf in srcs:
        url = conf.get("url") or os.environ.get("ZABBIX_URL", "")
        token = (os.environ.get(conf.get("token_env") or "", "") if conf.get("url")
                 else os.environ.get("ZABBIX_TOKEN", ""))
        if not (url and token):
            continue
        try:
            with httpx.Client() as c:
                got = _zabbix_names(c, url, token)
            found |= got
            per["zabbix:" + (name or "default")] = len(got)
        except Exception as e:
            errs.append("zabbix %s: %s" % (name or "default", e))

    if os.environ.get("LOKI_URL"):
        try:
            with httpx.Client() as c:
                got = _loki_names(c, os.environ["LOKI_URL"])
            found |= got
            per["loki"] = len(got)
        except Exception as e:
            errs.append("loki: %s" % e)

    if os.environ.get("WAZUH_INDEXER_URL"):
        try:
            with httpx.Client(verify=False) as c:
                got = _wazuh_names(c, os.environ["WAZUH_INDEXER_URL"],
                                   os.environ.get("WAZUH_INDEXER_USER", ""),
                                   os.environ.get("WAZUH_INDEXER_PASSWORD", ""))
            found |= got
            per["wazuh"] = len(got)
        except Exception as e:
            errs.append("wazuh: %s" % e)

    # 조회로 안 잡히는 이름(조용한 에이전트 등)을 사람이 적어 둔 것
    reg = 0
    for e in registry.entries():
        for k in ("name", "loki", "wazuh"):
            if e.get(k):
                found.add(("host", str(e[k])))
                reg += 1
    if reg:
        per["registry"] = reg

    allow = {a.lower() for a in registry.allow_terms()}
    table = {n: k for k, n in found if n and n.lower() not in allow}

    global _terms, _by_source, _error, _built_at
    if not table and _terms:
        log.error("이름 표를 새로 못 만들었다(%s) — 직전 표를 유지한다", "; ".join(errs))
        with _lock:
            _error = "; ".join(errs)
        return status()
    with _lock:
        _terms, _by_source, _error, _built_at = table, per, "; ".join(errs), now
    if errs:
        log.error("이름 표 일부 출처 실패: %s (총 %d개 확보)", "; ".join(errs), len(table))
    else:
        log.info("이름 표 %d개 확보 — %s", len(table), per)
    _save_cache()
    return status()


def _save_cache() -> None:
    """캐시 저장. 실패는 기록만 한다."""
    try:
        d = os.path.dirname(CACHE_FILE)
        if d:
            os.makedirs(d, exist_ok=True)
        with _lock:
            payload = {"built_at": _built_at, "by_source": _by_source, "terms": _terms}
        fd, tmp = tempfile.mkstemp(dir=d or None, prefix=".nametable-", suffix=".tmp")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, CACHE_FILE)   # 바꿔치기라 중간 상태 파일이 남지 않는다
    except Exception as e:
        log.warning("이름 표 캐시 저장 실패 %s: %s", CACHE_FILE, e)


def load_cache() -> int:
    """기동 시 직전 표를 읽는다. 없거나 깨졌으면 0."""
    global _terms, _by_source, _built_at
    try:
        with open(CACHE_FILE, encoding="utf-8") as f:
            doc = json.load(f)
        t = {str(k): str(v) for k, v in (doc.get("terms") or {}).items()}
        if not t:
            return 0
        with _lock:
            _terms, _by_source = t, dict(doc.get("by_source") or {})
            _built_at = float(doc.get("built_at") or 0)
        log.info("이름 표 캐시에서 %d개 로드 (%s)", len(t), CACHE_FILE)
        return len(t)
    except FileNotFoundError:
        return 0
    except Exception as e:
        log.warning("이름 표 캐시를 못 읽었다 %s: %s", CACHE_FILE, e)
        return 0


class Refresher:
    """주기 갱신 (생존 신호와 같은 형태)."""

    def __init__(self, interval_s: float = None):
        self.interval_s = REFRESH_S if interval_s is None else interval_s
        self._stop = threading.Event()
        self._thread = None

    def start(self) -> bool:
        if self._thread and self._thread.is_alive():
            return True
        load_cache()
        self._thread = threading.Thread(target=self._loop, name="nametable", daemon=True)
        self._thread.start()
        log.info("이름 표 갱신 시작 — %.0f초마다", self.interval_s)
        return True

    def stop(self):
        self._stop.set()

    def _loop(self):
        try:
            build()
        except Exception as e:
            log.error("이름 표 최초 생성 실패: %s", e)
        while not self._stop.wait(self.interval_s):
            try:
                build()
            except Exception as e:
                log.error("이름 표 갱신 실패: %s", e)
