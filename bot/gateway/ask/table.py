"""조회 대상 표 — 표에 없으면 도구가 대상을 지정할 방법이 없다(§27-1)."""

import logging
import re
from .. import masking, proxy
from . import config
from .policy import allowed_sources
from .session import _lock, _now

from .config import MENTION_MIN, TABLE_TTL_S
log = logging.getLogger("gateway.ask")


_WORDY = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{%d,}" % (MENTION_MIN - 1))


def resolve_mentions(text: str, table: dict) -> str:
    """질문에 적힌 이름 조각을 대상 토큰으로 바꾼다."""
    out = str(text or "")
    for frag in sorted(set(_WORDY.findall(out)), key=len, reverse=True):
        low = frag.lower()
        hits = [tok for tok, ent in (table or {}).items()
                if any(low in str(ent.get(k) or "").lower()
                       for k in ("host", "logs", "security"))]
        if len(hits) == 1:
            out = out.replace(frag, hits[0])
    return out


def _alias(mk, name: str, *others) -> None:
    """한 기계의 여러 이름을 **같은 토큰**에 묶는다."""
    base = mk._fwd.get(name)
    if not base:
        return
    for other in (name,) + tuple(others):
        for cand in (other, str(other or "").split(".")[0]):
            if cand and cand != name and cand not in mk._fwd:
                mk._fwd[cand] = base
                mk._re = None


_tables: dict = {}       # 소스 묶음 -> (만든 시각, 표)


def forget_tables() -> None:
    """대상 표·패널 목록 캐시를 버린다. 검사와 온보딩 직후에 쓴다."""
    with _lock:
        _tables.clear()
    from .fetch.panels import forget_panels

    forget_panels()


async def build_table(masker: masking.Masker = None, client_factory=None) -> dict:
    """질의가 조회할 수 있는 대상 표. `{토큰: {host, source, logs, security}}`."""
    import httpx                                  # 모듈 들여오기를 쓰는 자리에 둔다

    from ..alerts import collector
    mk = masker if masker is not None else proxy.build_masker()
    factory = client_factory or (lambda source="": collector.ZabbixClient(source=source))
    sources = allowed_sources()
    key = "|".join(sources)
    with _lock:
        made, cached = _tables.get(key, (0.0, None))
    if cached and _now() - made < TABLE_TTL_S:
        # 캐시를 쓰더라도 이름 등록은 이번 마스커에 다시 한다 — 마스커는 요청마다 새로 만들어진다
        for ent in cached.values():
            mk.register("host", ent.get("host", ""))
            _alias(mk, ent.get("host", ""), ent.get("logs", ""), ent.get("security", ""))
        return dict(cached)
    table = {}
    for source in sources:
        try:
            zbx = factory(source=source)
            async with httpx.AsyncClient() as client:
                hosts = await zbx.call(client, "host.get", {
                    "output": ["hostid", "host", "name", "status"],
                    "selectInterfaces": ["ip", "dns"]})
        except Exception as e:
            log.warning("대상 표를 못 만들었다 source=%s: %s", source, e)
            continue
        for h in hosts or []:
            name = str(h.get("host") or "")
            if not name:
                continue
            mk.register("host", name)
            # 축마다 이름이 다를 수 있다. 못 풀면 빈 값이고 그건 '없음'이 아니다.
            logs = collector._resolve_label(name, h, source, "logs")
            sec = collector._resolve_label(name, h, source, "security")
            _alias(mk, name, logs, sec)
            table[mk._fwd[name]] = {
                "host": name, "source": source, "logs": logs, "security": sec,
            }
    # 빈 표는 캐시하지 않는다 — 실패를 60초 붙들면 그동안 모든 질문이 대상 없음으로 끝난다
    if table:
        with _lock:
            _tables[key] = (_now(), dict(table))
    return table
