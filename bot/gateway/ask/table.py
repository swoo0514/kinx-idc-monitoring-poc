"""조회 대상 표 — 표에 없으면 도구가 대상을 지정할 방법이 없다(§27-1).

원본은 한 파일(`ask.py`, 1,289줄)이었다. 2026-08-19 에 옮기기만 했고
기능은 바꾸지 않았다.
"""

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
    """질문에 적힌 이름 조각을 대상 토큰으로 바꾼다.

    사람은 `vm-p3-target-002.novalocal` 을 `target-002` 로 줄여 말한다. 전체 이름과
    도메인 뗀 이름만 가려서는 그 조각이 안 풀리고, 모델은 "등록되지 않은 호스트" 라고
    답한 뒤 대화가 막힌다(2026-08-18 랩 실측).

    **여러 호스트에 걸리는 조각은 풀지 않는다.** 엉뚱한 기계를 짚는 것이 못 짚는 것보다
    나쁘다. 그때는 모델이 목록을 보고 되묻게 둔다.
    """
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
    """한 기계의 여러 이름을 **같은 토큰**에 묶는다.

    두 가지를 함께 다룬다.

    사람은 `vm-a.novalocal` 을 `vm-a` 로 줄여 친다. 그리고 **같은 기계를 축마다 다르게
    부른다** — Zabbix 는 `node1`, Loki 와 Wazuh 는 FQDN 이다. 패널이 넘기는 값은 축
    이름이라, Zabbix 이름만 등록하면 안 가려진 채 나가고 대상도 못 찾는다.

    새 토큰을 만들지 않고 기존 토큰을 가리키게 해야 같은 기계로 읽힌다.
    """
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
    """질의가 조회할 수 있는 대상 표. `{토큰: {host, source, logs, security}}`.

    **표에 없으면 도구가 대상을 지정할 방법이 없다.** 그래서 이 표가 곧 경계다.
    허용된 감시 서버에만 묻는다 — 나머지 서버에는 조회 자체를 보내지 않는다.

    실패해도 예외를 던지지 않는다. 답을 못 하더라도 왜 못 하는지는 말해야 하므로,
    빈 표를 받은 쪽이 그 사실을 사람에게 전한다.
    """
    import httpx                                  # 모듈 들여오기를 쓰는 자리에 둔다

    from ..alerts import collector
    mk = masker if masker is not None else proxy.build_masker()
    factory = client_factory or (lambda source="": collector.ZabbixClient(source=source))
    sources = allowed_sources()
    key = "|".join(sources)
    with _lock:
        made, cached = _tables.get(key, (0.0, None))
    if cached and _now() - made < TABLE_TTL_S:
        # 캐시를 쓰더라도 이름 등록은 이번 마스커에 다시 해야 한다. 마스커는 요청마다
        # 새로 만들어지므로, 안 하면 이번 턴에 실명이 안 가려진다.
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
    # **빈 표는 캐시하지 않는다.** 조회가 실패한 상태를 60초 동안 붙들면 그 사이 모든
    # 질문이 "조회할 수 있는 대상이 없다" 로 끝난다.
    if table:
        with _lock:
            _tables[key] = (_now(), dict(table))
    return table
