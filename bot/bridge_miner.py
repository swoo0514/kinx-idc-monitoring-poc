#!/usr/bin/env python3
"""브리지 후보 마이닝 — 이력에서 "같이 나타나는 축 쌍"을 찾아 추천한다.

왜: gateway/incident.py 의 BRIDGE_GROUPS 는 사람이 지정한 인과 쌍이고, 초기값은 우리
데모 시나리오에서 왔다. 그 큐레이션 의존을 데이터로 검증·확장하기 위한 도구다.
자동 적용하지 않는다 — 출력은 "검토하라"는 목록이다(판정은 사람, 후보 발굴은 데이터).

읽기 전용이다. Zabbix 는 event.get / trigger.get, Wazuh 는 인덱서 _search 만 쓴다.
실환경에도 그대로 돌릴 수 있다.

사용법·해석은 bot/BRIDGE_MINER_GUIDE.md.
"""

import argparse
import asyncio
import bisect
import itertools
import json
import os
import random
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# 한국어 Windows 콘솔은 기본 cp949 라 '—' 에서 죽는다. 조회가 끝난 뒤 출력에서 터져 원인이
# 눈에 안 띈다 — docs/03-pitfalls/build-traps.md.
for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass

from gateway import collector, incident  # noqa: E402

DEFAULT_DAYS = 90
DEFAULT_WINDOW_S = 600      # 같은 사건으로 볼 시간창. 게이트웨이 디바운스보다 넉넉하게.
DEFAULT_MIN_PAIRS = 5       # 이 미만은 우연으로 본다
DEFAULT_MIN_LIFT = 2.0      # 독립 가정 대비 몇 배로 함께 나오는가


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%d %H:%M")


_IP_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
_NUM_RE = re.compile(r"\d+(?:\.\d+)?")


def template(name: str) -> str:
    """트리거명의 변수부를 지워 '유형'으로 접는다. 축 선택 근거는 BRIDGE_MINER_GUIDE."""
    return _NUM_RE.sub("#", _IP_RE.sub("<IP>", name)).strip()


def axis_key(e: dict, axis: str) -> str:
    """이벤트 하나를 집계 축 값으로 접는다. mine 과 pair 분석이 같은 정의를 쓰도록 한 곳에 둔다."""
    if axis == "tmpl":
        return template(e.get("name") or "?")
    return e.get(axis) or "?"


def _windows(events: list, window_s: int, scope: str):
    """겹치지 않는 시간창을 만들어 (그룹키, 시작시각, 이벤트목록) 으로 돌려준다.

    mine 은 축 집합만 필요해 따로 세지만, 쌍 상세 분석은 창 안의 **원본 이벤트**가 필요하다.
    잘라내는 규칙은 동일해야 하므로 여기 한 번만 구현한다.
    """
    groups = defaultdict(list)
    for e in events:
        groups["*" if scope == "global" else e["host"]].append(e)
    for gkey, seq in groups.items():
        seq.sort(key=lambda x: x["ts"])
        i = 0
        while i < len(seq):
            start = seq[i]["ts"]
            j = i
            while j < len(seq) and seq[j]["ts"] - start <= window_s:
                j += 1
            yield gkey, start, seq[i:j]
            i = j


def resolve_axis_value(events: list, axis: str, needle: str) -> str:
    """CLI 로 받은 문자열을 실제 축 값으로 해석한다. 정확 일치 우선, 없으면 부분 일치."""
    vals = {axis_key(e, axis) for e in events}
    if needle in vals:
        return needle
    cands = sorted(v for v in vals if needle in v)
    if len(cands) == 1:
        return cands[0]
    if not cands:
        raise SystemExit("일치하는 축 값이 없다: %r" % needle)
    raise SystemExit("여러 축에 일치(%d개). 더 구체적으로 지정한다:\n  %s"
                     % (len(cands), "\n  ".join(_short(c, 72) for c in cands[:8])))


def report_pair(events: list, window_s: int, scope: str, axis: str,
                a_val: str, b_val: str, top: int = 8, samples: int = 6):
    """쌍 하나의 공동 발생을 원본 이벤트 수준에서 펼친다.

    왜 필요한가 — 지표만으로는 세 가지가 갈리지 않는다.
      (1) 같은 링크의 양단 — 한 사건이 양쪽에서 잡힌 것. **병합** 대상
      (2) 공통 원인(전원·상면·상류) — 서로 다른 트리거가 함께 남. **SPOF 리스크**
      (3) 우연 — 흔한 축끼리 겹친 것. 버림
    구분하려면 "그때 무슨 알림이었나"와 "누가 먼저였나"를 봐야 한다.
    """
    hits = []
    for _gkey, start, win in _windows(events, window_s, scope):
        keys = {axis_key(e, axis) for e in win}
        if a_val in keys and b_val in keys:
            hits.append((start, win))

    print()
    print("=" * 78)
    print("쌍 공동 발생 상세   (축: %s / 창 범위: %s / 창 %ds)" % (axis, scope, window_s))
    print("=" * 78)
    print("  A = %s" % a_val)
    print("  B = %s" % b_val)
    if not hits:
        print("\n공동 발생 창이 없다.")
        return
    days = {_iso(s)[:10] for s, _ in hits}
    print("\n공동 발생 창 %d개, %d일에 걸침 (%s ~ %s)"
          % (len(hits), len(days), min(days), max(days)))

    a_first = b_first = same = 0
    lags = []
    a_names, b_names = Counter(), Counter()
    for _start, win in hits:
        av = [e for e in win if axis_key(e, axis) == a_val]
        bv = [e for e in win if axis_key(e, axis) == b_val]
        for e in av:
            a_names[template(e.get("name") or "?")] += 1
        for e in bv:
            b_names[template(e.get("name") or "?")] += 1
        ta, tb = min(e["ts"] for e in av), min(e["ts"] for e in bv)
        lags.append(tb - ta)
        if ta < tb:
            a_first += 1
        elif tb < ta:
            b_first += 1
        else:
            same += 1

    print()
    print("[ 선후 관계 ]  A 먼저 %d회 / B 먼저 %d회 / 동시 %d회" % (a_first, b_first, same))
    lags.sort()
    med = lags[len(lags) // 2]
    print("  간격 중앙값 %+ds (양수면 B 가 늦다), 범위 %+ds ~ %+ds" % (med, lags[0], lags[-1]))

    # 시차가 한 값에 몰려 있으면 인과가 아니라 관측 시점 차이다.
    # 인과 사슬은 부하·전파에 따라 시차가 흩어지지만, 폴링 주기가 어긋난 두 장비는
    # 같은 사건을 항상 같은 만큼 늦게 본다.
    near = sum(1 for x in lags if abs(x - med) <= 30) / len(lags)
    print("  중앙값 ±30s 안에 %.0f%% 가 몰려 있다" % (100 * near))

    tot = a_first + b_first
    if near >= 0.7 and abs(med) > 60:
        print("  => 시차가 %+ds 근처에 고정돼 있다. 인과가 아니라 **수집 주기 오프셋**을 의심한다"
              % med)
        print("     (같은 사건을 한쪽이 늘 늦게 관측하는 형태). 아이템 갱신 주기를 대조해 확인한다.")
    elif abs(med) <= 5:
        # 시차가 초 단위면 방향 비율이 아무리 치우쳐도 인과가 아니다. 같은 순간에 난 것을
        # 밀리초 지터가 갈라놓은 것뿐이다. 방향 규칙보다 먼저 걸러야 오판하지 않는다.
        print("  => 시차가 초 단위다(중앙값 %+ds). 선후 비율이 치우쳐도 **인과가 아니다**." % med)
        print("     같은 사건의 양면이거나 상류 공통 원인이다. 양측 트리거 유형이 같으면 병합한다.")
    elif tot and max(a_first, b_first) / tot >= 0.7:
        lead = "A" if a_first > b_first else "B"
        print("  => %s 가 먼저인 경우가 %.0f%% 이고 시차가 흩어져 있다(중앙값 %+ds)."
              % (lead, 100 * max(a_first, b_first) / tot, med))
        print("     %s 를 근원 후보로 본다." % lead)
    elif abs(med) <= 30:
        print("  => 선후가 갈리지 않고 시차가 0 근처다. **공통 원인** 또는 같은 사건의 양면이다.")
        print("     양쪽 트리거 유형이 같으면 병합, 다르면 상류 공통 요소를 찾는다.")
    else:
        print("  => 방향도 시차도 일정하지 않다. 관계로 단정하지 않는다.")

    for label, cnt in (("A", a_names), ("B", b_names)):
        print()
        print("[ %s 쪽 트리거 유형 상위 %d ]" % (label, top))
        for nm, c in cnt.most_common(top):
            print("  %6d  %s" % (c, _short(nm, 66)))

    same_type = set(a_names) & set(b_names)
    print()
    if same_type:
        print("[ 판정 힌트 ] 양쪽에 같은 트리거 유형이 %d종 있다 — 같은 사건의 양면(병합) 쪽 근거."
              % len(same_type))
    else:
        print("[ 판정 힌트 ] 양쪽 트리거 유형이 겹치지 않는다 — 공통 원인(SPOF) 쪽 근거.")

    print()
    print("[ 표본 %d건 ]" % min(samples, len(hits)))
    for start, win in hits[:samples]:
        av = sorted((e for e in win if axis_key(e, axis) == a_val), key=lambda e: e["ts"])
        bv = sorted((e for e in win if axis_key(e, axis) == b_val), key=lambda e: e["ts"])
        print("  %s  A(%d건) %s" % (_iso(start), len(av), _short(av[0].get("name", ""), 56)))
        print("  %18s B(%d건) %s  (%+ds)"
              % ("", len(bv), _short(bv[0].get("name", ""), 56), bv[0]["ts"] - av[0]["ts"]))


async def diag_zabbix(days: int):
    """어느 파라미터에서 API 가 깨지는지 계단식으로 짚는다.

    500 은 본문에 사유가 없어 추측으로 좁히면 시간만 버린다. 가벼운 것부터 하나씩 얹어
    **처음 실패하는 지점**을 찾는다. 실환경에 부담을 주지 않도록 전부 limit 을 작게 둔다.
    """
    import httpx
    since = int(datetime.now(timezone.utc).timestamp()) - days * 86400
    zbx = collector.ZabbixClient()
    base = {"output": ["eventid", "clock"], "value": 1, "limit": 1}
    steps = [
        ("최소 조회 (limit 1)", dict(base)),
        ("+ objectid", dict(base, output=["eventid", "clock", "objectid"])),
        ("+ r_eventid (문서상 불가 — 확인용)",
         dict(base, output=["eventid", "clock", "r_eventid"])),
        ("output=extend (limit 1)", dict(base, output="extend")),
        ("+ selectHosts", dict(base, selectHosts=["host"])),
        ("+ selectTags", dict(base, selectTags="extend")),
        ("+ time_from %d일" % days, dict(base, time_from=since)),
        ("+ sortfield clock", dict(base, time_from=since, sortfield="clock",
                                   sortorder="ASC")),
        ("limit 1000", dict(base, time_from=since, limit=1000)),
        ("limit 20000", dict(base, time_from=since, limit=20000)),
        ("limit 20000 + extend", dict(base, time_from=since, limit=20000,
                                      output="extend")),
        ("limit 20000 + r_eventid", dict(base, time_from=since, limit=20000,
                                         output=["eventid", "clock", "r_eventid"])),
        ("limit 20000 + objectid", dict(base, time_from=since, limit=20000,
                                        output=["eventid", "clock", "objectid"])),
        ("limit 200000 최소", dict(base, time_from=since, limit=200000)),
        ("해소 이벤트 value=0 limit 200000",
         dict(output=["eventid", "clock", "objectid"], value=0, time_from=since,
              limit=200000)),
        ("실제 수집 쿼리 (전 기간 한 번에)",
         {"output": ["eventid", "name", "clock", "severity", "objectid"],
          "selectHosts": ["host"], "selectTags": "extend", "time_from": since,
          "value": 1, "sortfield": "clock", "sortorder": "ASC", "limit": 200000}),
        ("실제 수집 쿼리 (10일 조각)",
         {"output": ["eventid", "name", "clock", "severity", "objectid"],
          "selectHosts": ["host"], "selectTags": "extend", "time_from": since,
          "time_till": since + 10 * 86400,
          "value": 1, "sortfield": "clock", "sortorder": "ASC", "limit": 200000}),
    ]
    print("=== Zabbix API 계단식 진단 ===", file=sys.stderr)
    async with httpx.AsyncClient(verify=False) as client:
        for label, params in steps:
            try:
                r = await zbx.call(client, "event.get", params)
                print("  통과   %-34s (%d건)" % (label, len(r or [])), file=sys.stderr)
            except Exception as exc:
                msg = str(exc).splitlines()[0][:90]
                print("  실패   %-34s %s: %s" % (label, type(exc).__name__, msg),
                      file=sys.stderr)
    print("\n처음 실패한 지점이 원인이다. 그 앞까지는 서버가 받아들인다.", file=sys.stderr)


async def fetch_zabbix(days: int) -> list:
    """(host, class, epoch) 목록. 트리거 태그가 있으면 분류의 1차 신호로 쓴다.

    ZabbixClient.call 은 .get 이외의 메서드를 거부한다(읽기 전용이 코드로 강제됨).
    """
    import httpx
    if not os.environ.get("ZABBIX_URL") or not os.environ.get("ZABBIX_TOKEN"):
        print("[zabbix] ZABBIX_URL / ZABBIX_TOKEN 없음 — 건너뜀", file=sys.stderr)
        return []
    since = int(datetime.now(timezone.utc).timestamp()) - days * 86400
    zbx = collector.ZabbixClient()

    async def paged(client, params, label, chunk_days=10):
        """기간을 쪼개 나눠 받는다.

        90일치를 한 번에 요청하면 응답 크기 때문에 서버가 500 을 낸다. 한 조각이
        실패해도 나머지는 살리되, 그 기간이 '사건 없음'으로 오독되지 않게 반드시 남긴다.
        """
        out, gaps = [], []
        step = chunk_days * 86400
        for start in range(since, int(datetime.now(timezone.utc).timestamp()), step):
            end = start + step
            try:
                out += await zbx.call(client, "event.get",
                                      dict(params, time_from=start, time_till=end)) or []
            except Exception as exc:
                gaps.append((start, end))
                print("  [%s] %s ~ %s 조각 실패: %s"
                      % (label, _iso(start)[:10], _iso(end)[:10], type(exc).__name__),
                      file=sys.stderr)
        if gaps:
            print("  ⚠ [%s] 조각 %d개 누락 — 그 기간은 '사건 없음'이 아니라 '미수집'이다."
                  % (label, len(gaps)), file=sys.stderr)
        return out

    async with httpx.AsyncClient(verify=False) as client:
        events = await paged(client, {
            # objectid = 트리거 ID. 해소 시각을 짝짓는 데 쓴다. r_eventid 를 안 쓰는
            # 이유(대량 조회 응답 크기)는 --diag 진단 결과 — RECON 가이드 참조.
            "output": ["eventid", "name", "clock", "severity", "objectid"],
            "selectHosts": ["host"],
            "selectTags": "extend",
            "value": 1,
            "sortfield": "clock",
            "sortorder": "ASC",
            "limit": 200000,
        }, "problem")

        # 왜 해소 시각이 필요한가 — 발생 시각만 보면 **문제가 열려 있는 동안 일어난 일**이
        # 안 보인다. 디스크가 사흘 전부터 차 있고 오늘 서비스가 죽으면 두 시작 시각은
        # 사흘 떨어져 있어 어떤 시간창·시차로도 잡히지 않는다. 구간 겹침으로 봐야 잡힌다.
        oks = await paged(client, {
            "output": ["eventid", "clock", "objectid"],
            "value": 0,          # OK(해소) 이벤트
            "sortfield": "clock",
            "sortorder": "ASC",
            "limit": 200000,
        }, "recovery")

    by_trigger = defaultdict(list)
    for o in oks:
        by_trigger[str(o.get("objectid"))].append(int(o.get("clock", 0)))
    for v in by_trigger.values():
        v.sort()
    print("[zabbix] 해소 이벤트 %d건 (트리거 %d종)" % (len(oks), len(by_trigger)),
          file=sys.stderr)
    out = []
    for e in events or []:
        hosts = e.get("hosts") or []
        host = (hosts[0] or {}).get("host", "") if hosts else ""
        if not host:
            continue
        name = e.get("name", "")
        tags = e.get("tags") or []
        # 분류 결과만 저장하면 "지금 실제로 무슨 태그가 붙어 있나"가 사라진다 — 원값을 보관한다.
        declared = ""
        for t in tags:
            if isinstance(t, dict) and t.get("tag") == incident.CLASS_TAG:
                declared = str(t.get("value") or "")
                break
        start = int(e.get("clock", 0))
        # 같은 트리거의 해소 이벤트 중 이 발생 이후 처음 오는 것.
        oks_of = by_trigger.get(str(e.get("objectid")), [])
        pos = bisect.bisect_right(oks_of, start)
        end = oks_of[pos] if pos < len(oks_of) else 0
        out.append({"host": host, "cls": incident.classify(name, tags=tags),
                    "ts": start, "name": name, "src": "zabbix",
                    "declared": declared,
                    # 미해소·조회 범위 밖이면 0. "아직 열려 있다"와 "해소 시각을 모른다"는
                    # 다르지만 둘 다 구간 겹침 계산에서는 제외해야 하므로 0 으로 묶는다.
                    "end_ts": end})
    print("[zabbix] 이벤트 %d건 → 분류 완료" % len(out), file=sys.stderr)
    return out


def fetch_wazuh(days: int) -> list:
    """(host, class, epoch) 목록. rule.groups 를 1차 신호로 쓴다."""
    import httpx
    url = os.environ.get("WAZUH_INDEXER_URL", "").rstrip("/")
    if not url:
        print("[wazuh] WAZUH_INDEXER_URL 없음 — 건너뜀", file=sys.stderr)
        return []
    body = {
        "size": 10000,
        "sort": [{"@timestamp": {"order": "asc"}}],
        "query": {"bool": {"must": [
            {"range": {"@timestamp": {"gte": "now-%dd" % days}}},
            {"range": {"rule.level": {"gte": 7}}},   # 잡음 하한. SEV3 이상만 사건 후보로 본다
        ]}},
        "_source": ["@timestamp", "rule.description", "rule.groups", "rule.level", "agent.name"],
    }
    out = []
    # 연결은 짧게 끊는다. 사설망 주소를 밖에서 부르면 Windows 기본값으로 20초 넘게 매달린다.
    with httpx.Client(verify=False,
                      timeout=httpx.Timeout(30.0, connect=5.0)) as c:
        r = c.post(f"{url}/wazuh-alerts-*/_search", json=body,
                   auth=(os.environ.get("WAZUH_INDEXER_USER", ""),
                         os.environ.get("WAZUH_INDEXER_PASSWORD", "")))
        r.raise_for_status()
        for h in r.json().get("hits", {}).get("hits", []):
            s = h.get("_source", {})
            host = (s.get("agent") or {}).get("name", "")
            if not host:
                continue
            rule = s.get("rule") or {}
            name = rule.get("description", "")
            cls = incident.classify(name, groups=rule.get("groups"))
            ts = s.get("@timestamp", "")
            try:
                epoch = int(datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp())
            except ValueError:
                continue
            # groups 를 남긴다 — Zabbix 의 declared 와 같은 역할. 없으면 --load 재분류가
            # 이름만 보고 판단해 Wazuh 분류 품질이 실제보다 나쁘게 나온다.
            out.append({"host": host, "cls": cls, "ts": epoch, "name": name, "src": "wazuh",
                        "groups": rule.get("groups")})
    print("[wazuh] 알림 %d건 → 분류 완료" % len(out), file=sys.stderr)
    return out


def mine(events: list, window_s: int, min_pairs: int, min_lift: float,
         axis: str = "cls", min_axis: int = 1, scope: str = "host") -> dict:
    """호스트별 시간창 안에서 함께 나온 축 쌍의 연관 지표를 계산한다.

    lift = P(A와 B가 같은 창에) / (P(A) x P(B))
    독립이면 1. 1보다 크면 우연보다 자주 함께 나온다는 뜻이다.

    axis 로 집계 입도를 고른다.
      cls  — 사건 유형 8종. 축이 적어 조합이 28개뿐이라 신호가 접힌다.
      name — 트리거명. 축이 수백 개로 늘어 network 89.5% 내부 구조까지 보인다.
    같은 이름의 트리거가 호스트마다 있으므로 name 축은 호스트를 가로질러 묶인다.
    그것이 패턴 발굴에서 원하는 성질이다(특정 호스트 사정이 아니라 반복되는 조합).

    scope 로 시간창을 어떻게 자를지 고른다.
      host   — 호스트별로 따로 자른다. 같은 장비 안에서 함께 나는 것만 보인다.
      global — 전 호스트를 한 타임라인에 놓고 자른다. **호스트를 가로지르는 관계**가 보인다.

    global 이 필요한 이유 — 진단에서 확인된 가장 큰 구조가 호스트를 가로지른다. 사설 DNS
    1대가 감시 미등록이라 **29대에서 파생 알림이 나고 근원 알림은 0건**이었다. host 로
    자르면 그 관계는 서로 다른 창으로 흩어져 **구조적으로 관측되지 않는다.**
    `--by host --scope global` 이 "어느 장비가 죽을 때 어느 장비들이 따라 우는가"에 답한다.

    min_axis 는 등장 창 수가 이 미만인 축을 쌍 계산에서 뺀다. name 축에서 조합 폭증을
    막는 장치이며, 등장 자체가 희소한 축은 어차피 통계가 서지 않는다.

    lift 외에 leverage 와 zhangs 를 함께 낸다 — 희귀 조합에서 lift 가 부풀려지는 것을
    실측으로 확인했기 때문이다(`disk_space + service_down` 이 표본 확대에 따라
    5.53 -> 3.87 -> 1.22 로 수렴). 두 지표는 그 왜곡을 지표 자체가 보정한다.
    정의는 연관 규칙 분석의 표준을 따른다(mlxtend association_rules 와 동일 식).
    """
    def key(e):
        return axis_key(e, axis)

    groups = defaultdict(list)
    for e in events:
        # scope=global 이면 전 호스트를 한 타임라인에 놓는다. 그래야 호스트를 가로지르는
        # 관계(한 대가 죽고 여러 대가 따라 우는 형태)가 같은 창에 들어온다.
        groups["*" if scope == "global" else e["host"]].append((e["ts"], key(e)))

    windows = []              # 각 창에 등장한 축 집합
    for gkey, seq in groups.items():
        seq.sort()
        i = 0
        while i < len(seq):
            start = seq[i][0]
            bucket, j = set(), i
            while j < len(seq) and seq[j][0] - start <= window_s:
                bucket.add(seq[j][1]); j += 1
            windows.append((gkey, start, bucket))
            i = j                       # 겹치지 않는 창 (같은 이벤트를 두 번 세지 않는다)

    n = len(windows)
    if n == 0:
        return {"windows": 0, "pairs": [], "singles": {}}

    single = Counter()
    for _host, _start, bucket in windows:
        for c in bucket:
            single[c] += 1

    # 희소 축은 쌍 계산에서 뺀다. name 축은 축이 수백 개라 이 게이트가 없으면 조합이 폭증한다.
    keep = {c for c, v in single.items() if v >= min_axis}
    dropped = len(single) - len(keep)

    pair = Counter()
    pair_hosts = defaultdict(set)
    pair_days = defaultdict(set)
    for gkey, start, bucket in windows:
        kept = sorted(c for c in bucket if c in keep)
        day = _iso(start)[:10]
        for a, b in itertools.combinations(kept, 2):
            pair[(a, b)] += 1
            pair_hosts[(a, b)].add(gkey)
            # 며칠에 걸쳐 나타났는지. 같은 날 몰린 5회와 닷새에 걸친 5회는 다르다.
            pair_days[(a, b)].add(day)

    rows = []
    for (a, b), cnt in pair.items():
        p_a, p_b, p_ab = single[a] / n, single[b] / n, cnt / n
        lift = p_ab / (p_a * p_b) if p_a and p_b else 0.0
        leverage = p_ab - p_a * p_b
        den = max(p_ab * (1 - p_a), p_a * (p_b - p_ab))
        zhangs = leverage / den if den else 0.0
        # 조건부 확률도 같이 낸다 — lift 만 보면 희귀 쌍이 과대평가된다.
        rows.append({
            "pair": [a, b], "together": cnt,
            "a_windows": single[a], "b_windows": single[b],
            "lift": round(lift, 2),
            "leverage": round(leverage, 5),
            "zhangs": round(zhangs, 3),
            "p_b_given_a": round(cnt / single[a], 3) if single[a] else 0.0,
            "p_a_given_b": round(cnt / single[b], 3) if single[b] else 0.0,
            "hosts": len(pair_hosts[(a, b)]),
            "days": len(pair_days[(a, b)]),
        })
    rows.sort(key=lambda r: (-r["together"], -r["lift"]))
    recommended = [r for r in rows
                   if r["together"] >= min_pairs and r["lift"] >= min_lift
                   and (axis != "cls" or "other" not in r["pair"])]
    return {"windows": n, "axis": axis, "scope": scope, "axis_total": len(single),
            "axis_dropped": dropped, "min_axis": min_axis,
            "pairs": rows, "recommended": recommended,
            "singles": dict(single.most_common())}


def _short(s: str, n: int) -> str:
    s = str(s)
    return s if len(s) <= n else s[:n - 1] + "…"


def apply_exclusions(events: list, name_pats: list, host_pats: list) -> list:
    """만성 노이즈를 걷어낸 뒤 무엇이 보이는지 미리 보는 필터.

    제외분을 반드시 출력한다 — 무엇을 뺐는지 안 보이면 남은 결과를 전수로 오독한다.
    """
    name_res = [re.compile(p) for p in name_pats]
    host_res = [re.compile(p) for p in host_pats]
    kept, dropped = [], Counter()
    for e in events:
        nm, hs = e.get("name") or "", e.get("host") or ""
        hit = next((p.pattern for p in name_res if p.search(nm)), None) \
            or next(("host:" + p.pattern for p in host_res if p.search(hs)), None)
        if hit:
            dropped[hit] += 1
        else:
            kept.append(e)
    total = len(events)
    print("\n[ 제외 적용 ]  %d건 중 %d건 제외 (%.1f%%), 남은 %d건"
          % (total, total - len(kept), 100 * (total - len(kept)) / total if total else 0,
             len(kept)), file=sys.stderr)
    for pat, n in dropped.most_common():
        print("    %-46s %6d건 (%.1f%%)" % (_short(pat, 46), n, 100 * n / total),
              file=sys.stderr)
    print("  이 결과는 전수가 아니다. 위 계열을 정비했을 때의 예상 화면이다.", file=sys.stderr)
    return kept


def report_scope(events: list):
    """측정 범위 — 어느 소스가 데이터에 있었는지를 결과보다 먼저 밝힌다.

    이것이 없으면 "브리지 후보 0건"이 **"관계가 없다"로 오독된다.** 실제로는 축 자체가
    데이터에 없어 **측정 대상이 아니었던 것**일 수 있다. 게이트웨이가 조회 실패와 신호
    없음을 구분하는 것(G1)과 같은 원칙을 마이닝 결과에도 적용한다.
    """
    by_src = Counter(e.get("src") or "?" for e in events)
    hosts = {s: len({e["host"] for e in events if (e.get("src") or "?") == s}) for s in by_src}
    print()
    print("[ 측정 범위 ]")
    for s in ("zabbix", "wazuh"):
        cnt = by_src.get(s, 0)
        if cnt:
            print("  %-8s %8d건   호스트 %d" % (s, cnt, hosts.get(s, 0)))
        else:
            print("  %-8s %8s     — 데이터 없음. 이 소스가 낀 쌍은 측정되지 않았다" % (s, "0건"))
    for s in sorted(k for k in by_src if k not in ("zabbix", "wazuh")):
        print("  %-8s %8d건   호스트 %d" % (s, by_src[s], hosts.get(s, 0)))
    print("  %-8s %8s     — 로그는 발화하지 않으므로 구조상 마이닝 대상이 아니다" % ("loki", "N/A"))

    present = [s for s in ("zabbix", "wazuh") if by_src.get(s)]
    if len(present) < 2:
        print("  => **단일 소스 측정이다.** 교차 소스 쌍은 결과에 나올 수 없다.")
        return

    # 두 소스에 데이터가 있어도 **호스트명이 안 맞으면** 교차 조합이 구조적으로 0건이다.
    # 세 시스템이 같은 장비를 다르게 부르고 공유 키가 없기 때문이다(Zabbix `node1` /
    # Wazuh FQDN). 이걸 안 밝히면 0건이 "관계 없음"으로 읽힌다 — 조회 실패와 신호 없음을
    # 가르는 것(G1)과 같은 형태의 오독이다.
    #
    # 사이트 지식이 필요 없는 검사다. 각 소스의 호스트명 집합이 겹치는지만 본다.
    # 실제 번역은 HOST_LABEL_MAP(사이트 값)이고, 근본 해결은 배포 시 FQDN 정규화다.
    sets = {s: {e["host"] for e in events if (e.get("src") or "?") == s} for s in present}
    common = set.intersection(*sets.values())
    smaller = min(len(v) for v in sets.values()) or 1
    print("  호스트명 교집합 %d개 (적은 쪽 %d개 대비 %.0f%%)"
          % (len(common), smaller, 100 * len(common) / smaller))
    if not common:
        print("  => ⚠ **두 소스의 호스트명이 하나도 겹치지 않는다.** 같은 장비를 다르게 부르고")
        print("     있어 교차 조합이 나올 수 없다. 0건은 관계 없음이 아니라 **측정 불가**다.")
        print("     HOST_LABEL_MAP 으로 번역하거나, 배포 시 FQDN 을 통일한다.")
    elif len(common) < smaller * 0.5:
        print("  => ⚠ 겹치는 호스트가 절반 미만이다. 겹치지 않는 장비의 교차 조합은")
        print("     측정되지 않는다 — 그 부분의 0건은 근거가 되지 못한다.")
    else:
        print("  => 교차 소스 쌍이 측정 범위 안에 있다.")


def lag_counts(events: list, axis: str, lag_max: int, nbins: int):
    """알림 하나하나를 기준점으로 삼아, 이후 시차 구간별로 다른 알림이 따라오는지 센다.

    고정 창의 경계 손실을 없앤다. 한 기준점에 대해 같은 축은 처음 따라온 것만 세어
    값이 "A 중 B 가 따라온 비율"로 고정되게 한다. 방식 비교는 BRIDGE_MINER_GUIDE.
    """
    width = lag_max / nbins
    seq = sorted(events, key=lambda e: e["ts"])
    keys = [axis_key(e, axis) for e in seq]
    ts = [e["ts"] for e in seq]
    n_axis = Counter(keys)
    counts = defaultdict(lambda: [0] * nbins)
    for i in range(len(seq)):
        a, t0 = keys[i], ts[i]
        seen = set()
        j = i + 1
        while j < len(seq) and ts[j] - t0 <= lag_max:
            b = keys[j]
            if b != a and b not in seen:
                seen.add(b)
                idx = min(int((ts[j] - t0) / width), nbins - 1)
                counts[(a, b)][idx] += 1
            j += 1
    return counts, n_axis


def overlap_counts(events: list, axis: str, min_open_s: int = 0):
    """열려 있던 문제 위에서 다른 문제가 발생한 횟수를 센다.

    시차 방식으로도 못 잡는 형태가 있다 — 만성 문제가 며칠째 열려 있는 상태에서 다른
    장애가 터지는 경우다. 두 **시작 시각**은 며칠 떨어져 있으므로 시차를 아무리 넓혀도
    걸리지 않는다. 봐야 하는 것은 시작 시각의 근접이 아니라 **구간의 겹침**이다.

    end_ts 가 0 인 이벤트(미해소 또는 복구 이벤트 미확인)는 셈에서 제외한다. 열린 채로
    두면 그 뒤 모든 이벤트가 겹친 것으로 세어져 결과가 통째로 망가진다.
    """
    opens = [e for e in events if e.get("end_ts") and e["end_ts"] - e["ts"] >= min_open_s]
    if not opens:
        return None
    starts = sorted(events, key=lambda e: e["ts"])
    times = [e["ts"] for e in starts]
    keys = [axis_key(e, axis) for e in starts]
    pairs = Counter()
    # 일수도 함께 센다 — 없으면 한 번의 대형 사건이 통계를 지배한다.
    days = defaultdict(Counter)
    n_axis = Counter(axis_key(e, axis) for e in opens)
    for base in opens:
        a = axis_key(base, axis)
        # 이분 탐색으로 구간의 시작·끝 위치를 바로 잡는다. 매번 앞에서부터 훑으면
        # 만성 건(최장 40일) 하나가 전체를 다시 훑어 규모가 제곱으로 커진다.
        lo = bisect.bisect_right(times, base["ts"])
        hi = bisect.bisect_left(times, base["end_ts"])
        seen = set()
        for i in range(lo, hi):
            b = keys[i]
            if b != a and b not in seen:
                seen.add(b)
                pairs[(a, b)] += 1
                days[(a, b)][_iso(times[i])[:10]] += 1
    return {"pairs": pairs, "n_axis": n_axis,
            "days": {k: len(v) for k, v in days.items()},
            # 최대 하루가 차지하는 비중. 일수만으로는 '며칠에 걸쳤지만 하루에 몰린'
            # 형태가 안 걸러진다. 발생 빈도를 벌하지 않는 것이 이 지표의 요점이다.
            "max_day_share": {k: max(v.values()) / sum(v.values()) for k, v in days.items()},
            "with_end": len(opens), "total": len(events)}


def permute_overlap(events: list, observed: dict, axis: str, rounds: int,
                    seed: int = 7, min_open_s: int = 0) -> dict:
    """구간 겹침용 귀무모형 — 길이·라벨은 두고 위치만 시간축에서 무작위로 옮긴다.

    재는 것은 "이 문제가 오래 열리는가"가 아니라 "그 위에 나는 것이 특정 종류에
    쏠리는가"다. 라벨 셔플은 구간 길이와 라벨의 연결을 끊어 검정이 무너진다.
    """
    rng = random.Random(seed)
    starts = sorted(events, key=lambda e: e["ts"])
    times = [e["ts"] for e in starts]
    keys = [axis_key(e, axis) for e in starts]
    lo_t, hi_t = times[0], times[-1]
    bases = [(axis_key(e, axis), e["end_ts"] - e["ts"])
             for e in events if e.get("end_ts") and e["end_ts"] - e["ts"] >= min_open_s]

    ge = defaultdict(int)
    for _ in range(rounds):
        pairs = Counter()
        for a, dur in bases:
            s = rng.randrange(lo_t, max(hi_t - dur, lo_t + 1))
            i = bisect.bisect_right(times, s)
            j = bisect.bisect_left(times, s + dur)
            seen = set()
            for idx in range(i, j):
                b = keys[idx]
                if b != a and b not in seen:
                    seen.add(b)
                    pairs[(a, b)] += 1
        for k, obs in observed.items():
            if pairs.get(k, 0) >= obs:
                ge[k] += 1
    return {"rounds": rounds, "ge": dict(ge)}


def emit_open_link_rules(res: dict, picked: list, path: str, measured: str):
    """게이트웨이가 읽을 연계 규칙 파일을 낸다 — 측정과 운영을 잇는 고리.

    수치를 코드에 박으면 환경이 바뀌어도 조용히 낡는다. 그 환경에서 측정한 것만
    그 환경에 적용되도록, 도구가 파일을 내고 게이트웨이가 그 파일을 읽는다.
    (게이트웨이: OPEN_LINK_RULES_FILE)
    """
    pairs, n_axis, dayc = res["pairs"], res["n_axis"], res.get("days", {})
    # other 는 분류 실패 묶음이다. 그 안에 무엇이 들었는지 모르므로 규칙으로 쓸 수 없다.
    # 통계적으로 유의해도 마찬가지다 — "분류 안 되는 무언가가 열려 있으면"은 지시가 아니다.
    # 리포트에는 남기고(무엇을 분류해야 하는지 알려주므로) 규칙 파일에서만 뺀다.
    dropped = [k for k in picked if "other" in k]
    picked = [k for k in picked if "other" not in k]
    if dropped:
        print("[emit] other 가 낀 조합 %d건 제외 — 분류 실패 묶음이라 규칙이 될 수 없다: %s"
              % (len(dropped), ", ".join("%s->%s" % k for k in dropped)), file=sys.stderr)
    rules = [{"open": a, "followed": b,
              "rate": round(pairs[(a, b)] / n_axis[a], 3) if n_axis[a] else 0.0,
              "days": dayc.get((a, b), 0), "overlaps": pairs[(a, b)]}
             for a, b in picked]
    doc = {"measured": measured, "rules": rules}
    with open(path, "w", encoding="utf-8") as f:
        json.dump(doc, f, ensure_ascii=False, indent=1)
    print("", file=sys.stderr)
    print("[emit] %s — 규칙 %d건 저장. 게이트웨이에 OPEN_LINK_RULES_FILE 로 지정한다."
          % (path, len(rules)), file=sys.stderr)
    print("       측정 조건: %s" % measured, file=sys.stderr)


def report_overlap(res: dict, perm: dict, q: float, min_axis: int, min_pairs: int,
                   min_days: int = 3, max_day_share: float = 0.5, top: int = 25):
    R = perm["rounds"]
    pairs, n_axis = res["pairs"], res["n_axis"]
    # 검정 대상과 보고 대상이 달라지면 FDR 문턱이 어긋난다. main 과 같은 필터를 쓴다.
    dayc, share = res.get("days", {}), res.get("max_day_share", {})
    obs, concentrated = {}, []
    for k, v in pairs.items():
        if v < min_pairs or n_axis[k[0]] < min_axis or dayc.get(k, 0) < min_days:
            continue
        if share.get(k, 0) > max_day_share:
            concentrated.append(k)      # 버리지 않고 따로 보여준다
            continue
        obs[k] = v
    pvals = {k: (perm["ge"].get(k, 0) + 1) / (R + 1) for k in obs}
    picked = fdr_pass(pvals, q)
    print()
    print("=" * 78)
    print("구간 겹침   (열려 있던 문제 위에서 다른 문제가 난 횟수 · 셔플 %d회 · 오탐율 %.0f%%)"
          % (R, q * 100))
    print("=" * 78)
    print("  해소 시각이 확인된 이벤트 %d/%d건만 기준으로 쓴다(미해소는 제외)."
          % (res["with_end"], res["total"]))
    print("  시차 방식으로 못 잡는 형태를 본다 — 만성 문제가 며칠째 열린 상태에서 터지는 장애.")
    print("  검정 %d개 중 %d개 통과" % (len(pvals), len(picked)))
    if not picked:
        print("  => 통과한 쌍이 없다.")
        return
    print()
    print("  조건: %d일 이상 · 최대 하루 비중 %.0f%% 이하 — 대형 사건 1회의 지배를 막는다."
          % (min_days, 100 * max_day_share))
    if concentrated:
        print()
        print("  [ 한 날에 몰려 제외 %d건 ] — 버린 것이 아니라 규칙으로 쓸 수 없는 것이다."
              % len(concentrated))
        for k in sorted(concentrated, key=lambda x: -pairs[x])[:6]:
            print("     %5d겹침 %2d일 최대하루 %3.0f%%  %s -> %s"
                  % (pairs[k], dayc.get(k, 0), 100 * share.get(k, 0),
                     _short(k[0], 26), _short(k[1], 26)))
        print("     이 조합들은 단발 사건에서 나왔다. 사건 자체는 실재하지만 반복 규칙이 아니다.")
        print()
    print("%8s %6s %5s %6s  %s" % ("p", "겹침", "일수", "비율", "열린 문제 -> 그 위에서 난 문제"))
    report_overlap.picked = [k for k, _ in picked]   # --emit-rules 가 재계산 없이 쓴다
    for k, p in picked[:top]:
        a, b = k
        print("%8.4f %6d %5d %5.0f%%  %s -> %s"
              % (p, obs[k], dayc.get(k, 0), 100 * obs[k] / n_axis[a],
                 _short(a, 28), _short(b, 28)))
    if len(picked) > top:
        print("  ... 외 %d개" % (len(picked) - top))


def _profile_rows(counts: dict, n_axis: Counter, min_axis: int, min_pairs: int) -> dict:
    """순서 있는 쌍마다 총 후속 횟수를 낸다. 검정 통계량은 이 총합이다."""
    out = {}
    for (a, b), bins in counts.items():
        tot = sum(bins)
        if tot >= min_pairs and n_axis[a] >= min_axis and n_axis[b] >= min_axis:
            out[(a, b)] = tot
    return out


def permute_profile(events: list, observed: dict, axis: str, lag_max: int, nbins: int,
                    min_axis: int, min_pairs: int, rounds: int, seed: int = 7) -> dict:
    """시차 프로파일용 순열 검정. 라벨만 시간대별로 재배치한다(일주기 보존)."""
    rng = random.Random(seed)
    field = "host" if axis == "host" else "name"
    strata = defaultdict(list)
    for idx, e in enumerate(events):
        strata[datetime.fromtimestamp(e["ts"], timezone.utc).astimezone().hour].append(idx)
    ge = defaultdict(int)
    for _ in range(rounds):
        vals = [e.get(field) for e in events]
        for idxs in strata.values():
            picked = [vals[i] for i in idxs]
            rng.shuffle(picked)
            for i, v in zip(idxs, picked):
                vals[i] = v
        shuffled = [dict(e, **{field: v}) for e, v in zip(events, vals)]
        c, _na = lag_counts(shuffled, axis, lag_max, nbins)
        for k, obs in observed.items():
            # 셔플에서 그 쌍이 한 번도 이어지지 않으면 후속 0 이다. 부재를 건너뛰면
            # "셔플이 관측값에 못 미쳤다"로 세어져 유의 판정이 된다(고정 창에서 겪은 결함).
            if (sum(c[k]) if k in c else 0) >= obs:
                ge[k] += 1
    return {"rounds": rounds, "ge": dict(ge)}


def report_profile(counts: dict, n_axis: Counter, observed: dict, perm: dict,
                   lag_max: int, nbins: int, q: float, top: int = 25):
    R = perm["rounds"]
    pvals = {k: (perm["ge"].get(k, 0) + 1) / (R + 1) for k in observed}
    picked = fdr_pass(pvals, q)
    width = int(lag_max / nbins)
    print()
    print("=" * 78)
    print("시차 프로파일   (기준점 방식 · 최대 시차 %ds · 구간 %d개 · 셔플 %d회 · 오탐율 %.0f%%)"
          % (lag_max, nbins, R, q * 100))
    print("=" * 78)
    print("  고정 창과 달리 경계 손실이 없고 A->B 와 B->A 를 따로 센다.")
    print("  검정 %d개(순서 있는 쌍) 중 %d개 통과" % (len(pvals), len(picked)))
    floor = 1 / (R + 1)
    at_floor = sum(1 for v in pvals.values() if v <= floor)
    if at_floor and floor > q * at_floor / len(pvals):
        print("  ⚠ 셔플 부족 — --null %d 이상 필요. 지금의 '0개'는 관계 없음이 아니라 판정 불가."
              % int(len(pvals) / (q * at_floor)))
    if not picked:
        print("  => 통과한 쌍이 없다.")
        return []
    print()
    hdr = " ".join("%5d" % ((i + 1) * width) for i in range(nbins))
    print("%8s %6s %6s  %s" % ("p", "후속", "비율", "시차 구간별 (초 이하)"))
    print("%8s %6s %6s  %s" % ("", "", "", hdr))
    rows = []
    for k, p in picked[:top]:
        a, b = k
        bins = counts[k]
        rate = observed[k] / n_axis[a]
        rev = sum(counts.get((b, a), [0]))
        rows.append((k, p, observed[k], rate, bins, rev))
        print("%8.4f %6d %5.0f%%  %s" % (p, observed[k], 100 * rate,
                                         " ".join("%5d" % x for x in bins)))
        peak = bins.index(max(bins))
        print("         %s  ->  %s" % (_short(a, 32), _short(b, 32)))
        print("         최다 구간 %d~%ds · 역방향(B->A) %d회 %s"
              % (peak * width, (peak + 1) * width, rev,
                 "→ 방향성 있음" if observed[k] >= 2 * max(rev, 1) else "→ 방향 불분명"))
    if len(picked) > top:
        print("  ... 외 %d개" % (len(picked) - top))
    return rows


def permute(events: list, observed: dict, window_s: int, min_pairs: int, min_lift: float,
            axis: str, min_axis: int, scope: str, rounds: int, seed: int = 7) -> dict:
    """축 라벨만 섞고 시각은 그대로 둔 뒤 같은 마이닝을 반복한다.

    한 번의 셔플 루프에서 두 가지를 함께 얻는다.
      ceilings — 회차별 leverage 최대값. 전 쌍을 통틀어 우연이 낼 수 있는 상한.
      ge       — 쌍별로 '셔플이 관측값 이상을 낸 횟수'. 쌍별 p값의 재료.

    둘의 쓰임이 다르다. 최대값 기준은 검정 대상 쌍이 늘수록 함께 높아져 **기간을 늘릴수록
    오히려 둔감해진다**(실측: 60일 0.0068 -> 90일 0.0103, 유의 판정은 늘지 않음).
    진짜 관계의 leverage 는 확률이라 기간이 늘어도 커지지 않으므로, 최대값 기준만 쓰면
    데이터를 늘릴수록 손해다. 쌍별 p값에 FDR 을 적용하면 이 문제가 없다.
    """
    rng = random.Random(seed)
    field = "host" if axis == "host" else "name"
    strata = defaultdict(list)
    for idx, e in enumerate(events):
        strata[datetime.fromtimestamp(e["ts"], timezone.utc).astimezone().hour].append(idx)

    ceilings, cliques, ge = [], [], defaultdict(int)
    for _ in range(rounds):
        vals = [e.get(field) for e in events]
        for idxs in strata.values():
            picked = [vals[i] for i in idxs]
            rng.shuffle(picked)
            for i, v in zip(idxs, picked):
                vals[i] = v
        shuffled = [dict(e, **{field: v}) for e, v in zip(events, vals)]
        r = mine(shuffled, window_s, min_pairs, min_lift,
                 axis=axis, min_axis=min_axis, scope=scope)
        ceilings.append(max((p["leverage"] for p in r["pairs"]), default=0.0))
        cliques.append(len(_cliques(r["pairs"])))

        seen = set()
        for p in r["pairs"]:
            k = tuple(p["pair"])
            if k in observed:
                seen.add(k)
                if p["leverage"] >= observed[k]:
                    ge[k] += 1
        # 셔플에서 한 번도 함께 나오지 않은 쌍은 결과 목록에 없다. 그 부재를 그냥 넘기면
        # "셔플이 관측값에 못 미쳤다"로 세어져 유의 판정이 된다. 실제로는 동시 발생 0 이므로
        # leverage = -P(A)P(B) 이고, 관측값이 그보다 낮으면(즉 관측이 더 음수면) 셔플이 이긴다.
        # 이 처리가 없으면 **음의 상관 쌍이 후보로 올라온다**(실측으로 확인).
        n2, s2 = r["windows"], r["singles"]
        for k, obs_lev in observed.items():
            if k in seen or not n2:
                continue
            a, b = k
            if s2.get(a) and s2.get(b) and -(s2[a] / n2) * (s2[b] / n2) >= obs_lev:
                ge[k] += 1
    return {"rounds": rounds, "ceilings": ceilings, "cliques": cliques, "ge": dict(ge)}


def fdr_pass(pvals: dict, q: float) -> list:
    """Benjamini-Hochberg 절차. p 오름차순으로 p <= q*i/m 을 만족하는 최대 i 까지 채택한다.

    최대값 기준(family-wise)은 "한 건도 틀리면 안 된다"는 통제라 쌍이 수백 개면 사실상
    아무것도 통과하지 못한다. FDR 은 "채택분 중 오탐 비율을 q 이하로" 통제하므로
    검토 후보를 뽑는 용도에 맞다. 사람이 확인할 목록을 만드는 것이지 자동 적용이 아니다.
    """
    ordered = sorted(pvals.items(), key=lambda kv: kv[1])
    m, cut = len(ordered), 0
    for i, (_k, p) in enumerate(ordered, 1):
        if p <= q * i / m:
            cut = i
    return ordered[:cut]


def report_fdr(res: dict, perm: dict, q: float, top: int = 25):
    R = perm["rounds"]
    lev = {tuple(p["pair"]): p["leverage"] for p in res["pairs"] if p["leverage"] > 0}
    info = {tuple(p["pair"]): p for p in res["pairs"]}
    # (초과횟수+1)/(회차+1) — 0 이 나오지 않게 하는 표준 보정. 해상도는 1/(R+1) 이다.
    pvals = {k: (perm["ge"].get(k, 0) + 1) / (R + 1) for k in lev}
    picked = fdr_pass(pvals, q)
    print()
    print("=" * 78)
    print("쌍별 순열 검정 + FDR   (셔플 %d회, 목표 오탐율 %.0f%%)" % (R, q * 100))
    print("=" * 78)
    m = len(pvals)
    floor = 1 / (R + 1)
    at_floor = sum(1 for v in pvals.values() if v <= floor)
    print("  검정 %d쌍 중 %d쌍 통과   (p 해상도 %.4f)" % (m, len(picked), floor))
    print("  최대값 기준과의 차이 — 최대값은 전 쌍을 통틀어 한 번도 안 틀리는 선을 긋는다.")
    print("  쌍이 수백 개면 그 선이 지나치게 높아 leverage 가 작은 실제 관계가 전부 탈락한다.")

    # 셔플이 적으면 p 가 해상도 바닥에 깔려 BH 문턱을 못 내려간다. 그 상태의 "0쌍"은
    # 관계가 없다는 뜻이 아니라 **측정이 성립하지 않았다**는 뜻이다. 둘을 구분해 알린다.
    if at_floor and floor > q * at_floor / m:
        need = int(m / (q * at_floor))
        print()
        print("  ⚠ 셔플 횟수가 부족하다. 해상도 바닥에 걸린 쌍이 %d개인데 그 지점의 BH 문턱은"
              % at_floor)
        print("    %.5f 이라 %.4f 로는 도달할 수 없다. --null %d 이상이 필요하다."
              % (q * at_floor / m, floor, need))
        print("    이 상태의 '통과 0쌍'은 관계 없음이 아니라 **판정 불가**다.")
    if not picked:
        print("  => 통과 쌍이 없다.")
        return
    print()
    print("%8s %8s %6s %7s %7s  %s" % ("p", "leverage", "공동창", "일수", "P(B|A)", "쌍"))
    for k, p in picked[:top]:
        d = info[k]
        print("%8.4f %8.4f %6d %7d %7.3f  %s"
              % (p, d["leverage"], d["together"], d["days"], d["p_b_given_a"],
                 _short(" + ".join(k), 40)))
    if len(picked) > top:
        print("  ... 외 %d쌍" % (len(picked) - top))


def _cliques(pairs: list, min_conf: float = 0.8, min_days: int = 5, min_together: int = 5):
    """양방향 조건부확률이 모두 높고 여러 날에 걸친 쌍 — '늘 같이 뜨는' 조합.

    발생이 드물면 관측·기대 빈도 차이가 작아 leverage 로는 구조적으로 누락된다.
    min_days: 하루에 몰린 10회는 한 번의 사건을 여러 번 센 것이다.
    """
    return [p for p in pairs
            if p["together"] >= min_together and p["days"] >= min_days
            and min(p["p_b_given_a"], p["p_a_given_b"]) >= min_conf]


def report_cliques(res: dict, perm: dict, top: int = 15):
    obs = _cliques(res["pairs"])
    ceiling = max(perm["cliques"]) if perm["cliques"] else 0
    print()
    print("=" * 78)
    print("완전 동반 후보   (양방향 조건부확률 0.8 이상 · 5일 이상 · 5회 이상)")
    print("=" * 78)
    print("  관측 %d쌍 / 셔플에서 같은 조건을 통과한 최대 %d쌍" % (len(obs), ceiling))
    if ceiling:
        print("  주의: 셔플에서도 통과하는 쌍이 있다. 조건이 느슨하다는 뜻이므로 개별 확인이 필요하다.")
    if not obs:
        print("  => 해당 쌍이 없다.")
        return
    print()
    print("%8s %6s %7s %7s  %s" % ("공동창", "일수", "P(B|A)", "P(A|B)", "쌍"))
    for p in sorted(obs, key=lambda p: -p["together"])[:top]:
        print("%8d %6d %7.3f %7.3f  %s"
              % (p["together"], p["days"], p["p_b_given_a"], p["p_a_given_b"],
                 _short(" + ".join(p["pair"]), 44)))


def report_null(res: dict, perm: dict, top: int = 10):
    print()
    print("=" * 78)
    print("우연 기준선 — 최대값 방식   (축 라벨 %d회 셔플, 시각·빈도·일주기 보존)"
          % perm["rounds"])
    print("=" * 78)
    ceiling = max(perm["ceilings"])
    print("  셔플 최대 leverage: %s" % "  ".join("%.4f" % x for x in perm["ceilings"][:8]))
    print("  우연의 천장       : %.4f" % ceiling)
    obs = [p for p in res["pairs"] if p["leverage"] > ceiling]
    print("  천장을 넘은 쌍     : %d개 / 전체 %d개" % (len(obs), len(res["pairs"])))
    if not obs:
        print("  => 천장을 넘는 쌍이 없다. 이 축·창에서는 후보를 올리지 않는다.")
        return
    print()
    print("%-6s %8s %10s %s" % ("배수", "공동창", "leverage", "쌍"))
    for p in obs[:top]:
        print("%5.0fx %8d %10.4f %s"
              % (p["leverage"] / ceiling if ceiling else 0, p["together"], p["leverage"],
                 _short(" + ".join(p["pair"]), 48)))


def report(res: dict, existing: list, min_pairs: int, min_lift: float, top: int = 30):
    axis = res.get("axis", "cls")
    scope = res.get("scope", "host")
    w = 34 if axis == "cls" else 44
    print()
    print("=" * 78)
    print("브리지 후보 마이닝 결과   (집계 축: %s / 창 범위: %s)" % (axis, scope))
    print("=" * 78)
    print("시간창 수: %d   (겹치지 않는 창, %s)"
          % (res["windows"], "전 호스트 단일 타임라인" if scope == "global" else "호스트별"))
    if scope == "global":
        print("주의: 전역 창이므로 서로 다른 장비의 알림이 같은 창에 들어간다.")
        print("      hosts 열은 의미가 없으므로 대신 days(며칠에 걸쳐 나타났나)를 본다.")
    if not res["windows"]:
        print("데이터가 없다. 환경변수와 기간을 확인한다.")
        return
    if res.get("axis_dropped"):
        print("축 %d개 중 %d개는 등장 창 수 %d 미만이라 쌍 계산에서 제외"
              % (res["axis_total"], res["axis_dropped"], res["min_axis"]))

    print()
    print("[ 축별 등장 창 수 상위 %d ]" % top)
    for cls, cnt in list(res["singles"].items())[:top]:
        print("  %-*s %6d  (%.1f%%)" % (w, _short(cls, w), cnt, 100 * cnt / res["windows"]))
    if len(res["singles"]) > top:
        print("  ... 외 %d개" % (len(res["singles"]) - top))

    if axis == "cls":
        print()
        print("[ 현행 BRIDGE_GROUPS 가 데이터에서 지지되는가 ]")
        idx = {tuple(sorted(r["pair"])): r for r in res["pairs"]}
        for grp in existing:
            for a, b in itertools.combinations(sorted(grp), 2):
                r = idx.get((a, b))
                if r:
                    verdict = "지지" if (r["together"] >= min_pairs and r["lift"] >= min_lift) else "약함"
                    print("  %-34s together=%-5d lift=%-6s %s"
                          % ("%s + %s" % (a, b), r["together"], r["lift"], verdict))
                else:
                    print("  %-34s 데이터에 함께 나온 적 없음 — 근거 없음" % ("%s + %s" % (a, b)))
    else:
        print()
        print("[ 현행 BRIDGE_GROUPS 대조는 생략 ] 축이 %s 라 class 쌍과 직접 비교되지 않는다." % axis)

    print()
    print("[ 추천 후보 (together>=%d, lift>=%.1f%s) ]  총 %d건, 상위 %d 표시"
          % (min_pairs, min_lift, ", other 제외" if axis == "cls" else "",
             len(res["recommended"]), top))
    cur = {tuple(sorted(g)) for g in existing}
    if not res["recommended"]:
        print("  없음")
    for r in res["recommended"][:top]:
        mark = "이미 반영" if tuple(sorted(r["pair"])) in cur else "신규"
        spread = ("days=%-4d" % r.get("days", 0)) if scope == "global" \
            else ("hosts=%-3d days=%-4d" % (r["hosts"], r.get("days", 0)))
        metrics = ("together=%-5d lift=%-6s zhangs=%-6s lev=%-9s P(B|A)=%-5s P(A|B)=%-5s %s [%s]"
                   % (r["together"], r["lift"], r["zhangs"], r["leverage"],
                      r["p_b_given_a"], r["p_a_given_b"], spread, mark))
        if axis == "cls":
            print("  %-34s %s" % ("%s + %s" % tuple(r["pair"]), metrics))
        else:
            print("  %s" % _short(r["pair"][0], 72))
            print("  + %s" % _short(r["pair"][1], 72))
            print("      %s" % metrics)

    print()
    print("해석 주의")
    print("  - lift 가 높아도 together 가 작으면 우연이다. 둘을 함께 본다.")
    print("  - zhangs 는 -1~1 이고 희귀성에 덜 민감하다. lift 가 크고 zhangs 가 낮으면 부풀려진 것이다.")
    print("  - leverage 는 관측 빈도와 독립 가정 기대 빈도의 차이다. 0에 가까우면 실질 연관이 약하다.")
    print("  - 상관은 인과가 아니다. 추천은 '검토 대상'이고 브리지 확정은 사람이 한다.")
    print("  - days 가 1이면 한 번의 사건이 여러 번 센 것일 수 있다. 여러 날에 걸친 쌍이 강하다.")
    if scope == "global":
        print("  - P(B|A) 와 P(A|B) 의 비대칭이 방향을 시사한다. 한쪽만 1.0 이면 그쪽이 파생이다.")
    else:
        print("  - hosts 가 1이면 특정 호스트 사정일 수 있다. 여러 호스트에서 보이는 쌍이 강하다.")
    if axis == "cls":
        print("  - other 는 분류 실패 묶음이라 제외한다. other 비중이 크면 분류기를 먼저 고친다.")
    else:
        print("  - name 축 결과에는 실 트리거명이 그대로 나온다. 출력을 리포에 커밋하지 말 것.")


def report_declared_tags(events: list):
    """실환경에 이미 붙어 있는 class 태그 값 현황.

    "팀이 태그를 붙이면 코드 수정 없이 분류가 정확해진다"를 주장하려면 세 가지를 알아야 한다 —
    지금 몇 %에 태그가 있는가, 어떤 값을 쓰는가, 그중 우리가 모르는 값은 무엇인가.
    모르는 값은 우리 매핑에 추가하면 되므로 **가장 값싼 개선 대상**이다.
    """
    known = incident._KNOWN_CLASSES
    tagged = [e for e in events if e.get("declared")]
    print()
    print("[ 실환경 class 태그 현황 ]  태그 있음 %d/%d건 (%.1f%%)"
          % (len(tagged), len(events), 100 * len(tagged) / max(len(events), 1)))
    if not tagged:
        print("  없음 — 태그가 하나도 붙어 있지 않다. 부여가 곧 처방이다.")
        return
    for val, cnt in Counter(e["declared"] for e in tagged).most_common():
        mark = "인식됨" if val in known else "** 모르는 값 — 매핑 추가 대상 **"
        print("  %6d  class=%-24s %s" % (cnt, val, mark))


def report_unclassified(events: list, top: int = 15):
    """other 로 떨어진 알림명을 빈도순으로. 여기 나온 것이 태그 부여 1순위다.

    가이드가 규정한 대로 other 가 크면 답은 키워드를 늘리는 것이 아니라 소스에 태그를 붙이는
    것이므로, "무엇에 붙일지" 목록이 곧 처방이 된다.
    """
    others = [e for e in events if e["cls"] == "other"]
    if not others:
        print("\n[ 미분류(other) 없음 ]")
        return
    print()
    print("[ 미분류(other) 상위 알림명 — 태그 부여 1순위 ]  총 %d/%d건 (%.1f%%)"
          % (len(others), len(events), 100 * len(others) / len(events)))
    for name, cnt in Counter(e["name"] for e in others).most_common(top):
        print("  %6d  %s" % (cnt, name[:90]))


def main():
    ap = argparse.ArgumentParser(description="브리지 후보 마이닝 (읽기 전용)")
    ap.add_argument("--days", type=int, default=DEFAULT_DAYS)
    ap.add_argument("--window", type=int, default=DEFAULT_WINDOW_S, help="초")
    ap.add_argument("--min-pairs", type=int, default=DEFAULT_MIN_PAIRS)
    ap.add_argument("--min-lift", type=float, default=DEFAULT_MIN_LIFT)
    ap.add_argument("--by", choices=["cls", "tmpl", "name", "host"], default="cls",
                    help="집계 축. cls=사건 유형 / tmpl=트리거 유형(권장) / name=원본명 / host=호스트")
    ap.add_argument("--scope", choices=["host", "global"], default="host",
                    help="시간창 범위. host=호스트별 / global=전 호스트 한 타임라인(근원 판정용)")
    ap.add_argument("--min-axis", type=int, default=1,
                    help="등장 창 수가 이 미만인 축은 쌍 계산에서 제외 (name 축 조합 폭증 방지)")
    ap.add_argument("--top", type=int, default=30, help="목록 출력 상한")
    ap.add_argument("--pair", nargs=2, metavar=("A", "B"),
                    help="쌍 하나를 원본 이벤트 수준으로 펼친다. 부분 문자열로 지정 가능")
    ap.add_argument("--samples", type=int, default=6, help="--pair 표본 출력 건수")
    ap.add_argument("--null", type=int, default=0, metavar="N",
                    help="축 라벨을 N회 셔플해 유의성을 검정한다 (FDR 용도로는 200 권장)")
    ap.add_argument("--fdr", type=float, default=0.05, metavar="Q",
                    help="쌍별 순열 p값에 적용할 목표 오탐율 (기본 0.05)")
    ap.add_argument("--max-day-share", type=float, default=0.5, metavar="R",
                    help="--overlap 에서 최대 하루가 이 비중을 넘는 조합은 뺀다 (단일 사건 지배 방지)")
    ap.add_argument("--emit-rules", metavar="FILE",
                    help="--overlap 결과를 게이트웨이용 연계 규칙 파일로 저장 (--by cls 전용)")
    ap.add_argument("--min-days", type=int, default=3, metavar="D",
                    help="--overlap 에서 이 일수 미만으로만 나타난 조합은 뺀다 (대형 사건 1회 지배 방지)")
    ap.add_argument("--min-open", type=int, default=0, metavar="S",
                    help="--overlap 에서 이 시간 미만으로 열렸던 문제는 기준에서 뺀다(초)")
    ap.add_argument("--diag", action="store_true",
                    help="Zabbix API 가 어느 파라미터에서 깨지는지 계단식으로 짚는다")
    ap.add_argument("--overlap", action="store_true",
                    help="열려 있던 문제 위에서 난 문제를 센다 (해소 시각 포함 재수집 필요)")
    ap.add_argument("--profile", action="store_true",
                    help="고정 창 대신 기준점 방식으로 시차 프로파일을 낸다 (경계 손실 없음, 방향 산출)")
    ap.add_argument("--lag-max", type=int, default=7200, help="--profile 최대 시차(초)")
    ap.add_argument("--lag-bins", type=int, default=6, help="--profile 시차 구간 개수")
    ap.add_argument("--exclude", metavar="REGEX", action="append", default=[],
                    help="트리거명이 이 정규식에 걸리는 이벤트를 분석에서 뺀다. 여러 번 지정 가능. "
                         "만성 노이즈를 걷어낸 뒤 무엇이 보이는지 확인하는 용도")
    ap.add_argument("--exclude-host", metavar="REGEX", action="append", default=[],
                    help="호스트명이 이 정규식에 걸리는 이벤트를 뺀다")
    ap.add_argument("--json", action="store_true", help="원시 결과를 stdout 에 JSON 으로")
    ap.add_argument("--source", choices=["all", "zabbix", "wazuh"], default="all")
    ap.add_argument("--dump", metavar="FILE",
                    help="조회 결과를 파일로 저장(실 호스트명·알림명 포함 — private/ 에만 둘 것)")
    ap.add_argument("--load", metavar="FILE", action="append",
                    help="조회 대신 파일에서 읽는다. **여러 번 지정하면 합친다** — 소스마다 "
                         "닿는 망이 달라 나눠 떠야 할 때 쓴다")
    a = ap.parse_args()

    if a.diag:
        asyncio.run(diag_zabbix(a.days))
        return

    failed = []
    if a.load:
        # 여러 파일을 합친다 — 소스마다 닿는 망이 달라 나눠 떠야 할 때가 있다.
        events, spans = [], []
        for path in a.load:
            with open(path, encoding="utf-8") as f:
                saved = json.load(f)
            got = saved["events"]
            events += got
            failed += saved.get("failed_sources") or []
            ts = [e["ts"] for e in got] or [0]
            spans.append((path, saved.get("fetched_at", "?"), saved.get("days", "?"),
                          len(got), min(ts), max(ts)))
            print("[load] %s — %d건 (수집 %s, --days %s)"
                  % (path, len(got), saved.get("fetched_at", "?"), saved.get("days", "?")),
                  file=sys.stderr)

        # 측정 창이 어긋난 파일을 합치면 "그 기간엔 신호가 없었다"가 되어 결과가 왜곡된다.
        # 리포 규칙(서로 다른 측정 기간의 수치를 섞지 않는다)을 코드로 강제하지는 않되,
        # 어긋난 사실은 반드시 드러낸다.
        if len(spans) > 1:
            lo = max(sp[4] for sp in spans)
            hi = min(sp[5] for sp in spans)
            gap = max(abs(sp[4] - lo) for sp in spans) + max(abs(sp[5] - hi) for sp in spans)
            print("[load] 파일 %d개 합침 — 겹치는 구간 %s ~ %s"
                  % (len(spans), _iso(lo)[:10], _iso(hi)[:10]), file=sys.stderr)
            if gap > 2 * 86400:
                print("  ⚠ 파일마다 측정 창이 %.1f일 어긋난다. 겹치지 않는 구간은 한쪽 소스만"
                      " 있으므로 그 구간의 교차 조합은 **없는 것이 아니라 측정 불가**다."
                      % (gap / 86400), file=sys.stderr)

        # 저장된 cls 를 쓰지 않고 다시 분류한다 — 분류기는 코드, 덤프는 데이터다.
        # 얼려 두면 분류기를 고쳐도 재수집 전까지 반영되지 않는다.
        rec = 0
        for e in events:
            tags = ([{"tag": incident.CLASS_TAG, "value": e["declared"]}]
                    if e.get("declared") else None)
            new_cls = incident.classify(e.get("name") or "", tags=tags,
                                        groups=e.get("groups"))
            if new_cls != e.get("cls"):
                rec += 1
            e["cls"] = new_cls
        if rec:
            print("[load] 현재 분류기로 재분류 — %d건 변경 (덤프 저장 시점 규칙과 다름)" % rec,
                  file=sys.stderr)
        failed = sorted(set(failed))
        if failed:
            print("⚠ %s 조회가 실패한 상태로 저장된 파일이 있다. 해당 소스가 낀 조합은"
                  " 없는 것이 아니라 측정되지 않은 것이다." % ", ".join(failed),
                  file=sys.stderr)
    else:
        events = []
        # 소스 하나가 안 닿았다고 전체를 죽이지 않는다. Zabbix 90일 조회를 끝낸 뒤
        # Wazuh 타임아웃으로 수집분을 통째로 잃는 일이 실제로 발생했다.
        # 다만 실패를 조용히 넘기면 "그 소스에 신호가 없었다"로 오독되므로 크게 남긴다.
        failed = []
        for want, fn in (("zabbix", lambda: asyncio.run(fetch_zabbix(a.days))),
                         ("wazuh", lambda: fetch_wazuh(a.days))):
            if a.source not in ("all", want):
                continue
            try:
                events += fn()
            except Exception as exc:
                failed.append(want)
                print("[%s] 조회 실패 — %s: %s" % (want, type(exc).__name__, exc),
                      file=sys.stderr)
        if failed:
            print("\n⚠ 조회에 실패한 소스: %s" % ", ".join(failed), file=sys.stderr)
            print("  이 소스가 낀 조합은 **없는 것이 아니라 측정되지 않은 것**이다.",
                  file=sys.stderr)
            print("  사설망 주소면 관제망 안에서 실행해야 한다.", file=sys.stderr)
        if not events:
            raise SystemExit("수집된 이벤트가 없다. 환경변수를 확인한다: python bot/probe.py env")

    if a.exclude or a.exclude_host:
        events = apply_exclusions(events, a.exclude, a.exclude_host)

    if a.dump:
        with open(a.dump, "w", encoding="utf-8") as f:
            json.dump({"fetched_at": _iso(datetime.now(timezone.utc).timestamp()),
                       "days": a.days, "source": a.source,
                       # 어느 소스가 실패했는지 파일에 남긴다. 안 남기면 나중에 --load 로
                       # 읽었을 때 "그 소스에 신호가 없었다"와 구분되지 않는다.
                       "failed_sources": failed,
                       "events": events},
                      f, ensure_ascii=False)
        print("[dump] %s — %d건 저장. 실 호스트명·알림명이 들어 있으므로 커밋하지 말 것."
              % (a.dump, len(events)), file=sys.stderr)

    if a.pair:
        av = resolve_axis_value(events, a.by, a.pair[0])
        bv = resolve_axis_value(events, a.by, a.pair[1])
        report_scope(events)
        report_pair(events, a.window, a.scope, a.by, av, bv, top=a.top, samples=a.samples)
        return

    if a.overlap:
        report_scope(events)
        res = overlap_counts(events, a.by, a.min_open)
        if not res:
            raise SystemExit(
                "해소 시각(end_ts)이 있는 이벤트가 없다. 재수집이 필요하다.\n"
                "  이 덤프는 r_eventid 조회를 넣기 전에 뜬 것이다. 새로 --dump 하면 채워진다.")
        if not a.null:
            raise SystemExit("--overlap 은 유의성 검정이 필요하다. --null 200 이상을 함께 지정한다.")
        obs = {k: v for k, v in res["pairs"].items()
               if v >= a.min_pairs and res["n_axis"][k[0]] >= a.min_axis
               and res["days"].get(k, 0) >= a.min_days
               and res["max_day_share"].get(k, 0) <= a.max_day_share}
        report_overlap(res, permute_overlap(events, obs, a.by, a.null, min_open_s=a.min_open),
                       a.fdr, a.min_axis, a.min_pairs, a.min_days, a.max_day_share,
                       top=a.top)
        if a.emit_rules:
            if a.by != "cls":
                raise SystemExit("--emit-rules 는 --by cls 에서만 쓴다. 게이트웨이가 "
                                 "사건 유형(class) 단위로 연계를 판정하기 때문이다.")
            picked = getattr(report_overlap, "picked", [])
            src = "+".join(a.load) if a.load else ("%d일 조회" % a.days)
            excl = (" / 제외: " + "|".join(a.exclude)) if a.exclude else ""
            emit_open_link_rules(res, picked, a.emit_rules,
                                 "%s / 창 %ds 이상 열림 / 최소 %d일 / 오탐율 %.0f%%%s"
                                 % (src, a.min_open, a.min_days, a.fdr * 100, excl))
        return

    if a.profile:
        report_scope(events)
        counts, n_axis = lag_counts(events, a.by, a.lag_max, a.lag_bins)
        observed = _profile_rows(counts, n_axis, a.min_axis, a.min_pairs)
        if not a.null:
            raise SystemExit("--profile 은 유의성 검정이 필요하다. --null 200 이상을 함께 지정한다.")
        perm = permute_profile(events, observed, a.by, a.lag_max, a.lag_bins,
                               a.min_axis, a.min_pairs, a.null)
        report_profile(counts, n_axis, observed, perm, a.lag_max, a.lag_bins,
                       a.fdr, top=a.top)
        return

    res = mine(events, a.window, a.min_pairs, a.min_lift,
               axis=a.by, min_axis=a.min_axis, scope=a.scope)
    if a.json:
        res["source_counts"] = dict(Counter(e.get("src") or "?" for e in events))
        print(json.dumps(res, ensure_ascii=False, indent=1))
    else:
        report_scope(events)
        report(res, incident.BRIDGE_GROUPS, a.min_pairs, a.min_lift, top=a.top)
        if a.null:
            # 음의 상관(우연보다 덜 붙는 쌍)은 브리지 후보가 아니다. 검정 대상에서 빼면
            # 다중 검정 부담도 함께 줄어 문턱이 내려간다.
            observed = {tuple(p["pair"]): p["leverage"]
                        for p in res["pairs"] if p["leverage"] > 0}
            perm = permute(events, observed, a.window, a.min_pairs, a.min_lift,
                           a.by, a.min_axis, a.scope, a.null)
            report_null(res, perm)
            report_fdr(res, perm, a.fdr, top=a.top)
            report_cliques(res, perm)
        # 태그·미분류 현황은 분류기 진단이라 cls 축에서만 의미가 있다.
        if a.by == "cls":
            report_declared_tags(events)
            report_unclassified(events)


if __name__ == "__main__":
    try:
        main()
    except RuntimeError as e:
        # 설정 실수에 스택을 붙이면 무엇을 고쳐야 하는지가 묻힌다.
        sys.exit(str(e))
