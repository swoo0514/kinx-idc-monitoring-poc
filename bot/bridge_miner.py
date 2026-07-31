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
import itertools
import json
import os
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from gateway import collector, incident  # noqa: E402

DEFAULT_DAYS = 90
DEFAULT_WINDOW_S = 600      # 같은 사건으로 볼 시간창. 게이트웨이 디바운스보다 넉넉하게.
DEFAULT_MIN_PAIRS = 5       # 이 미만은 우연으로 본다
DEFAULT_MIN_LIFT = 2.0      # 독립 가정 대비 몇 배로 함께 나오는가


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%d %H:%M")


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
    async with httpx.AsyncClient(verify=False) as client:
        events = await zbx.call(client, "event.get", {
            "output": ["eventid", "name", "clock", "severity"],
            "selectHosts": ["host"],
            "selectTags": "extend",
            "time_from": since,
            "value": 1,
            "sortfield": "clock",
            "sortorder": "ASC",
            "limit": 200000,
        })
    out = []
    for e in events or []:
        hosts = e.get("hosts") or []
        host = (hosts[0] or {}).get("host", "") if hosts else ""
        if not host:
            continue
        name = e.get("name", "")
        out.append({"host": host, "cls": incident.classify(name, tags=e.get("tags")),
                    "ts": int(e.get("clock", 0)), "name": name, "src": "zabbix"})
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
    with httpx.Client(verify=False, timeout=30) as c:
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
            out.append({"host": host, "cls": cls, "ts": epoch, "name": name, "src": "wazuh"})
    print("[wazuh] 알림 %d건 → 분류 완료" % len(out), file=sys.stderr)
    return out


def mine(events: list, window_s: int, min_pairs: int, min_lift: float) -> dict:
    """호스트별 시간창 안에서 함께 나온 class 쌍의 lift 를 계산한다.

    lift = P(A와 B가 같은 창에) / (P(A) x P(B))
    독립이면 1. 1보다 크면 우연보다 자주 함께 나온다는 뜻이다.
    """
    by_host = defaultdict(list)
    for e in events:
        by_host[e["host"]].append((e["ts"], e["cls"]))

    windows = []              # 각 창에 등장한 class 집합
    for host, seq in by_host.items():
        seq.sort()
        i = 0
        while i < len(seq):
            start = seq[i][0]
            bucket, j = set(), i
            while j < len(seq) and seq[j][0] - start <= window_s:
                bucket.add(seq[j][1]); j += 1
            windows.append((host, start, bucket))
            i = j                       # 겹치지 않는 창 (같은 이벤트를 두 번 세지 않는다)

    n = len(windows)
    if n == 0:
        return {"windows": 0, "pairs": [], "singles": {}}

    single = Counter()
    pair = Counter()
    pair_hosts = defaultdict(set)
    for host, _start, bucket in windows:
        for c in bucket:
            single[c] += 1
        for a, b in itertools.combinations(sorted(bucket), 2):
            pair[(a, b)] += 1
            pair_hosts[(a, b)].add(host)

    rows = []
    for (a, b), cnt in pair.items():
        p_a, p_b, p_ab = single[a] / n, single[b] / n, cnt / n
        lift = p_ab / (p_a * p_b) if p_a and p_b else 0.0
        # 조건부 확률도 같이 낸다 — lift 만 보면 희귀 쌍이 과대평가된다.
        rows.append({
            "pair": [a, b], "together": cnt,
            "a_windows": single[a], "b_windows": single[b],
            "lift": round(lift, 2),
            "p_b_given_a": round(cnt / single[a], 3) if single[a] else 0.0,
            "p_a_given_b": round(cnt / single[b], 3) if single[b] else 0.0,
            "hosts": len(pair_hosts[(a, b)]),
        })
    rows.sort(key=lambda r: (-r["together"], -r["lift"]))
    recommended = [r for r in rows
                   if r["together"] >= min_pairs and r["lift"] >= min_lift
                   and "other" not in r["pair"]]
    return {"windows": n, "pairs": rows, "recommended": recommended,
            "singles": dict(single.most_common())}


def report(res: dict, existing: list, min_pairs: int, min_lift: float):
    print()
    print("=" * 78)
    print("브리지 후보 마이닝 결과")
    print("=" * 78)
    print("시간창 수: %d   (겹치지 않는 창, 호스트별)" % res["windows"])
    if not res["windows"]:
        print("데이터가 없다. 환경변수와 기간을 확인한다.")
        return

    print()
    print("[ 축별 등장 창 수 ]")
    for cls, cnt in res["singles"].items():
        print("  %-16s %6d  (%.1f%%)" % (cls, cnt, 100 * cnt / res["windows"]))

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

    print()
    print("[ 추천 후보 (together>=%d, lift>=%.1f, other 제외) ]" % (min_pairs, min_lift))
    cur = {tuple(sorted(g)) for g in existing}
    if not res["recommended"]:
        print("  없음")
    for r in res["recommended"]:
        mark = "이미 반영" if tuple(sorted(r["pair"])) in cur else "신규"
        print("  %-34s together=%-5d lift=%-6s P(B|A)=%-5s hosts=%-3d [%s]"
              % ("%s + %s" % tuple(r["pair"]), r["together"], r["lift"],
                 r["p_b_given_a"], r["hosts"], mark))

    print()
    print("해석 주의")
    print("  - lift 가 높아도 together 가 작으면 우연이다. 둘을 함께 본다.")
    print("  - 상관은 인과가 아니다. 추천은 '검토 대상'이고 브리지 확정은 사람이 한다.")
    print("  - hosts 가 1이면 특정 호스트 사정일 수 있다. 여러 호스트에서 보이는 쌍이 강하다.")
    print("  - other 는 분류 실패 묶음이라 제외한다. other 비중이 크면 분류기를 먼저 고친다.")


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
    ap.add_argument("--json", action="store_true", help="원시 결과를 stdout 에 JSON 으로")
    ap.add_argument("--source", choices=["all", "zabbix", "wazuh"], default="all")
    ap.add_argument("--dump", metavar="FILE",
                    help="조회 결과를 파일로 저장(실 호스트명·알림명 포함 — private/ 에만 둘 것)")
    ap.add_argument("--load", metavar="FILE",
                    help="조회 대신 파일에서 읽는다. 창·임계값을 바꿔가며 재분석할 때 쓴다")
    a = ap.parse_args()

    if a.load:
        with open(a.load, encoding="utf-8") as f:
            saved = json.load(f)
        events = saved["events"]
        print("[load] %s — %d건 (수집 %s, --days %s)"
              % (a.load, len(events), saved.get("fetched_at", "?"), saved.get("days", "?")),
              file=sys.stderr)
    else:
        events = []
        if a.source in ("all", "zabbix"):
            events += asyncio.run(fetch_zabbix(a.days))
        if a.source in ("all", "wazuh"):
            events += fetch_wazuh(a.days)

    if a.dump:
        with open(a.dump, "w", encoding="utf-8") as f:
            json.dump({"fetched_at": _iso(datetime.now(timezone.utc).timestamp()),
                       "days": a.days, "source": a.source, "events": events},
                      f, ensure_ascii=False)
        print("[dump] %s — %d건 저장. 실 호스트명·알림명이 들어 있으므로 커밋하지 말 것."
              % (a.dump, len(events)), file=sys.stderr)

    res = mine(events, a.window, a.min_pairs, a.min_lift)
    if a.json:
        print(json.dumps(res, ensure_ascii=False, indent=1))
    else:
        report(res, incident.BRIDGE_GROUPS, a.min_pairs, a.min_lift)
        report_unclassified(events)


if __name__ == "__main__":
    main()
