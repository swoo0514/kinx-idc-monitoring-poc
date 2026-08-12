"""판정 품질 산출. 지표 정의와 정직성 기준은 bot/GATEWAY_GUIDE.md §25-5.

  python -m gateway.quality --days 30
  python -m gateway.quality --days 30 --send --target quality-bot
"""

import argparse
import math
import os
import time

from . import store

# 이 아래로는 백분율을 만들지 않는다. 표본이 적으면 숫자가 아니라 상태를 낸다.
MIN_LABELS = int(os.environ.get("QUALITY_MIN_LABELS", "20"))
# 같은 호스트에서 이 안에 갈라져 열린 사건은 병합 후보다. 인시던트 최대 창과 같은 값.
SPLIT_WINDOW_S = float(os.environ.get("INCIDENT_MAX_WINDOW_S", "300"))
AXES = ("overall", "gate", "merge", "cause")
NOT_MEASURED = "판정 불가"


def wilson(k: int, n: int, z: float = 1.96) -> tuple:
    """비율의 95% 신뢰구간. 9/10 은 90%가 아니라 90%±폭이다."""
    if not n:
        return None
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    m = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (max(0.0, c - m), min(1.0, c + m))


def _quantile(vals: list, q: float) -> float:
    if not vals:
        return 0.0
    s = sorted(vals)
    i = min(len(s) - 1, int(round(q * (len(s) - 1))))
    return s[i]


def _split_incidents(rows: list) -> int:
    """같은 호스트에서 창 안에 서로 다른 지문으로 갈라진 사건 수 (§25-5)."""
    by_host = {}
    for r in rows:
        if r.get("event_ts"):
            by_host.setdefault((r.get("realm"), r.get("host")), []).append(r)
    n = 0
    for group in by_host.values():
        group.sort(key=lambda r: r["event_ts"])
        for i in range(1, len(group)):
            prev, cur = group[i - 1], group[i]
            if (cur["event_ts"] - prev["event_ts"] <= SPLIT_WINDOW_S
                    and cur.get("fingerprint") != prev.get("fingerprint")):
                n += 1
    return n


def collect(days: int = 30, now: float = None) -> dict:
    now = time.time() if now is None else now
    since = now - days * 86400
    all_rows = store.judgments(since=since, now=now, limit=100000)
    rows = [r for r in all_rows if (r.get("origin") or "auto") == "auto"]
    forced = len(all_rows) - len(rows)
    n = len(rows)

    lat = [r["total_s"] for r in rows if r.get("total_s") is not None]
    fired = [r for r in rows if r.get("gate_fired")]
    changes = [r["change"] for r in rows if r.get("change")]
    sizes = {}
    for r in rows:
        k = min(3, int(r.get("alert_count") or 1))
        sizes["%d건" % k if k < 3 else "3건+"] = sizes.get(
            "%d건" % k if k < 3 else "3건+", 0) + 1

    axis_ok = {}
    labels = store.labels_for([r["id"] for r in rows])
    for axis in AXES:
        marks = [v[axis]["ok"] for v in labels.values() if axis in v]
        axis_ok[axis] = {"n": len(marks), "ok": sum(1 for x in marks if x),
                         "rate": None, "ci": None}
        if len(marks) >= MIN_LABELS:
            axis_ok[axis]["rate"] = axis_ok[axis]["ok"] / len(marks)
            axis_ok[axis]["ci"] = wilson(axis_ok[axis]["ok"], len(marks))

    src = {}
    for r in rows:
        for part in (r.get("sources") or "").split(","):
            if ":" in part:
                k, v = part.split(":", 1)
                d = src.setdefault(k, {"ok": 0, "total": 0})
                d["total"] += 1
                d["ok"] += 1 if v == "ok" else 0

    routes = store.routes(since=since, now=now)
    route_mix = {}
    for r in routes:
        route_mix[r.get("route") or "미상"] = route_mix.get(r.get("route") or "미상", 0) + 1

    return {
        "days": days, "now": now, "judgments": n, "forced": forced,
        "labeled": len(labels),
        "gate_fire_rate": (len(fired) / n) if n else None,
        "merge_sizes": sizes,
        "degraded_rate": (sum(1 for r in rows if r.get("degraded")) / n) if n else None,
        "latency": {"n": len(lat), "excluded": n - len(lat),
                    "p50": _quantile(lat, 0.5), "p90": _quantile(lat, 0.9),
                    "max": max(lat) if lat else 0.0},
        "annotation_rate": (sum(1 for r in fired if r.get("annotation_id")) / len(fired))
                           if fired else None,
        "same_rate": (sum(1 for c in changes if "동일" in c) / len(changes))
                     if changes else None,
        "same_n": len(changes),
        "split_incidents": _split_incidents(rows),
        "sources": src, "routes": route_mix,
        "route_dup": sum(1 for r in routes if r.get("dup")),
        "route_total": len(routes),
        "accuracy": axis_ok,
    }


def _pct(x) -> str:
    return "%.1f%%" % (100.0 * x) if x is not None else "미산출"


def render_accuracy(m: dict) -> str:
    """라벨이 있어야 성립하는 값만. 표본이 모자라면 백분율 문자열을 만들지 않는다."""
    out = ["[정확도 — 사람 라벨 필요]"]
    for axis in AXES:
        a = m["accuracy"][axis]
        if a["rate"] is None:
            out.append("  %-8s %s (라벨 %d/%d, 최소 %d)"
                       % (axis, NOT_MEASURED, a["n"], m["judgments"], MIN_LABELS))
        else:
            lo, hi = a["ci"]
            out.append("  %-8s %.1f%% (%d/%d, 95%% CI %.1f–%.1f)"
                       % (axis, 100.0 * a["rate"], a["ok"], a["n"],
                          100.0 * lo, 100.0 * hi))
    out.append("  조치 성공률  미확인 — 봇 판정 이력에 조치 결과가 회수되지 않는다."
               " Keep 실행 이력 API 경유 가능성은 미확인")
    return "\n".join(out)


def render(m: dict) -> str:
    ts = time.strftime("%Y-%m-%d %H:%M", time.localtime(m["now"]))
    head = ("판정 품질 — 창 %d일 · 판정 %d건(강제 재분석 %d건 제외) · 라벨 %d건 · 산출 %s"
            % (m["days"], m["judgments"], m["forced"], m["labeled"], ts))
    lat = m["latency"]
    body = [
        head, "=" * len(head),
        "[관측 — 라벨 없이 산출. 정확도 주장이 아니다]",
        "  게이트 발동률   %s" % _pct(m["gate_fire_rate"]),
        "  병합 규모       %s" % (", ".join("%s %d" % (k, v)
                                        for k, v in sorted(m["merge_sizes"].items()))
                                or "없음"),
        "  열화율          %s" % _pct(m["degraded_rate"]),
        "  응답시간        p50 %.1fs · p90 %.1fs · 최대 %.1fs (%d건, 값 없는 %d건 제외)"
        % (lat["p50"], lat["p90"], lat["max"], lat["n"], lat["excluded"]),
        "  주석 발행률     %s" % _pct(m["annotation_rate"]),
        "  '동일' 응답     %s (%d건) — 100%% 로 수렴하면 과거 결론을 되풀이하는 것이다"
        % (_pct(m["same_rate"]), m["same_n"]),
        "  동시 발생 분할  %d건 (병합 후보. 오류 수가 아니다)" % m["split_incidents"],
        "  라우팅          %s / 중복 %d of %d"
        % (", ".join("%s %d" % (k, v) for k, v in sorted(m["routes"].items())) or "없음",
           m["route_dup"], m["route_total"]),
        "  축 커버리지     %s"
        % (", ".join("%s %d/%d" % (k, v["ok"], v["total"])
                     for k, v in sorted(m["sources"].items())) or "없음"),
        "",
        render_accuracy(m),
    ]
    return "\n".join(body)


def trapper_values(m: dict) -> dict:
    """Zabbix trapper 로 보낼 값. 키는 ansible/quality_metrics.yml 과 문자 단위로 같아야 한다."""
    lat = m["latency"]
    v = {"quality.judgments": m["judgments"],
         "quality.labeled": m["labeled"],
         "quality.gate_fire_rate": round(100.0 * (m["gate_fire_rate"] or 0), 1),
         "quality.degraded_rate": round(100.0 * (m["degraded_rate"] or 0), 1),
         "quality.latency_p50": round(lat["p50"], 1),
         "quality.latency_p90": round(lat["p90"], 1),
         "quality.split_incidents": m["split_incidents"],
         "quality.annotation_rate": round(100.0 * (m["annotation_rate"] or 0), 1)}
    for axis in AXES:
        a = m["accuracy"][axis]
        # 산출 안 된 것과 0% 를 구분한다. 안 보내면 지난 값이 화면에 남는다.
        v["quality.acc_" + axis] = (round(100.0 * a["rate"], 1)
                                    if a["rate"] is not None else -1)
    return v


def main() -> int:
    ap = argparse.ArgumentParser(description="판정 품질 산출")
    ap.add_argument("--days", type=int, default=30)
    ap.add_argument("--send", action="store_true", help="Zabbix trapper 로 전송")
    ap.add_argument("--target", default=os.environ.get("QUALITY_TARGET_HOST",
                                                       "quality-bot"))
    # 기본값을 msp_report.py 와 맞춘다 — 랩에서 감시 서버가 같은 기계에 떠 있다.
    ap.add_argument("--zabbix-server",
                    default=os.environ.get("ZBX_TRAPPER_HOST", "127.0.0.1"))
    ap.add_argument("--zabbix-port", type=int,
                    default=int(os.environ.get("ZBX_TRAPPER_PORT", "10051")))
    a = ap.parse_args()

    if not store.init():
        print("판정 이력 저장소를 열지 못했다: %s" % store.status().get("error"))
        return 3
    m = collect(days=a.days)
    print(render(m))
    if a.send:
        if not a.zabbix_server:
            print("보낼 곳이 없다 — ZBX_TRAPPER_HOST 를 지정한다")
            return 2
        import sys
        sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        from msp_report import zbx_send
        print(zbx_send(a.zabbix_server, a.zabbix_port, a.target, trapper_values(m)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
