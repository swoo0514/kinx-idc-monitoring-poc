#!/usr/bin/env python3
"""MSP 월간 리포트 집계 — Keep 알림 이력에서 봇만 계산할 수 있는 값을 뽑아 Zabbix 로 보낸다.

왜 이 스크립트가 있나. 매니저 답변(B-7)상 팀은 Zabbix Scheduled report 를 이미 운용 중이다.
그래서 새 리포트 도구를 만들지 않는다. 대신 그 리포트가 그리는 대시보드에 **Zabbix 가
자체적으로는 낼 수 없는 값**을 넣는다.

  Zabbix 가 낼 수 있는 것 : 알림 수, 심각도 분포, 가용성
  Zabbix 가 못 내는 것    : 알림 N건 -> 사건 M건(병합), 만성/신규 판정, 조치 후보 이력

뒤쪽은 게이트웨이가 계산해 Keep 에 쌓아둔 값이다. 이 스크립트는 그것을 월 단위로 접어
Zabbix trapper 아이템으로 밀어 넣는다. 발송 파이프는 손대지 않는다.

  Keep API  ->  집계  ->  Zabbix trapper  ->  대시보드  ->  Scheduled report(기존)

읽기: Keep 은 GET /alerts (읽기 전용). 쓰기: Zabbix trapper 뿐이며 랩 전용이다.
sender 프로토콜은 공식 스펙(헤더 "ZBXD\\x01" + little-endian uint64 길이 + JSON).

사용법·전략은 ansible/DEPLOY_GUIDE.md "MSP 월간 리포트".
"""

import argparse
import json
import os
import socket
import struct
import sys
from collections import Counter
from datetime import datetime, timedelta, timezone

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass

BOT_SOURCE = "kinx-bot"
HOLMES_SOURCE = "holmesgpt"


def fetch_alerts(keep_url: str, api_key: str) -> list:
    import httpx
    r = httpx.get(f"{keep_url.rstrip('/')}/alerts",
                  headers={"x-api-key": api_key or "keep-noauth"}, timeout=30)
    r.raise_for_status()
    return r.json() or []


def _ts(a: dict) -> datetime:
    """lastReceived 를 aware datetime 으로. 파싱 실패는 매우 과거로 밀어 창 밖에 둔다."""
    raw = a.get("lastReceived") or a.get("firstTimestamp") or ""
    try:
        return datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
    except ValueError:
        return datetime.min.replace(tzinfo=timezone.utc)


def aggregate(alerts: list, days: int, host_filter: str = "") -> dict:
    """봇 알림만 사건으로 센다. Zabbix 가 직접 넣은 원시 알림은 사건이 아니다.

    분모를 섞지 않는 것이 중요하다 — "알림"은 사건에 병합된 원시 알림 수(alert_count)와
    분석을 생략한 저심각도 기록의 합이고, "사건"은 봇이 확정한 인시던트 수다.
    """
    since = datetime.now(timezone.utc) - timedelta(days=days)
    win = [a for a in alerts if _ts(a) >= since]
    if host_filter:
        win = [a for a in win if host_filter in (a.get("host") or "")]

    incidents = [a for a in win
                 if BOT_SOURCE in (a.get("source") or []) and a.get("prejudge")]
    lowsev = [a for a in win
              if BOT_SOURCE in (a.get("source") or []) and not a.get("prejudge")]
    # 조치 후보는 playbook 필드가 있는 것. "완료"가 아니라 "등록"이다 —
    # 실제 실행은 Keep 워크플로 기록이고 알림 레코드만으로는 알 수 없다.
    candidates = [a for a in win if a.get("playbook")]

    raw = sum(int(a.get("alert_count") or 1) for a in incidents) + len(lowsev)
    verdicts = Counter((a.get("prejudge") or "미상").strip() for a in incidents)
    classes = Counter()
    for a in incidents + lowsev:
        for c in str(a.get("classes") or "").split(","):
            if c.strip():
                classes[c.strip()] += 1
    repeat = Counter(a.get("name") or "(이름 없음)" for a in incidents
                     if (a.get("prejudge") or "") in ("만성", "재발"))

    return {
        "report.alerts": raw,
        "report.incidents": len(incidents),
        "report.chronic": verdicts.get("만성", 0),
        "report.novel": verdicts.get("신규", 0),
        "report.auto_candidates": len(candidates),
        "report.top_repeat": " / ".join(f"{n}({c}회)" for n, c in repeat.most_common(3))
                             or "반복 없음",
        "report.by_class": " / ".join(f"{c}:{n}" for c, n in classes.most_common(6))
                           or "분류 없음",
        "report.period": "%s ~ %s (%d일)" % (since.astimezone().strftime("%Y-%m-%d"),
                                             datetime.now().strftime("%Y-%m-%d"), days),
        "_holmes": len([a for a in win if HOLMES_SOURCE in (a.get("source") or [])]),
        "_window_alerts": len(win),
    }


def zbx_send(server: str, port: int, target_host: str, values: dict) -> dict:
    """Zabbix sender 프로토콜. 헤더 = "ZBXD" + \\x01 + 페이로드 길이(LE uint64)."""
    data = [{"host": target_host, "key": k, "value": str(v)}
            for k, v in values.items() if not k.startswith("_")]
    payload = json.dumps({"request": "sender data", "data": data}).encode("utf-8")
    packet = b"ZBXD\x01" + struct.pack("<Q", len(payload)) + payload
    with socket.create_connection((server, port), timeout=15) as s:
        s.sendall(packet)
        buf = b""
        while len(buf) < 13:
            chunk = s.recv(4096)
            if not chunk:
                break
            buf += chunk
        need = struct.unpack("<Q", buf[5:13])[0]
        while len(buf) < 13 + need:
            chunk = s.recv(4096)
            if not chunk:
                break
            buf += chunk
    return json.loads(buf[13:13 + need].decode("utf-8"))


def main():
    ap = argparse.ArgumentParser(description="MSP 월간 리포트 집계 (Keep 읽기 → Zabbix trapper)")
    ap.add_argument("--days", type=int, default=30)
    ap.add_argument("--host-filter", default="", help="이 문자열이 host 에 포함된 알림만")
    ap.add_argument("--target", help="값을 받을 Zabbix 호스트명 (예: report-Customer-B)")
    ap.add_argument("--send", action="store_true", help="실제 전송. 없으면 계산만(드라이런)")
    ap.add_argument("--keep-url", default=os.environ.get("KEEP_URL", ""))
    ap.add_argument("--zabbix-server", default=os.environ.get("ZBX_TRAPPER_HOST", "127.0.0.1"))
    ap.add_argument("--zabbix-port", type=int,
                    default=int(os.environ.get("ZBX_TRAPPER_PORT", "10051")))
    a = ap.parse_args()

    if not a.keep_url:
        sys.exit("[!] --keep-url 또는 환경변수 KEEP_URL 이 필요하다")
    alerts = fetch_alerts(a.keep_url, os.environ.get("KEEP_API_KEY", ""))
    res = aggregate(alerts, a.days, a.host_filter)

    print("=" * 62)
    print("MSP 월간 리포트 집계  (Keep %d건 조회, 창 안 %d건)" % (len(alerts), res["_window_alerts"]))
    print("=" * 62)
    for k, v in res.items():
        if not k.startswith("_"):
            print("  %-26s %s" % (k, v))
    if res["report.incidents"]:
        print("\n  압축률: 알림 %d건 → 사건 %d건 (%.1f:1)"
              % (res["report.alerts"], res["report.incidents"],
                 res["report.alerts"] / res["report.incidents"]))
    print("  심층조사(홈즈) %d건" % res["_holmes"])

    if not a.send:
        print("\n[드라이런] 전송하지 않았다. 보내려면 --send --target <호스트명>")
        return
    if not a.target:
        sys.exit("[!] --send 에는 --target 이 필요하다")
    r = zbx_send(a.zabbix_server, a.zabbix_port, a.target, res)
    print("\n[send] %s -> %s" % (a.target, r.get("info", r)))
    # Zabbix 는 실패해도 HTTP 200 대신 info 문자열로 알린다 — failed 를 눈으로 봐야 한다.
    if "failed: 0" not in str(r.get("info", "")):
        print("[!] failed 가 0 이 아니다 — 아이템 키·호스트명 불일치 가능. 위 info 확인.")


if __name__ == "__main__":
    main()
