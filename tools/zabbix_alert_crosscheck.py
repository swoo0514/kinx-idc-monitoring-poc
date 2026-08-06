#!/usr/bin/env python3
"""alert.get 교차 검산 — 미디어별×상태별 집계 + 실패 사유 + 시도 시점 범위 (읽기 전용)

발송 결과 교차 검산용. 사용법은 tools/RECON_GUIDE.md. 이 1콜로 확정되는 것:
  1) 발송 성공분이 어느 미디어에서 나온 것인지 (미디어×상태 교차표)
  2) Pushover-script 실패의 사유 (error 필드 — "미디어 비활성" vs 스크립트 실행 실패)
  3) 미디어별 최초/최종 시도 시각 — 시도가 언제 끊겼는지

사용법은 기존 정찰 스크립트와 동일:
  (PowerShell)  $env:ZABBIX_URL="..."; $env:ZABBIX_TOKEN="..."
  python tools/zabbix_alert_crosscheck.py [--days 30]

주의: error 필드에 스크립트 stderr가 담겨 웹훅 URL 등이 섞일 수 있음 —
출력을 저장한다면 private/ 아래에만 둘 것.
API 근거: https://www.zabbix.com/documentation/7.0/en/manual/api/reference/alert/object
(status: 0=미발송, 1=발송 성공, 2=재시도 후 실패, 3=미처리 신규 / error: 발송 실패 사유)
"""
import argparse
import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.request
from collections import Counter, defaultdict
from datetime import datetime

STATUS_NAMES = {"0": "미발송", "1": "발송 성공", "2": "발송 실패", "3": "신규(미처리)"}


def api_call(url, token, method, params, timeout=60, insecure=False):
    # 작업 원칙 4 를 코드로 강제한다(독스트링의 "읽기 전용"은 보증이 아니다).
    if not method.endswith(".get"):
        raise RuntimeError("read-only violation: %s — 이 도구는 .get 만 호출한다" % method)
    if not url.rstrip("/").endswith("api_jsonrpc.php"):
        url = url.rstrip("/") + "/api_jsonrpc.php"
    payload = {"jsonrpc": "2.0", "method": method, "params": params, "id": 1}
    headers = {
        "Content-Type": "application/json-rpc",
        "Authorization": "Bearer " + token,
    }
    ctx = ssl._create_unverified_context() if insecure else None
    req = urllib.request.Request(url, json.dumps(payload).encode("utf-8"), headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            body = json.loads(resp.read().decode("utf-8"))
    except urllib.error.URLError as e:
        sys.exit("[!] 접속 실패: %s" % e)
    if "error" in body:
        sys.exit("[!] API 오류: %s" % json.dumps(body["error"], ensure_ascii=False))
    return body["result"]


def ts(clock):
    return datetime.fromtimestamp(int(clock)).strftime("%m-%d %H:%M")


def main():
    for s in (sys.stdout, sys.stderr):
        try:
            s.reconfigure(encoding="utf-8", errors="replace")
        except AttributeError:
            pass

    ap = argparse.ArgumentParser(description="발송 알림 미디어별 교차 검산 (읽기 전용)")
    ap.add_argument("--url", default=os.environ.get("ZABBIX_URL"))
    ap.add_argument("--token", default=os.environ.get("ZABBIX_TOKEN"))
    ap.add_argument("--days", type=int, default=30)
    ap.add_argument("--limit", type=int, default=20000)
    ap.add_argument("--insecure", action="store_true", help="TLS 인증서 검증 생략")
    args = ap.parse_args()
    if not args.url or not args.token:
        sys.exit("[!] ZABBIX_URL / ZABBIX_TOKEN 환경변수 또는 --url/--token 필요")

    mtypes = {m["mediatypeid"]: m["name"] for m in api_call(
        args.url, args.token, "mediatype.get",
        {"output": ["mediatypeid", "name"]}, insecure=args.insecure)}

    alerts = api_call(args.url, args.token, "alert.get", {
        "output": ["alertid", "clock", "mediatypeid", "status", "error", "retries", "alerttype"],
        "time_from": int(time.time()) - args.days * 86400,
        "sortfield": "clock", "sortorder": "DESC",
        "limit": args.limit,
    }, insecure=args.insecure)
    alerts = [a for a in alerts if str(a.get("alerttype", "0")) == "0"]  # 메시지만

    if len(alerts) >= args.limit:
        print("[주의] 조회 한도 %d건 도달 — 최신 우선이므로 오래된 구간이 잘렸을 수 있음" % args.limit)
    print("총 %d건 (%d일)" % (len(alerts), args.days))
    print()

    cross = Counter()               # (media, status) -> count
    errors = defaultdict(Counter)   # media -> error text -> count
    span = {}                       # media -> [min_clock, max_clock]
    for a in alerts:
        m = mtypes.get(str(a.get("mediatypeid")), "mediatypeid=%s" % a.get("mediatypeid"))
        st = str(a.get("status"))
        cross[(m, st)] += 1
        if st == "2" and a.get("error"):
            errors[m][a["error"][:120]] += 1
        c = int(a["clock"])
        if m not in span:
            span[m] = [c, c]
        else:
            span[m][0] = min(span[m][0], c)
            span[m][1] = max(span[m][1], c)

    print("| 미디어 타입 | 상태 | 건수 |")
    print("|---|---|---:|")
    for (m, st), cnt in sorted(cross.items(), key=lambda x: -x[1]):
        print("| %s | %s | %d |" % (m, STATUS_NAMES.get(st, "status=%s" % st), cnt))

    print()
    print("| 미디어 타입 | 최초 시도 | 최종 시도 |")
    print("|---|---|---|")
    for m, (lo, hi) in sorted(span.items()):
        print("| %s | %s | %s |" % (m, ts(lo), ts(hi)))

    print()
    print("실패 사유 Top (미디어별, error 필드 앞 120자):")
    for m, cnt in errors.items():
        print("- %s:" % m)
        for e, c in cnt.most_common(3):
            print("    [%d건] %s" % (c, e))


if __name__ == "__main__":
    main()
