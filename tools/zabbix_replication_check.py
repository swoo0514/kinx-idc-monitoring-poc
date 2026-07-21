#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
zabbix_replication_check.py — DB 복제 감시가 "상태 플래그(켜짐/꺼짐)"인지
"지연(몇 초 뒤처졌나)"인지 확인 (읽기 전용)

배경
  커스텀 아이템 `mysql.replication.status` 12개가 있으나, 이름만으로는 복제가
  돌아가는지(예/아니오)만 보는지 몇 초 밀렸는지(Seconds_Behind_Master)까지 보는지
  구분되지 않는다. 또 Zabbix 기본 MySQL 템플릿은 지연 아이템을 원래 포함하므로,
  기본 템플릿 경유로 이미 지연을 보고 있을 수 있다. 이 스크립트는 그 두 가지를
  아이템 정의(자료형/단위)와 최근 수집값으로 판별해, "복제 지연을 이미 보고 있나"를
  발표 전에 확정하기 위한 근거를 모은다.

판별 원리
  - 단위가 `s` 또는 자료형이 float 이고 값이 오르내리면 → 지연(초)
  - 값이 0/1 정수로 고정이면 → 상태 플래그(켜짐/꺼짐)
  - 유래(호스트 직접 정의 vs 템플릿 상속)도 함께 표시해, 커스텀 12개와 기본 템플릿
    아이템을 구분한다.

읽기 전용
  item.get / history.get 만 호출한다. 쓰기·설정 변경 API는 일절 호출하지 않는다.

사용
  export ZABBIX_URL="https://zabbix.internal/zabbix"
  export ZABBIX_TOKEN="****"
  python3 zabbix_replication_check.py --insecure --history -o repl_check_infra.md
  # MSP 세트는 해당 URL/토큰으로 따로 한 번 더 실행

주의: 출력에 실제 호스트명이 포함되므로 결과 파일은 커밋하지 말고 private/ 에 보관한다.
"""
import argparse
import os
import sys
from datetime import datetime

try:
    # 같은 tools/ 폴더의 검증된 JSON-RPC 클라이언트를 재사용 (인증·버전 호환 로직 공유)
    from zabbix_snapshot import ZabbixAPI, ZabbixAPIError, mask_ips
except ImportError:
    sys.exit("[!] 같은 tools/ 폴더의 zabbix_snapshot.py 가 필요합니다 (tools/ 안에서 실행).")

VTYPE = {"0": "float", "1": "char", "2": "log", "3": "uint", "4": "text"}

# 복제 아이템을 찾을 검색어. key_ 와 name 을 각각 부분일치로 조회한 뒤 itemid 로 중복 제거.
KEY_KEYWORDS = ["replication", "slave", "behind", "seconds_behind", "gtid", "repl"]
NAME_KEYWORDS = ["복제", "replication", "Seconds_Behind", "slave"]


def fetch_items(api):
    seen = {}
    base = {
        "output": ["itemid", "name", "key_", "value_type", "units",
                   "lastvalue", "lastclock", "status", "templateid"],
        "selectHosts": ["name"],
        "sortfield": ["key_"],
        "limit": 3000,
    }
    for kw in KEY_KEYWORDS:
        for it in api.call("item.get", dict(base, search={"key_": kw})):
            seen[it["itemid"]] = it
    for kw in NAME_KEYWORDS:
        for it in api.call("item.get", dict(base, search={"name": kw})):
            seen[it["itemid"]] = it
    return list(seen.values())


def classify(it):
    """정의(단위/자료형)와 최근값으로 '지연(초)'인지 '상태 플래그'인지 힌트를 낸다."""
    units = (it.get("units") or "").strip()
    vt = it.get("value_type")
    lv = it.get("lastvalue")
    if units in ("s", "uptime"):
        return "▶ 지연(초) 후보 — 단위=%s" % units
    if units:
        return "값 있음 — 단위=%s" % units
    if vt == "0":
        return "▶ 지연/연속값 후보 (float, 단위 없음)"
    if lv in ("0", "1"):
        return "○ 상태 플래그 후보 (값=%s)" % lv
    if vt == "1":
        return "문자값 — 최근값·추이 확인 필요"
    return "판별 필요 — 최근값·추이 확인"


def fmt_clock(c):
    try:
        c = int(c)
    except (TypeError, ValueError):
        return "-"
    return "미수집" if c == 0 else datetime.fromtimestamp(c).strftime("%m-%d %H:%M")


def build(api, args):
    L = []
    items = fetch_items(api)
    L.append("# 복제 감시 방식 확인 — 상태 플래그 vs 지연(초)")
    L.append("")
    L.append("- 생성 %s / Zabbix %s / 복제 관련 아이템 %d개"
             % (datetime.now().strftime("%Y-%m-%d %H:%M"), api.version, len(items)))
    L.append("- 판별: 단위 `s` 또는 float 이면서 값이 오르내리면 **지연(초)**, "
             "값이 0/1 정수로 고정이면 **상태 플래그**. 유래로 커스텀/기본템플릿 구분.")
    L.append("")
    if not items:
        L.append("복제 관련 아이템이 조회되지 않음 (검색어에 걸리는 키/이름 없음). "
                 "API 계정 권한 범위도 함께 확인하세요.")
        return "\n".join(L)

    L.append("| 호스트 | 키 | 이름 | 자료형 | 단위 | 최근값 | 수집시각 | 상태 | 유래 | 힌트 |")
    L.append("|---|---|---|---|---|---|---|---|---|---|")
    lag_like = flag_like = 0
    for it in sorted(items, key=lambda x: (x["hosts"][0]["name"] if x.get("hosts") else "",
                                           x.get("key_", ""))):
        host = it["hosts"][0]["name"] if it.get("hosts") else "-"
        hint = classify(it)
        if hint.startswith("▶"):
            lag_like += 1
        elif hint.startswith("○"):
            flag_like += 1
        origin = "호스트직접" if str(it.get("templateid") or "0") == "0" else "템플릿상속"
        status = "사용" if str(it.get("status")) == "0" else "비활성"
        lv = it.get("lastvalue")
        lv = "-" if lv is None else str(lv)
        if len(lv) > 24:
            lv = lv[:24] + "…"
        L.append("| %s | `%s` | %s | %s | %s | %s | %s | %s | %s | %s |" % (
            host, it.get("key_", ""), (it.get("name") or "").replace("|", "/"),
            VTYPE.get(it.get("value_type"), it.get("value_type")),
            it.get("units") or "-", lv, fmt_clock(it.get("lastclock")),
            status, origin, hint))
    L.append("")
    L.append("## 요약")
    L.append("")
    L.append("- 지연(초) 후보 **%d개** / 상태 플래그 후보 **%d개** / 나머지 %d개는 최근값 확인 필요"
             % (lag_like, flag_like, len(items) - lag_like - flag_like))
    L.append("- **지연(초) 후보가 있고 값이 실제로 오르내리면** → 복제 지연을 이미 보고 있음 "
             "= 복제 데모의 '약점' 전제 재검토 필요.")
    L.append("- **지연 후보가 없고 상태 플래그만이면** → 복제 지연은 미감시 "
             "= 복제 데모 근거 성립.")
    L.append("")

    if args.history:
        L.append("## 최근값 추이 (값이 변하면 지연, 고정이면 상태 플래그)")
        L.append("")
        for it in items:
            if str(it.get("lastclock") or "0") == "0":
                continue
            try:
                h = api.call("history.get", {
                    "itemids": [it["itemid"]], "history": int(it.get("value_type") or 0),
                    "sortfield": "clock", "sortorder": "DESC", "limit": 8,
                })
            except (ZabbixAPIError, ValueError):
                continue
            host = it["hosts"][0]["name"] if it.get("hosts") else "-"
            vals = ", ".join(str(x.get("value")) for x in h)
            L.append("- `%s` @ %s → %s" % (it.get("key_", ""), host, vals or "(이력 없음)"))
        L.append("")
    return "\n".join(L)


def main():
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except AttributeError:
            pass
    ap = argparse.ArgumentParser(
        description="DB 복제 감시가 상태 플래그인지 지연(초)인지 확인 (읽기 전용)")
    ap.add_argument("--url", default=os.environ.get("ZABBIX_URL"))
    ap.add_argument("--token", default=os.environ.get("ZABBIX_TOKEN"))
    ap.add_argument("--user", default=os.environ.get("ZABBIX_USER"))
    ap.add_argument("--password", default=os.environ.get("ZABBIX_PASSWORD"))
    ap.add_argument("--history", action="store_true", help="각 아이템 최근값 8개 추이까지 조회")
    ap.add_argument("--mask-ip", action="store_true", help="출력의 IPv4를 IP-NNN 으로 치환")
    ap.add_argument("--insecure", action="store_true", help="TLS 검증 생략 (자체서명 인증서)")
    ap.add_argument("-o", "--output", default="zabbix_replication_check.md")
    args = ap.parse_args()

    if not args.url:
        sys.exit("[!] --url 또는 환경변수 ZABBIX_URL 이 필요합니다.")
    if not args.token and not (args.user and args.password):
        sys.exit("[!] --token(권장) 또는 --user/--password 가 필요합니다.")
    try:
        api = ZabbixAPI(args.url, insecure=args.insecure)
        print("[*] Zabbix %s 연결 — 복제 아이템 조회 중..." % api.version, file=sys.stderr)
        api.login(token=args.token, user=args.user, password=args.password)
        report = build(api, args)
        if args.mask_ip:
            report = mask_ips(report)
    except ZabbixAPIError as e:
        sys.exit("[오류] %s" % e)
    with open(args.output, "w", encoding="utf-8") as f:
        f.write(report)
    print(report)
    print("\n[*] 저장: %s — 결과는 private/ 에 보관(커밋 금지)" % args.output, file=sys.stderr)


if __name__ == "__main__":
    main()
