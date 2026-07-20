#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
zabbix_serverstats.py — 인터뷰 없이 API로 자가 확인 가능한 항목 수집 (읽기 전용)

수집 내용 (전부 .get 호출만 사용)
  1) NVPS: zabbix[requiredperformance] / zabbix[wcache,values*] 내부 아이템의 최근 값
  2) 프록시 사용 여부: proxy.get + host.get의 프록시 배정 필드 집계
  3) 알림 라우팅(권한 되면): action.get으로 트리거 액션의 심각도 조건·통보 대상
     (읽기 전용 계정은 권한 부족일 수 있음 — 실패해도 나머지는 정상 출력)
  4) 실제 발송된 알림: alert.get으로 최근 N일 발송 건수·성공/실패·미디어 타입별 집계
     — Problem 이벤트 수(트리거 발화)와 실제 통보량의 차이를 확정하는 핵심 수치

사용 예
  export ZABBIX_URL=... ZABBIX_TOKEN=...
  python3 zabbix_serverstats.py [--insecure] [-o private/serverstats.md]
"""
import argparse
import os
import sys
from collections import Counter
from datetime import datetime, timedelta

from zabbix_snapshot import ZabbixAPI, ZabbixAPIError, mask_ips  # 같은 폴더의 클라이언트 재사용

NVPS_KEYS = [
    "zabbix[requiredperformance]",   # 서버가 계산한 필요 NVPS
    "zabbix[wcache,values]",         # 실제 초당 처리 값 수
    "zabbix[wcache,values,float]",
    "zabbix[wcache,values,uint]",   # 유효 mode: all/float/uint/str/log/text/bin/json
]


def section_nvps(api, L):
    L.append("## 1. NVPS (Zabbix 내부 아이템)")
    L.append("")
    items = api.call("item.get", {
        "output": ["itemid", "hostid", "name", "key_", "lastvalue", "lastclock", "value_type"],
        "filter": {"key_": NVPS_KEYS},
        "selectHosts": ["name"],
    })
    if not items:
        L.append("- 내부 아이템 미발견 — Template App Zabbix Server가 이 계정 권한 범위 밖이거나 미연결")
        L.append("")
        return
    L.append("| 호스트 | 아이템 | 키 | 최근 값 | 수집 시각 |")
    L.append("|---|---|---|---:|---|")
    for it in items:
        host = it["hosts"][0]["name"] if it.get("hosts") else "-"
        ts = it.get("lastclock")
        when = (datetime.fromtimestamp(int(ts)).strftime("%m-%d %H:%M")
                if ts and str(ts) != "0" else "-")
        L.append("| %s | %s | `%s` | %s | %s |" % (
            host, it.get("name", ""), it.get("key_", ""), it.get("lastvalue", "-"), when))
    L.append("")
    L.append("- requiredperformance = 설정상 필요한 초당 값 수(NVPS), wcache values = 실측 처리량")
    L.append("")


def section_proxy(api, L):
    L.append("## 2. 프록시 사용 여부")
    L.append("")
    try:
        # 7.0에서 proxy의 host 필드는 name으로 개명 — output은 extend로 받아 필드 차이 흡수
        proxies = api.call("proxy.get", {"output": "extend"})
        if proxies:
            L.append("- 등록된 프록시 %d대: %s" % (
                len(proxies),
                ", ".join(p.get("name") or p.get("host", "?") for p in proxies)))
        else:
            L.append("- **등록된 프록시 없음** — 전 호스트를 서버가 직수집")
    except ZabbixAPIError as e:
        # 7.0은 User 타입도 proxy.get 조회 가능 — 실패는 권한보다 다른 원인일 가능성
        L.append("- proxy.get 실패 (%s) — host.get 배정 필드로 대체 확인" % e)
    # 7.0은 monitored_by/proxyid, 구버전은 proxy_hostid — extend로 받아 존재하는 키만 사용
    hosts = api.call("host.get", {"output": "extend"})
    assigned = 0
    for h in hosts:
        pid = h.get("proxyid") or h.get("proxy_hostid") or "0"
        mb = str(h.get("monitored_by", "0"))
        if str(pid) not in ("0", "", "None") or mb in ("1", "2"):  # 1=proxy, 2=proxy group
            assigned += 1
    L.append("- 호스트 %d대 중 프록시 경유 %d대 / 서버 직수집 %d대"
             % (len(hosts), assigned, len(hosts) - assigned))
    L.append("")


def section_actions(api, L):
    L.append("## 3. 알림 라우팅 (action.get — 권한 필요)")
    L.append("")
    try:
        actions = api.call("action.get", {
            "output": ["actionid", "name", "status", "eventsource"],
            "selectFilter": "extend",
            "selectOperations": "extend",
            "filter": {"eventsource": 0},   # 트리거 액션만
        })
    except ZabbixAPIError as e:
        L.append("- 조회 실패(예상됨 — 읽기 전용 계정 권한 부족일 수 있음): %s" % e)
        L.append("- 이 경우 이 항목만 인터뷰/UI에서 확인: Alerts → Actions → Trigger actions")
        L.append("")
        return
    sev_names = {0: "NotClassified", 1: "Information", 2: "Warning",
                 3: "Average", 4: "High", 5: "Disaster"}
    op_names = {0: "메시지 발송", 1: "원격 명령"}
    cond_names = {"0": "호스트그룹", "1": "호스트", "2": "트리거", "3": "트리거명",
                  "4": "심각도", "6": "시간대", "13": "템플릿", "16": "유지보수 억제",
                  "25": "이벤트 태그", "26": "이벤트 태그 값"}
    # 호스트그룹/호스트 조건의 ID를 이름으로 해석
    gids, hids = set(), set()
    for a in actions:
        for c in (a.get("filter") or {}).get("conditions") or []:
            t, v = str(c.get("conditiontype")), c.get("value")
            if t == "0" and v:
                gids.add(str(v))
            elif t == "1" and v:
                hids.add(str(v))
    gname, hname = {}, {}
    if gids:
        for g in api.call("hostgroup.get", {"output": ["groupid", "name"],
                                            "groupids": sorted(gids)}):
            gname[str(g["groupid"])] = g["name"]
    if hids:
        for h in api.call("host.get", {"output": ["hostid", "name"],
                                       "hostids": sorted(hids)}):
            hname[str(h["hostid"])] = h["name"]
    for a in actions:
        state = "활성" if str(a.get("status")) == "0" else "비활성"
        L.append("### %s (%s)" % (a.get("name", "?"), state))
        conds = (a.get("filter") or {}).get("conditions") or []
        if conds:
            for c in conds:
                t, v = str(c.get("conditiontype")), str(c.get("value", ""))
                op = {"0": "=", "1": "<>", "2": "like", "3": "not like",
                      "5": ">=", "6": "<="}.get(str(c.get("operator")), "?")
                if t == "4":
                    L.append("- **심각도 조건: %s %s**" % (op, sev_names.get(int(v or 0), v)))
                elif t == "0":
                    L.append("- 호스트그룹 %s **%s**" % (op, gname.get(v, "groupid=" + v)))
                elif t == "1":
                    L.append("- 호스트 %s **%s**" % (op, hname.get(v, "hostid=" + v)))
                else:
                    L.append("- %s %s %s" % (cond_names.get(t, "type=" + t), op, v))
        else:
            L.append("- 조건 없음 (모든 트리거 이벤트 대상)")
        # 심각도 조건(type 4)이 하나도 없으면 명시 — 그룹만 거르고 전 심각도 발송이라는 뜻
        if conds and not any(str(c.get("conditiontype")) == "4" for c in conds):
            L.append("- (심각도 조건 없음 — 위 조건에 걸리면 심각도 무관 발송,"
                     " 단 수신자 미디어 설정의 심각도 필터는 별도)")
        for o in (a.get("operations") or []):
            kind = op_names.get(int(o.get("operationtype", 0)), "type=%s" % o.get("operationtype"))
            L.append("- 동작: %s" % kind)
        L.append("")


def section_alerts(api, L, days):
    """실제 발송된 알림 통계 — Problem 이벤트 수와 별개의 숫자임에 주의."""
    L.append("## 4. 실제 발송된 알림 (alert.get, 최근 %d일)" % days)
    L.append("")
    L.append("- 주의: 스냅샷의 Problem 이벤트 수는 '트리거 발화' 수이고, 여기는 Action을")
    L.append("  통과해 실제 '발송'된 알림 수 — 두 수의 차이가 곧 통보되지 않는 물량")
    L.append("")
    mtypes = {}
    try:
        for m in api.call("mediatype.get", {"output": ["mediatypeid", "name"]}):
            mtypes[str(m["mediatypeid"])] = m.get("name", "?")
    except ZabbixAPIError:
        pass  # 권한 없으면 mediatypeid 숫자 그대로 표기
    time_from = int((datetime.now() - timedelta(days=days)).timestamp())
    limit = 100000
    try:
        # 주의: 7.0의 alert.get filter는 alerttype을 허용하지 않음(Invalid parameter) —
        # output으로 받아 클라이언트에서 메시지(alerttype=0)만 걸러낸다
        alerts = api.call("alert.get", {
            "output": ["alertid", "clock", "mediatypeid", "status", "alerttype"],
            "time_from": time_from,
            "sortfield": "clock", "sortorder": "DESC",   # 한도 도달 시 최신 우선
            "limit": limit,
        })
    except ZabbixAPIError as e:
        L.append("- 조회 실패: %s" % e)
        L.append("- 이 항목만 인터뷰/UI에서 확인 (Reports → Action log)")
        L.append("")
        return
    alerts = [a for a in alerts if str(a.get("alerttype", "0")) == "0"]  # 메시지만
    if not alerts:
        L.append("- **발송 이력 0건** — 단, 7.0.9+에서는 Super admin이 아니면 자기 유저그룹")
        L.append("  수신분만 조회되므로 읽기 전용 계정의 0건은 실제 발송량과 무관할 수 있음.")
        L.append("  Super admin 토큰으로 재실행하거나 UI(Reports → Action log)에서 확인 권장")
        L.append("")
        return
    L.append("- [주의] 비 Super admin 계정은 자기 유저그룹 수신분만 집계됨(7.0.9+) — 아래는 하한값")
    L.append("")
    per_media = Counter(str(a.get("mediatypeid")) for a in alerts)
    per_status = Counter(str(a.get("status")) for a in alerts)
    status_names = {"0": "미발송", "1": "발송 성공", "2": "발송 실패", "3": "신규(처리 대기)"}
    L.append("- 총 %d건 (일평균 %.1f건)%s" % (
        len(alerts), len(alerts) / days,
        " — [주의] 조회 한도 %d건 도달, 실제는 더 많음" % limit if len(alerts) >= limit else ""))
    L.append("- 상태: " + " / ".join("%s %d건" % (status_names.get(s, "status=%s" % s), c)
                                     for s, c in per_status.most_common()))
    L.append("")
    L.append("| 미디어 타입 | 발송 수 |")
    L.append("|---|---:|")
    for mid, cnt in per_media.most_common():
        L.append("| %s | %d |" % (mtypes.get(mid, "mediatypeid=" + mid), cnt))
    L.append("")


def main():
    for s in (sys.stdout, sys.stderr):
        try:
            s.reconfigure(encoding="utf-8", errors="replace")
        except AttributeError:
            pass

    ap = argparse.ArgumentParser(description="Zabbix 서버 통계/라우팅 자가 확인 (읽기 전용)")
    ap.add_argument("--url", default=os.environ.get("ZABBIX_URL"))
    ap.add_argument("--token", default=os.environ.get("ZABBIX_TOKEN"))
    ap.add_argument("--user", default=os.environ.get("ZABBIX_USER"))
    ap.add_argument("--password", default=os.environ.get("ZABBIX_PASSWORD"))
    ap.add_argument("--days", type=int, default=30, help="알림 발송 집계 기간(일), 기본 30")
    ap.add_argument("--mask-ip", action="store_true",
                    help="리포트 내 모든 IPv4를 IP-NNN 토큰으로 일관 치환 (127.0.0.1/0.0.0.0 제외)")
    ap.add_argument("--insecure", action="store_true")
    ap.add_argument("-o", "--output", default="zabbix_serverstats.md")
    args = ap.parse_args()

    if not args.url:
        sys.exit("[!] --url 또는 ZABBIX_URL 필요")
    if not args.token and not (args.user and args.password):
        sys.exit("[!] --token 또는 --user/--password 필요")

    try:
        api = ZabbixAPI(args.url, insecure=args.insecure)
        api.login(token=args.token, user=args.user, password=args.password)
        L = ["# Zabbix 서버 통계 자가 확인", "",
             "- 생성: %s / Zabbix %s" % (datetime.now().strftime("%Y-%m-%d %H:%M"), api.version), ""]
        section_nvps(api, L)
        section_proxy(api, L)
        section_actions(api, L)
        section_alerts(api, L, args.days)
        report = "\n".join(L) + "\n"
        if args.mask_ip:
            report = mask_ips(report)
    except ZabbixAPIError as e:
        sys.exit("[오류] %s" % e)

    with open(args.output, "w", encoding="utf-8") as f:
        f.write(report)
    print(report)
    print("[*] 저장: %s (실환경 결과는 private/ 아래로)" % args.output, file=sys.stderr)


if __name__ == "__main__":
    main()
