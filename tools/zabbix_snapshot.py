#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
zabbix_snapshot.py — Zabbix 구성/알림 현황 스냅샷 리포트 생성기
(모니터링 고도화 PoC 사전조사용 / 읽기 전용 .get API만 호출)

수집 내용
  1) 호스트그룹 목록 + 그룹별 호스트 수
  2) 호스트에 연결된 템플릿 목록 (연결 호스트/아이템/트리거 수)
  3) 최근 N일 Problem 이벤트 통계: 심각도 분포 + 최다 발화 트리거 Top N
     (웹 UI의 Reports → Top 100 triggers에 해당)

특징
  - 파이썬 표준 라이브러리만 사용 (pip 불필요, Python 3.6+ → Rocky 8 기본 python3 OK)
  - Zabbix 5.0 ~ 7.x 자동 호환 (버전 감지 후 6.4+는 Authorization: Bearer 헤더 인증)
  - --mask 옵션으로 고객사명 등 민감 명칭을 일관되게 익명화

사용 예
  export ZABBIX_URL="https://zabbix.internal/zabbix"     # /api_jsonrpc.php 생략 가능
  export ZABBIX_TOKEN="****"                              # (권장) 읽기전용 계정의 API 토큰
  python3 zabbix_snapshot.py --days 30 --top 20

  # 계정/비밀번호 인증 + 자체서명 인증서 환경
  python3 zabbix_snapshot.py --url https://10.0.0.1/zabbix --user readonly --password '****' --insecure

  # MSP 고객사 그룹명 익명화
  python3 zabbix_snapshot.py --mask '(?i)msp|고객' -o snapshot.md

API 토큰 발급: Zabbix UI → 사용자 설정(또는 Administration) → API tokens → Create
(조회 권한만 있는 별도 계정으로 발급 권장. 이 스크립트는 쓰기 API를 일절 호출하지 않음)
"""
import argparse
import json
import os
import re
import ssl
import sys
import urllib.error
import urllib.request
from collections import Counter
from datetime import datetime, timedelta

SEVERITY = {0: "NotClassified", 1: "Information", 2: "Warning",
            3: "Average", 4: "High", 5: "Disaster"}

# --deep 모드에서 커스텀 아이템/트리거 최대 조회 수
DEEP_LIMIT = 500


class ZabbixAPIError(RuntimeError):
    pass


READ_ONLY_EXTRA = frozenset({"apiinfo.version", "user.login", "user.logout"})


def assert_read_only(method):
    """작업 원칙 4(실환경에는 조회 API만)를 코드로 강제한다.

    종래에는 독스트링에만 '읽기 전용'이라 적혀 있어 보증이 관례였다. 이 도구들은 실환경
    super admin 토큰으로도 돌 수 있으므로 오타 하나가 쓰기 호출이 될 수 있다. 세션 인증과
    버전 조회만 예외로 둔다 — 둘 다 데이터를 바꾸지 않는다.
    """
    if method.endswith(".get") or method in READ_ONLY_EXTRA:
        return
    raise ZabbixAPIError(
        "read-only violation: %s — 이 도구는 조회만 한다 (허용: *.get, %s)"
        % (method, ", ".join(sorted(READ_ONLY_EXTRA))))


class ZabbixAPI:
    """최소 기능 JSON-RPC 클라이언트."""

    def __init__(self, url, insecure=False, timeout=60):
        url = url.rstrip("/")
        if not url.endswith("api_jsonrpc.php"):
            url += "/api_jsonrpc.php"
        self.url = url
        self.timeout = timeout
        self.token = None
        self._id = 0
        self._ctx = ssl._create_unverified_context() if insecure else None

        self.version = str(self.call("apiinfo.version", {}, auth=False))
        m = re.match(r"(\d+)\.(\d+)", self.version)
        ver = (int(m.group(1)), int(m.group(2))) if m else (0, 0)
        # Zabbix 6.4+: Bearer 헤더 지원 / body auth 필드는 7.0 deprecated, 7.2에서 제거
        self._use_header = ver >= (6, 4)

    def login(self, token=None, user=None, password=None):
        if token:
            self.token = token
            return
        try:
            self.token = self.call("user.login",
                                   {"username": user, "password": password}, auth=False)
        except ZabbixAPIError as e:
            # Zabbix 5.2 이하는 파라미터명이 'user' — 파라미터 오류일 때만 폴백
            # (비밀번호 오류 등에서 재시도하면 실패 로그인 2회 + 원인 오도)
            if "username" not in str(e):
                raise
            self.token = self.call("user.login",
                                   {"user": user, "password": password}, auth=False)

    def call(self, method, params, auth=True):
        assert_read_only(method)
        self._id += 1
        payload = {"jsonrpc": "2.0", "method": method, "params": params, "id": self._id}
        headers = {"Content-Type": "application/json-rpc"}
        if auth and self.token:
            if self._use_header:
                headers["Authorization"] = "Bearer " + self.token
            else:
                payload["auth"] = self.token
        req = urllib.request.Request(self.url, json.dumps(payload).encode("utf-8"), headers)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=self._ctx) as resp:
                body = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            detail = ""
            try:
                detail = e.read().decode("utf-8", "replace")[:300].strip()
            except Exception:
                pass
            raise ZabbixAPIError("HTTP %s %s (URL: %s)%s"
                                 % (e.code, e.reason, self.url,
                                    "\n  응답: " + detail if detail else ""))
        except urllib.error.URLError as e:
            raise ZabbixAPIError("접속 실패: %s (URL: %s)" % (e.reason, self.url))
        except ValueError:
            raise ZabbixAPIError("JSON이 아닌 응답 수신 — URL이 Zabbix 프론트엔드가 맞는지 확인하세요")
        if "error" in body:
            err = body["error"]
            raise ZabbixAPIError("%s → %s %s" % (method, err.get("message", ""),
                                                 err.get("data", "")))
        return body["result"]


class Masker:
    """--mask 정규식과 일치하는 그룹/호스트/템플릿명을 'MASKED-NN'으로 일관 치환."""

    def __init__(self, pattern=None):
        self._re = re.compile(pattern) if pattern else None
        self.mapping = {}

    def name(self, original):
        if not self._re or not original or not self._re.search(original):
            return original
        if original not in self.mapping:
            self.mapping[original] = "MASKED-%02d" % (len(self.mapping) + 1)
        return self.mapping[original]

    def text(self, s):
        # 이미 익명화된 원본 명칭이 자유 텍스트(트리거 설명 등)에 섞여 있으면 치환
        # (긴 명칭부터 치환해 'MSP-A'와 'MSP-A-web01' 같은 겹침에서도 일관성 유지)
        for orig, alias in sorted(self.mapping.items(), key=lambda kv: -len(kv[0])):
            s = s.replace(orig, alias)
        return s


def as_count(v):
    """selectX: 'count' 응답(문자열 숫자) 또는 리스트 응답을 정수로 정규화."""
    if isinstance(v, list):
        return len(v)
    try:
        return int(v)
    except (TypeError, ValueError):
        return 0


def md_escape(s):
    return str(s).replace("|", "\\|").replace("\n", " ").strip()


def clip(s, n=120):
    s = str(s)
    return s if len(s) <= n else s[:n] + "..."


# IP 마스킹: 동일 IP는 동일 토큰으로 일관 치환 (127.0.0.1/0.0.0.0은 의미 보존 위해 제외)
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def mask_ips(text, mapping=None):
    mapping = {} if mapping is None else mapping

    def _sub(m):
        ip = m.group(0)
        if ip in ("127.0.0.1", "0.0.0.0"):
            return ip
        if ip not in mapping:
            mapping[ip] = "IP-%03d" % (len(mapping) + 1)
        return mapping[ip]

    return _IP_RE.sub(_sub, text)


# 값이 비밀일 가능성이 있는 매크로는 리포트에 값 미표기
_SECRET_MACRO_RE = re.compile(r"(?i)passw|secret|token|community|auth|priv|\bkey\b|\.key|_key")


def redact_macro(macro, value):
    if value is None:
        return "(secret 매크로 — API가 값 미반환)"
    if _SECRET_MACRO_RE.search(macro or ""):
        return "(redacted)"
    return value


def build_report(api, args, masker):
    L = []

    # ── 데이터 수집 ─────────────────────────────────────────────
    groups = api.call("hostgroup.get", {
        "output": ["groupid", "name"],
        "selectHosts": "count",
        "sortfield": "name",
    })
    total_hosts = as_count(api.call("host.get", {"countOutput": True}))
    templates = api.call("template.get", {
        "output": ["templateid", "name"],
        "selectHosts": "count",
        "selectItems": "count",
        "selectTriggers": "count",
    })

    time_from = int((datetime.now() - timedelta(days=args.days)).timestamp())
    events = api.call("event.get", {
        "output": ["objectid", "severity"],
        "source": 0, "object": 0, "value": 1,   # 트리거가 만든 PROBLEM 이벤트만
        "time_from": time_from,
        # 한도 도달 시 오래된 쪽이 잘리도록 최신순 조회 (기본 정렬은 오래된 순)
        "sortfield": "eventid",
        "sortorder": "DESC",
        "limit": args.limit,
    })
    truncated = len(events) >= args.limit
    per_trigger = Counter(e["objectid"] for e in events)
    per_sev = Counter(int(e.get("severity", 0)) for e in events)
    top = per_trigger.most_common(args.top)

    trig_info = {}
    if top:
        for t in api.call("trigger.get", {
            "triggerids": [tid for tid, _ in top],
            "output": ["triggerid", "description", "priority"],
            "selectHosts": ["name"],
            "expandDescription": True,
        }):
            trig_info[t["triggerid"]] = t

    # ── 리포트 작성 ─────────────────────────────────────────────
    L.append("# Zabbix 현황 스냅샷")
    L.append("")
    L.append("- 생성: %s / Zabbix %s" % (datetime.now().strftime("%Y-%m-%d %H:%M"), api.version))
    L.append("- 전체 호스트 %d대 / 호스트그룹 %d개" % (total_hosts, len(groups)))
    L.append("- 이벤트 집계 구간: 최근 %d일" % args.days)
    L.append("- 참고: API 계정 권한 범위 내 데이터만 포함됩니다.")
    L.append("")

    L.append("## 1. 호스트그룹별 호스트 수")
    L.append("")
    L.append("| 호스트그룹 | 호스트 수 |")
    L.append("|---|---:|")
    for g in sorted(groups, key=lambda x: -as_count(x.get("hosts"))):
        L.append("| %s | %d |" % (md_escape(masker.name(g["name"])), as_count(g.get("hosts"))))
    L.append("")

    linked = sorted([t for t in templates if as_count(t.get("hosts")) > 0],
                    key=lambda x: -as_count(x.get("hosts")))
    L.append("## 2. 사용 중인 템플릿 (%d개 / 미연결 %d개는 생략)"
             % (len(linked), len(templates) - len(linked)))
    L.append("")
    L.append("| 템플릿 | 연결 호스트 | 아이템 | 트리거 |")
    L.append("|---|---:|---:|---:|")
    for t in linked:
        L.append("| %s | %d | %d | %d |" % (
            md_escape(masker.name(t["name"])),
            as_count(t.get("hosts")),
            as_count(t.get("items")),
            as_count(t.get("triggers")),
        ))
    L.append("")

    L.append("## 3. 최근 %d일 알림 발생 현황 (Problem 이벤트)" % args.days)
    L.append("")
    avg = (len(events) / args.days) if args.days else 0.0
    L.append("- 총 %d건 (일평균 %.1f건)" % (len(events), avg))
    sev_line = " / ".join("%s **%d**" % (SEVERITY[s], per_sev[s])
                          for s in range(5, -1, -1) if per_sev.get(s))
    L.append("- 심각도 분포: %s" % (sev_line if sev_line else "없음"))
    if truncated:
        L.append("- [주의] 조회 한도(%d건) 도달 — 최신 %d건만 집계됨(오래된 이벤트 잘림). --limit 상향 후 재실행 권장"
                 % (args.limit, args.limit))
    L.append("")
    L.append("### 최다 발화 트리거 Top %d" % min(args.top, len(top)))
    L.append("")
    L.append("| # | 발화 수 | 심각도 | 호스트 | 트리거 |")
    L.append("|---:|---:|---|---|---|")
    for rank, (tid, cnt) in enumerate(top, 1):
        t = trig_info.get(tid)
        if t:
            host = masker.name(t["hosts"][0]["name"]) if t.get("hosts") else "-"
            desc = masker.text(t.get("description", ""))
            sev = SEVERITY.get(int(t.get("priority", 0)), "?")
        else:
            host, desc, sev = "-", "(삭제된 트리거)", "-"
        L.append("| %d | %d | %s | %s | %s |" % (rank, cnt, sev, md_escape(host), md_escape(desc)))
    L.append("")

    # ── [심층] 기본 템플릿에서 벗어난 커스텀 요소 (--deep) ────────
    if getattr(args, "deep", False):
        custom_items = api.call("item.get", {
            "output": ["itemid", "name", "key_", "delay", "status"],
            "inherited": False, "templated": False,
            "filter": {"flags": "0"},           # LLD 생성분 제외, 직접 만든 것만
            "selectHosts": ["name"],
            "limit": DEEP_LIMIT,
        })
        custom_trigs = api.call("trigger.get", {
            "output": ["triggerid", "description", "priority", "expression", "status"],
            "inherited": False, "templated": False,
            "filter": {"flags": "0"},
            "expandExpression": True, "expandDescription": True,
            "selectHosts": ["name"],
            "limit": DEEP_LIMIT,
        })
        host_macros = api.call("host.get", {
            "output": ["hostid", "name"],
            "selectMacros": ["macro", "value"],
        })
        tmpl_macros = api.call("template.get", {
            "output": ["templateid", "name"],
            "selectMacros": ["macro", "value"],
        })

        L.append("## 4. [심층] 호스트에 직접 정의된 커스텀 아이템 (%d개)" % len(custom_items))
        L.append("")
        if len(custom_items) >= DEEP_LIMIT:
            L.append("[주의] 조회 한도(%d개) 도달 — 실제 커스텀 아이템은 더 많을 수 있음" % DEEP_LIMIT)
            L.append("")
        if custom_items:
            L.append("| 호스트 | 아이템 | 키 | 주기 | 상태 |")
            L.append("|---|---|---|---|---|")
            for it in custom_items:
                host = masker.name(it["hosts"][0]["name"]) if it.get("hosts") else "-"
                st = "사용" if str(it.get("status")) == "0" else "비활성"
                L.append("| %s | %s | `%s` | %s | %s |" % (
                    md_escape(host), md_escape(masker.text(it.get("name", ""))),
                    md_escape(clip(it.get("key_", ""))), it.get("delay", ""), st))
        else:
            L.append("없음 — 모든 수집이 템플릿 경유로 이루어짐")
        L.append("")

        L.append("## 5. [심층] 호스트에 직접 정의된 커스텀 트리거 (%d개)" % len(custom_trigs))
        L.append("")
        if len(custom_trigs) >= DEEP_LIMIT:
            L.append("[주의] 조회 한도(%d개) 도달 — 실제 커스텀 트리거는 더 많을 수 있음" % DEEP_LIMIT)
            L.append("")
        if custom_trigs:
            L.append("| 호스트 | 심각도 | 트리거 | 조건식 |")
            L.append("|---|---|---|---|")
            for t in sorted(custom_trigs, key=lambda x: -int(x.get("priority", 0))):
                host = masker.name(t["hosts"][0]["name"]) if t.get("hosts") else "-"
                sev = SEVERITY.get(int(t.get("priority", 0)), "?")
                L.append("| %s | %s | %s | `%s` |" % (
                    md_escape(host), sev,
                    md_escape(masker.text(t.get("description", ""))),
                    md_escape(clip(masker.text(t.get("expression", ""))))))
        else:
            L.append("없음 — 모든 알림 조건이 템플릿 기본 트리거")
        L.append("")

        macro_rows = []
        for h in host_macros:
            for m in (h.get("macros") or []):
                macro_rows.append(("호스트", masker.name(h.get("name", "")),
                                   m.get("macro", ""), m.get("value")))
        for t in tmpl_macros:
            for m in (t.get("macros") or []):
                macro_rows.append(("템플릿", masker.name(t.get("name", "")),
                                   m.get("macro", ""), m.get("value")))
        L.append("## 6. [심층] 매크로 오버라이드 (%d건) — 임계치 튜닝 흔적" % len(macro_rows))
        L.append("")
        if macro_rows:
            L.append("| 위치 | 이름 | 매크로 | 값 |")
            L.append("|---|---|---|---|")
            for where, name, macro, value in macro_rows:
                L.append("| %s | %s | `%s` | %s |" % (
                    where, md_escape(name), md_escape(macro),
                    md_escape(redact_macro(macro, value))))
        else:
            L.append("없음 — 임계치·수집 매크로가 전부 기본값 (환경 맞춤 튜닝 이력 없음)")
        L.append("")

    L.append("---")
    note = "공유 전 체크: 고객사명·내부 호스트명 노출 여부를 확인하세요."
    if masker.mapping:
        note += " (익명화 적용 %d건)" % len(masker.mapping)
    else:
        note += " (--mask 옵션으로 익명화 가능)"
    L.append(note)
    L.append("")
    return "\n".join(L)


def main():
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except AttributeError:
            pass  # Python 3.6 등

    ap = argparse.ArgumentParser(
        description="Zabbix 구성/알림 현황 스냅샷 리포트 생성 (읽기 전용)",
        epilog="환경변수로도 지정 가능: ZABBIX_URL, ZABBIX_TOKEN, ZABBIX_USER, ZABBIX_PASSWORD",
    )
    ap.add_argument("--url", default=os.environ.get("ZABBIX_URL"),
                    help="Zabbix 프론트엔드 URL (예: https://zabbix.internal/zabbix)")
    ap.add_argument("--token", default=os.environ.get("ZABBIX_TOKEN"),
                    help="API 토큰 (권장, Zabbix 5.4+)")
    ap.add_argument("--user", default=os.environ.get("ZABBIX_USER"))
    ap.add_argument("--password", default=os.environ.get("ZABBIX_PASSWORD"))
    ap.add_argument("--days", type=int, default=30, help="이벤트 집계 기간(일), 기본 30")
    ap.add_argument("--top", type=int, default=20, help="Top 트리거 개수, 기본 20")
    ap.add_argument("--limit", type=int, default=100000, help="이벤트 최대 조회 수, 기본 100000")
    ap.add_argument("--mask", metavar="REGEX",
                    help="정규식과 일치하는 그룹/호스트명 익명화 (예: '(?i)고객|msp')")
    ap.add_argument("--mask-ip", action="store_true",
                    help="리포트 내 모든 IPv4를 IP-NNN 토큰으로 일관 치환 (127.0.0.1/0.0.0.0 제외)")
    ap.add_argument("--deep", action="store_true",
                    help="심층 모드: 템플릿 밖 커스텀 아이템/트리거/매크로 오버라이드까지 수집")
    ap.add_argument("--insecure", action="store_true",
                    help="TLS 인증서 검증 생략 (자체서명 인증서 환경)")
    ap.add_argument("-o", "--output", default="zabbix_snapshot.md", help="저장 파일명")
    args = ap.parse_args()

    if not args.url:
        sys.exit("[!] --url 또는 환경변수 ZABBIX_URL 이 필요합니다.")
    if not args.token and not (args.user and args.password):
        sys.exit("[!] --token(권장) 또는 --user/--password 가 필요합니다.")

    try:
        api = ZabbixAPI(args.url, insecure=args.insecure)
        print("[*] Zabbix %s 연결 확인 — 데이터 수집 중..." % api.version, file=sys.stderr)
        api.login(token=args.token, user=args.user, password=args.password)
        report = build_report(api, args, Masker(args.mask))
        if args.mask_ip:
            report = mask_ips(report)
    except ZabbixAPIError as e:
        sys.exit("[오류] %s" % e)
    except re.error as e:
        sys.exit("[오류] --mask 정규식이 잘못되었습니다: %s" % e)

    with open(args.output, "w", encoding="utf-8") as f:
        f.write(report)
    print(report)
    print("\n[*] 저장 완료: %s — 내용 검토 후 대화에 붙여넣거나 파일로 업로드하세요."
          % args.output, file=sys.stderr)


if __name__ == "__main__":
    main()
