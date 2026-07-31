#!/usr/bin/env python3
"""MSP 월간 리포트 대시보드 생성 — 요약 3페이지를 코드로 만든다.

왜 대시보드를 나누지 않고 페이지로 두나. 예약 리포트는 대시보드를 하나만 고를 수 있고
(공식: "only one dashboard can be selected at a time"), Zabbix 7.0 은 대시보드 페이지를
PDF 페이지로 그대로 낸다(ZBXNEXT-6741, 7.0.0alpha7 Fixed — 6.4 까지는 첫 장만 나왔다).
그래서 "주제별로 구분" 을 대시보드를 늘리지 않고 얻는다. 늘리면 고객당 리포트·구독·권한이
전부 배수가 된다.

페이지는 결론부터 둔다. 기존 자원 그래프 격자는 손대지 않고 뒤(4페이지 이후)에 그대로 남는다.

  1. 이번 달 요약 — 무슨 일이 있었나
  2. 사건 상세   — 무엇이 반복되나
  3. 보안        — 노출은 어떤가

**쓰기 API 를 쓰는 유일한 tools 스크립트다.** 실환경 금지 규칙(읽기 전용)을 지키기 위해
--apply 는 사설/로컬 주소에만 허용하고, 그 밖의 대상은 ZBX_WRITE_ALLOW 로 명시해야 한다.

사용법·배치 근거는 ansible/DEPLOY_GUIDE.md "MSP 월간 리포트".
"""

import argparse
import json
import os
import re
import sys
import urllib.request

for _s in (sys.stdout, sys.stderr):
    try:
        _s.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass

GRID_W = 72          # 7.0 그리드 폭 (6.4 에서 24 -> 72 로 바뀌었다)
PRIVATE_RE = re.compile(r"^(localhost|127\.0\.0\.1|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)")


class ApiError(RuntimeError):
    pass


def call(url: str, token: str, method: str, params) -> dict:
    req = urllib.request.Request(
        url, method="POST",
        data=json.dumps({"jsonrpc": "2.0", "method": method, "params": params,
                         "id": 1}).encode("utf-8"),
        headers={"Content-Type": "application/json-rpc",
                 "Authorization": "Bearer %s" % token})
    with urllib.request.urlopen(req, timeout=30) as r:
        body = json.loads(r.read().decode("utf-8"))
    if "error" in body:
        raise ApiError("%s: %s" % (method, body["error"]))
    return body["result"]


# ── 위젯 조립 ────────────────────────────────────────────────────────────────
# 큰 숫자는 4개까지만 둔다. 여섯 개가 넘으면 한 눈에 아무것도 안 읽힌다.

def tile(item_id: str, label: str, x: int, y: int, w: int, h: int, units: str = "") -> dict:
    f = [{"type": 4, "name": "itemid.0", "value": item_id},
         {"type": 0, "name": "show.0", "value": 1},     # 설명
         {"type": 0, "name": "show.1", "value": 2},     # 값
         {"type": 1, "name": "description", "value": label},
         {"type": 0, "name": "decimal_places", "value": 0}]
    if units:
        f += [{"type": 1, "name": "units", "value": units},
              {"type": 0, "name": "units_show", "value": 1}]
    return {"type": "item", "name": "", "x": x, "y": y, "width": w, "height": h, "fields": f}


def table(cols: list, x: int, y: int, w: int, h: int, ref: str,
          vertical: bool = True, mono: bool = False) -> dict:
    """itemhistory — 7.0 에서 plaintext 를 대체한 위젯. 텍스트 값을 표로 낸다.

    vertical(layout=1) 은 항목을 행으로 세운다 — 길이가 제각각인 텍스트에 맞다.
    긴 서사 한 편은 horizontal 로 두어 폭을 다 쓴다.
    """
    f = [{"type": 0, "name": "layout", "value": 1 if vertical else 0},
         {"type": 0, "name": "show_lines", "value": 1},
         {"type": 0, "name": "show_timestamp", "value": 0},
         {"type": 0, "name": "show_column_header", "value": 1},
         # reference 는 7.0 필수(위젯 간 데이터 브로드캐스트 식별자), 5자 고유.
         {"type": 1, "name": "reference", "value": ref}]
    for i, (item_id, name) in enumerate(cols):
        f += [{"type": 1, "name": "columns.%d.name" % i, "value": name},
              {"type": 4, "name": "columns.%d.itemid" % i, "value": item_id},
              # display 1 = as is — 줄바꿈이 보존된다. LLM 서사는 여러 줄이라 필수.
              {"type": 0, "name": "columns.%d.display" % i, "value": 1}]
        if mono:
            f += [{"type": 0, "name": "columns.%d.monospace_font" % i, "value": 1}]
    return {"type": "itemhistory", "name": "", "x": x, "y": y,
            "width": w, "height": h, "fields": f}


def build_pages(ids: dict) -> list:
    """ids: 아이템 키 -> itemid. 없는 키는 그 위젯만 조용히 빠진다."""
    def i(k):
        return ids.get(k)

    def keep(widgets):
        return [w for w in widgets if w]

    def T(cols, *a, **kw):
        cols = [(i(k), n) for k, n in cols if i(k)]
        return table(cols, *a, **kw) if cols else None

    p1 = keep([
        tile(i("report.alerts"), "원시 알림", 0, 0, 18, 4) if i("report.alerts") else None,
        tile(i("report.incidents"), "→ 사건 (병합 후)", 18, 0, 18, 4) if i("report.incidents") else None,
        tile(i("report.chronic"), "만성 사건", 36, 0, 18, 4) if i("report.chronic") else None,
        tile(i("report.response_s"), "초동 대응 중앙값", 54, 0, 18, 4, "s") if i("report.response_s") else None,
        T([("report.insight", "월간 종합 분석")], 0, 4, 48, 13, "MR101", vertical=False, mono=True),
        T([("report.period", "집계 기간"), ("report.evidence", "판단 근거 커버리지")],
          48, 4, 24, 13, "MR102"),
    ])
    p2 = keep([
        T([("report.top_repeat", "반복 상위"), ("report.by_class", "유형별"),
           ("report.by_severity", "심각도별")], 0, 0, 72, 6, "MR201"),
        T([("report.summary", "주요 사건 요약")], 0, 6, 48, 14, "MR202",
          vertical=False, mono=True),
        tile(i("report.auto_candidates"), "자동 조치 후보 등록", 48, 6, 24, 7)
        if i("report.auto_candidates") else None,
        tile(i("report.novel"), "신규 사건", 48, 13, 24, 7) if i("report.novel") else None,
    ])
    p3 = keep([
        tile(i("report.compliance"), "설정 준수율", 0, 0, 24, 6, "%")
        if i("report.compliance") else None,
        T([("report.security_status", "보안 집계 상태")], 24, 0, 48, 6, "MR301", vertical=False),
        T([("report.vuln", "취약점 (신규 · 재고)"), ("report.vuln_top", "상위 패키지"),
           ("report.fim", "파일 무결성 변경")], 0, 6, 72, 9, "MR302"),
    ])
    pages = [("1. 이번 달 요약", p1), ("2. 사건 상세", p2), ("3. 보안", p3)]
    return [{"name": n, "widgets": w} for n, w in pages if w]


# ── 적용 ─────────────────────────────────────────────────────────────────────

def resolve_items(url: str, token: str, host: str) -> dict:
    rows = call(url, token, "item.get",
                {"host": host, "output": ["itemid", "key_"],
                 "search": {"key_": "report."}, "startSearch": True})
    return {r["key_"]: r["itemid"] for r in rows}


def apply_dashboard(url: str, token: str, name: str, pages: list, share_user: str) -> str:
    users = []
    if share_user:
        u = call(url, token, "user.get", {"filter": {"username": share_user},
                                          "output": ["userid"]})
        if u:
            # 공개(private=0)로 두면 대시보드 목록에서 **고객사 이름이 서로 보인다.**
            # 비공개 + 해당 고객 계정에만 읽기 공유로 테넌트 격리를 유지한다.
            users = [{"userid": u[0]["userid"], "permission": 2}]
        else:
            print("[!] 공유 계정 %s 없음 — 소유자만 접근 가능하게 만든다" % share_user)
    found = call(url, token, "dashboard.get", {"filter": {"name": name}, "output": ["dashboardid"]})
    body = {"name": name, "display_period": 30, "private": 1, "pages": pages, "users": users}
    if found:
        body["dashboardid"] = found[0]["dashboardid"]
        return call(url, token, "dashboard.update", body)["dashboardids"][0]
    return call(url, token, "dashboard.create", body)["dashboardids"][0]


def guard_write(url: str) -> None:
    host = re.sub(r"^https?://", "", url).split("/")[0].split(":")[0]
    allow = [h.strip() for h in os.environ.get("ZBX_WRITE_ALLOW", "").split(",") if h.strip()]
    if PRIVATE_RE.match(host) or host in allow:
        return
    sys.exit("[!] 쓰기 거부 — %s 는 사설 주소가 아니다. 실환경 Zabbix 는 읽기 전용이 원칙이다.\n"
             "    랩이 맞다면 ZBX_WRITE_ALLOW=%s 로 명시할 것." % (host, host))


ALL_KEYS = ("report.alerts", "report.incidents", "report.chronic", "report.novel",
            "report.auto_candidates", "report.top_repeat", "report.by_class",
            "report.by_severity", "report.response_s", "report.evidence",
            "report.security_status", "report.compliance", "report.fim", "report.vuln",
            "report.summary", "report.insight", "report.period", "report.vuln_top")


def selftest() -> None:
    """API 없이 도는 배치 검사. 좌표가 틀린 대시보드는 만들고 나서야 보이므로 여기서 막는다."""
    n = 0
    pages = build_pages({k: str(1000 + i) for i, k in enumerate(ALL_KEYS)})
    assert len(pages) == 3, "페이지 3장이 아니다"
    n += 1
    refs = []
    for p in pages:
        cells = set()
        for w in p["widgets"]:
            x, y, ww, h = w["x"], w["y"], w["width"], w["height"]
            assert 0 <= x and 0 <= y and x + ww <= GRID_W and y + h <= 64, \
                "그리드를 벗어난다(%s): %s" % (p["name"], w["type"])
            for c in ((a, b) for a in range(x, x + ww) for b in range(y, y + h)):
                assert c not in cells, "위젯이 겹친다(%s) at %s" % (p["name"], c)
                cells.add(c)
            refs += [f["value"] for f in w["fields"] if f["name"] == "reference"]
            n += 1
    assert len(refs) == len(set(refs)) and all(len(r) == 5 for r in refs), \
        "reference 는 5자 고유여야 한다: %s" % refs
    n += 1
    # 아이템이 일부만 있어도 빈 페이지·빈 위젯이 남지 않아야 한다.
    part = build_pages({"report.alerts": "1", "report.summary": "2"})
    assert part and all(p["widgets"] for p in part), "부분 구성에서 빈 페이지가 남았다"
    n += 1
    # 실환경 주소에는 쓰지 않는다.
    try:
        guard_write("https://zabbix.example.com/api_jsonrpc.php")
        raise AssertionError("공인 주소 쓰기가 막히지 않았다")
    except SystemExit:
        n += 1
    guard_write("http://192.168.20.26:8080/api_jsonrpc.php")
    n += 1
    print("ALL OK (%d checks)" % n)


def main():
    ap = argparse.ArgumentParser(description="MSP 월간 리포트 요약 대시보드 (3페이지)")
    ap.add_argument("--selftest", action="store_true", help="API 없이 배치·가드 검사")
    ap.add_argument("--url", default=os.environ.get("ZABBIX_API_URL",
                                                    "http://127.0.0.1:8080/api_jsonrpc.php"))
    ap.add_argument("--token", default=os.environ.get("ZABBIX_API_TOKEN", ""))
    ap.add_argument("--host", help="리포트 값이 들어간 Zabbix 호스트명")
    ap.add_argument("--name", help="대시보드 이름. 기본 MSP_REPORT_<호스트 접미사>")
    ap.add_argument("--share-user", default="", help="읽기 공유할 고객 조회 계정")
    ap.add_argument("--apply", action="store_true", help="실제 생성/갱신. 없으면 JSON 만 출력")
    ap.add_argument("--out", help="구성 JSON 을 파일로도 저장(리포 리뷰용)")
    a = ap.parse_args()

    if a.selftest:
        selftest()
        return
    if not a.host:
        sys.exit("[!] --host 가 필요하다 (예: report-Customer-B)")
    if not a.token:
        sys.exit("[!] --token 또는 ZABBIX_API_TOKEN 이 필요하다")
    ids = resolve_items(a.url, a.token, a.host)
    if not ids:
        sys.exit("[!] %s 에 report.* 아이템이 없다. 먼저 ansible/msp_report.yml 을 돌릴 것" % a.host)
    pages = build_pages(ids)
    name = a.name or "MSP_REPORT_%s" % a.host.replace("report-", "")

    n_w = sum(len(p["widgets"]) for p in pages)
    print("아이템 %d종 확인 → 페이지 %d장 / 위젯 %d개" % (len(ids), len(pages), n_w))
    for p in pages:
        print("  %-16s 위젯 %d" % (p["name"], len(p["widgets"])))
    missing = [k for k in ("report.insight", "report.compliance", "report.vuln")
               if k not in ids]
    if missing:
        print("[!] 아이템 없음 → 해당 위젯 생략: %s" % ", ".join(missing))

    if a.out:
        with open(a.out, "w", encoding="utf-8") as f:
            json.dump({"name": name, "pages": pages}, f, ensure_ascii=False, indent=1)
        print("[out] %s" % a.out)
    if not a.apply:
        print("\n[드라이런] 적용하지 않았다. 만들려면 --apply")
        return
    guard_write(a.url)
    did = apply_dashboard(a.url, a.token, name, pages, a.share_user)
    print("\n[apply] %s (dashboardid=%s)" % (name, did))
    print("다음: Reports > Scheduled reports 에서 이 대시보드로 리포트 등록")


if __name__ == "__main__":
    main()
