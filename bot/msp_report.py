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
import re
import socket
import statistics
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
# 리포트 승인 초안이 자기 자신을 오염시키지 않도록 별도 source 로 넣고 집계에서 뺀다.
# 이 값이 없으면 초안이 원시 알림 1건 + playbook 있으니 자동 조치 후보 1건으로도 세어진다.
REPORT_SOURCE = "kinx-report"

# prejudge 자리에 판정이 아닌 값이 들어간 옛 레코드가 있다 — "단일", "2건 병합", "deep-dive".
# keep.py 독스트링이 경고한 바로 그 오염이며 2026-07-29 에 고쳤으나 이전 기록은 남아 있다.
# 접두로 판정한다: "재발(90일 3회) — 자동화 후보" 처럼 접미사가 붙는 경우가 있다.
VERDICTS = ("만성", "재발", "신규")


def verdict_of(a: dict) -> str:
    v = str(a.get("prejudge") or "").strip()
    for k in VERDICTS:
        if v.startswith(k):
            return k
    return ""          # 미상·오염값·없음 — 전부 판정 없음으로 본다


PENDING = "검토 대기 — 승인 후 게시됩니다"

# 봇 분석은 번호 절로 강제돼 있다("**2) 추정 원인**", 때로 "**② …**").
# 새 LLM 호출 없이 이미 만들어진 분석에서 절만 잘라 쓴다(Day8 결의 ⑥ "데모 C 출력 재활용만").
_SEC = {
    "cause": re.compile(r"\*\*\s*(?:2\)|②)[^\n]*\*\*(.*?)(?=\*\*\s*(?:3\)|③)|\Z)", re.S),
    "action": re.compile(r"\*\*\s*(?:4\)|④)[^\n]*\*\*(.*?)(?=\*\*\s*(?:5\)|⑤)|\Z)", re.S),
}


def _first_line(block: str, limit: int = 150) -> str:
    """절에서 첫 실질 줄만. 마크다운 강조·불릿 기호를 걷어낸다.

    길이로 거르지 않는다 — "발신지 차단." 같은 짧은 권고가 오히려 핵심이다.
    거르는 것은 글자가 없는 장식 줄(---, ###)뿐이다.
    """
    for ln in (block or "").splitlines():
        s = ln.strip().lstrip("-*•# ").replace("**", "").replace("`", "").strip()
        if len(s) >= 2 and re.search(r"\w", s):
            return s[:limit] + ("…" if len(s) > limit else "")
    return ""


def _section(text: str, which: str) -> str:
    m = _SEC[which].search(text or "")
    return _first_line(m.group(1)) if m else ""


def summarize(a: dict) -> str:
    """사건 1건 -> '이름 / 원인 / 권고' 한 덩어리. 형식이 어긋나면 앞부분으로 폴백한다."""
    text = str(a.get("analysis") or "")
    out = ["· %s  [%s]" % (a.get("name") or "(이름 없음)", verdict_of(a) or "판정없음")]
    cause, action = _section(text, "cause"), _section(text, "action")
    if not cause and not action:
        cause = _first_line(text, 200) or "(분석 본문 없음)"
    if cause:
        out.append("   원인: " + cause)
    if action:
        out.append("   권고: " + action)
    return "\n".join(out)


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

    def src(a):
        return a.get("source") or []

    win = [a for a in win if REPORT_SOURCE not in src(a)]

    # 원시 알림 = 감시 시스템이 낸 것(Keep 이 Zabbix 등에서 받은 provider 알림).
    # 사건 = 봇이 확정한 인시던트. 둘은 별개 레코드이므로 겹쳐 세지 않는다.
    # 홈즈는 기존 사건의 심층조사 결과라 어느 쪽도 아니다.
    incidents = [a for a in win if BOT_SOURCE in src(a)]
    raw = [a for a in win if BOT_SOURCE not in src(a) and HOLMES_SOURCE not in src(a)]
    holmes = [a for a in win if HOLMES_SOURCE in src(a)]
    merged = [a for a in incidents if int(a.get("alert_count") or 1) > 1]
    # "완료" 가 아니라 "등록" 이다 — 실제 실행은 Keep 워크플로 기록이고 알림 레코드만으론 모른다.
    candidates = [a for a in win if a.get("playbook")]

    verdicts = Counter(verdict_of(a) for a in incidents)
    judged = sum(verdicts[k] for k in VERDICTS)
    sev = Counter(str(a.get("severity") or "?") for a in incidents)

    # 초동 대응 = 원시 알림 발생 -> 봇 사건 게시. 같은 호스트에서 사건 직전의 원시 알림을
    # 짝지어 잰다. 정확한 인과 짝은 아니므로 "중앙값" 으로만 쓰고 개별 값은 내지 않는다.
    gaps = []
    for inc in incidents:
        t_inc = _ts(inc)
        prior = [_ts(r) for r in raw
                 if r.get("host") == inc.get("host") and _ts(r) <= t_inc]
        if prior:
            gaps.append((t_inc - max(prior)).total_seconds())
    response = round(statistics.median(gaps), 1) if gaps else 0.0

    # 서사는 심각도가 높고 최근인 것부터 3건. 분석 본문이 있는 것만 — 없으면 쓸 게 없다.
    top = sorted([a for a in incidents if a.get("analysis")],
                 key=lambda a: (-int(a.get("alert_count") or 1), _ts(a)), reverse=False)[:3]
    summary = "\n".join(summarize(a) for a in top) or "이번 기간 분석된 사건 없음"
    classes = Counter()
    for a in incidents:
        for c in str(a.get("classes") or "").split(","):
            if c.strip():
                classes[c.strip()] += 1
    repeat = Counter(a.get("name") or "(이름 없음)" for a in incidents
                     if verdict_of(a) in ("만성", "재발"))

    return {
        "report.alerts": len(raw),
        "report.incidents": len(incidents),
        "report.chronic": verdicts.get("만성", 0),
        "report.novel": verdicts.get("신규", 0),
        "report.auto_candidates": len(candidates),
        "report.top_repeat": " / ".join(f"{n}({c}회)" for n, c in repeat.most_common(3))
                             or "반복 없음",
        "report.by_class": " / ".join(f"{c}:{n}" for c, n in classes.most_common(6))
                           or "분류 없음",
        "report.by_severity": " / ".join(f"{s}:{n}" for s, n in sev.most_common()) or "없음",
        "report.response_s": response,
        # 승인 전에는 서사가 나가지 않는다. 호출측(--approve)이 이 값을 덮어쓴다.
        "report.summary": PENDING,
        "report.period": "%s ~ %s (%d일)" % (since.astimezone().strftime("%Y-%m-%d"),
                                             datetime.now().strftime("%Y-%m-%d"), days),
        "_summary_draft": summary,
        "_holmes": len(holmes),
        "_merged": len(merged),
        "_folded": sum(int(a.get("alert_count") or 1) for a in merged),
        # 판정이 붙은 사건 비율. Wazuh 알림은 trigger_id 가 없어 선판정이 안 붙는다(G11).
        # 이 값이 낮으면 만성/신규 수치를 전체로 읽으면 안 된다 — 커버리지를 함께 본다.
        "_judged": judged,
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


def _push_draft(target: str, draft: str) -> None:
    """요약 초안을 Keep 승인 큐에 올린다 — 데모 B 의 조치 후보와 같은 자리, 같은 UI.

    playbook 필드에 report_approve 를 실어 Keep 워크플로가 분기할 수 있게 한다.
    실패해도 전체 흐름을 막지 않는다(집계·숫자 전송은 별개다).
    """
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    try:
        from gateway import keep
    except ImportError as e:
        print("[keep] 초안 등록 건너뜀 — %s" % e)
        return
    note = ("*월간 리포트 요약 — 승인 대기*\n대상: `%s`\n\n"
            "아래 서사는 LLM 이 만든 것이고 **고객에게 나가는 문서**다. 검토 후 승인해야 "
            "리포트에 실린다. 미승인이면 %r 로 나간다.\n\n```\n%s\n```" % (target, PENDING, draft))
    res = keep.push_alert("월간 리포트 승인 대기 — %s" % target, "SEV3", target, note,
                          source=REPORT_SOURCE, playbook="report_approve",
                          fingerprint="msp-report|%s" % target)
    print("[keep] 승인 큐 등록 %s" % ("성공" if res.get("ok") else "실패/스킵: %s" % res))


def selftest() -> None:
    """Keep 없이 도는 검사. 한 번 고친 함정은 여기 남겨 다음에 되돌아가지 않게 한다."""
    from datetime import timedelta
    now = datetime.now(timezone.utc)
    n = 0

    def mk(source, **kw):
        d = {"lastReceived": now.isoformat(), "source": [source], "host": "h1",
             "severity": "high", "name": "x"}
        d.update(kw)
        return d

    def ck(cond, why):
        nonlocal n
        assert cond, why
        n += 1

    body = ("**1) 요약**\n한 줄.\n\n**2) 추정 원인·인과**\n- 브루트포스 시도 후 인증 성공.\n"
            "\n**3) 확인 명령**\nlast -a\n\n**4) 권장 조치**\n- 발신지 차단.\n")
    alerts = [
        {"lastReceived": (now - timedelta(seconds=30)).isoformat(),
         "source": ["zabbix"], "host": "h1", "name": "원시"},
        mk(BOT_SOURCE, name="사건", prejudge="만성", classes="auth_security",
           alert_count=3, analysis=body),
        mk(BOT_SOURCE, name="디스크", prejudge="신규", severity="warning",
           analysis="**② 원인**\n- 로그 급증.\n**④ 권장 조치**\n- 로테이션."),
        mk(BOT_SOURCE, name="형식없음", prejudge="재발", analysis="번호 절 없는 자유 텍스트."),
        mk(HOLMES_SOURCE, name="심층조사"),
        # 지난달 승인 초안이 Keep 에 남아 있는 상태
        mk(REPORT_SOURCE, name="월간 리포트 승인 대기", playbook="report_approve"),
    ]
    r = aggregate(alerts, 30)

    ck(r["report.alerts"] == 1, "승인 초안이 원시 알림으로 세어졌다")
    ck(r["report.auto_candidates"] == 0, "승인 초안이 자동 조치 후보로 세어졌다")
    ck(r["report.incidents"] == 3, "사건 수 불일치: %s" % r["report.incidents"])
    ck(r["_holmes"] == 1, "홈즈 분리 실패")
    ck(r["report.chronic"] == 1 and r["report.novel"] == 1, "만성/신규 판정 집계 오류")
    ck(r["report.by_severity"].startswith("high:"), "심각도 분포 형식")
    ck(r["report.response_s"] > 0, "초동 대응 중앙값이 0")

    # 승인 게이트 — 고객에게 나가는 문서이므로 기본값이 미승인이어야 한다.
    ck(r["report.summary"] == PENDING, "승인 전에 LLM 서사가 전송 대상에 실렸다")
    d = r["_summary_draft"]
    ck("브루트포스" in d, "원인 절(2)) 추출 실패")
    ck("발신지 차단" in d, "권고 절(4)) 추출 실패")
    ck("로그 급증" in d, "② 원문자 스타일 절 추출 실패")
    ck("자유 텍스트" in d, "절 없는 분석의 폴백 실패")
    ck("[만성]" in d, "판정 표기 누락")

    # sender 는 내부 필드를 보내면 안 된다(Zabbix 에 그런 아이템이 없어 failed 로 잡힌다).
    ck(all(not k.startswith("_") for k in r if k.startswith("report.")) and
       any(k.startswith("_") for k in r), "내부 필드 규약 위반")

    print("ALL OK (%d checks)" % n)


def main():
    ap = argparse.ArgumentParser(description="MSP 월간 리포트 집계 (Keep 읽기 → Zabbix trapper)")
    ap.add_argument("--selftest", action="store_true", help="Keep 없이 집계·승인 게이트 검사")
    ap.add_argument("--days", type=int, default=30)
    ap.add_argument("--host-filter", default="", help="이 문자열이 host 에 포함된 알림만")
    ap.add_argument("--target", help="값을 받을 Zabbix 호스트명 (예: report-Customer-B)")
    ap.add_argument("--send", action="store_true", help="실제 전송. 없으면 계산만(드라이런)")
    ap.add_argument("--approve", action="store_true",
                    help="LLM 서사(report.summary)까지 전송. 사람이 초안을 검토한 뒤에만 쓴다")
    ap.add_argument("--draft-to-keep", action="store_true",
                    help="요약 초안을 Keep 승인 큐에 등록(데모 B 와 같은 승인 UI)")
    ap.add_argument("--keep-url", default=os.environ.get("KEEP_URL", ""))
    ap.add_argument("--zabbix-server", default=os.environ.get("ZBX_TRAPPER_HOST", "127.0.0.1"))
    ap.add_argument("--zabbix-port", type=int,
                    default=int(os.environ.get("ZBX_TRAPPER_PORT", "10051")))
    a = ap.parse_args()

    if a.selftest:
        selftest()
        return
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
    n_inc = res["report.incidents"]
    if n_inc:
        print("\n  원시 알림 %d건 → 사건 %d건" % (res["report.alerts"], n_inc), end="")
        if res["report.alerts"]:
            print("  (%.1f:1)" % (res["report.alerts"] / n_inc))
        else:
            print()
        print("  그중 병합 사건 %d건 (알림 %d건이 접힘)" % (res["_merged"], res["_folded"]))
        cov = 100 * res["_judged"] / n_inc
        print("  만성/신규 판정이 붙은 사건 %d/%d (%.0f%%)" % (res["_judged"], n_inc, cov))
        if cov < 60:
            print("    ↳ 판정 커버리지가 낮다. Wazuh 알림은 trigger_id 가 없어 선판정이 안 "
                  "붙는다(로드맵 G11). 만성/신규 수치를 전체로 읽지 말 것.")
    print("  심층조사(홈즈) %d건" % res["_holmes"])

    print()
    print("-" * 62)
    print("주요 사건 요약 초안  (LLM 서사 — 승인 전에는 전송되지 않는다)")
    print("-" * 62)
    print(res["_summary_draft"])

    if a.draft_to_keep:
        _push_draft(a.target or "(미지정)", res["_summary_draft"])

    if a.approve:
        # 사람이 위 초안을 읽고 승인한 경우에만 서사가 실린다. 고객에게 나가는 문서이므로
        # 시스템 변경(Ansible 조치)과 같은 등급으로 다룬다 — 읽기=자동/쓰기=승인.
        res["report.summary"] = res["_summary_draft"]
        print("\n[승인됨] report.summary 에 서사를 싣는다.")
    else:
        print("\n[미승인] report.summary = %r 로 나간다. 승인하려면 --approve." % PENDING)

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
