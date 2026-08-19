#!/usr/bin/env python3
"""MSP 월간 리포트 집계 — Keep 알림 이력에서 봇만 계산할 수 있는 값을 뽑아 Zabbix 로 보낸다."""

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
# 승인 초안이 자기 자신을 오염시키지 않도록 별도 source 로 넣고 집계에서 뺀다
REPORT_SOURCE = "kinx-report"

# 접두로 판정한다 — 접미사가 붙거나 판정이 아닌 값이 들어간 옛 레코드가 섞여 있다
VERDICTS = ("만성", "재발", "신규")


def verdict_of(a: dict) -> str:
    v = str(a.get("prejudge") or "").strip()
    for k in VERDICTS:
        if v.startswith(k):
            return k
    return ""          # 미상·오염값·없음 — 전부 판정 없음으로 본다


PENDING = "검토 대기 — 승인 후 게시됩니다"

# "없음"을 명시적으로 보낸다 — 0 은 "전부 실패"로 읽히고 안 보내면 지난 값이 남는다
NOT_MEASURED = -1
NOT_MEASURED_TEXT = "미산출 — 이 범위에서 집계된 데이터 없음"

# 봇 분석은 번호 절로 강제돼 있다 — 새 호출 없이 이미 만들어진 분석에서 절만 잘라 쓴다
_SEC = {
    "cause": re.compile(r"\*\*\s*(?:2\)|②)[^\n]*\*\*(.*?)(?=\*\*\s*(?:3\)|③)|\Z)", re.S),
    "action": re.compile(r"\*\*\s*(?:4\)|④)[^\n]*\*\*(.*?)(?=\*\*\s*(?:5\)|⑤)|\Z)", re.S),
}


def _first_line(block: str, limit: int = 150) -> str:
    """절에서 첫 실질 줄만. 마크다운 강조·불릿 기호를 걷어낸다."""
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


SEV_ORDER = ("Critical", "High", "Medium", "Low")
# 팀 Slack 컷라인(레벨 10) 위로 승격해 둔 파일 무결성 룰. 이 아래는 대시보드용이다.
FIM_PROMOTED_MIN = 12


def _wz_search(index: str, body: dict) -> dict:
    """Wazuh Indexer 검색. 실패는 예외로 올린다 — 호출측이 '0건'과 구분해야 하기 때문이다."""
    import httpx
    url = os.environ.get("WAZUH_INDEXER_URL", "").rstrip("/")
    if not url:
        raise RuntimeError("WAZUH_INDEXER_URL 미설정")
    auth = (os.environ.get("WAZUH_INDEXER_USER", ""),
            os.environ.get("WAZUH_INDEXER_PASSWORD", ""))
    # 랩 인덱서는 자체서명 TLS. 프로덕션은 사내 CA 로 verify=True 로 돌려야 한다.
    r = httpx.post(f"{url}/{index}/_search", json=body, auth=auth, verify=False, timeout=30)
    r.raise_for_status()
    return r.json()


def _terms(index: str, query: dict, field: str) -> Counter:
    """terms 집계. 매핑이 text 면 field.keyword 로 한 번 더 시도한다."""
    last = None
    for f in (field, field + ".keyword"):
        try:
            b = {"size": 0, "query": query, "aggs": {"g": {"terms": {"field": f, "size": 20}}}}
            buckets = _wz_search(index, b)["aggregations"]["g"]["buckets"]
            return Counter({str(x["key"]): x["doc_count"] for x in buckets})
        except Exception as e:
            last = e
    raise RuntimeError("terms 집계 실패 %s: %s" % (field, str(last)[:200]))


def security_posture(agent_filter: str, days: int) -> dict:
    """SCA 준수율 · 파일 무결성 · 취약점 재고. 상태를 반드시 함께 반환한다."""
    if not os.environ.get("WAZUH_INDEXER_URL"):
        return {"status": "disabled"}
    # 접두 일치로 잡는다 — 양쪽 와일드카드면 다른 고객 수치가 이 리포트에 합산된다
    who = [{"prefix": {"agent.name": agent_filter}}] if agent_filter else []
    win = {"range": {"@timestamp": {"gte": "now-%dd" % days}}}
    # 절마다 따로 잡는다 — 인덱스 하나가 없다고 SCA·FIM 결과까지 버리면 안 된다
    out = {"status": "ok", "errors": []}

    try:
        # 설정 준수율 — SCA 점수는 스캔마다 기록되므로 기간 평균으로 본다.
        agg = _wz_search("wazuh-alerts-*", {
            "size": 0,
            "query": {"bool": {"must": who + [win, {"exists": {"field": "data.sca.score"}}]}},
            "aggs": {"avg": {"avg": {"field": "data.sca.score"}},
                     "hosts": {"cardinality": {"field": "agent.id"}}},
        }).get("aggregations", {})
        score = agg.get("avg", {}).get("value")
        out["compliance"] = round(score, 1) if score is not None else None
        out["scanned"] = int(agg.get("hosts", {}).get("value") or 0)
    except Exception as e:
        out["errors"].append("설정 준수율: %s" % str(e)[:100])

    try:
        # 파일 무결성 — 전체 변경 건수와, 그중 승격 룰에 걸린 건수를 나눠 센다.
        def fim(extra):
            q = {"bool": {"must": who + [win, {"term": {"rule.groups": "syscheck"}}] + extra}}
            return _wz_search("wazuh-alerts-*", {"size": 0, "query": q})["hits"]["total"]["value"]
        out["fim_all"] = int(fim([]))
        out["fim_promoted"] = int(fim([{"range": {"rule.level": {"gte": FIM_PROMOTED_MIN}}}]))
    except Exception as e:
        out["errors"].append("파일 무결성: %s" % str(e)[:100])

    try:
        # 취약점은 시계열이 아니라 **현재 재고 스냅샷**이라 기간 조건을 걸지 않는다.
        idx = "wazuh-states-vulnerabilities-*"
        base = {"bool": {"must": who}} if who else {"match_all": {}}
        out["vuln"] = _terms(idx, base, "vulnerability.severity")
        # 재고 총계만 실으면 읽는 사람이 쓸 수 없다 — 이번 달 신규와 패키지 상위를 더한다
        new_q = {"bool": {"must": who + [{"range": {"vulnerability.detected_at":
                                                    {"gte": "now-%dd" % days}}}]}}
        out["vuln_new"] = _terms(idx, new_q, "vulnerability.severity")
        out["vuln_pkg"] = _terms(idx, base, "package.name")
    except Exception as e:
        out["errors"].append("취약점: %s" % str(e)[:100])

    if len(out["errors"]) == 3:
        out["status"] = "unavailable"
    return out


def posture_items(p: dict) -> dict:
    """보안 절을 trapper 값으로. 상태가 ok 가 아니면 **숫자를 만들지 않는다.**"""
    if p.get("status") != "ok":
        why = {"disabled": "보안 연동 미설정 — 이 절은 집계 대상이 아님",
               "unavailable": "조회 불가 — 이 절의 수치는 집계되지 않음"}.get(p.get("status"), "상태 미상")
        # 숫자·문장 항목 모두 "없음"을 보낸다 — 안 보내면 지난 집계 값이 그대로 남는다
        return {"report.security_status": why, "report.compliance": NOT_MEASURED,
                "report.fim": NOT_MEASURED_TEXT, "report.vuln": NOT_MEASURED_TEXT,
                "report.vuln_top": NOT_MEASURED_TEXT}

    # 산출 못 했으면 옛 값이 남지 않도록 "없음" 을 명시적으로 보낸다.
    out = {"report.compliance": p.get("compliance")
           if p.get("compliance") is not None else NOT_MEASURED}
    if "fim_all" in p:
        out["report.fim"] = "승격 룰 %d건 / 전체 파일 변경 %d건" % (p["fim_promoted"], p["fim_all"])
    else:
        out["report.fim"] = NOT_MEASURED_TEXT
    if "vuln" in p:
        def sev_line(c):
            return " / ".join("%s %d" % (s, c[s]) for s in SEV_ORDER if c.get(s))
        new = p.get("vuln_new") or Counter()
        total = sum(p["vuln"].values())
        n_new = sum(new.values())
        if not total:
            out["report.vuln"] = "취약점 재고 없음"
        elif n_new >= total * 0.95:
            # 처음 붙인 기간이면 재고 전량이 "이번 달 탐지"로 잡힌다 — 기준선이라고 밝힌다
            out["report.vuln"] = ("최초 스캔 기준선 — 재고 %d건 (%s). 신규 증분은 다음 기간부터 유효"
                                  % (total, sev_line(p["vuln"])))
        else:
            # 실행 가능한 숫자를 앞에 둔다 — "이번 달 새로 생긴 것" 이 먼저고 재고 총계는 뒤다.
            out["report.vuln"] = ("이번 달 신규 %d건 (%s) · 전체 재고 %d건 (%s)"
                                  % (n_new, sev_line(new) or "없음",
                                     total, sev_line(p["vuln"])))
        pkg = p.get("vuln_pkg") or Counter()
        if pkg:
            top = pkg.most_common(3)
            share = 100 * sum(n for _, n in top) / total if total else 0
            out["report.vuln_top"] = ("%s — 상위 3개가 전체의 %.0f%%"
                                      % (" / ".join("%s %d건" % (k, n) for k, n in top), share))
        else:
            out["report.vuln_top"] = NOT_MEASURED_TEXT
    else:
        out["report.vuln"] = NOT_MEASURED_TEXT
        out["report.vuln_top"] = NOT_MEASURED_TEXT

    ok_n = sum(1 for k in ("report.compliance", "report.fim", "report.vuln")
               if k in out and out[k] not in (NOT_MEASURED, NOT_MEASURED_TEXT))
    note = "정상 집계 (점검 대상 %d대)" % p.get("scanned", 0)
    if p.get("compliance") is None and "설정 준수율" not in " ".join(p.get("errors", [])):
        note = "설정 점검 결과 없음 — 준수율 미산출"
    if p.get("errors"):
        # 무엇이 빠졌는지 리포트에 그대로 쓴다. 빠진 절을 조용히 비우면 "해당 없음" 으로 읽힌다.
        note = "부분 집계 (%d/3) — 미집계: %s" % (ok_n, " ; ".join(p["errors"]))
    out["report.security_status"] = note
    return out


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
    """봇 알림만 사건으로 센다. Zabbix 가 직접 넣은 원시 알림은 사건이 아니다."""
    since = datetime.now(timezone.utc) - timedelta(days=days)
    win = [a for a in alerts if _ts(a) >= since]
    if host_filter:
        win = [a for a in win if host_filter in (a.get("host") or "")]

    def src(a):
        return a.get("source") or []

    win = [a for a in win if REPORT_SOURCE not in src(a)]

    # 원시 알림과 사건은 별개 레코드라 겹쳐 세지 않는다
    incidents = [a for a in win if BOT_SOURCE in src(a)]
    raw = [a for a in win if BOT_SOURCE not in src(a) and HOLMES_SOURCE not in src(a)]
    holmes = [a for a in win if HOLMES_SOURCE in src(a)]
    merged = [a for a in incidents if int(a.get("alert_count") or 1) > 1]
    # "완료" 가 아니라 "등록" 이다 — 실제 실행은 Keep 워크플로 기록이고 알림 레코드만으론 모른다.
    candidates = [a for a in win if a.get("playbook")]

    verdicts = Counter(verdict_of(a) for a in incidents)
    judged = sum(verdicts[k] for k in VERDICTS)
    sev = Counter(str(a.get("severity") or "?") for a in incidents)

    # 초동 대응 = 원시 알림 → 봇 사건 게시. 정확한 인과 짝이 아니므로 중앙값으로만 쓴다
    gaps = []
    for inc in incidents:
        t_inc = _ts(inc)
        prior = [_ts(r) for r in raw
                 if r.get("host") == inc.get("host") and _ts(r) <= t_inc]
        if prior:
            gaps.append((t_inc - max(prior)).total_seconds())
    # 짝이 없으면 0.0 을 보내지 않는다 — "초동 대응 0초"로 읽혀 실제보다 좋아 보인다.
    response = round(statistics.median(gaps), 1) if gaps else None

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

    # 근거 커버리지 — sources 가 없는 옛 레코드는 세지 않는다(모르는 것을 확보로 세면 과장)
    with_src = [a for a in incidents if a.get("sources")]
    ev_logs = sum(1 for a in with_src if "logs:ok" in str(a.get("sources")))
    ev_sec = sum(1 for a in with_src if "security:ok" in str(a.get("sources")))

    out = {
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
        "report.evidence": ("로그 근거 %d건 / 보안 근거 %d건 (근거 기록이 있는 사건 %d건 중)"
                            % (ev_logs, ev_sec, len(with_src))) if with_src
                           else "근거 기록 없음 — 이 항목 도입 이전 사건",
        # 승인 전에는 서사가 나가지 않는다. 호출측(--approve)이 이 두 값을 덮어쓴다.
        "report.summary": PENDING,
        "report.insight": PENDING,
        "report.period": "%s ~ %s (%d일)" % (since.astimezone().strftime("%Y-%m-%d"),
                                             datetime.now().strftime("%Y-%m-%d"), days),
        "_summary_draft": summary,
        "_incidents": incidents,
        "_holmes": len(holmes),
        "_merged": len(merged),
        "_folded": sum(int(a.get("alert_count") or 1) for a in merged),
        # 판정이 붙은 사건 비율 — 낮으면 만성/신규 수치를 전체로 읽으면 안 된다 (G11)
        "_judged": judged,
        "_window_alerts": len(win),
        "_gaps": len(gaps),
    }
    out["report.response_s"] = response if response is not None else NOT_MEASURED
    return out


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


def _guess_group(target: str) -> str:
    """report-Customer-B -> Customers/Customer-B. 우리가 만든 이름 규칙이라 유추해도 된다."""
    short = target[len("report-"):] if target.startswith("report-") else target
    return "Customers/%s" % short


def draft_path(target: str) -> str:
    d = os.environ.get("REPORT_DRAFT_DIR") or os.path.join(
        os.path.expanduser("~"), ".kinx-report-drafts")
    safe = re.sub(r"[^A-Za-z0-9_.-]", "_", target or "unknown")
    return os.path.join(d, safe + ".txt")


def save_draft(target: str, draft: str) -> str:
    """승인한 문장과 실제로 나가는 문장이 같아야 한다."""
    p = draft_path(target)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "w", encoding="utf-8") as f:
        f.write(draft)
    return p


def load_draft(target: str) -> str:
    p = draft_path(target)
    if not os.path.exists(p):
        sys.exit("[!] 승인할 초안이 없다: %s\n"
                 "    먼저 --draft-to-keep 로 초안을 만들고 사람이 검토해야 한다." % p)
    with open(p, encoding="utf-8") as f:
        return f.read()


def _push_draft(target: str, draft: str, extra: dict = None) -> None:
    """요약 초안을 Keep 승인 큐에 올린다 — 데모 B 의 조치 후보와 같은 자리, 같은 UI."""
    # `bot/` 을 경로에 넣는다. 이 파일이 bot/tools/ 로 내려갔으므로 부모다.
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    try:
        from gateway.integrations import keep
    except ImportError as e:
        print("[keep] 초안 등록 건너뜀 — %s" % e)
        return
    note = ("*월간 리포트 요약 — 승인 대기*\n대상: `%s`\n\n"
            "아래 서사는 LLM 이 만든 것이고 **고객에게 나가는 문서**다. 검토 후 승인해야 "
            "리포트에 실린다. 미승인이면 %r 로 나간다.\n\n```\n%s\n```" % (target, PENDING, draft))
    res = keep.push_alert("월간 리포트 승인 대기 — %s" % target, "SEV3", target, note,
                          source=REPORT_SOURCE, playbook="report_approve",
                          fingerprint="msp-report|%s" % target, extra=extra)
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
           alert_count=3, analysis=body, sources="logs:ok,security:ok"),
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
    # 짝지을 원시 알림이 없으면 값을 만들지 않는다 — 0.0 은 "0초 대응" 으로 읽힌다.
    r_no = aggregate([mk(BOT_SOURCE, name="사건만", prejudge="신규", analysis="x")], 30)
    ck(r_no["report.response_s"] == NOT_MEASURED,
       "측정 불가를 0 으로 냈거나 아예 안 보냈다(안 보내면 옛 값이 남는다)")

    # 승인 게이트 — 고객에게 나가는 문서이므로 기본값이 미승인이어야 한다.
    ck(r["report.summary"] == PENDING, "승인 전에 LLM 서사가 전송 대상에 실렸다")
    d = r["_summary_draft"]
    ck("브루트포스" in d, "원인 절(2)) 추출 실패")
    ck("발신지 차단" in d, "권고 절(4)) 추출 실패")
    ck("로그 급증" in d, "② 원문자 스타일 절 추출 실패")
    ck("자유 텍스트" in d, "절 없는 분석의 폴백 실패")
    ck("[만성]" in d, "판정 표기 누락")

    ck(r["report.insight"] == PENDING, "월간 분석도 승인 전에는 나가면 안 된다")

    # 근거 커버리지 — sources 기록이 있는 사건만 센다.
    ck("로그 근거 1건" in r["report.evidence"] and "보안 근거 1건" in r["report.evidence"],
       "근거 커버리지 오집계: %s" % r["report.evidence"])

    # sender 는 내부 필드를 보내면 안 된다(Zabbix 에 그런 아이템이 없어 failed 로 잡힌다).
    ck(all(not k.startswith("_") for k in r if k.startswith("report.")) and
       any(k.startswith("_") for k in r), "내부 필드 규약 위반")

    # 보안 절 — 조회 실패로 절대 숫자를 만들면 안 된다. "취약점 0건"은 안전 신호로 읽힌다
    for st in ("unavailable", "disabled"):
        p = posture_items({"status": st})
        # 숫자를 만들지 않되, 항목 자체는 보낸다 — 안 보내면 지난 집계 값이 그대로 남는다.
        ck(p["report.fim"] == NOT_MEASURED_TEXT and p["report.vuln"] == NOT_MEASURED_TEXT
           and p["report.vuln_top"] == NOT_MEASURED_TEXT,
           "%s 인데 보안 문장 항목에 옛 값이 남을 수 있다" % st)
        ck(p["report.compliance"] == NOT_MEASURED,
           "%s 인데 준수율에 옛 값이 남을 수 있다" % st)
        ck("report.security_status" in p, "%s 상태를 리포트에 알리지 않았다" % st)
    p = posture_items({"status": "ok", "compliance": 52.4, "scanned": 4,
                       "fim_all": 107, "fim_promoted": 3,
                       "vuln": Counter({"High": 10, "Critical": 13, "Low": 5}),
                       "vuln_new": Counter({"Critical": 2}),
                       "vuln_pkg": Counter({"kernel": 14, "glibc": 8, "curl": 4, "vim": 2})})
    ck(p["report.compliance"] == 52.4 and "4대" in p["report.security_status"], "정상 집계 형식")
    # 실행 가능한 숫자(이번 달 신규)가 앞, 재고 총계가 뒤. 재고만 내면 읽는 사람이 못 쓴다.
    ck(p["report.vuln"].startswith("이번 달 신규 2건 (Critical 2)"),
       "신규가 앞에 안 왔다: %s" % p["report.vuln"])
    ck("전체 재고 28건 (Critical 13 / High 10 / Low 5)" in p["report.vuln"],
       "재고 심각도 정렬: %s" % p["report.vuln"])
    ck(p["report.vuln_top"].startswith("kernel 14건 / glibc 8건 / curl 4건")
       and "93%" in p["report.vuln_top"], "상위 패키지 형식: %s" % p["report.vuln_top"])
    ck("승격 룰 3건" in p["report.fim"], "FIM 형식")
    # 최초 스캔이면 재고 전량이 신규로 잡힌다 — "이번 달 1.4만 건 발생" 으로 읽히면 안 된다.
    pb = posture_items({"status": "ok", "compliance": 1.0, "scanned": 1,
                        "vuln": Counter({"High": 100}), "vuln_new": Counter({"High": 100})})
    ck(pb["report.vuln"].startswith("최초 스캔 기준선"), "기준선 표기 누락: %s" % pb["report.vuln"])
    # 점검 결과가 없으면 준수율을 0% 로 만들지 않는다(0% 는 "전부 실패" 로 읽힌다).
    p0 = posture_items({"status": "ok", "compliance": None, "scanned": 0,
                        "fim_all": 0, "fim_promoted": 0, "vuln": Counter()})
    ck(p0["report.compliance"] == NOT_MEASURED, "점검 결과 없음을 준수율 0 으로 냈다")
    # 고객 범위에 취약점이 없으면 상위 패키지도 낼 수 없다 — 안 보내면 랩 전체 통계가 남는다
    ck(p0["report.vuln_top"] == NOT_MEASURED_TEXT,
       "재고 0인데 상위 패키지를 안 보냈다 — 다른 호스트의 옛 값이 남는다")

    # 한 절이 실패해도 나머지는 살아야 한다 — 2026-07-31 결함의 회귀 검사
    pp = posture_items({"status": "ok", "compliance": 52.4, "scanned": 4,
                        "fim_all": 107, "fim_promoted": 3, "errors": ["취약점: 인덱스 없음"]})
    ck("report.compliance" in pp and "report.fim" in pp, "한 절 실패로 나머지가 버려졌다")
    ck(pp["report.vuln"] == NOT_MEASURED_TEXT and pp["report.vuln_top"] == NOT_MEASURED_TEXT,
       "실패한 절에 숫자를 만들었거나, 안 보내서 옛 값이 남는다")
    ck("부분 집계 (2/3)" in pp["report.security_status"] and "취약점" in pp["report.security_status"],
       "무엇이 빠졌는지 리포트에 안 적었다: %s" % pp["report.security_status"])

    # 초안 왕복 — 승인이 게시하는 문장은 사람이 읽은 그 문장이어야 한다.
    import tempfile
    os.environ["REPORT_DRAFT_DIR"] = tempfile.mkdtemp()
    SEP = "\n\n[월간 종합 분석]\n"
    body2 = "· 사건 A\n   원인: 가." + SEP + "**1) 한 줄**\n조용한 달."
    pth = save_draft("report-Customer-B", body2)
    ck(os.path.exists(pth), "초안 파일이 안 만들어졌다")
    ck(load_draft("report-Customer-B") == body2, "초안 왕복이 깨졌다")
    head, tail = body2.split(SEP)
    ck(tail.startswith("**1)"), "월간 분석 절 분리")
    ck("[월간 종합 분석]" not in head, "요약에 월간 분석이 섞였다")
    ck(_guess_group("report-Customer-B") == "Customers/Customer-B", "그룹 유추")

    print("ALL OK (%d checks)" % n)


def main():
    ap = argparse.ArgumentParser(description="MSP 월간 리포트 집계 (Keep 읽기 → Zabbix trapper)")
    ap.add_argument("--selftest", action="store_true", help="Keep 없이 집계·승인 게이트 검사")
    ap.add_argument("--days", type=int, default=30)
    ap.add_argument("--host-filter", default="", help="이 문자열이 host 에 포함된 알림만")
    ap.add_argument("--agent-filter", default="",
                    help="Wazuh agent.name 필터. 생략 시 --host-filter 를 쓴다")
    ap.add_argument("--target", help="값을 받을 Zabbix 호스트명 (예: report-Customer-B)")
    ap.add_argument("--send", action="store_true", help="실제 전송. 없으면 계산만(드라이런)")
    ap.add_argument("--approve", action="store_true",
                    help="LLM 서사(report.summary)까지 전송. 사람이 초안을 검토한 뒤에만 쓴다")
    ap.add_argument("--from-draft", action="store_true",
                    help="저장된 초안을 그대로 게시(승인 실행용). 재생성하지 않는다")
    ap.add_argument("--customer-group", default="",
                    help="Grafana 대시보드 변수용 그룹 (예: Customers/Customer-B)")
    ap.add_argument("--recipient", default="", help="리포트 수신자 메일 (승인 큐에 실어 보냄)")
    ap.add_argument("--allow-unscoped", action="store_true",
                    help="범위 지정 없이 전체 집계를 고객 리포트로 보낸다(랩 시연 전용)")
    ap.add_argument("--insight", action="store_true",
                    help="월간 종합 분석 LLM 1회 호출(고객당 월 1회). 승인 게이트 아래에 있다")
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
    # 범위 게이트 — 기본값을 거부로 둔다. 밖으로 나가는 첫 지점보다 앞이어야 한다
    if not (a.host_filter or a.agent_filter) and not a.allow_unscoped:
        sys.exit("[!] 범위가 지정되지 않았다 — --host-filter 없이 돌리면 다른 고객·사내 "
                 "호스트가 이 고객 리포트에 실리고, 외부 분석에도 그대로 나간다.\n"
                 "    고객별: --host-filter <이 고객 호스트 접두>\n"
                 "    랩 시연처럼 알고도 전체를 넣으려면: --allow-unscoped")
    alerts = fetch_alerts(a.keep_url, os.environ.get("KEEP_API_KEY", ""))
    res = aggregate(alerts, a.days, a.host_filter)

    posture = security_posture(a.agent_filter or a.host_filter, a.days)
    res.update(posture_items(posture))
    if posture.get("why"):
        print("[!] 보안 조회 실패: %s" % posture["why"])

    print("=" * 62)
    print("MSP 월간 리포트 집계  (Keep %d건 조회, 창 안 %d건)" % (len(alerts), res["_window_alerts"]))
    print("=" * 62)
    for k, v in res.items():
        if not k.startswith("_"):
            print("  %-26s %s" % (k, v))
    n_inc = res["report.incidents"]
    if n_inc:
        print("\n  원시 알림 %d건 → 사건 %d건" % (res["report.alerts"], n_inc), end="")
        if res.get("report.alerts"):
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

    insight = ""
    if a.insight:
        # `bot/` 을 경로에 넣는다. 이 파일이 bot/tools/ 로 내려갔으므로 부모다.
        sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        from gateway import llm
        r = llm.monthly_reply({k: v for k, v in res.items() if not k.startswith("_")},
                              res["_incidents"])
        insight = r["text"]
        print("\n[llm] 월간 분석 %s (%.1fs)%s"
              % (r["provider"], r["elapsed_s"], " · 열화" if r["degraded"] else ""))

    print()
    print("-" * 62)
    print("승인 대기 초안  (LLM 서사 — 승인 전에는 전송되지 않는다)")
    print("-" * 62)
    print("[사건 요약]")
    print(res["_summary_draft"])
    if insight:
        print("\n[월간 종합 분석]")
        print(insight)

    draft = res["_summary_draft"] + (("\n\n[월간 종합 분석]\n" + insight) if insight else "")
    if a.draft_to_keep:
        tgt = a.target or "(미지정)"
        print("[draft] %s" % save_draft(tgt, draft))
        # 워크플로가 실행에 필요한 값을 알림에서 읽는다 — 고객·수신자를 하드코딩하지 않는다
        _push_draft(tgt, draft, extra={
            "customer": a.customer_group or _guess_group(tgt),
            "host_filter": a.host_filter, "recipient": a.recipient})

    if a.from_draft:
        # 사람이 읽고 승인한 **그 문장**을 게시한다. 다시 만들면 다른 글이 나간다.
        saved = load_draft(a.target or "")
        res["report.summary"] = saved.split("\n\n[월간 종합 분석]\n")[0]
        if "\n\n[월간 종합 분석]\n" in saved:
            res["report.insight"] = saved.split("\n\n[월간 종합 분석]\n", 1)[1]
        print("\n[승인됨] 저장된 초안을 그대로 싣는다 (%s)" % draft_path(a.target or ""))
    elif a.approve:
        # 사람이 초안을 읽고 승인한 경우에만 서사가 실린다 — 읽기=자동 / 쓰기=승인
        res["report.summary"] = res["_summary_draft"]
        if insight:
            res["report.insight"] = insight
        print("\n[승인됨] 서사를 리포트에 싣는다.")
    else:
        print("\n[미승인] LLM 서사 항목은 %r 로 나간다. 승인하려면 --approve." % PENDING)

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
