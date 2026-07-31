"""KINX MSP 월간 리포트 Grafana 대시보드 생성기 (일회성 — 산출물은 JSON)."""
import io
import json
import os

ZBX = {"type": "alexanderzobnin-zabbix-datasource", "uid": "zabbix"}
WZ = {"type": "grafana-opensearch-datasource", "uid": "wazuh"}
WZS = {"type": "grafana-opensearch-datasource", "uid": "wazuh-states"}
LOKI = {"type": "loki", "uid": "loki"}
_id = [0]


def nid():
    _id[0] += 1
    return _id[0]


# 호스트 필터는 **표시명**에 걸린다(플러그인 동작, 2026-07-31 실측). 리포트 호스트의
# 표시명이 기술명과 같은 접두로 시작하도록 msp_report.yml 에서 맞춰 두었다.
def zt(item, host="/^report-/", qtype="0", fmt="time_series"):
    return {"refId": "A", "datasource": ZBX, "queryType": qtype,
            "group": {"filter": "$customer"}, "host": {"filter": host},
            "application": {"filter": ""}, "item": {"filter": item},
            "itemTag": {"filter": ""}, "macro": {"filter": ""}, "proxy": {"filter": ""},
            "functions": [], "textFilter": "", "resultFormat": fmt,
            "options": {"showDisabledItems": False, "skipEmptyValues": False,
                        "useTrends": "default", "useZabbixValueMapping": False}}


def stat(title, item, x, y, w, h, unit="", desc="", dec=0):
    return {"id": nid(), "type": "stat", "title": title, "description": desc,
            "datasource": ZBX, "gridPos": {"h": h, "w": w, "x": x, "y": y},
            "targets": [zt(item)],
            "fieldConfig": {"defaults": {"color": {"mode": "thresholds"}, "mappings": [],
                                         "decimals": dec, "unit": unit,
                                         "thresholds": {"mode": "absolute",
                                                        "steps": [{"color": "text"}]}},
                            "overrides": []},
            "options": {"colorMode": "none", "graphMode": "none", "justifyMode": "auto",
                        "orientation": "auto", "textMode": "value_and_name",
                        "reduceOptions": {"calcs": ["lastNotNull"], "fields": "",
                                          "values": False}}}


def textbl(title, item, x, y, w, h, desc=""):
    return {"id": nid(), "type": "table", "title": title, "description": desc,
            "datasource": ZBX, "gridPos": {"h": h, "w": w, "x": x, "y": y},
            "targets": [zt(item, qtype="2", fmt="table")],
            "fieldConfig": {"defaults": {"custom": {"align": "left", "filterable": False,
                                                    "cellOptions": {"type": "auto",
                                                                    "wrapText": True}},
                                         "mappings": []},
                            "overrides": [
                                {"matcher": {"id": "byName", "options": "Item"},
                                 "properties": [{"id": "custom.width", "value": 190}]},
                                {"matcher": {"id": "byName", "options": "Key"},
                                 "properties": [{"id": "custom.hidden", "value": True}]},
                                {"matcher": {"id": "byName", "options": "Host"},
                                 "properties": [{"id": "custom.hidden", "value": True}]}]},
            "options": {"showHeader": True, "cellHeight": "sm",
                        "footer": {"show": False, "reducer": ["sum"], "countRows": False,
                                   "fields": ""}}}


def row(title, y):
    return {"id": nid(), "type": "row", "title": title, "collapsed": False,
            "gridPos": {"h": 1, "w": 24, "x": 0, "y": y}, "panels": []}


def ts_zbx(title, item, x, y, w, h, unit="", repeat=None):
    p = {"id": nid(), "type": "timeseries", "title": title, "datasource": ZBX,
         "gridPos": {"h": h, "w": w, "x": x, "y": y},
         "targets": [zt(item, host="$host")],
         "fieldConfig": {"defaults": {"unit": unit,
                                      "custom": {"lineWidth": 1, "fillOpacity": 8,
                                                 "showPoints": "never"}},
                         "overrides": []},
         "options": {"legend": {"displayMode": "list", "placement": "bottom",
                                "showLegend": True},
                     "tooltip": {"mode": "multi", "sort": "none"}}}
    if repeat:
        p["repeat"] = repeat
        p["repeatDirection"] = "h"
    return p


def wz(title, query, x, y, w, h, ds=WZ, terms=None, desc=""):
    if terms:
        buckets = [{"field": terms, "id": "3", "type": "terms",
                    "settings": {"min_doc_count": "0", "order": "desc",
                                 "orderBy": "_count", "size": "10"}}]
    else:
        buckets = [{"field": "@timestamp", "id": "2", "type": "date_histogram",
                    "settings": {"interval": "auto", "min_doc_count": "0"}}]
    return {"id": nid(), "type": "table" if terms else "timeseries", "title": title,
            "description": desc, "datasource": ds,
            "gridPos": {"h": h, "w": w, "x": x, "y": y},
            "targets": [{"refId": "A", "datasource": ds, "alias": "", "format": "table",
                         "luceneQueryType": "Metric", "query": query,
                         "queryType": "lucene", "timeField": "@timestamp",
                         "bucketAggs": buckets, "metrics": [{"id": "1", "type": "count"}]}],
            "fieldConfig": {"defaults": {}, "overrides": []},
            "options": {"showHeader": True} if terms else
                       {"legend": {"displayMode": "list", "placement": "bottom",
                                   "showLegend": True},
                        "tooltip": {"mode": "multi", "sort": "none"}}}


P = []
y = 0
P.append(row("1. 이번 달 요약 — 무슨 일이 있었나", y))
y += 1
P.append(stat("원시 알림", "월간 알림 수", 0, y, 6, 4,
              desc="감시 시스템이 낸 알림 수. 오른쪽 '사건'과 짝으로 읽는다."))
P.append(stat("→ 사건 (병합 후)", "월간 사건 수 (병합 후)", 6, y, 6, 4,
              desc="봇이 (호스트, 유형)으로 묶어 확정한 사건 수. Zabbix 단독으로는 낼 수 없는 값."))
P.append(stat("만성 사건", "만성 사건 수", 12, y, 6, 4,
              desc="90일 내 반복. 자동화 1순위 후보."))
P.append(stat("자동 조치 후보 등록", "자동 조치 후보 등록", 18, y, 6, 4,
              desc="'완료'가 아니라 '등록'이다. 실행 여부는 워크플로 기록에 있다."))
y += 4
P.append(textbl("월간 종합 분석 (승인 후 게시)", "월간 종합 분석", 0, y, 14, 11,
                desc="LLM 서사. 승인 전에는 '검토 대기'가 표시된다."))
P.append(textbl("집계 기간 · 판단 근거 · 보안 집계 상태",
                "/집계 기간|판단 근거 커버리지|보안 집계 상태/", 14, y, 10, 6,
                desc="'판단 근거'는 로그·보안을 실제로 조회해 판단한 사건 수다."))
P.append(stat("초동 대응 중앙값", "초동 대응 중앙값(초)", 14, y + 6, 10, 5, unit="s", dec=1,
              desc="원시 알림 → 봇 사건 게시. 측정 짝이 없으면 비며 0으로 만들지 않는다."))
y += 11

P.append(row("2. 사건 상세 — 무엇이 반복되나", y))
y += 1
P.append(textbl("주요 사건 요약 (승인 후 게시)", "주요 사건 요약", 0, y, 14, 11))
P.append(textbl("반복 · 유형 · 심각도", "/반복 상위|유형별 분포|심각도 분포/", 14, y, 10, 6))
P.append(stat("신규 사건", "신규 사건 수", 14, y + 6, 10, 5))
y += 11

P.append(row("3. 보안 (Wazuh) — 노출은 어떤가", y))
y += 1
P.append(stat("설정 준수율", "설정 준수율(%, 기간 평균)", 0, y, 6, 6, unit="percent", dec=1,
              desc="CIS 벤치마크 통과 비율. Zabbix 에는 이 데이터가 없다."))
P.append(textbl("취약점 · 상위 패키지 · 파일 무결성", "/취약점|파일 무결성 변경/", 6, y, 18, 6,
                desc="총계가 아니라 '무엇을 고치면 대부분 사라지나'로 낸다."))
y += 6
P.append(wz("인증 활동 — $host 로그인 실패", "rule.groups:authentication_failed AND agent.name:/$host/",
            0, y, 8, 7, desc="집계값이 아니라 Wazuh 를 직접 조회한 실시간 패널."))
P.append(wz("취약점 재고 — $host 심각도별", "agent.name:/$host/", 8, y, 8, 7,
            ds=WZS, terms="vulnerability.severity"))
P.append({"id": nid(), "type": "text", "title": "이 두 패널이 비어 있다면",
          "gridPos": {"h": 7, "w": 8, "x": 16, "y": y},
          "options": {"mode": "markdown", "content":
                      "**빈 패널은 '이상 없음'이 아니다.**\n\n"
                      "왼쪽 두 패널은 Wazuh 를 직접 조회한다. 값이 없다면 그 고객 호스트에 "
                      "`wazuh-agent` 가 배포되지 않은 것이다. 기술 제약이 아니라 배포 여부의 문제이며, "
                      "`ansible/deploy_agents.yml` 이 3종을 한 번에 깐다.\n\n"
                      "반면 위쪽 **보안 집계 상태** 항목은 봇이 집계한 값이고, 조회에 실패하면 "
                      "숫자를 만들지 않고 '조회 불가'라고 적는다 — 실패를 0건으로 보이게 하지 않기 위해서다.\n\n"
                      "에이전트를 못 까는 고객은 프록시에 Wazuh syslog 수신을 얹는 대안이 있다. "
                      "단 그 구간이 PSK/TLS 없는 일반 인터넷이면 암호화 적용과 묶어야 한다."}})
y += 7

P.append(row("4. 로그 (Loki) — 근거", y))
y += 1
P.append({"id": nid(), "type": "logs", "title": "로그 — $host", "datasource": LOKI,
          "description": "리포트 문서에는 로그 본문을 싣지 않는다(고객 자산·반출 표면). "
                         "화면에서는 같은 자리에서 근거를 바로 확인할 수 있다.",
          "gridPos": {"h": 8, "w": 24, "x": 0, "y": y},
          "targets": [{"refId": "A", "datasource": LOKI, "expr": '{host=~"$host"}',
                       "queryType": "range", "direction": "backward",
                       "editorMode": "code"}],
          "options": {"showTime": True, "wrapLogMessage": True, "sortOrder": "Descending",
                      "enableLogDetails": True, "dedupStrategy": "none",
                      "prettifyLogMessage": False}})
y += 8

r = row("5. 자원 — $host", y)
# 행 자체를 호스트마다 반복시킨다. 실환경 MSP_REPORT 대시보드는 서버마다 같은 6종 그래프를
# 손으로 복제해 격자를 만들고 있는데, 그 반복이 여기서는 설정 한 줄이 된다.
r["repeat"] = "host"
P.append(r)
y += 1
P.append(ts_zbx("서버 부하도 — $host", "/^Load average/", 0, y, 12, 7))
P.append(ts_zbx("CPU 사용률 — $host", "/CPU utilization/", 12, y, 12, 7, unit="percent"))
y += 7
P.append(ts_zbx("메모리 사용률 — $host", "/Memory utilization/", 0, y, 12, 7, unit="percent"))
# 아이템 이름은 표준 Linux 템플릿 실측을 따른다 — "FS [/]: Space: Used, in %".
# "Space utilization" 으로 걸면 한 건도 안 잡힌다(2026-07-31 실측).
P.append(ts_zbx("디스크 사용률 — $host", "/Space: Used, in %/", 12, y, 12, 7, unit="percent"))

DASH = {
    "uid": "kinx-msp-report",
    "title": "KINX MSP 월간 리포트",
    "tags": ["kinx", "msp", "report"],
    "timezone": "browser",
    "schemaVersion": 39,
    "version": 0,
    "refresh": "",
    "time": {"from": "now-30d", "to": "now"},
    "editable": True,
    "graphTooltip": 0,
    "templating": {"list": [
        {"name": "customer", "label": "고객사", "type": "query", "datasource": ZBX,
         "definition": "", "refresh": 1, "sort": 1, "regex": "", "options": [],
         "current": {"text": "Customers/Customer-B", "value": "Customers/Customer-B"},
         "query": {"queryType": "group", "group": "/^Customers.Customer-/", "host": "",
                   "application": "", "item": "", "itemTag": "",
                   "showDisabledItems": False}},
        # 고객 그룹에는 실제 감시 대상 외에 **가상 호스트**도 들어 있다 — 리포트 값을 받는
        # trapper 호스트와 도메인별 인증서 호스트다(둘 다 권한 상속 때문에 일부러 이 그룹에
        # 넣었다). 자원 그래프를 그것들까지 반복하면 빈 패널이 생기므로 이름으로 걸러낸다.
        {"name": "host", "label": "호스트", "type": "query", "datasource": ZBX,
         "definition": "", "refresh": 1, "sort": 1, "options": [],
         "regex": "/^(?!report-)(?!.*인증서).*$/",
         # allValue 를 비워 둔다. ".+" 로 두면 '전체'가 **다른 고객 호스트까지** 뜻하게 되어
         # Wazuh·Loki 패널에 남의 데이터가 들어온다. 비우면 Grafana 가 이 고객의 호스트
         # 목록을 (a|b) 로 펼치므로 '전체' 가 '이 고객의 전체' 로 한정된다.
         "includeAll": True, "allValue": "", "multi": True,
         "current": {"text": "All", "value": "$__all"},
         "query": {"queryType": "host", "group": "$customer", "host": "/.*/",
                   "application": "", "item": "", "itemTag": "",
                   "showDisabledItems": False}}]},
    "panels": P,
}

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "lab",
                   "grafana", "provisioning", "dashboards", "json", "kinx-msp-report.json")
json.dump(DASH, io.open(OUT, "w", encoding="utf-8"), ensure_ascii=False, indent=1)

cells = set()
for p in P:
    g = p["gridPos"]
    assert g["x"] + g["w"] <= 24, ("가로 넘침", p["title"])
    for xx in range(g["x"], g["x"] + g["w"]):
        for yy in range(g["y"], g["y"] + g["h"]):
            assert (xx, yy) not in cells, ("겹침", p["title"], xx, yy)
            cells.add((xx, yy))
print("패널 %d개 / 행 %d개 / 총 높이 %d — 좌표 검사 OK"
      % (len([p for p in P if p["type"] != "row"]),
         len([p for p in P if p["type"] == "row"]),
         max(p["gridPos"]["y"] + p["gridPos"]["h"] for p in P)))
