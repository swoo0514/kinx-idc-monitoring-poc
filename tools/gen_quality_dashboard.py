"""판정 품질 Grafana 대시보드 생성기 (일회성 — 산출물은 JSON).

지표 정의는 bot/GATEWAY_GUIDE.md §25-5, 아이템은 ansible/quality_metrics.yml.
"""
import io
import json
import os

ZBX = {"type": "alexanderzobnin-zabbix-datasource", "uid": "zabbix"}
_id = [0]


def nid():
    _id[0] += 1
    return _id[0]


def zt(item):
    # 호스트 필터는 표시명에 걸린다(플러그인 동작, 2026-07-31 실측).
    # useTrends=false 필수 — 하루 1회 찍히는 값은 trends 에 없어 조용히 No data 가 된다.
    return {"refId": "A", "datasource": ZBX, "queryType": "0",
            "group": {"filter": "Reports"}, "host": {"filter": "/^quality-/"},
            "application": {"filter": ""}, "item": {"filter": item},
            "itemTag": {"filter": ""}, "macro": {"filter": ""}, "proxy": {"filter": ""},
            "functions": [], "textFilter": "", "resultFormat": "time_series",
            "options": {"showDisabledItems": False, "skipEmptyValues": False,
                        "useTrends": "false", "useZabbixValueMapping": False}}


NEUTRAL = [{"color": "text"}]
GOOD = [{"color": "text"}, {"color": "blue", "value": 1}]
WORSE = [{"color": "green"}, {"color": "orange", "value": 5}, {"color": "red", "value": 20}]
SCORE = [{"color": "red"}, {"color": "orange", "value": 60}, {"color": "green", "value": 85}]

# 봇이 산출 못 한 정확도는 -1 로 온다. 0 을 보내면 "정확도 0%" 로 읽히고, 안 보내면
# 지난 값이 그대로 남는다(2026-07-31 실측). 여기서 -1 을 글자로 바꾼다.
NOT_MEASURED = [{"type": "value",
                 "options": {"-1": {"text": "판정 불가", "color": "text", "index": 0}}}]


def stat(title, item, x, y, w, h, unit="", desc="", dec=0, steps=None):
    return {"id": nid(), "type": "stat", "title": title, "description": desc,
            "datasource": ZBX, "gridPos": {"h": h, "w": w, "x": x, "y": y},
            "targets": [zt(item)],
            "fieldConfig": {"defaults": {"color": {"mode": "thresholds"},
                                         "mappings": NOT_MEASURED, "decimals": dec,
                                         "unit": unit,
                                         "thresholds": {"mode": "absolute",
                                                        "steps": steps or NEUTRAL}},
                            "overrides": []},
            "options": {"colorMode": "value", "graphMode": "area", "justifyMode": "auto",
                        "orientation": "auto", "textMode": "value_and_name",
                        "reduceOptions": {"calcs": ["lastNotNull"], "fields": "",
                                          "values": False}}}


def ts(title, items, x, y, w, h, unit="", desc=""):
    p = {"id": nid(), "type": "timeseries", "title": title, "description": desc,
         "datasource": ZBX, "gridPos": {"h": h, "w": w, "x": x, "y": y},
         "targets": [dict(zt(i), refId=chr(65 + n)) for n, i in enumerate(items)],
         "fieldConfig": {"defaults": {"unit": unit, "custom": {"fillOpacity": 8,
                                                               "lineWidth": 2}},
                         "overrides": []},
         "options": {"legend": {"displayMode": "list", "placement": "bottom",
                                "showLegend": True},
                     "tooltip": {"mode": "multi", "sort": "none"}}}
    return p


def row(title, y):
    return {"id": nid(), "type": "row", "title": title, "collapsed": False,
            "gridPos": {"h": 1, "w": 24, "x": 0, "y": y}, "panels": []}


P = []
y = 0
P.append(row("1. 관측 — 라벨 없이 산출. 정확도 주장이 아니다", y))
y += 1
P.append(stat("판정 수", "판정 수", 0, y, 4, 5,
              desc="강제 재분석은 빠진 값이다."))
P.append(stat("게이트 발동률", "게이트 발동률(%)", 4, y, 5, 5, unit="percent", dec=1,
              desc="분석까지 간 비율. 높고 낮음 자체가 좋고 나쁨은 아니다."))
P.append(stat("열화율", "열화율(%)", 9, y, 5, 5, unit="percent", dec=1, steps=WORSE,
              desc="LLM 없이 코드 판정만으로 회신한 비율."))
P.append(stat("동시 발생 분할", "동시 발생 분할 건수", 14, y, 5, 5, steps=GOOD,
              desc="같은 호스트에서 창 안에 갈라져 열린 사건. 오류 수가 아니라 병합 후보다."))
P.append(stat("주석 발행률", "판정 주석 발행률(%)", 19, y, 5, 5, unit="percent", dec=1,
              desc="관측 타임라인에 판정이 실제로 올라간 비율. 떨어지면 Grafana 토큰·주소를 본다."))
y += 5
P.append(ts("응답시간", ["응답시간 p50(초)", "응답시간 p90(초)"], 0, y, 24, 7, unit="s",
            desc="값이 없는 판정(분석 중 재기동 등)은 빠져 있다."))
y += 7

P.append(row("2. 정확도 — 사람 라벨이 있어야 성립한다", y))
y += 1
P.append(stat("사람 라벨 수", "사람 라벨 수", 0, y, 4, 5, steps=GOOD,
              desc="Keep 카드의 판정 확인·정정 버튼으로 쌓인다. 이 수가 적으면 아래 값은 판정 불가로 나온다."))
for i, (title, item) in enumerate((("판정 정확도", "판정 정확도(%, -1=미산출)"),
                                   ("게이트 정확도", "게이트 정확도(%, -1=미산출)"),
                                   ("병합 정확도", "병합 정확도(%, -1=미산출)"),
                                   ("원인 정확도", "원인 정확도(%, -1=미산출)"))):
    P.append(stat(title, item, 4 + i * 5, y, 5, 5, unit="percent", dec=1, steps=SCORE,
                  desc="표본이 모자라면 '판정 불가'로 뜬다. 백분율이 안 보이는 것이 정상이다."))

DASH = {
    "uid": "kinx-quality",
    "title": "KINX 봇 판정 품질",
    "tags": ["kinx", "quality", "bot"],
    "timezone": "browser",
    "schemaVersion": 39,
    "version": 0,
    "refresh": "",
    "time": {"from": "now-90d", "to": "now"},
    "editable": True,
    "graphTooltip": 0,
    "templating": {"list": []},
    "panels": P,
}

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "lab",
                   "grafana", "provisioning", "dashboards", "json", "kinx-quality.json")
json.dump(DASH, io.open(OUT, "w", encoding="utf-8"), ensure_ascii=False, indent=1)

cells = set()
for p in P:
    g = p["gridPos"]
    assert g["x"] + g["w"] <= 24, ("가로 넘침", p["title"])
    for xx in range(g["x"], g["x"] + g["w"]):
        for yy in range(g["y"], g["y"] + g["h"]):
            assert (xx, yy) not in cells, ("겹침", p["title"], xx, yy)
            cells.add((xx, yy))
print("panels %d - grid check OK" % len([p for p in P if p["type"] != "row"]))
