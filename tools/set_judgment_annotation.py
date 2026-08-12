"""판정 주석 질의를 대시보드에 심는다 — 패널을 제목으로 고른다.

Grafana 는 주석을 보여 줄 패널을 **번호 목록**으로만 받는다(스키마에 제목으로 지정하는
방법이 없다). 번호를 손으로 적어 두면 패널을 지우고 다시 만들 때 번호가 바뀌어, 주석이
엉뚱한 패널로 옮겨 가거나 사라진다. 그때 오류는 나지 않는다.

그래서 여기서는 **제목으로 찾아 번호를 채워 넣는다.** 제목에 맞는 패널이 하나도 없으면
실패로 끝난다. 셀프테스트가 같은 표로 대조하므로, 번호가 어긋난 채 커밋되면 검사에서
드러난다(bot/gateway/selftest.py 의 대시보드 주석 검사).

  python tools/set_judgment_annotation.py
"""
import io
import json
import os
import sys

QUERY_NAME = "봇 판정"
TAG = "kinx-bot"

# 대시보드별로 주석을 세울 패널. 값은 제목에 들어 있어야 하는 문자열이다.
# 기준은 **호스트 단위 시계열** — 전체 호스트를 모으는 패널에 특정 호스트의 판정을 세우면
# 읽는 사람이 없는 연결을 짓는다.
SPEC = {
    "kinx-overview": ["CPU 사용률", "복제 지연", "인증 활동"],
    "kinx-replication": ["복제 지연", "오류율"],
    "kinx-quality": ["응답시간"],
}

BUILTIN = {"builtIn": 1, "datasource": {"type": "grafana", "uid": "-- Grafana --"},
           "enable": True, "hide": True, "iconColor": "rgba(0, 211, 255, 1)",
           "name": "Annotations & Alerts", "type": "dashboard"}

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "lab",
                    "grafana", "provisioning", "dashboards", "json")


def resolve(dash: dict, patterns: list) -> list:
    """제목으로 패널 번호를 찾는다. 하나도 못 찾은 제목이 있으면 예외."""
    ids, missing = [], []
    for pat in patterns:
        hit = [p["id"] for p in dash.get("panels", [])
               if p.get("type") in ("timeseries", "graph")
               and pat in (p.get("title") or "")]
        if not hit:
            missing.append(pat)
        ids += hit
    if missing:
        raise RuntimeError("제목에 맞는 시계열 패널이 없다: %s" % ", ".join(missing))
    return sorted(set(ids))


def query(ids: list) -> dict:
    return {"datasource": {"type": "grafana", "uid": "-- Grafana --"},
            "enable": True, "hide": False, "iconColor": "purple",
            "name": QUERY_NAME,
            "target": {"limit": 100, "matchAny": False, "tags": [TAG],
                       "type": "tags"},
            "filter": {"exclude": False, "ids": ids}}


def apply(uid: str, patterns: list) -> str:
    path = os.path.join(ROOT, uid + ".json")
    dash = json.load(io.open(path, encoding="utf-8"))
    ids = resolve(dash, patterns)
    lst = [a for a in (dash.get("annotations") or {}).get("list") or []
           if a.get("name") != QUERY_NAME]
    if not any(a.get("builtIn") for a in lst):
        lst.insert(0, dict(BUILTIN))
    lst.append(query(ids))
    dash["annotations"] = {"list": lst}
    json.dump(dash, io.open(path, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    return "%s -> %s" % (uid, ids)


def main() -> int:
    for uid, patterns in SPEC.items():
        try:
            print(apply(uid, patterns))
        except (OSError, RuntimeError) as e:
            print("%s: %s" % (uid, e), file=sys.stderr)
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
