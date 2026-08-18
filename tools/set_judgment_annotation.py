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

# 패널마다 "이 패널은 어떤 사건을 다루는가" 를 적는다. 봇이 주석에 사건 유형을 태그로
# 달아 두므로, 패널은 자기가 다루는 유형만 가져간다. 값이 빈 목록이면 유형을 가리지 않고
# 전부 가져간다.
#
# 기준은 **호스트 단위 시계열**이다. 전체 호스트를 모으는 패널에 특정 호스트의 판정을
# 세우면 읽는 사람이 없는 연결을 짓는다.
#
# 유형에 맞는 패널이 없는 사건(디스크 등)은 관측 화면에서는 안 보인다. 그래서 판정 품질
# 화면 한 곳을 **전부 보이는 곳**으로 둔다. 봇 자신의 화면이므로 거기가 맞다.
SPEC = {
    "kinx-overview": {
        "CPU 사용률": ["cpu_io_pressure", "memory_pressure"],
        "복제 지연": ["replication"],
        "인증 활동": ["auth_security"],
    },
    "kinx-replication": {
        "복제 지연": ["replication"],
        "오류율": ["service_down", "cpu_io_pressure"],
    },
    "kinx-quality": {
        "응답시간": [],          # 유형 무관 — 모든 판정
    },
}

BUILTIN = {"builtIn": 1, "datasource": {"type": "grafana", "uid": "-- Grafana --"},
           "enable": True, "hide": True, "iconColor": "rgba(0, 211, 255, 1)",
           "name": "Annotations & Alerts", "type": "dashboard"}

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "lab",
                    "grafana", "provisioning", "dashboards", "json")


def resolve(dash: dict, title: str) -> list:
    """제목으로 시계열 패널 번호를 찾는다. 하나도 없으면 예외."""
    ids = [p["id"] for p in dash.get("panels", [])
           if p.get("type") in ("timeseries", "graph")
           and title in (p.get("title") or "")]
    if not ids:
        raise RuntimeError("제목에 맞는 시계열 패널이 없다: %s" % title)
    return sorted(ids)


# 유형을 사람이 읽는 말로. 토글 이름에 붙여 같은 패널에 걸린 질의를 구분한다.
CLASS_LABEL = {
    "cpu_io_pressure": "자원 압박",
    "memory_pressure": "메모리",
    "replication": "복제",
    "auth_security": "인증·보안",
    "service_down": "서비스 중단",
}


def query(title: str, classes: list, ids: list) -> dict:
    # matchAny=false 라 나열한 태그를 모두 가진 주석만 걸린다. 봇은 kinx-bot·심각도·
    # 호스트·사건 유형을 함께 달므로, 여기에 유형 하나를 더하면 그 유형만 남는다.
    return {"datasource": {"type": "grafana", "uid": "-- Grafana --"},
            "enable": True, "hide": False, "iconColor": "purple",
            # 같은 패널에 유형이 둘이면 이름이 겹쳐 화면에 같은 토글이 두 개 뜬다
            # (2026-08-18 실측). 유형을 이름에 붙여 구분한다.
            "name": "%s · %s%s" % (
                QUERY_NAME, title,
                "".join(" · " + CLASS_LABEL.get(c, c) for c in classes)),
            "target": {"limit": 100, "matchAny": False,
                       "tags": [TAG] + list(classes), "type": "tags"},
            "filter": {"exclude": False, "ids": ids}}


def queries(dash: dict, spec: dict) -> list:
    """유형이 여럿이면 질의도 여럿이다 — 태그 조건이 AND 라 한 질의에 못 담는다."""
    out = []
    for title, classes in spec.items():
        ids = resolve(dash, title)
        if not classes:
            out.append(query(title, [], ids))
            continue
        for cls in classes:
            out.append(query(title, [cls], ids))
    return out


def apply(uid: str, spec: dict) -> str:
    path = os.path.join(ROOT, uid + ".json")
    dash = json.load(io.open(path, encoding="utf-8"))
    qs = queries(dash, spec)
    lst = [a for a in (dash.get("annotations") or {}).get("list") or []
           if not (a.get("name") or "").startswith(QUERY_NAME)]
    if not any(a.get("builtIn") for a in lst):
        lst.insert(0, dict(BUILTIN))
    dash["annotations"] = {"list": lst + qs}
    json.dump(dash, io.open(path, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    return "%s -> 질의 %d개 %s" % (
        uid, len(qs), [(q["target"]["tags"][1:] or ["전체"], q["filter"]["ids"]) for q in qs])


def main() -> int:
    for uid, spec in SPEC.items():
        try:
            print(apply(uid, spec))
        except (OSError, RuntimeError) as e:
            print("%s: %s" % (uid, e), file=sys.stderr)
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
