"""인시던트 병합 — 알림 N건을 (host, class) 기준으로 1개 사건으로 묶는다.

설계·근거는 bot/GATEWAY_GUIDE.md §8. 순수 로직(classify/bridge/Incident)과 비동기 버퍼
(IncidentManager)를 분리했다.
"""

import asyncio
import hashlib
import json
import logging
import os
import re
import time
from dataclasses import dataclass, field

from . import registry
from .collector import SOURCE_UNAVAILABLE, SOURCE_UNMATCHED

log = logging.getLogger("gateway.incident")


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        return default


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, default))
    except ValueError:
        return default


# 위에서부터 먼저 걸리는 것. 순서와 키워드 폭이 곧 분류 정확도다 — GATEWAY_GUIDE §8.
# 손대면 selftest 의 CASES_CLASSIFY 를 함께 늘린다.
CLASS_RULES = [
    ("replication", ["복제", "replication", "repl", "slave", "seconds_behind",
                     "리플리케이션", "슬레이브"]),
    ("cpu_io_pressure", ["iowait", "io wait", "i/o", "load average", "cpu", "load",
                         "디스크 지연", "디스크 응답", "disk latency", "await",
                         "부하 평균", "아이오웨이트",
                         "read/write request", "disk read/write"]),
    ("auth_security", ["브루트포스", "brute", "authentication", "login fail", "sshd",
                       "unauthorized", "비인가", "sca", "fim", "rootcheck",
                       "integrity", "무결성", "syscheck", "파일 무결성", "루트킷",
                       "로그인 실패", "권한 상승", "인증 실패",
                       # Zabbix 쪽 인증 파일 변경 감시. Wazuh FIM 과 같은 성격이다.
                       "/etc/passwd", "/etc/shadow"]),
    ("memory_pressure", ["메모리", "memory", "스왑", "swap", "oom"]),
    ("disk_space", ["디스크 사용률", "디스크 사용", "filesystem", "vfs.fs", "disk space",
                    "space is", "pused",
                    "디스크 여유", "여유 공간", "용량 부족", "파일시스템", "파티션"]),
    ("network", ["interface", "packet", "drop", "crc", "link down", "ifoperstatus",
                 # BGP 피어 단절은 회선 사건인데 service_down 의 "down" 이 먼저 잡았다
                 # (실환경 90일 기준 98%). 이름을 소문자로 맞춰 보므로 한글 알림명의
                 # "BGP 피어 다운"도 이 한 낱말로 걸린다.
                 "bgp",
                 # network 만 한글 키워드가 없어 한글 트리거명이 미분류로 떨어졌다.
                 "인터페이스", "패킷", "링크 다운", "인바운드 에러", "아웃바운드 에러",
                 "회선"]),
    ("service_down", ["proc.num", "process", "not running", "not available", "재기동",
                      "down", "unreachable",
                      # 표준 템플릿·일반 용어만 둔다. 사이트 관용구는 SITE_CLASS_KEYWORDS.
                      "restarted", "health check", "not response", "no snmp data",
                      # "응답 없음"·"무응답"은 느린 것이 아니라 죽은 것이다. service_latency
                      # 의 "응답"이 가로채지 않도록 이 클래스(앞 순서)에 둔다.
                      "무응답", "응답 없음", "다운", "중지", "정지", "죽음", "미개방",
                      "프로세스"]),
    ("service_latency", ["지연", "latency", "response time", "응답", "qps", "queue",
                         "적체", "처리 지연"]),
    # 마지막에 둔다 — "바뀌었다"는 generic 이라 앞에 두면 다른 판정을 가로챈다.
    # 나머지 클래스가 "무엇이 잘못됐나"라면 이 축은 "무엇이 바뀌었나"다.
    ("config_change", ["has changed", "was changed", "changed on", "구성 변경",
                       "listened ports", "installed packages", "설정 변경",
                       "설정 파일", "패키지", "변경 감지", "변경됨"]),
]

# 사이트 고유 트리거명 키워드. 조직마다 다르므로 환경변수로 받는다.
# 형식: "class=키워드|키워드,class=키워드"  예) service_down=not connect|check is fail
def _site_keywords():
    out = {}
    for part in os.environ.get("SITE_CLASS_KEYWORDS", "").split(","):
        if "=" not in part:
            continue
        cls, kws = part.split("=", 1)
        cls = cls.strip()
        if cls not in {c for c, _ in CLASS_RULES}:
            log.warning("SITE_CLASS_KEYWORDS: 모르는 클래스 %r — 무시", cls)
            continue
        out.setdefault(cls, []).extend(k.strip().lower() for k in kws.split("|") if k.strip())
    return out


SITE_CLASS_KEYWORDS = _site_keywords()
if SITE_CLASS_KEYWORDS:
    CLASS_RULES = [(c, kws + SITE_CLASS_KEYWORDS.get(c, [])) for c, kws in CLASS_RULES]
    log.info("사이트 고유 키워드 적용: %s",
             {c: len(v) for c, v in SITE_CLASS_KEYWORDS.items()})

_IP_RE = re.compile(r"\d{1,3}(?:\.\d{1,3}){3}")
_NUM_RE = re.compile(r"\d+(?:\.\d+)?")


def name_template(name: str) -> str:
    """알림명의 변수부(숫자·IP)를 지워 '유형'으로 접는다. 분류 파일·마이닝이 같은 키를 쓴다."""
    return _NUM_RE.sub("#", _IP_RE.sub("<IP>", name or "")).strip()


_WORD_BOUNDARY_MAX = 5


def _matcher(keyword: str):
    # 경계를 \w 가 아니라 영숫자로 잡는다 — \w 는 밑줄을 단어 문자로 보므로 "sshd" 가
    # "sshd_config" 에 안 걸린다. 근거는 GATEWAY_GUIDE §8.
    if keyword.isascii() and " " not in keyword and len(keyword) <= _WORD_BOUNDARY_MAX:
        return re.compile(rf"(?<![A-Za-z0-9]){re.escape(keyword)}(?![A-Za-z0-9])")
    return None


_COMPILED_RULES = [(cls, [(kw, _matcher(kw)) for kw in kws]) for cls, kws in CLASS_RULES]

# 서로 겹치면 안 된다 — _bridge_id 가 첫 매칭을 반환하므로 겹치면 뒤 그룹이 死코드가 된다.
# 아래 _validate_bridges 가 import 시점에 강제한다. 조합 근거는 GATEWAY_GUIDE §8.
BRIDGE_GROUPS = [
    frozenset({"replication", "cpu_io_pressure"}),
    frozenset({"disk_space", "service_down"}),
]


# 열린 문제 연계 규칙 — (열린 쪽, 뒤따르는 쪽). BRIDGE_GROUPS 와 달리 방향이 있고
# 병합 키를 만들지 않으므로 겹쳐도 된다. 설계는 open_problem_linkage_design.md.
#
# 아래는 형식을 보이기 위한 자리표시자이며 어떤 환경의 측정값도 아니다. 실제로는 그
# 환경에서 측정한 파일을 OPEN_LINK_RULES_FILE 로 지정해 쓴다 — 코드에 박으면 환경이
# 바뀌어도 아무도 모른다. 생성은 bridge_miner --emit-rules.
_EXAMPLE_OPEN_LINK_RULES = {
    ("disk_space", "cpu_io_pressure"): {"rate": 0.90, "days": 10, "overlaps": 20},
    ("disk_space", "service_down"): {"rate": 0.70, "days": 10, "overlaps": 15},
}
_EXAMPLE_MEASURED = "자리표시자 — 측정값 아님. OPEN_LINK_RULES_FILE 미지정 상태"


def _load_open_link_rules():
    """측정 파일이 있으면 그것을, 없으면 예시값을 쓴다. 어느 쪽인지 로그로 드러낸다.

    파일 형식(마이닝 도구 --emit-rules 산출):
      {"measured": "<측정 조건>", "rules": [{"open": "...", "followed": "...",
                                             "rate": 0.96, "days": 13, "overlaps": 22}]}
    """
    path = os.environ.get("OPEN_LINK_RULES_FILE", "")
    if not path:
        # 예전에는 여기서 예시값을 돌려줬다. 그런데 시스템 프롬프트는 이 수치를
        # "과거 이력에서 실제로 측정된 값"이라고 모델에게 알려 준다. 그래서 봇이
        # 근거 없는 90% 를 근거처럼 인용해 고객 대응 채널에 냈다. 측정 파일이 없으면
        # 연계 자체를 끈다 — 없는 근거보다 없는 문장이 낫다.
        # 예시값은 파일 형식을 보여 주는 용도로만 남긴다(OPEN_LINK_RULES_FILE 참고).
        log.warning("열린 문제 연계: 측정 파일 없음(OPEN_LINK_RULES_FILE) — 연계를 끈다. "
                    "근거 없는 비율을 실측값처럼 회신하지 않기 위해서다")
        return {}, ""
    try:
        with open(path, encoding="utf-8") as f:
            doc = json.load(f)
        rules = {(r["open"], r["followed"]):
                 {"rate": r["rate"], "days": r["days"], "overlaps": r.get("overlaps")}
                 for r in doc.get("rules", [])}
        measured = doc.get("measured") or path
        log.info("열린 문제 연계: %s 에서 규칙 %d건 로드 (%s)", path, len(rules), measured)
        return rules, measured
    except Exception as e:
        # 조용히 예시값으로 떨어지면 남의 환경 수치로 판단하게 된다. 크게 남긴다.
        log.error("열린 문제 연계 규칙 로드 실패 %s: %s — 연계 비활성", path, e)
        return {}, "규칙 로드 실패"


OPEN_LINK_RULES, OPEN_LINK_MEASURED = _load_open_link_rules()
# 방금 난 것은 이미 시간창 병합 대상이다. 그보다 오래 열린 것만 "선행 문제"로 본다.
OPEN_LINK_MIN_AGE_S = _env_int("OPEN_LINK_MIN_AGE_S", 300)
OPEN_LINK_MAX = _env_int("OPEN_LINK_MAX", 3)
# 오래 열린 것은 선행 원인이 아니라 방치 항목이다 — 버리지 않고 표시만 한다.
# 통계가 아니라 운영 판단이므로 환경변수로 조정한다.
OPEN_LINK_STALE_AGE_S = _env_int("OPEN_LINK_STALE_AGE_S", 7 * 86400)


def open_link(open_cls: str, current_classes) -> dict:
    """열린 문제의 클래스가 현재 인시던트 클래스와 연계 관계인지. 아니면 빈 dict."""
    for cur in current_classes or []:
        hit = OPEN_LINK_RULES.get((open_cls, cur))
        if hit:
            return dict(hit, open_class=open_cls, followed_class=cur,
                        measured=OPEN_LINK_MEASURED)
    return {}


def _validate_bridges(groups=None):
    groups = BRIDGE_GROUPS if groups is None else groups
    seen = set()
    for grp in groups:
        overlap = seen & grp
        if overlap:
            raise ValueError(
                f"BRIDGE_GROUPS 겹침 {sorted(overlap)} — 첫 매칭 반환이라 뒤 그룹이 死코드가 된다")
        seen |= grp


_validate_bridges()

_SEV_ORDER = {"SEV1": 1, "SEV2": 2, "SEV3": 3, "SEV4": 4, "NONE": 5}

# 우리 분류를 선언하는 트리거 태그 이름. "class" 를 쓰면 안 된다 — Zabbix 표준 템플릿이
# 이미 그 이름을 쓴다(class=os / class=database). 근거는 next-steps §1-1-12.
CLASS_TAG = os.environ.get("CLASS_TAG", "incident_class")
WAZUH_GROUP_CLASS = {
    "syscheck": "auth_security",
    "sca": "auth_security",
    "rootcheck": "auth_security",
    "authentication_failed": "auth_security",
    "authentication_failures": "auth_security",
    "invalid_login": "auth_security",
    "vulnerability-detector": "vulnerability",
}
_KNOWN_CLASSES = {c for c, _ in CLASS_RULES} | set(WAZUH_GROUP_CLASS.values()) | {"other"}


def _load_class_map():
    """발행 측에 태그를 못 다는 동안 쓰는 같은 선언. 태그가 붙으면 자동으로 무시된다.

    형식: {"zabbix": {"<정규화된 알림명>": "class"}, "wazuh": {"<rule_id>": "class"}}
    """
    path = os.environ.get("INCIDENT_CLASS_FILE", "")
    if not path:
        return {}, {}
    try:
        with open(path, encoding="utf-8") as f:
            doc = json.load(f)
        zbx = {k: v for k, v in (doc.get("zabbix") or {}).items() if v in _KNOWN_CLASSES}
        wz = {str(k): v for k, v in (doc.get("wazuh") or {}).items() if v in _KNOWN_CLASSES}
        log.info("분류 선언 파일 %s — zabbix %d종 / wazuh %d종", path, len(zbx), len(wz))
        return zbx, wz
    except Exception as e:
        log.error("분류 선언 파일 로드 실패 %s: %s — 키워드 폴백으로 진행", path, e)
        return {}, {}


CLASS_MAP_ZBX, CLASS_MAP_WZH = _load_class_map()


def classify(alert_name: str, item_key: str = "", tags=None, groups=None,
             rule_id: str = "") -> str:
    """선언(태그 → 그룹 → 파일) → 폴백(키워드) 순. 선언이 있으면 문자열을 보지 않는다."""
    declared = _tag_class(tags)
    if declared:
        return declared

    mapped = _group_class(groups)
    if mapped:
        return mapped

    if rule_id and str(rule_id) in CLASS_MAP_WZH:
        return CLASS_MAP_WZH[str(rule_id)]
    hit = CLASS_MAP_ZBX.get(name_template(alert_name))
    if hit:
        return hit

    text = f"{alert_name} {item_key}".lower()
    for cls, matchers in _COMPILED_RULES:
        for kw, rx in matchers:
            if rx.search(text) if rx else kw in text:
                return cls
    return "other"


_WARNED_TAGS = set()


def _tag_class(tags) -> str:
    for t in tags or []:
        if isinstance(t, dict) and t.get("tag") == CLASS_TAG:
            v = (t.get("value") or "").strip().lower()
            # 오타 하나가 조용히 새 클래스를 만들면 병합이 갈린다 — 모르는 값은 폴백으로.
            if v in _KNOWN_CLASSES:
                return v
            if v and v not in _WARNED_TAGS:
                # 알림마다 찍으면 로그가 같은 문장으로 덮인다 — 값당 한 번만 남긴다.
                _WARNED_TAGS.add(v)
                log.warning("알 수 없는 %s 태그 %r — 무시하고 폴백. 허용값: %s",
                            CLASS_TAG, v, sorted(_KNOWN_CLASSES))
    return ""


def _group_class(groups) -> str:
    if not groups:
        return ""
    if isinstance(groups, str):
        groups = [g.strip() for g in groups.split(",")]
    present = {str(g).strip().lower() for g in groups if g}
    # 한 알림이 여러 그룹을 갖는 것이 흔하므로(syscheck + pci_dss 등) 매핑 순서로 결정한다.
    for grp, cls in WAZUH_GROUP_CLASS.items():
        if grp in present:
            return cls
    return ""


def _bridge_id(cls: str) -> str:
    for i, grp in enumerate(BRIDGE_GROUPS):
        if cls in grp:
            return f"bridge{i}"
    return cls


# 호스트 이름은 감시 서버 안에서만 유일하다. 감시 서버가 둘이면(사내·MSP) 서로 다른
# 기계가 같은 이름을 가질 수 있고, 이름만으로 묶으면 남의 고객 알림이 한 사건이 된다.
# 그래서 "어느 감시 영역의 무슨 이름"으로 식별한다.
#
# 소스를 그대로 쓰지 않는 이유가 있다. 같은 기계를 Zabbix 와 Wazuh 가 각각 보고하는데,
# 소스를 키에 넣으면 그 둘이 갈라져 교차 소스 병합이 아예 불가능해진다. 영역은 소스보다
# 위의 개념이다 — 사내 Zabbix 와 사내 Wazuh 는 같은 영역이고, MSP Zabbix 는 다른 영역이다.
#
# 형식: "소스=영역,소스=영역"  예) zabbix-internal=internal,zabbix-msp=msp,wazuh=internal
# 안 적으면 전부 한 영역으로 본다 — 감시 서버가 하나인 환경의 현행 동작 그대로다.
def _realm_map():
    out = {}
    for pair in os.environ.get("INCIDENT_REALM_MAP", "").split(","):
        if "=" in pair:
            k, v = pair.split("=", 1)
            out[k.strip()] = v.strip()
    return out


REALM_MAP = _realm_map()
if REALM_MAP:
    log.info("감시 영역 구분 적용: %s", REALM_MAP)
else:
    log.info("감시 영역 매핑 없음 — 소스 이름을 그대로 영역으로 쓴다(사내·MSP 자동 분리). "
             "같은 기계를 두 소스가 보고하면 그 둘을 같은 영역으로 묶어야 한다")


def realm_for(source: str, host: str = "") -> str:
    """이 알림이 어느 감시 영역에서 왔는가. 명부 → 환경변수 → 소스 그대로."""
    return registry.realm(source, host, REALM_MAP)


def incident_key(source: str, host: str, cls: str) -> tuple:
    """같은 키의 알림은 한 인시던트. 브리지 조합이면 다른 class여도 같은 키."""
    return (realm_for(source, host), host, _bridge_id(cls))


@dataclass
class Alert:
    source: str
    event_id: str
    trigger_id: str
    host: str
    alert_name: str
    sev: str
    incident_class: str
    recv: float  # time.monotonic() — 버퍼 타이밍용(수집 시간창은 wall clock 별도)


@dataclass
class Incident:
    key: tuple
    host: str
    alerts: list = field(default_factory=list)
    opened_at: float = 0.0
    last_at: float = 0.0
    anchor_ts: str = ""   # 첫 원시 신호 카드의 Slack ts — 후속 신호가 이 스레드에 붙는다

    def add(self, a: Alert, max_alerts: int) -> bool:
        if len(self.alerts) >= max_alerts:
            return False
        self.alerts.append(a)
        self.last_at = a.recv
        return True

    def classes(self) -> set:
        return {a.incident_class for a in self.alerts}

    def dominant_sev(self) -> str:
        return min((a.sev for a in self.alerts),
                   key=lambda s: _SEV_ORDER.get(s, 9), default="NONE")

    def window_s(self) -> float:
        return round(self.last_at - self.opened_at, 1)

    def is_merged(self) -> bool:
        return len(self.alerts) > 1

    def fingerprint(self) -> str:
        # 영역을 넣어야 서로 다른 고객의 같은 이름 호스트가 관제 화면에서 한 행으로
        # 합쳐지지 않는다. 키의 앞 두 칸이 (영역, 호스트)다.
        # 키를 통째로 넣는다. 키에 영역이 들어 있으므로 서로 다른 고객의 같은 이름
        # 호스트가 관제 화면에서 한 행으로 합쳐지지 않는다. 키 모양이 바뀌어도 따라간다.
        raw = "|".join([str(x) for x in self.key]
                       + [self.host, ",".join(sorted(self.classes()))])
        return hashlib.sha1(raw.encode()).hexdigest()[:12]

    def merge_reason(self) -> str:
        classes = sorted(self.classes())
        n = len(self.alerts)
        if n == 1:
            return f"단일 알림 (유형 {classes[0]})"
        combo = ""
        if any(len(set(classes) & grp) > 1 for grp in BRIDGE_GROUPS):
            combo = " · 알려진 인과 조합"
        return (f"동일 호스트 · {self.window_s()}s 관측창 · {n}건 · "
                f"유형 {classes}{combo}")


def dominant_verdict(context: dict) -> str:
    """인시던트 전체의 만성/신규 판정 — 알림별 선판정을 하나로 접는다.

    모르는 것이 하나라도 있으면 "신규", 전부 아는 문제면 "만성", 그 사이는 "재발".
    근거는 docs/02-design/rules-inventory.md §1-7.
    """
    verdicts = [(a.get("prejudge") or {}).get("verdict")
                for a in (context.get("alerts") or [])]
    verdicts = [v for v in verdicts if v]
    if not verdicts:   # 단건 경로 컨텍스트 호환
        single = (context.get("prejudge") or {}).get("verdict")
        verdicts = [single] if single else []
    if not verdicts:
        return ""
    if "신규" in verdicts:
        return "신규"
    if all(v == "만성" for v in verdicts):
        return "만성"
    return "재발"


GATE_MIN_CROSS = _env_int("INCIDENT_GATE_MIN_CROSS", 1)
GATE_FIRE_ON_NEW = os.environ.get("INCIDENT_GATE_FIRE_ON_NEW", "1") not in ("0", "false", "no")

# 사유별 발동 횟수 (최근 1시간). **통제가 아니라 관측이다.**
#
# 예전에는 이 수치가 사유별 한도로 쓰였다. 그 구조에는 세 가지 문제가 있었다.
# 첫째, 한도가 규칙 가지마다 붙어 있어 보호 범위가 규칙 목록에 묶였다. 규칙을 늘릴
# 때마다 한도를 또 걸어야 했고, 빠뜨려도 아무 신호가 없었다(실제로 5개 중 3개가
# 빠져 있었고 폭주 때 실제로 터지는 경로가 그 안에 있었다). 둘째, 한도에 걸린
# 사건은 다시 시도되지 않고 그대로 버려졌다. 늦게 왔다는 이유로 분석에서 빠졌다.
# 셋째, 20·30 이라는 값에 산정 근거가 없었다.
#
# 그래서 부하 보호는 호출이 실제로 나가는 한 지점(llm.triage_reply)으로 옮겼다.
# 게이트는 "볼 만한 사건인가"만 판단한다. 여기 남은 수치는 무엇 때문에 분석이
# 돌았는지를 밖에서 보기 위한 것이다 — 조회 실패 수가 치솟으면 관측 소스를
# 고치라는 신호다. 근거는 GATEWAY_GUIDE §8-3.
_fires = {"new": [], "degraded": []}


def fire_counts(now: float = None) -> dict:
    """최근 1시간 사유별 발동 횟수. 생존 신호로 내보낸다."""
    now = time.time() if now is None else now
    out = {}
    for kind, q in _fires.items():
        q[:] = [t for t in q if now - t <= 3600]
        out[kind] = len(q)
    return out


def _mark(kind: str, now: float) -> int:
    """이 사유로 발동했다고 세고, 최근 1시간 누계를 돌려준다."""
    q = _fires.setdefault(kind, [])
    q[:] = [t for t in q if now - t <= 3600]
    q.append(now)
    return len(q)


def should_triage(incident, context: dict, min_cross: int = None, now: float = None) -> tuple:
    """LLM 트리아지 발동 여부 + 사유. 반환 (bool, 사유).

    조건과 순서의 근거는 GATEWAY_GUIDE §8-3.
    """
    min_cross = GATE_MIN_CROSS if min_cross is None else min_cross
    now = time.time() if now is None else now
    if incident.dominant_sev() == "SEV1":
        return True, "SEV1 — 위중, 무조건 발동"
    if incident.is_merged():
        return True, f"{len(incident.alerts)}건 병합 — 교차 축 존재"

    sources = context.get("sources") or {}
    failed = [k for k in ("logs", "security") if sources.get(k) == SOURCE_UNAVAILABLE]
    unmatched = [k for k in ("logs", "security") if sources.get(k) == SOURCE_UNMATCHED]
    if failed or unmatched:
        why = (f"조회 실패({', '.join(failed)})" if failed else "") + \
              (" · " if failed and unmatched else "") + \
              (f"이름 불일치({', '.join(unmatched)})" if unmatched else "")
        n = _mark("degraded", now)
        return True, f"교차 소스 {why} — 신호 없음이 아니라 미상, 보수적 발동 (1시간 {n}건째)"

    cross = sum(1 for k in ("logs", "security") if context.get(k))
    if cross >= min_cross:
        return True, f"단일 알림 + 교차 소스 {cross}종(로그/보안)"

    if GATE_FIRE_ON_NEW and dominant_verdict(context) == "신규":
        n = _mark("new", now)
        return True, f"처음 보는 문제 — 과거 이력 없음 (1시간 {n}건째)"
    return False, "단일 축·교차 신호 없음(조회는 정상) — LLM 스킵"


class IncidentManager:
    """알림을 (host, class) 버퍼에 모아, 디바운스 창이 닫히면 on_close(incident) 1회 호출.

    on_signal(alert, thread_ts) -> ts : 알림 도착 즉시 원시 신호를 게시하는 선택적 콜백.
    신규 인시던트면 thread_ts=None(최상위, 반환 ts 가 앵커), 후속이면 앵커 ts(답글).
    창 마감 조건과 fast-path 설계는 GATEWAY_GUIDE §8·§9.
    """

    def __init__(self, on_close, debounce_s: float = None, max_window_s: float = None,
                 priority_debounce_s: float = None, max_alerts: int = None,
                 on_signal=None):
        self._on_close = on_close
        self._on_signal = on_signal
        self.debounce_s = _env_float("INCIDENT_DEBOUNCE_S", 90) if debounce_s is None else debounce_s
        self.max_window_s = _env_float("INCIDENT_MAX_WINDOW_S", 300) if max_window_s is None else max_window_s
        self.priority_debounce_s = (_env_float("INCIDENT_PRIORITY_DEBOUNCE_S", 15)
                                    if priority_debounce_s is None else priority_debounce_s)
        self.max_alerts = _env_int("INCIDENT_MAX_ALERTS", 20) if max_alerts is None else max_alerts
        self._open: dict = {}
        self._timers: dict = {}
        # 키마다 잠금 — 첫 카드가 올라가 anchor_ts 가 채워진 뒤에 후속 알림이 답글을 단다.
        self._locks: dict = {}

    async def submit(self, a: Alert):
        key = incident_key(a.source, a.host, a.incident_class)
        inc = self._open.get(key)
        new = inc is None
        if new:
            inc = Incident(key=key, host=a.host, alerts=[a],
                           opened_at=a.recv, last_at=a.recv)
            # ★ 등록을 아래 await 보다 먼저 한다. 게시하는 동안 같은 키의 알림이 도착하면
            #   그것도 신규로 보여 부모 카드가 두 번 뜨고 스레드가 갈라진다.
            self._open[key] = inc
        else:
            if not inc.add(a, self.max_alerts):
                log.warning("incident %s at max_alerts(%d) — dropping extra %s",
                            key, self.max_alerts, a.alert_name)
                return
        self._schedule(key, inc)
        if self._on_signal:
            async with self._locks.setdefault(key, asyncio.Lock()):
                await self._signal(a, inc, new)

    async def _signal(self, a: Alert, inc: Incident, new: bool):
        if not new and not inc.anchor_ts:
            return   # 첫 카드 게시가 실패한 경우 — 최상위 카드가 늘어나는 것을 막는다
        try:
            ts = await self._on_signal(a, None if new else inc.anchor_ts)
        except Exception as e:
            log.warning("on_signal failed for incident %s: %s", inc.key, e)
            return
        if new and ts:
            inc.anchor_ts = ts

    def _delay_for(self, inc: Incident) -> float:
        base = self.priority_debounce_s if inc.dominant_sev() == "SEV1" else self.debounce_s
        elapsed = time.monotonic() - inc.opened_at
        return max(0.0, min(base, self.max_window_s - elapsed))

    def _schedule(self, key, inc):
        old = self._timers.get(key)
        if old and not old.done():
            old.cancel()
        self._timers[key] = asyncio.create_task(self._fire_after(key, self._delay_for(inc)))

    async def _fire_after(self, key, delay):
        try:
            if delay > 0:
                await asyncio.sleep(delay)
        except asyncio.CancelledError:
            return
        await self._close(key)

    async def _close(self, key, done=None):
        inc = self._open.pop(key, None)
        timer = self._timers.pop(key, None)
        self._locks.pop(key, None)
        if timer and not timer.done():
            timer.cancel()
        if inc is None:
            return
        try:
            await self._on_close(inc)
        except Exception as e:
            log.warning("on_close failed for incident %s: %s", key, e)
        # 여기까지 왔으면 처리가 끝난 것이다. 중간에 취소되면 이 줄에 도달하지 않으므로
        # 마감 건수에 안 잡히고, 알림은 대기 파일에 남아 재기동 후 다시 처리된다.
        if done is not None:
            done.append(key)

    async def flush(self, timeout_s: float = None):
        """열려 있는 사건을 창 마감을 기다리지 않고 지금 닫는다.

        정상 종료 때 부른다. 안 부르면 대기 중이던 사건이 버려지고 재기동 후 파일에서
        다시 집어 처리하는데, 그러면 디바운스 창을 처음부터 다시 세고 재시도 횟수도
        재기동한 만큼 올라간다. 배포로 몇 번 재기동하면 아직 처리도 안 한 알림이
        한도에 걸려 버려진다.

        timeout_s 를 넘기면 남은 것은 파일에 남겨 둔 채 나간다 — 종료가 무한정
        늦어지면 관리자가 강제로 죽이고, 그건 정상 종료가 아니게 된다.
        """
        keys = list(self._open)
        if not keys:
            return 0
        timeout_s = _env_float("INCIDENT_FLUSH_TIMEOUT_S", 25) if timeout_s is None else timeout_s
        log.info("종료 전 열린 사건 %d건을 마감한다(제한 %.0f초)", len(keys), timeout_s)
        done = []
        try:
            await asyncio.wait_for(
                asyncio.gather(*[self._close(k, done) for k in keys],
                               return_exceptions=True),
                timeout=timeout_s)
        except asyncio.TimeoutError:
            log.warning("마감 시간이 초과됐다 — %d건은 대기 파일에 남긴다(재기동 후 처리)",
                        len(keys) - len(done))
        log.info("종료 전 마감 완료 %d건 / 전체 %d건", len(done), len(keys))
        return len(done)
