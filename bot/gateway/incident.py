"""인시던트 병합 — 알림 N건을 (host, class) 기준으로 1개 사건으로 묶는다.

설계·근거는 bot/GATEWAY_GUIDE.md §14. 순수 로직(classify/bridge/Incident)과 비동기 버퍼
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

from .collector import SOURCE_UNAVAILABLE

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


# 위에서부터 먼저 걸리는 것. 순서와 키워드 폭이 곧 분류 정확도다 — GATEWAY_GUIDE §14.
# 손대면 selftest 의 CASES_CLASSIFY 를 함께 늘린다.
CLASS_RULES = [
    ("replication", ["복제", "replication", "repl", "slave", "seconds_behind"]),
    # 아래 실환경 키워드 3종은 2026-08-07 사내 90일 실측으로 추가했다. 미분류의 96%가 이 키워드로 해소되고 **기존 분류를 뺏은 건은 0건**임을 확인했다.
    # 표준 템플릿 트리거명이라 실환경 전반에 적용된다. 근거: correlation_mining_methodology.md
    ("cpu_io_pressure", ["iowait", "io wait", "i/o", "load average", "cpu", "load",
                         "디스크 지연", "disk latency", "await",
                         # "vdb: Disk read/write request responses are too high" —
                         # 디스크 응답 지연인데 이름에 latency·i/o·await 가 없어 미분류였다.
                         # 단일 유형으로 실환경 미분류의 92%를 차지한다.
                         "read/write request", "disk read/write"]),
    ("auth_security", ["브루트포스", "brute", "authentication", "login fail", "sshd",
                       "unauthorized", "비인가", "sca", "fim", "rootcheck",
                       "integrity", "무결성", "syscheck", "파일 변경", "루트킷",
                       # Zabbix 쪽 인증 파일 변경 감시. Wazuh FIM 과 같은 성격이다.
                       "/etc/passwd", "/etc/shadow"]),
    ("memory_pressure", ["메모리", "memory", "스왑", "swap", "oom"]),
    ("disk_space", ["디스크 사용률", "디스크 사용", "filesystem", "vfs.fs", "disk space",
                    "space is", "pused"]),
    ("network", ["interface", "packet", "drop", "crc", "link down", "ifoperstatus"]),
    ("service_down", ["proc.num", "process", "not running", "not available", "재기동",
                      "down", "unreachable",
                      # 실측 추가. 여기 있는 것은 **표준 템플릿·일반 용어만** 둔다 —
                      # 특정 사이트의 커스텀 트리거명은 아래 SITE_CLASS_KEYWORDS 로 뺀다.
                      "restarted", "health check", "not response", "no snmp data"]),
    ("service_latency", ["지연", "latency", "response time", "응답", "qps", "queue"]),
]

# 사이트 고유 트리거명 키워드. 조직마다 다르므로 코드에 박지 않고 환경변수로 받는다.
# 형식: "class=키워드|키워드,class=키워드"  예) service_down=not connect|check is fail
# 왜 분리하나 — 한 조직의 관용구를 범용 규칙에 섞으면 다른 환경에서 뜻 없는 규칙이 되고,
# 나중에 왜 있는지 아무도 모르는 줄이 된다.
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

_WORD_BOUNDARY_MAX = 5


def _matcher(keyword: str):
    # 경계를 \w 가 아니라 영숫자로 잡는다 — \w 는 밑줄을 단어 문자로 보므로 "sshd" 가
    # "sshd_config" 에 안 걸린다. 근거는 GATEWAY_GUIDE §14.
    if keyword.isascii() and " " not in keyword and len(keyword) <= _WORD_BOUNDARY_MAX:
        return re.compile(rf"(?<![A-Za-z0-9]){re.escape(keyword)}(?![A-Za-z0-9])")
    return None


_COMPILED_RULES = [(cls, [(kw, _matcher(kw)) for kw in kws]) for cls, kws in CLASS_RULES]

# 서로 겹치면 안 된다 — _bridge_id 가 첫 매칭을 반환하므로 겹치면 뒤 그룹이 死코드가 된다.
# 아래 _validate_bridges 가 import 시점에 강제한다. 조합 근거는 GATEWAY_GUIDE §14.
BRIDGE_GROUPS = [
    frozenset({"replication", "cpu_io_pressure"}),
    frozenset({"disk_space", "service_down"}),
]


# 열린 문제 연계 규칙 — (열린 쪽, 뒤따르는 쪽): 측정 근거.
#
# BRIDGE_GROUPS 와 무엇이 다른가:
#   BRIDGE_GROUPS 는 **같은 시간창** 안의 알림을 하나로 묶는 병합 키다. 무방향이고
#   서로 겹칠 수 없다(_bridge_id 가 첫 매칭을 반환하므로).
#   이 표는 **이미 열려 있는 문제**를 컨텍스트로 붙이기 위한 것이다. 방향이 있고,
#   병합 키를 만들지 않으므로 겹쳐도 된다 — disk_space 가 두 항목에 모두 나온다.
#
# 왜 필요한가 — 실측(2026-08-07, 사내 90일). 게이트웨이의 실제 창(무알림 90초/최대 300초)
# 안에서 **서로 다른 클래스가 함께 나는 일이 일어나지 않는다**(유형 혼합 0건). 병합 정책을
# 3안으로 바꿔 시뮬레이션해도 결과가 전부 동일했다. 반면 "열려 있는 동안 뒤따랐는가"로
# 보면 아래 관계가 오탐율 5% 통제를 통과한다. 창을 넓히는 것은 6시간까지 가야 효과가 나고
# 그 대가로 사건 수가 절반이 된다. 설계 판단은 private/docs/open_problem_linkage_design.md.
# **값은 환경마다 다르다.** 아래는 기본값이 아니라 예시이며, 실제 운영에서는 그 환경에서
# 측정한 파일을 읽어 쓴다(OPEN_LINK_RULES_FILE). 값을 코드에 박아 두면 환경이 바뀌어도
# 조용히 낡는다 — 마이닝 도구가 파일을 내고 게이트웨이가 그 파일을 읽는 것이 고리다.
#   생성: python bot/bridge_miner.py --load <덤프> --by cls --overlap --null 200 --emit-rules <파일>
#   적용: OPEN_LINK_RULES_FILE=<파일>
# 아래 값은 **형식을 보이기 위한 자리표시자**이며 어떤 환경의 측정값도 아니다.
# 실측값은 리포에 두지 않는다(리포 규칙: 실환경에서 뽑은 데이터는 마스킹해도 커밋 금지).
# 측정한 파일을 OPEN_LINK_RULES_FILE 로 지정해 쓴다.
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
        log.info("열린 문제 연계: 측정 파일 없음 — 예시값 사용(%s). 운영 적용 전 재측정 필요",
                 _EXAMPLE_MEASURED)
        return dict(_EXAMPLE_OPEN_LINK_RULES), _EXAMPLE_MEASURED
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

# 우리 분류를 선언하는 트리거 태그 이름.
#
# **"class" 를 쓰면 안 된다.** 실측(2026-08-07 랩·실환경) — Zabbix 표준 템플릿 트리거가
# 이미 `class=os`(Linux 계열)·`class=database`(MySQL 계열) 태그를 달고 나온다. 같은 이름에
# 우리 값을 얹으면 한 트리거에 의미가 다른 두 값이 공존하고, 어느 쪽이 읽힐지가 태그 순서에
# 좌우된다. 발행 측에 태그를 부여하는 개선안(next-steps §1-1-12)은 이 충돌을 전제로 다시
# 써야 한다. 이름을 분리하면 표준 태그를 아예 보지 않으므로 경고도 사라진다.
# 이미 class= 로 운영 중인 곳은 CLASS_TAG=class 로 되돌릴 수 있다.
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


def classify(alert_name: str, item_key: str = "", tags=None, groups=None) -> str:
    """선언(태그·그룹) → 폴백(키워드) 순. 선언이 있으면 문자열을 보지 않는다."""
    declared = _tag_class(tags)
    if declared:
        return declared

    mapped = _group_class(groups)
    if mapped:
        return mapped

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


def incident_key(host: str, cls: str) -> tuple:
    """같은 키의 알림은 한 인시던트. 브리지 조합이면 다른 class여도 같은 키."""
    return (host, _bridge_id(cls))


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
        raw = f"{self.host}|{self.key[1]}|{','.join(sorted(self.classes()))}"
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


def should_triage(incident, context: dict, min_cross: int = None) -> tuple:
    """LLM 트리아지 발동 여부 + 사유. 반환 (bool, 사유).

    조건과 순서의 근거는 GATEWAY_GUIDE §14 발동조건 게이트.
    """
    min_cross = GATE_MIN_CROSS if min_cross is None else min_cross
    if incident.dominant_sev() == "SEV1":
        return True, "SEV1 — 위중, 무조건 발동"
    if incident.is_merged():
        return True, f"{len(incident.alerts)}건 병합 — 교차 축 존재"
    sources = context.get("sources") or {}
    failed = [k for k in ("logs", "security") if sources.get(k) == SOURCE_UNAVAILABLE]
    if failed:
        return True, f"교차 소스 조회 실패({', '.join(failed)}) — 신호 없음이 아니라 미상, 보수적 발동"
    cross = sum(1 for k in ("logs", "security") if context.get(k))
    if cross >= min_cross:
        return True, f"단일 알림 + 교차 소스 {cross}종(로그/보안)"
    return False, "단일 축·교차 신호 없음(조회는 정상) — LLM 스킵"


class IncidentManager:
    """알림을 (host, class) 버퍼에 모아, 디바운스 창이 닫히면 on_close(incident) 1회 호출.

    on_signal(alert, thread_ts) -> ts : 알림 도착 즉시 원시 신호를 게시하는 선택적 콜백.
    신규 인시던트면 thread_ts=None(최상위, 반환 ts 가 앵커), 후속이면 앵커 ts(답글).
    창 마감 조건과 fast-path 설계는 GATEWAY_GUIDE §14·§18.
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
        key = incident_key(a.host, a.incident_class)
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
        inc = self._open.pop(key, None)
        self._timers.pop(key, None)
        self._locks.pop(key, None)
        if inc is None:
            return
        try:
            await self._on_close(inc)
        except Exception as e:
            log.warning("on_close failed for incident %s: %s", key, e)
