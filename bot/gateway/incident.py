"""인시던트 병합 — 알림 N건을 (host, class) 기준으로 1개 사건으로 묶는다.

병합 여부는 코드가 결정하고 LLM은 설명만 한다(선판정과 동일 원칙). 설계·근거는
bot/GATEWAY_GUIDE.md §14. 순수 로직(classify/bridge/Incident)과 비동기 버퍼
(IncidentManager)를 분리 — 앞은 selftest로, 뒤는 짧은 디바운스로 검증.
"""

import asyncio
import hashlib
import logging
import os
import re
import time
from dataclasses import dataclass, field

from .collector import SOURCE_UNAVAILABLE   # 조회 상태 상수는 생산자(collector)에 1곳만 정의

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


# 알림명·아이템키 → incident_class. 위에서부터 먼저 걸리는 것. (근거: demo_c_scenario.md)
# 순서와 키워드 폭이 곧 분류 정확도다 — 틀리면 인시던트 키가 갈려 병합·브리지가 조용히 실패한다.
CLASS_RULES = [
    ("replication", ["복제", "replication", "repl", "slave", "seconds_behind"]),
    ("cpu_io_pressure", ["iowait", "io wait", "i/o", "load average", "cpu", "load",
                         "디스크 지연", "disk latency", "await"]),
    # "ssh" 단독 금지 — "SSH service is down"(서비스 장애)까지 보안 사건으로 끌어갔다.
    ("auth_security", ["브루트포스", "brute", "authentication", "login fail", "sshd",
                       "unauthorized", "비인가", "sca", "fim", "rootcheck"]),
    ("memory_pressure", ["메모리", "memory", "스왑", "swap", "oom"]),
    # "사용률" 단독 금지 — 메모리·CPU 사용률까지 디스크로 흡수했다. "space is"는 표준
    # 템플릿의 "FS [/]: Space is critically low" 형태를 잡기 위한 것(랩 실측 알림명).
    ("disk_space", ["디스크 사용률", "디스크 사용", "filesystem", "vfs.fs", "disk space",
                    "space is", "pused"]),
    # network 를 service_down 보다 앞에 둔다 — "Link down"이 "down"에 걸려 서비스 장애로
    # 분류되던 것을 바로잡는다.
    ("network", ["interface", "packet", "drop", "crc", "link down", "ifoperstatus"]),
    ("service_down", ["proc.num", "process", "not running", "not available", "재기동",
                      "down", "unreachable"]),
    ("service_latency", ["지연", "latency", "response time", "응답", "qps", "queue"]),
]

# 짧은 ASCII 토큰은 단어 경계로 매칭한다. 부분 일치가 실제 오분류를 만들었다 —
# "fim"이 confirm, "sca"가 scan/escalation, "oom"이 room, "down"이 shutdown 에 걸린다.
_WORD_BOUNDARY_MAX = 5


def _matcher(keyword: str):
    if keyword.isascii() and " " not in keyword and len(keyword) <= _WORD_BOUNDARY_MAX:
        return re.compile(rf"(?<!\w){re.escape(keyword)}(?!\w)")
    return None


_COMPILED_RULES = [(cls, [(kw, _matcher(kw)) for kw in kws]) for cls, kws in CLASS_RULES]

# 서로 다른 class라도 같은 호스트·시간창에 겹치면 하나의 인과 후보로 병합하는 조합.
# 복제 지연 시나리오: replication_lag + high_iowait/cpu = 자원 경합이라는 단일 사건.
# 디스크 포화 시나리오(데모 B): 디스크가 차서 서비스가 멈추는 것은 한 사건이다.
#
# 그룹은 서로 겹치면 안 된다 — _bridge_id 가 첫 매칭을 반환하므로 겹치는 class 가 있으면
# 뒤 그룹이 통째로 死코드가 되고, 그것도 조용히 그렇게 된다. 아래 _validate_bridges 가
# import 시점에 이 규칙을 강제한다.
BRIDGE_GROUPS = [
    frozenset({"replication", "cpu_io_pressure"}),
    frozenset({"disk_space", "service_down"}),
]


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


def classify(alert_name: str, item_key: str = "") -> str:
    text = f"{alert_name} {item_key}".lower()
    for cls, matchers in _COMPILED_RULES:
        for kw, rx in matchers:
            if rx.search(text) if rx else kw in text:
                return cls
    return "other"


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

    def add(self, a: Alert, max_alerts: int) -> bool:
        if len(self.alerts) >= max_alerts:
            return False   # 캡 초과 — 창을 늘리지 않아 폭주 시에도 마감됨
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


GATE_MIN_CROSS = _env_int("INCIDENT_GATE_MIN_CROSS", 1)


def should_triage(incident, context: dict, min_cross: int = None) -> tuple:
    """LLM 트리아지 발동 여부 + 사유. 교차 상관할 게 있을 때만 값비싼 LLM을 부른다.

    context = collect_incident_context 결과(로그·보안 포함). 반환 (bool, 사유).
    발동: SEV1 / 병합(2건+) / 교차 소스 조회 실패(미상) / 단일이라도 같은 창에 교차 소스 존재.

    조회 실패를 "신호 없음"으로 취급하면 관측 백엔드가 죽을수록 봇이 조용해진다 — 가장 필요할
    때 침묵하는 셈이라, 실패는 미상으로 보고 보수적으로 발동한다 (G1). 미배선(disabled)은
    의도된 구성이므로 발동 사유가 아니다.
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

    on_close: async 콜러블. 창 마감 = 마지막 알림 후 debounce_s 무알림, 또는 max_window_s 초과.
    SEV1은 priority_debounce_s 로 짧게 대기(조기 회신).
    """

    def __init__(self, on_close, debounce_s: float = None, max_window_s: float = None,
                 priority_debounce_s: float = None, max_alerts: int = None):
        self._on_close = on_close
        self.debounce_s = _env_float("INCIDENT_DEBOUNCE_S", 90) if debounce_s is None else debounce_s
        self.max_window_s = _env_float("INCIDENT_MAX_WINDOW_S", 300) if max_window_s is None else max_window_s
        self.priority_debounce_s = (_env_float("INCIDENT_PRIORITY_DEBOUNCE_S", 15)
                                    if priority_debounce_s is None else priority_debounce_s)
        self.max_alerts = _env_int("INCIDENT_MAX_ALERTS", 20) if max_alerts is None else max_alerts
        self._open: dict = {}
        self._timers: dict = {}

    async def submit(self, a: Alert):
        key = incident_key(a.host, a.incident_class)
        inc = self._open.get(key)
        if inc is None:
            inc = Incident(key=key, host=a.host, alerts=[a],
                           opened_at=a.recv, last_at=a.recv)
            self._open[key] = inc
        else:
            if not inc.add(a, self.max_alerts):
                log.warning("incident %s at max_alerts(%d) — dropping extra %s",
                            key, self.max_alerts, a.alert_name)
                return
        self._schedule(key, inc)

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
        if inc is None:
            return
        try:
            await self._on_close(inc)
        except Exception as e:   # 콜백 실패가 루프를 죽이지 않게
            log.warning("on_close failed for incident %s: %s", key, e)
