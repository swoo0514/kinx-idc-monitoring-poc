"""인시던트 병합 — 알림 N건을 (host, class) 기준으로 1개 사건으로 묶는다.

병합 여부는 코드가 결정하고 LLM은 설명만 한다(선판정과 동일 원칙). 설계·근거는
bot/GATEWAY_GUIDE.md §14. 순수 로직(classify/bridge/Incident)과 비동기 버퍼
(IncidentManager)를 분리 — 앞은 selftest로, 뒤는 짧은 디바운스로 검증.
"""

import asyncio
import hashlib
import logging
import os
import time
from dataclasses import dataclass, field

log = logging.getLogger("gateway.incident")

# 알림명·아이템키 → incident_class. 위에서부터 먼저 걸리는 것. (근거: demo_c_scenario.md)
CLASS_RULES = [
    ("replication", ["복제", "replication", "repl", "slave", "seconds_behind"]),
    ("cpu_io_pressure", ["iowait", "io wait", "i/o", "load average", "cpu", "load",
                         "디스크 지연", "disk latency", "await"]),
    ("auth_security", ["브루트포스", "brute", "authentication", "login fail", "ssh",
                       "unauthorized", "비인가", "5712", "sca", "fim", "rootcheck"]),
    ("disk_space", ["사용률", "filesystem", "vfs.fs", "disk space", "디스크 사용", "pused"]),
    ("service_down", ["proc.num", "process", "not running", "재기동", "down", "unreachable"]),
    ("service_latency", ["지연", "latency", "response time", "응답", "qps", "queue"]),
    ("network", ["interface", "packet", "drop", "crc", "link down", "ifoperstatus"]),
]

# 서로 다른 class라도 같은 호스트·시간창에 겹치면 하나의 인과 후보로 병합하는 조합.
# 복제 지연 시나리오: replication_lag + high_iowait/cpu = 자원 경합이라는 단일 사건.
BRIDGE_GROUPS = [
    frozenset({"replication", "cpu_io_pressure"}),
]

_SEV_ORDER = {"SEV1": 1, "SEV2": 2, "SEV3": 3, "SEV4": 4, "NONE": 5}


def classify(alert_name: str, item_key: str = "") -> str:
    text = f"{alert_name} {item_key}".lower()
    for cls, keywords in CLASS_RULES:
        if any(k in text for k in keywords):
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
        if len(classes) > 1 and any(set(classes) & grp == set(classes) or
                                    len(set(classes) & grp) > 1 for grp in BRIDGE_GROUPS):
            combo = " · 알려진 인과 조합"
        return (f"동일 호스트 · {self.window_s()}s 관측창 · {n}건 · "
                f"유형 {classes}{combo}")


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
