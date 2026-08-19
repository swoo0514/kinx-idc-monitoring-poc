"""게이트웨이 생존 신호 — 이상이 아니라 **정상 신호의 부재**로 고장을 잡는다."""

import json
import logging
import os
import re
import socket
import struct
import threading
import time

import httpx

from . import registry

log = logging.getLogger("gateway.heartbeat")

HEADER = b"ZBXD\x01"
TIMEOUT_S = 5

# 조용함으로 판정하지 않고 발행 측 이벤트 수와 받은 수를 비교한다 (§20-3)
RECENT_WINDOW_S = int(os.environ.get("HEARTBEAT_RECENT_WINDOW_S", "3600"))
# 이보다 짧은 구간으로는 비교하지 않는다 — 재기동할 때마다 뜬다
MIN_COMPARE_WINDOW_S = int(os.environ.get("HEARTBEAT_MIN_COMPARE_S", "600"))


def _cfg():
    return (os.environ.get("HEARTBEAT_ZABBIX_SERVER", "").strip(),
            int(os.environ.get("HEARTBEAT_ZABBIX_PORT", "10051")),
            os.environ.get("HEARTBEAT_HOST", "").strip(),
            os.environ.get("HEARTBEAT_KEY", "gateway.heartbeat").strip())


def enabled() -> bool:
    server, _port, host, _key = _cfg()
    return bool(server and host)


def send(values: dict, now: float = None) -> dict:
    """트래퍼로 값을 보낸다. 반환은 서버 응답(또는 실패 사유). 예외를 던지지 않는다."""
    server, port, host, _key = _cfg()
    if not (server and host):
        return {"ok": False, "reason": "미설정"}
    clock = int(time.time() if now is None else now)
    payload = json.dumps({
        "request": "sender data",
        "data": [{"host": host, "key": k, "value": str(v), "clock": clock}
                 for k, v in values.items()],
    }).encode("utf-8")
    packet = HEADER + struct.pack("<II", len(payload), 0) + payload
    try:
        with socket.create_connection((server, port), timeout=TIMEOUT_S) as s:
            s.sendall(packet)
            head = _recv_exact(s, 13)
            if not head or not head.startswith(b"ZBXD"):
                return {"ok": False, "reason": "응답 헤더가 Zabbix 형식이 아니다"}
            (length,) = struct.unpack("<I", head[5:9])
            body = _recv_exact(s, length)
        res = json.loads(body.decode("utf-8"))
        info = res.get("info", "")
        # Zabbix trapper 는 아이템이 없어도 response=success 를 준다 — 실패는 info 문자열에만 있다
        ok = res.get("response") == "success" and _accepted(info)
        if not ok:
            log.warning("heartbeat 거부됨: %s", res)
        return {"ok": ok, "info": info}
    except Exception as e:
        # 여기서 실패하면 Zabbix 쪽에서 nodata 로 잡힌다. 그게 이 기능의 설계다.
        log.warning("heartbeat 전송 실패 %s:%s: %s", server, port, e)
        return {"ok": False, "reason": str(e)}


def _accepted(info: str) -> bool:
    """info 문자열의 failed 가 0인가. 못 읽으면 참으로 본다(형식 변화로 오탐 금지)."""
    m = re.search(r"failed:\s*(\d+)", str(info or ""))
    return int(m.group(1)) == 0 if m else True


def _recv_exact(sock, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            break
        buf += chunk
    return buf


def zabbix_recent_events(window_s: int, now: float = None, source: str = ""):
    """최근 창에서 그 Zabbix 가 만든 문제 이벤트 수. 읽기 전용 조회이고 실패하면 None."""
    conf = registry.source_conf(source) if source else {}
    if conf.get("url"):
        url = str(conf["url"]).rstrip("/")
        token = os.environ.get(conf.get("token_env") or "", "")
    else:
        url = os.environ.get("ZABBIX_URL", "").rstrip("/")
        token = os.environ.get("ZABBIX_TOKEN", "")
    if not (url and token):
        return None
    now = int(time.time() if now is None else now)
    try:
        r = httpx.post(url + "/api_jsonrpc.php", timeout=TIMEOUT_S,
                       headers={"Authorization": "Bearer " + token,
                                "Content-Type": "application/json-rpc"},
                       json={"jsonrpc": "2.0", "id": 1, "method": "event.get",
                             "params": {"source": 0, "object": 0, "value": 1,
                                        "time_from": now - int(window_s),
                                        "time_till": now, "countOutput": True}})
        r.raise_for_status()
        return int(r.json()["result"])
    except Exception as e:
        log.warning("발행 측 이벤트 수 조회 실패%s: %s",
                    " (%s)" % source if source else "", e)
        return None


class Beat:
    """주기 전송 + 처리량 집계."""

    def __init__(self, interval_s: float = None):
        self.interval_s = float(os.environ.get("HEARTBEAT_INTERVAL_S", "60")
                                if interval_s is None else interval_s)
        self.started_at = time.time()
        self.last_alert_at = None
        self.counters = {"alerts": 0, "incidents": 0, "analyzed": 0, "skipped": 0}
        self._recv: list = []   # 최근 수신 시각 — 누적 수로는 "요즘" 을 판정할 수 없다
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread = None

    def mark_alert(self, source: str = ""):
        now = time.time()
        with self._lock:
            self.counters["alerts"] += 1
            self.last_alert_at = now
            # 어느 감시 서버에서 왔는지 같이 남긴다 — 서버별로 비교해야 한쪽 끊김을 잡는다
            self._recv.append((now, source))
            self._recv[:] = [r for r in self._recv if now - r[0] <= RECENT_WINDOW_S]

    def mark(self, name: str):
        with self._lock:
            if name in self.counters:
                self.counters[name] += 1

    def recent_alerts(self, now: float = None, source: str = None) -> int:
        """최근 창에 받은 알림 수. source 를 주면 그 감시 서버 것만 센다."""
        now = time.time() if now is None else now
        with self._lock:
            self._recv[:] = [r for r in self._recv if now - r[0] <= RECENT_WINDOW_S]
            if source is None:
                return len(self._recv)
            return len([r for r in self._recv if r[1] == source])

    def values(self, now: float = None) -> dict:
        now = time.time() if now is None else now
        with self._lock:
            c = dict(self.counters)
            last = self.last_alert_at
        # 한 번도 못 받았으면 기동 시각 기준 — 비우면 "아직 없음"과 "오래 없음"이 안 갈린다
        since = now - (last if last else self.started_at)
        out = {
            "gateway.alive": 1,
            "gateway.uptime": int(now - self.started_at),
            "gateway.since_last_alert": int(since),
            "gateway.alerts": c["alerts"],
            "gateway.incidents": c["incidents"],
            "gateway.analyzed": c["analyzed"],
            "gateway.skipped": c["skipped"],
            "gateway.recent_alerts": self.recent_alerts(now),   # 아래에서 같은 구간으로 맞춘다
        }
        # 열화로 내려간 건수 — 늘면 분석 품질이 조용히 떨어진 것이므로 밖에서 보여야 한다
        try:
            from . import egress
            from .alerts import incident
            st = egress.stats()
            out["gateway.llm_peak_inflight"] = egress.peak_last_hour(now)
            out["gateway.llm_queue_timeouts"] = st["queue_timeouts"]
            out["gateway.llm_hour_blocked"] = st["hour_blocked"]
            out["gateway.llm_calls_1h"] = egress.calls_last_hour(now)
            # 용도별로 나눠 본다 — 상한을 올릴지 리포트를 옮길지 정하려면 필요하다
            kc = egress.kind_counts(now)
            out["gateway.llm_calls_triage_1h"] = kc.get("triage", 0)
            out["gateway.llm_calls_monthly_1h"] = kc.get("monthly", 0)
            # 무엇 때문에 분석이 돌았는지 — 조회 실패가 치솟으면 관측 소스를 고치라는 신호다
            fc = incident.fire_counts(now)
            out["gateway.fire_degraded_1h"] = fc.get("degraded", 0)
            out["gateway.fire_new_1h"] = fc.get("new", 0)
        except Exception as e:
            log.warning("LLM 혼잡 지표 수집 실패: %s", e)
        # 이름 표 신선도 — 없으면 표가 얼어붙어도 아무 지표가 안 움직인다
        # 개수·나이·오류를 따로 보낸다. 조용한 고장은 0 이 아니라 줄어드는 모양이다
        try:
            from . import nametable
            st = nametable.status()
            out["gateway.names"] = int(st.get("terms") or 0)
            built = float(st.get("built_at") or 0)
            # 한 번도 못 만들었으면 나이를 지어내지 않는다. -1 은 "모름" 이다.
            out["gateway.names_age"] = int(now - built) if built else -1
            out["gateway.names_error"] = 1 if st.get("error") else 0
        except Exception as e:
            log.warning("이름 표 상태 수집 실패: %s", e)
        # 발행 측이 같은 구간에 몇 건을 만들었는지 — 창을 기동 이후로 잘라야 비교가 성립한다
        window = min(RECENT_WINDOW_S, int(now - self.started_at))
        if window < MIN_COMPARE_WINDOW_S:
            return out   # 기동 직후라 비교할 만한 구간이 없다 — 값 자체를 안 보낸다
        # 못 읽으면 아예 안 보낸다 — 0 을 보내면 "발행 측도 조용했다"로 읽힌다
        for name in registry.source_names():
            # 아이템 키에 서버 이름을 붙인다 — 트래퍼 호스트는 하나로 두고 항목만 늘린다
            got = self.recent_alerts(now, source=name)
            out["gateway.recent_alerts[%s]" % name] = got
            produced = zabbix_recent_events(window, now, source=name)
            if produced is not None:
                out["gateway.zbx_events[%s]" % name] = produced
        if not registry.source_names():
            produced = zabbix_recent_events(window, now)
            if produced is not None:
                out["gateway.zbx_events"] = produced
        return out

    def start(self):
        if not enabled():
            log.info("heartbeat 미설정 — 전송하지 않는다(HEARTBEAT_ZABBIX_SERVER·HEARTBEAT_HOST)")
            return False
        if self._thread and self._thread.is_alive():
            return True
        self._thread = threading.Thread(target=self._loop, name="heartbeat", daemon=True)
        self._thread.start()
        log.info("heartbeat 시작 — %.0f초마다 전송", self.interval_s)
        return True

    def stop(self):
        self._stop.set()

    def _loop(self):
        while not self._stop.wait(self.interval_s):
            send(self.values())
