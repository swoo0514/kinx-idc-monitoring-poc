"""게이트웨이 생존 신호 — 이상이 아니라 **정상 신호의 부재**로 고장을 잡는다.

봇이 죽으면 알림은 계속 오는데 아무도 분석하지 않고, 그 상태가 조용하다. 실환경에서
알림 채널 하나가 30일간 9,198건을 연속 실패했는데 아무도 몰랐던 것과 같은 구조다.
그래서 봇이 살아 있다는 신호를 주기적으로 Zabbix 에 보내고, 끊기면 Zabbix 가
`nodata()` 로 잡게 한다. 감시하는 쪽을 감시 대상 밖에 두는 것이 요점이다.

Zabbix sender 프로토콜을 직접 쓴다(공식 문서 확인: 헤더 `ZBXD` + 플래그 1바이트 +
길이 4바이트 리틀엔디언 + 예약 4바이트, 본문은 `{"request":"sender data","data":[...]}`).
zabbix_sender 실행 파일을 요구하지 않으므로 설치 환경을 가리지 않는다.

⚠ 실환경에는 보내지 않는다. 값 전송도 쓰기이며, 이 프로젝트는 실환경 Zabbix 에
읽기 전용으로만 접근한다. 실환경 적용 절차는 GATEWAY_GUIDE §20.

설정·운영 기준은 bot/GATEWAY_GUIDE.md §20.
"""

import json
import logging
import os
import socket
import struct
import threading
import time

import httpx

from . import registry

log = logging.getLogger("gateway.heartbeat")

HEADER = b"ZBXD\x01"
TIMEOUT_S = 5

# "알림이 안 들어온다"를 조용함으로 판정하면 안 된다. 조용한 시간대가 정상인 환경이
# 대부분이라 그러면 우리가 없애려던 노이즈를 새로 만든다. 대신 **발행 측이 만든 이벤트
# 수와 우리가 받은 수를 비교한다** — Zabbix 에는 이벤트가 쌓였는데 봇에 하나도 안 왔으면
# 그건 조용한 것이 아니라 경로가 끊긴 것이다. 근거는 GATEWAY_GUIDE §20-3.
RECENT_WINDOW_S = int(os.environ.get("HEARTBEAT_RECENT_WINDOW_S", "3600"))
# 이보다 짧은 구간으로는 비교하지 않는다. 기동 직후 몇 초 사이의 한두 건으로
# 경로 고장을 판정하면 재기동할 때마다 뜬다.
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
    """트래퍼로 값을 보낸다. 반환은 서버 응답(또는 실패 사유). 예외를 던지지 않는다.

    values 는 {아이템키: 값}. 보내는 쪽이 죽어도 봇 흐름은 계속되어야 하므로
    모든 실패를 삼키고 기록만 남긴다.
    """
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
        ok = res.get("response") == "success"
        if not ok:
            log.warning("heartbeat 거부됨: %s", res)
        return {"ok": ok, "info": res.get("info", "")}
    except Exception as e:
        # 여기서 실패하면 Zabbix 쪽에서 nodata 로 잡힌다. 그게 이 기능의 설계다.
        log.warning("heartbeat 전송 실패 %s:%s: %s", server, port, e)
        return {"ok": False, "reason": str(e)}


def _recv_exact(sock, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            break
        buf += chunk
    return buf


def zabbix_recent_events(window_s: int, now: float = None, source: str = ""):
    """최근 창에서 그 Zabbix 가 만든 문제 이벤트 수. 읽기 전용 조회이고 실패하면 None.

    countOutput 을 쓰므로 몇만 건이어도 응답이 한 줄이다(공식 문서 확인).
    수집기와 달리 여기서는 동기 호출이다 — 전송 스레드 안에서 돌기 때문이다.

    감시 서버가 둘 이상이면 **서버마다 따로 세야 한다.** 한 곳만 세면 그 서버는
    멀쩡한데 다른 서버의 알림 경로가 끊긴 상태를 못 잡는다.
    """
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
    """주기 전송 + 처리량 집계.

    보내는 값은 생존 여부만이 아니다. 살아는 있는데 알림이 한 건도 안 들어오는 상태가
    따로 있고(발행 측 액션·미디어 고장), 그건 생존 신호만으로는 구분되지 않는다.
    그래서 마지막 알림 이후 경과 시간도 함께 보낸다.
    """

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
            # 어느 감시 서버에서 왔는지 같이 남긴다 — 서버별로 비교해야 한쪽만
            # 끊긴 것을 잡는다.
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
        # 알림을 한 번도 못 받았으면 기동 시각을 기준으로 잰다 — 값을 비우면 Zabbix 가
        # "아직 없음"과 "오래 없음"을 구분하지 못한다.
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
        # LLM 혼잡. 상한에 밀려 열화로 내려간 건수가 늘면 분석 품질이 조용히 떨어진
        # 것이므로 밖에서 보여야 한다. 값을 못 읽어도 생존 신호는 계속 보낸다.
        try:
            from . import incident, llm
            st = llm.stats()
            out["gateway.llm_peak_inflight"] = st["peak_inflight"]
            out["gateway.llm_queue_timeouts"] = st["queue_timeouts"]
            out["gateway.llm_hour_blocked"] = st["hour_blocked"]
            out["gateway.llm_calls_1h"] = llm.calls_last_hour(now)
            # 무엇 때문에 분석이 돌았는지. 조회 실패 쪽이 치솟으면 봇이 아니라
            # 관측 소스를 고쳐야 한다는 신호다. 예전에는 이 신호가 조용한 차단으로
            # 나타나 밖에서 보이지 않았다.
            fc = incident.fire_counts(now)
            out["gateway.fire_degraded_1h"] = fc.get("degraded", 0)
            out["gateway.fire_new_1h"] = fc.get("new", 0)
        except Exception as e:
            log.warning("LLM 혼잡 지표 수집 실패: %s", e)
        # 발행 측이 **같은 구간에** 몇 건을 만들었는지. 창을 기동 이후로 자르는 것이
        # 중요하다 — 재기동하면 우리 수신 기록은 비는데 발행 측은 지난 한 시간을 그대로
        # 세므로, 자르지 않으면 재기동 직후 한 시간 동안 "저쪽엔 있는데 이쪽은 0" 이
        # 되어 오탐이 난다. 두 값이 같은 구간을 봐야 비교가 성립한다.
        window = min(RECENT_WINDOW_S, int(now - self.started_at))
        if window < MIN_COMPARE_WINDOW_S:
            return out   # 기동 직후라 비교할 만한 구간이 없다 — 값 자체를 안 보낸다
        # 못 읽으면 아예 안 보낸다 — 0 을 보내면 "발행 측도 조용했다"로 읽혀
        # 경로 고장을 정상으로 만든다.
        for name in registry.source_names():
            # 아이템 키에 서버 이름을 붙인다. 감시 서버가 늘어도 트래퍼 호스트는
            # 하나로 두고 항목만 늘리면 된다 — Zabbix 쪽 구성 부담이 작다.
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
