"""질의 도구의 질의문 조립과 검사. 설계는 bot/GATEWAY_GUIDE.md §27.

`collector.ZabbixClient.call` 은 `.get` 아닌 메서드를 거부한다. Loki 와 Wazuh 에는
메서드 이름이 없어 같은 검사를 걸 수 없다. **두 축의 등가물은 호출자가 질의문을 못
주는 것이다.** 도구는 라벨·기간·문자열 필터만 받고 질의문은 여기서 만든다.
"""

import logging
import re

log = logging.getLogger("gateway.asktools")

# 조회 기간(분). 모델이 큰 값을 넣어도 여기서 잘린다.
WINDOW_DEFAULT_M = 60
WINDOW_MAX_M = 1440
# 건수 상한이 있어 구간을 넓혀도 무겁지 않은 조회(보안 경보·문제 목록). 사람이 보는
# 대시보드 구간이 7일인 일이 흔한데 하루로 자르면 그 화면을 설명하지 못한다.
WINDOW_MAX_WIDE_M = 10080
# 추세(trend)는 시간 단위로 집계돼 있어 긴 구간도 가볍다. Zabbix 기본 보관도 이력보다
# 훨씬 길다. "90일 추이" 는 사람이 흔히 묻는 것이라 그만큼은 볼 수 있어야 한다.
WINDOW_MAX_TREND_M = 129600
# 이 길이를 넘으면 이력 대신 추세를 본다. 이력 보관이 짧아 그보다 길면 비거나 잘린다.
TREND_FROM_S = 2 * 86400

# 문자열 필터 상한. 길면 질의가 무거워지고, 정규식으로 쓰려는 시도이기도 하다.
FILTER_MAX_CHARS = 80
# LogQL 질의문을 깨뜨리는 글자. 하나라도 있으면 안 만든다.
_UNSAFE = re.compile(r'["{}\\\r\n]')
# 라벨 값은 호스트 이름이라 더 좁게 본다.
_LABEL_OK = re.compile(r"^[A-Za-z0-9._\-]+$")
# `a|b` 로 나눈 낱말 하나. 정규식 특수문자를 빼서 조립한 질의문이 의도대로만 돌게 한다.
_TERM_OK = re.compile(r"^[A-Za-z0-9._/\- ]+$")
# 한 번에 찾을 낱말 수. 늘리면 질의가 무거워진다.
FILTER_MAX_TERMS = 5

# 도구가 쓰는 Zabbix 메서드. `.get` 이어도 이 목록 밖이면 거부한다 — 읽기 전용이라고
# 다 열어 주면 사용자·설정 조회까지 나간다.
ZBX_METHODS = frozenset((
    "host.get", "item.get", "history.get", "trend.get", "problem.get", "trigger.get",
    "event.get",
))


# 지표 표본을 얼마나 받아 얼마로 줄일지. 상한만큼만 최신순으로 받으면 긴 구간의
# 앞부분이 통째로 잘려 먼저 난 스파이크를 못 본다(2026-08-18 실측).
HISTORY_FETCH_MAX = 2000
HISTORY_BUCKETS = 60


def downsample(points: list, buckets: int = HISTORY_BUCKETS) -> list:
    """시계열을 구간별로 줄이되 **극단값을 살린다.**

    사람이 그래프를 보고 묻는 이유는 대개 튄 자리 때문이다. 균등하게 솎아 내면 그
    한 점이 사라져 "정상입니다" 가 나온다. 구간마다 최소·최대만 남기면 모양이 유지된다.
    """
    pts = sorted(points or [], key=lambda p: p["t"])
    if len(pts) <= buckets or buckets <= 0:
        return pts
    span = max(1, len(pts) // buckets)
    out = []
    for i in range(0, len(pts), span):
        chunk = pts[i:i + span]
        lo = min(chunk, key=lambda p: float(p["v"]))
        hi = max(chunk, key=lambda p: float(p["v"]))
        out.append(lo)
        if hi is not lo:
            out.append(hi)
    return sorted(out, key=lambda p: p["t"])


def parse_when(value):
    """시각 한 개를 유닉스 초로. 못 읽으면 None — 지어내지 않는다.

    사람은 화면에 보이는 절대 시각으로 묻는다. 도구가 상대 창만 받으면 모델이 그것을
    "지금부터 N분" 으로 바꾸고, 그러면 **엉뚱한 날을 본다**(2026-08-18 실측).
    """
    if value is None or value == "":
        return None
    try:                                   # 유닉스 초(문자열 포함)
        n = int(float(value))
        if n > 10 ** 12:                   # 밀리초로 준 경우
            n //= 1000
        if n > 10 ** 8:
            return n
    except (TypeError, ValueError):
        pass
    text = str(value).strip().replace("Z", "+00:00")
    try:
        import datetime
        dt = datetime.datetime.fromisoformat(text)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=datetime.timezone.utc)
        return int(dt.timestamp())
    except ValueError:
        return None


# 사람이 붙여 넣는 글에 든 시각. 화면이 넘긴 구간이 없을 때만 쓴다.
_ISO_RE = re.compile(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?Z?")


def span_in_text(text: str):
    """질문 글에 적힌 구간 `(시작, 끝)`. 못 읽으면 None.

    화면에서 열지 않고 질문 글만 붙여 넣는 일이 잦다. 그러면 패널 맥락이 아예 안 오고
    도구는 최근 창을 본다. 사람은 글에 구간을 적어 놓고 물었는데 봇은 다른 구간을 보고
    답한다(2026-08-18 실측: 답은 8월 11~13일을 말하는데 붙은 그림은 최근 1시간이었다).

    **지어내지 않는다.** 글에서 시각 두 개를 실제로 읽었을 때만 쓴다.
    """
    found = []
    for m in _ISO_RE.findall(str(text or "")):
        t = parse_when(m)
        if t:
            found.append(t)
    if len(found) < 2:
        return None
    a, b = min(found), max(found)
    return (a, b) if a < b else None


def window_bounds(args: dict, now: int, max_m: int = 0, default_span=None) -> tuple:
    """조회 구간 `(시작, 끝, 잘렸는가)`. 절대 구간이 있으면 그것을, 없으면 상대 창을.

    구간 길이는 상한 안으로 자른다. 뒤집혀 오면 바로잡는다 — 사람이 끌어 놓은 순서를
    모델이 그대로 옮기는 일이 있다.

    **잘랐으면 잘랐다고 돌려준다.** 조용히 자르면 7일을 물은 사람이 1일치 결과를 보고
    7일 내내 아무 일도 없었다고 읽는다(2026-08-18 랩 실측).
    """
    cap = int(max_m or WINDOW_MAX_M) * 60
    a = parse_when((args or {}).get("from"))
    b = parse_when((args or {}).get("to"))
    # **사람이 보던 구간을 모델에게 받아 적으라고 시키지 않는다.** 화면이 이미 넘겨 준
    # 값이 있는데 모델이 인자로 안 옮기면 조용히 최근 창으로 떨어진다. 2026-08-18 실측:
    # 8월 11~13일 패널을 보고 물었는데 최근 1시간만 조회하고 "과거 구간 조회가
    # 불가능합니다" 라고 답했다. 모델이 구간을 직접 주면 그쪽이 이긴다.
    if (a is None and b is None and default_span
            and not (args or {}).get("window_m") and not (args or {}).get("at")):
        a, b = int(default_span[0]), int(default_span[1])
    if a is not None and b is not None:
        if a > b:
            a, b = b, a
        # 자를 때는 **최신 쪽을 남긴다.** 조회가 최신순 정렬이라 앞쪽을 남기면 사람이
        # 보고 있는 화면의 오른쪽 끝이 통째로 빠지고, 방금 난 일을 못 본다.
        return max(a, b - cap), b, (b - a) > cap
    at = parse_when((args or {}).get("at"))
    asked = raw_window_s((args or {}).get("window_m"))
    win = min(clamp_window((args or {}).get("window_m"), cap // 60) * 60, cap)
    # **상대 구간도 잘렸으면 잘렸다고 말한다.** 절대 구간에만 통지를 붙였더니 90일을
    # 물은 요청이 조용히 하루가 됐고, 모델은 하루치를 90일치로 알고 답했다(실측).
    cut = asked > win
    if at is not None:                     # 그 시각을 가운데 두고 앞뒤로
        return at - win // 2, at + win // 2, cut
    return now - win, now, cut


def raw_window_s(minutes) -> int:
    """사람이 실제로 요청한 창 길이(초). 상한을 적용하기 전 값이다."""
    try:
        m = int(minutes)
    except (TypeError, ValueError):
        return 0
    return max(0, m) * 60


def window_label(start: int, end: int) -> str:
    """실제로 본 구간을 사람이 읽는 형태로.

    잘렸는지만 알려서는 모델이 몇 시부터 몇 시까지를 봤는지 모른다. 물결표는 쓰지
    않는다 — 화면의 마크다운이 취소선으로 읽는다.
    """
    import datetime
    def fmt(t):
        return datetime.datetime.utcfromtimestamp(int(t)).strftime("%Y-%m-%d %H:%M")
    return "%s → %s UTC" % (fmt(start), fmt(end))


# 이름으로 아이템을 고를 때 몇 개까지 볼 것인가. 접두사가 캐시에 올라가 있어 여유가 있다.
ITEM_LIMIT = 8

_WORD = re.compile(r"[A-Za-z0-9]+")


def rank_items(items: list, match: str) -> list:
    """이름 검색 결과를 관련도 순으로. 검색어가 없으면 순서를 안 바꾼다.

    Zabbix 는 이름 가나다순으로 돌려주는데, 그 앞쪽이 원하는 값이라는 보장이 없다.
    2026-08-18 랩 실측으로 `cpu` 는 17개가 걸리고 앞 5개가 guest·idle·interrupt·iowait·
    nice 로 채워져 **`CPU utilization` 이 한 번도 안 들어왔다.**

    기준은 둘이다. 검색어가 낱말로 맞는 것을 먼저 보고, 그다음 이름이 짧은 것을 먼저
    본다. 낱말이 적은 이름일수록 그 값을 직접 가리킨다("CPU utilization" 대 "CPU guest
    nice time"). 잡음 낱말 목록을 코드에 박지 않는다 — 환경마다 다르고 금방 낡는다.
    """
    want = str(match or "").strip().lower()
    if not want:
        return list(items or [])

    def score(it):
        name = str(it.get("name") or "")
        words = [w.lower() for w in _WORD.findall(name)]
        exact = 0 if want in words else 1          # 낱말로 맞으면 앞
        return (exact, len(words), len(name), name)

    return sorted(items or [], key=score)


def note_if_cut(out, total: int, shown: int, dropped: list):
    """이름 검색이 잘렸으면 몇 개를 못 봤고 그것이 무엇인지 결과에 적는다.

    이름은 짧아서 열 몇 개라도 부담이 없다. 안 알리면 모델은 실린 것이 전부인 줄 알고
    "정상" 이라 답한다.
    """
    if not isinstance(out, dict) or int(total or 0) <= int(shown or 0):
        return out
    names = ", ".join(str(n) for n in (dropped or [])[:20])
    msg = ("이름이 맞는 아이템 %d개 중 %d개만 실었다. 안 실은 것: %s. 원하는 것이 없으면 "
           "match 를 더 좁혀서 다시 불러라." % (int(total), int(shown), names))
    out["note"] = (str(out.get("note") or "") + " " + msg).strip()
    return out


def note_if_no_points(out):
    """지표를 받았는데 점이 0개면 그 사실을 결과에 적는다.

    조회는 성공했고 아이템도 있는데 값이 없다면 구간을 잘못 고른 것이다. 안 알리면
    모델은 현재 값(last)만 보고 "지금 정상" 으로 답한다. 2026-08-18 랩 실측으로 2025년
    1월을 조회하고 90일 추이 질문에 현재 상태로 답했다.
    """
    if not isinstance(out, dict):
        return out
    items = out.get("metrics") or []
    if items and all(int(m.get("sampled_from") or 0) == 0 for m in items):
        msg = ("이 구간에는 값이 하나도 없다. 구간을 잘못 골랐을 수 있다. 긴 추이는 "
               "window_m 에 분으로 준다(90일이면 129600). last 는 현재값이라 추이가 아니다.")
        out["note"] = (str(out.get("note") or "") + " " + msg).strip()
    return out


def note_if_capped(out, limit: int = 0):
    """받을 수 있는 줄 수를 다 채웠으면 그 사실을 결과에 적는다.

    로그는 최신순으로 받는다. 상한을 채웠다는 것은 구간 앞부분이 안 실렸다는 뜻이다.
    안 알리면 모델은 실린 것이 그 구간 전부인 줄 알고 "없었다" 로 답한다.

    **그 조회에 실제로 쓴 상한을 받는다.** 예전에는 알림 경로의 상수(300)와 견줬는데
    질의는 늘 60줄로 조회하므로 통지가 한 번도 안 붙었다(2026-08-19 감사). 고쳤다고
    적어 둔 고장이 임계값 불일치로 살아 있었다.
    """
    if not isinstance(out, dict):
        return out
    from . import collector
    cap = int(limit or 0) or collector.LOKI_FETCH_LIMIT
    if int(out.get("fetched") or 0) >= cap:
        msg = ("받을 수 있는 줄 수를 다 채웠다. 최신 쪽만 실렸고 구간 앞부분은 안 들어왔다. "
               "구간을 좁히거나 contains 로 걸러서 다시 불러라.")
        out["note"] = (str(out.get("note") or "") + " " + msg).strip()
    return out


def bad_when(args: dict) -> list:
    """시각으로 읽지 못한 인자 이름들.

    **조용히 기본 창으로 떨어지면 모델은 잘못 물은 줄 모른다.** 2026-08-18 랩 실측으로
    `at: 90` 을 시작으로 네 번 되풀이하며 라운드를 다 썼다. 결과가 그럴듯해 보였기
    때문이다.
    """
    out = []
    for key in ("at", "from", "to"):
        v = (args or {}).get(key)
        if v not in (None, "") and parse_when(v) is None:
            out.append(key)
    return out


def when_note(args: dict) -> str:
    """못 읽은 시각을 알리는 문장. 없으면 빈 문자열."""
    bad = bad_when(args)
    if not bad:
        return ""
    return ("%s 값을 시각으로 읽지 못해 무시했다. 유닉스 초나 ISO8601 로 준다. "
            "긴 기간은 window_m 에 분으로 준다(90일이면 129600)."
            % ", ".join("%s=%r" % (k, (args or {}).get(k)) for k in bad))


def cut_note(cut: bool, max_m: int) -> str:
    """구간을 잘랐을 때 도구 결과에 실을 문장. 안 잘랐으면 빈 문자열."""
    if not cut:
        return ""
    if max_m % 1440 == 0:
        span = "%d일" % (max_m // 1440)
    else:
        span = "%d분" % max_m
    return ("물어본 구간이 상한(%s)보다 길어 **최근 %s만** 조회했다. 그보다 앞선 "
            "구간은 확인하지 않았다 — 없다고 답하지 마라." % (span, span))


def use_trend(start: int, end: int) -> bool:
    """이 구간을 이력으로 볼까 추세로 볼까."""
    return (int(end) - int(start)) > TREND_FROM_S


def clamp_window(minutes, max_m: int = 0) -> int:
    """조회 기간을 상한 안으로. 0 이나 이상한 값은 기본값으로.

    상한은 도구마다 다르다. 여기서 기본 상한을 고정하면 도구가 넓힌 상한이 무시된다.
    """
    cap = int(max_m or WINDOW_MAX_M)
    try:
        m = int(minutes)
    except (TypeError, ValueError):
        return min(WINDOW_DEFAULT_M, cap)
    if m <= 0:
        return min(WINDOW_DEFAULT_M, cap)
    return min(m, cap)


def check_filter(text: str) -> tuple:
    """로그 문자열 필터가 쓸 만한가. 반환 `(가능 여부, 사유)`.

    `a|b` 는 "둘 중 하나" 로 받는다. 모델은 이 표기를 정규식으로 쓰는데, 글자 그대로
    찾으면 절대 맞지 않아 결과가 비고 사람은 그것을 "기록 없음" 으로 읽는다
    (2026-08-18 랩 실측).
    """
    s = str(text or "")
    if len(s) > FILTER_MAX_CHARS:
        return False, "필터가 %d자를 넘는다" % FILTER_MAX_CHARS
    if _UNSAFE.search(s):
        return False, "질의문을 깨뜨리는 글자가 있다(따옴표·중괄호·역슬래시·줄바꿈)"
    terms = filter_terms(s)
    if s and not terms:
        return False, "찾을 낱말이 없다"
    if len(terms) > FILTER_MAX_TERMS:
        return False, "한 번에 찾을 낱말은 %d개까지다" % FILTER_MAX_TERMS
    for t in terms:
        if not _TERM_OK.match(t):
            return False, "낱말에 쓸 수 없는 글자가 있다: %r" % t
    return True, ""


def filter_terms(text: str) -> list:
    """`a|b|c` 를 낱말 목록으로. 빈 조각은 버린다."""
    return [t.strip() for t in str(text or "").split("|") if t.strip()]


def build_logql(label_value: str, contains: str = "") -> str:
    """라벨 등식 하나에 문자열 필터만 붙인다. 정규식은 만들지 않는다."""
    if not _LABEL_OK.match(str(label_value or "")):
        raise ValueError("라벨 값에 쓸 수 없는 글자가 있다: %r" % label_value)
    q = '{host="%s"}' % label_value
    if contains:
        ok, why = check_filter(contains)
        if not ok:
            raise ValueError(why)
        terms = filter_terms(contains)
        if len(terms) == 1:
            q += ' |= "%s"' % terms[0]
        else:
            # 낱말마다 위 검사를 통과했으므로 질의문을 깨뜨릴 글자가 없다.
            q += ' |~ "(%s)"' % "|".join(terms)
    return q


def zbx_method_ok(method: str) -> bool:
    return str(method or "") in ZBX_METHODS


def build_wazuh_query(agent_name: str, start: int, end: int, min_level: int,
                      rule_group: str = "") -> dict:
    """Wazuh 질의 본문. 틀을 코드가 만들고 값만 끼운다.

    에이전트명은 정확 일치(`term`)를 유지한다. 부분 일치로 바꾸면 이름이 비슷한 다른
    호스트의 경보가 섞인다.
    """
    try:
        lvl = max(0, min(15, int(min_level)))
    except (TypeError, ValueError):
        lvl = 0
    return {
        "size": 50,
        # **총 건수를 함께 받는다.** 50건만 받아 세면 그보다 많을 때 조용히 적게 센다.
        # 오늘 하루 반복된 실패가 전부 이 모양이었다(2026-08-19).
        "track_total_hits": True,
        "sort": [{"@timestamp": {"order": "desc"}}],
        "_source": ["@timestamp", "rule.level", "rule.id", "rule.description",
                    "rule.groups", "agent.name", "syscheck.path", "syscheck.event"],
        "query": {"bool": {"filter": ([{"term": {"rule.groups": str(rule_group)}}]
                                     if rule_group else []) + [
            {"term": {"agent.name": str(agent_name)}},
            {"range": {"rule.level": {"gte": lvl}}},
            {"range": {"@timestamp": {"gte": int(start) * 1000,
                                      "lte": int(end) * 1000,
                                      "format": "epoch_millis"}}},
        ]}},
    }


# ---------------------------------------------------------------------------
# 도구 목록과 실행
#
# 모델이 도구 이름과 인자를 정한다. 그 값이 어떻든 **거부는 예외가 아니라 도구 결과로
# 돌려준다** — 예외로 끝내면 모델이 스스로 고칠 기회가 없고, 사람은 답 대신 오류를 본다.
#
# 대상은 언제나 가명 토큰으로 받는다. 실명은 표에만 있고 표는 허용된 감시 서버에서만
# 만들어지므로, 표에 없는 대상은 조회 자체가 불가능하다.
# ---------------------------------------------------------------------------

LOG_LIMIT_DEFAULT = 60
# 모델이 더 달라고 할 수 있는 최대. 알림 경로가 받는 줄 수와 같다(collector.LOKI_FETCH_LIMIT).
LOG_LIMIT_MAX = 300
JUDGMENT_DAYS_DEFAULT = 7
# 판정 이력은 90일까지 남는다(store.KEEP_DAYS). **분 단위 상한을 쓰면 안 된다** —
# days 를 분 상한(1440)에 통과시켜 30일이 1일이 됐다(2026-08-18 실측).
JUDGMENT_DAYS_MAX = 90

# 값이 정해져 있는 인자는 스키마로 묶는다.
#
# 프롬프트로 "없는 이름을 쓰지 마라" 라고 부탁하는 것과, 스키마가 값의 집합을 좁히는
# 것은 다르다. 부탁은 지켜지기도 하고 안 지켜지기도 하지만 스키마는 표현 자체를 막는다.
#
# **묶는 자리를 고르는 기준은 캐시다.** 도구 정의는 프롬프트 맨 앞에 놓이므로, 정의가
# 바뀌면 그 뒤 전부가 캐시에서 빠진다. 그래서 요청 내내 안 바뀌는 값(호스트 토큰)만
# enum 으로 묶고, 턴 중에 생기는 값(그림 손잡이·조회 구간)은 코드가 검증한다.

def _host_prop(desc: str, tokens=None, allow_all: bool = False) -> dict:
    """대상 호스트 인자. `allow_all` 이면 "전체" 를 뜻하는 빈 값도 고를 수 있다.

    빈 값을 목록에 안 넣으면 설명이 "전체면 빈 문자열" 이어도 모델이 그 값을 넣지
    못한다. 2026-08-19 실측으로 `open_problems` 를 필수 인자로 옮기면서 "열린 문제
    전부" 가 통째로 막혔다. 설명과 목록이 어긋나면 목록이 이긴다.
    """
    p = {"type": "string", "description": desc}
    if tokens:
        # 정렬은 필수다. 순서가 흔들리면 접두사 바이트가 달라져 캐시가 한 번도 안 걸린다.
        p["enum"] = ([""] if allow_all else []) + sorted(tokens)
    return p


_WINDOW_PROPS = {
    "window_m": {"type": "integer",
                 "description": ("지금부터 거슬러 볼 분. 90일이면 129600. 셋 다 비우면 "
                                 "사람이 화면에서 보고 있는 구간을 본다")},
    "from": {"type": "string", "description": "절대 구간 시작. ISO8601 또는 유닉스 초"},
    "to": {"type": "string", "description": "절대 구간 끝"},
}


# 엄격 모드(strict)에서 도구 정의 전체가 가질 수 있는 선택 인자 수. 넘기면 API 가 호출을
# 통째로 거부한다(2026-08-18 실측: "Schemas contains too many optional parameters (25),
# which would make grammar compilation inefficient ... limit: 24"). 인자를 하나 더할 때마다
# 이 한도를 먼저 본다.
OPTIONAL_PARAM_MAX = 24


def optional_params(specs: list) -> int:
    """도구 정의에 든 선택 인자 수. 필수(required)로 적힌 것은 안 센다."""
    n = 0
    for t in (specs or []):
        sch = (t or {}).get("input_schema") or {}
        req = set(sch.get("required") or [])
        n += len([k for k in (sch.get("properties") or {}) if k not in req])
    return n


def _spec(name: str, desc: str, props: dict, required=None) -> dict:
    """도구 하나. 목록 밖 인자를 아예 못 넣게 스키마대로 검증시킨다."""
    return {
        "name": name,
        "description": desc,
        "strict": True,
        "input_schema": {
            "type": "object",
            "properties": props,
            "required": list(required or []),
            "additionalProperties": False,
        },
    }


def build_tool_specs(table: dict = None) -> list:
    """이번 요청의 도구 정의. 대상 표에서 고를 수 있는 토큰을 스키마에 박는다.

    표가 비면 enum 을 넣지 않는다. 빈 enum 은 모든 값을 막아 도구를 죽인다.
    """
    toks = list(table or {})
    return [
        _spec("list_hosts", "질의할 수 있는 호스트 목록. 대상 토큰을 모를 때 먼저 부른다.",
              {"query": {"type": "string",
                         "description": "이름에 포함된 문자열로 좁힌다. 전체면 빈 문자열"}},
              ["query"]),
        _spec("host_logs",
              "그 호스트의 로그. 기간과 문자열 필터로 좁힌다. 정규식은 못 쓴다.",
              dict(_WINDOW_PROPS,
                   host=_host_prop("조회할 호스트 토큰", toks),
                   limit={"type": "integer",
                          "description": ("받을 줄 수. 기본 60, 최대 300. 잘렸다는 안내를 "
                                          "받으면 늘려서 다시 부른다")},
                   contains={"type": "string",
                             "description": "이 문자열이 든 줄만. 세로줄로 이으면 "
                                            "그중 하나라도 든 줄(failed|timeout), 5개까지"}),
              ["host"]),
        _spec("security_alerts", "그 호스트의 보안 경보. 레벨 하한으로 좁힌다.",
              dict(_WINDOW_PROPS,
                   host=_host_prop("조회할 호스트 토큰", toks),
                   rule_group={"type": "string",
                               "description": ("규칙 그룹으로 좁힌다(예 "
                                               "authentication_failed). 대시보드 패널의 "
                                               "질의문에 적힌 값을 그대로 쓴다")},
                   min_level={"type": "integer", "description": "0~15"}),
              ["host"]),
        _spec("host_metrics",
              "그 호스트의 Zabbix 지표. 이름 조각으로 아이템을 고르고 값의 추이를 본다. "
              "복제 지연·CPU·메모리처럼 수치로 보는 것은 여기서 본다.",
              dict(_WINDOW_PROPS,
                   host=_host_prop("조회할 호스트 토큰", toks),
                   match={"type": "string",
                          "description": "아이템 이름·키에 든 문자열 "
                                         "(예: replication, cpu, memory)"}),
              ["host"]),
        _spec("open_problems", "그 호스트에 지금 열려 있는 문제(Zabbix).",
              {"host": _host_prop("전체면 빈 문자열", toks, allow_all=True)}, ["host"]),
        _spec("panel_image",
              "그 호스트의 관측 화면(패널)을 그림으로 붙인다. 사람이 보고 있는 그래프를 "
              "답과 함께 보여 줄 때 쓴다. 반환된 id 를 answer 의 image_ids 에 적는다.",
              dict(_WINDOW_PROPS,
                   host=_host_prop("조회할 호스트 토큰", toks),
                   panel_ref={"type": "string",
                              "description": ("비우면 사람이 보고 있는 패널을 그린다. "
                                              "다른 패널을 그릴 때만 list_panels 가 준 "
                                              "ref 를 그대로 적는다")}),
              ["host"]),
        _spec("list_panels",
              "볼 수 있는 관측 화면(패널) 목록. 다른 대시보드의 패널을 가리킬 때 먼저 "
              "부른다. 여기서 받은 ref 를 panel_image 에 넣으면 그 패널이 그려진다.",
              {"dashboard": {"type": "string",
                             "description": "대시보드 제목의 일부. 전체면 빈 문자열"}},
              ["dashboard"]),
        _spec("past_judgments", "봇이 전에 내린 판정 기록. 같은 일이 반복되는지 볼 때 쓴다.",
              {"host": _host_prop("전체면 빈 문자열", toks, allow_all=True),
               "days": {"type": "integer", "description": "며칠 전까지. 최대 90"}}),
        _spec("answer",
              "사람에게 줄 최종 답. 조사가 끝나면 이 도구로 답한다. 산문에 그림 손잡이나 "
              "조회 구간을 적지 말고 여기 필드에 넣는다.",
              {"summary": {"type": "string", "description": "결론 한두 문장"},
               "window_utc": {"type": "string",
                              "description": "조회 결과가 알려 준 구간을 그대로 옮긴다. "
                                             "조회를 안 했으면 비운다"},
               "findings": {"type": "array", "items": {"type": "string"},
                            "description": "근거 항목. 조회로 확인한 것만"},
               "image_ids": {"type": "array", "items": {"type": "string"},
                             "description": "panel_image 가 준 id 만"}},
              ["summary"]),
    ]


# 기존 호출자를 위한 기본 정의. 표를 못 만든 경우에도 도구는 있어야 한다.
TOOL_SPECS = build_tool_specs()


def check_answer(args: dict, images, windows) -> tuple:
    """답 도구의 인자를 검증한다. 반환 `(통과 여부, 사유)`.

    턴 중에 생기는 값은 enum 으로 묶을 수 없다. 묶으면 도구 정의가 라운드마다 바뀌어
    캐시가 죽는다. 대신 여기서 본다. 위반은 예외가 아니라 도구 결과로 돌려주어 모델이
    스스로 고치게 한다.
    """
    a = args or {}
    for iid in (a.get("image_ids") or []):
        if iid not in (images or set()):
            return False, ("%s 는 이번에 만든 그림이 아니다. panel_image 가 준 id 만 "
                           "적을 수 있다" % iid)
    win = str(a.get("window_utc") or "").strip()
    if win and win not in (windows or set()):
        return False, ("%r 은 조회 결과가 알려 준 구간이 아니다. 도구가 돌려준 "
                       "window_utc 를 그대로 옮겨라" % win)
    if not str(a.get("summary") or "").strip():
        return False, "summary 가 비어 있다"
    return True, ""


def panel_pick(panel: dict) -> tuple:
    """보고 있는 패널. 반환 `(대시보드 uid, 패널 번호)`. 화면 맥락이 없으면 `(None, None)`.

    화면이 패널 번호를 넘겨 주므로 제목으로 뒤지지 않는다. 제목으로 찾으면 이름이
    비슷한 옆 패널이 걸린다(2026-08-18 실측).

    다른 대시보드의 패널은 `list_panels` 로 목록을 받아 **손잡이로 가리킨다.** 제목을
    인자로 넘기는 길은 없앴다 — 그 길이 있는 한 이름이 비슷한 패널이 계속 걸린다.
    """
    p = panel or {}
    uid, pid = p.get("uid"), p.get("panelId")
    if not uid or pid in (None, ""):
        return None, None
    return uid, pid


PANEL_REF_MAX = 40


def panel_refs(items: list, refs: dict) -> list:
    """패널 목록에 손잡이를 붙여 모델에 줄 형태로. 대시보드 식별자는 안 나간다.

    그림 손잡이(`img-...`)와 같은 방식이다. 모델은 `pnl-3` 만 보고, 그 뒤의 대시보드
    uid 와 패널 번호는 서버가 들고 있는다.
    """
    out = []
    for it in (items or [])[:PANEL_REF_MAX]:
        ref = "pnl-%d" % (len(refs) + 1)
        refs[ref] = (it.get("uid"), it.get("panel_id"), it.get("title") or "")
        row = {"ref": ref, "dashboard": it.get("dashboard") or "",
               "title": it.get("title") or ""}
        # 무엇을 조회하는 패널인지 함께 준다. 제목만 주면 두 패널이 같은 값을 보는지
        # 짐작하게 되고, 짐작은 틀린다(2026-08-19 실측).
        for key in ("source", "query"):
            if it.get(key):
                row[key] = it[key]
        out.append(row)
    return out


def query_count(trace) -> int:
    """조회 횟수. **답 도구는 안 센다.**

    답은 조사가 아니라 마무리다. 상한에 세면 조사할 수 있는 횟수가 하나 줄고 그만큼
    답이 얕아진다(2026-08-18 실측: 답을 부르려다 rounds 로 끝났다).
    """
    return sum(1 for t in (trace or []) if (t or {}).get("tool") != "answer")


def _err(msg: str) -> dict:
    return {"error": msg}


def _lookup(tok: str, ctx: dict):
    """토큰 하나를 표에서 찾는다. **대상을 찾는 규칙은 한 곳에만 둔다.**

    대괄호 완화를 `_target` 에만 넣었더니 past_judgments·open_problems 가 같은 값을
    거부했다(2026-08-18 실측). 규칙이 도구마다 다르면 어느 도구는 되고 어느 도구는
    안 되는 상태가 조용히 생긴다.
    """
    table = ctx.get("table") or {}
    return table.get(tok) or table.get("[%s]" % str(tok).strip("[]"))


def _target(args: dict, ctx: dict) -> tuple:
    """인자의 호스트 토큰을 표에서 찾는다. 반환 `(항목, 오류)`."""
    tok = str((args or {}).get("host") or "").strip()
    if not tok:
        return None, _err("host 인자가 없다. list_hosts 로 대상 토큰을 먼저 확인하라")
    ent = _lookup(tok, ctx)
    if not ent:
        return None, _err("알 수 없는 대상이다: %s. list_hosts 에 있는 토큰만 쓸 수 있다" % tok)
    return ent, None


async def run_tool(name: str, args: dict, ctx: dict) -> dict:
    """도구 하나를 실행한다. 어떤 실패도 예외로 던지지 않는다."""
    fn = _TOOLS.get(name)
    if fn is None:
        return _err("그런 도구는 없다: %s. 쓸 수 있는 것은 %s"
                    % (name, ", ".join(sorted(_TOOLS))))
    try:
        out = await fn(args or {}, ctx)
        return _hint_if_empty(name, out)
    except ValueError as e:                      # 조립기가 막은 인자
        return _err(str(e))
    except Exception as e:                       # 조회 실패는 없음이 아니다
        log.warning("도구 %s 실패: %s", name, e)
        return _err("조회하지 못했다(%s). 이 결과를 '없음'으로 읽지 마라" % type(e).__name__)


# 빈 결과에 붙일 다음 수. **그냥 비어 있으면 모델이 포기한다** — 오늘 랩에서
# "찾을 수 없습니다" 로 끝난 자리가 이것이다. 조회는 성공했으니 다르게 물어보게 한다.
_EMPTY_HINT = {
    "host_logs": "그 창에 로그가 없다. 기간을 넓히거나 contains 를 빼고 다시 보라",
    "host_metrics": "그 조건에 맞는 아이템이 없다. match 를 넓히거나 빼고 다시 보라",
    "security_alerts": "그 창에 경보가 없다. min_level 을 낮추거나 기간을 넓혀 보라",
    "open_problems": "지금 열린 문제가 없다. 지난 일을 보려면 past_judgments 를 써라",
    "past_judgments": "그 기간에 판정 기록이 없다. days 를 늘려 보라",
}
_LIST_KEYS = ("logs", "metrics", "alerts", "problems", "judgments", "hosts")


def _hint_if_empty(name: str, out):
    """비어 있는데 조회는 성공한 경우에만 다음 수를 붙인다.

    조회가 실패한 경우에는 붙이지 않는다 — 그건 '없다' 가 아니라 '못 봤다' 이고,
    이미 그렇게 표시하고 있다.
    """
    if not isinstance(out, dict) or out.get("error") or out.get("hint"):
        return out
    if out.get("status") not in (None, "ok"):
        return out
    for k in _LIST_KEYS:
        if k in out and not out[k]:
            out["hint"] = _EMPTY_HINT.get(name, "다른 조건으로 다시 물어보라")
            break
    return out


def span_note(start: int, end: int, span) -> str:
    """화면 구간이 있는데 다른 구간을 봤으면 그 사실과 되부르는 법을 알린다.

    모델이 `window_m` 을 스스로 넣으면 화면 구간 기본값이 안 쓰인다. 그 자체는 옳다 —
    사람이 "그럼 지금은?" 하고 물을 수 있어야 한다. 문제는 모델이 최근 창 결과를 받고
    **화면 구간은 조회할 수 없다고 단정한 것**이다(2026-08-18 실측: "현재 시스템의 조회
    도구가 현시점 기준의 제한된 시간 범위만 지원하고 있습니다").

    그래서 결과에 되부르는 법을 적는다. 지시문에 적는 것으로는 부족했다.
    """
    if not span or not start or not end:
        return ""
    if int(start) == int(span[0]) and int(end) == int(span[1]):
        return ""
    return ("이 조회는 사람이 보고 있는 구간이 아니다. 화면 구간은 %s 다. 시간 인자를 "
            "모두 비우고 다시 부르면 그 구간을 본다. 조회할 수 없다고 답하지 마라."
            % window_label(span[0], span[1]))


def _add_cut(out, cut: bool, max_m: int, start: int = 0, end: int = 0,
             args: dict = None, span=None):
    """**실제로 본 구간**과, 잘랐다면 잘랐다는 사실을 도구 결과에 얹는다.

    프롬프트가 아니라 결과에 실어야 모델이 답에 옮긴다. 이미 안내가 있으면 뒤에 붙인다.
    """
    if not isinstance(out, dict):
        return out
    if start and end:
        out["window_utc"] = window_label(start, end)
    for note in (when_note(args or {}), cut_note(cut, max_m),
                 span_note(start, end, span)):
        if note:
            out["note"] = (str(out.get("note") or "") + " " + note).strip()
    return out


async def _tool_list_hosts(args: dict, ctx: dict) -> dict:
    """표에서 만든다. 조회를 안 하므로 라운드를 아낀다."""
    # **검색은 실명으로 맞춘다.** 사람은 실명으로 묻고 모델은 그 말을 그대로 옮긴다.
    # 토큰 문자열을 훑으면 아무것도 안 맞는다(2026-08-18 랩 실측). 실명은 여기서만
    # 쓰이고 결과에는 토큰만 실린다.
    q = str(args.get("query") or "").lower()
    out = []
    for tok, ent in (ctx.get("table") or {}).items():
        if q and q not in str(ent.get("host", "")).lower():
            continue
        # 표의 호스트는 전부 감시 서버에서 왔으므로 지표는 언제나 볼 수 있다.
        # 안 알리면 모델이 "이 호스트는 지표가 없다"고 단정한다(2026-08-18 실측).
        axes = ["metrics"] + sorted(k for k in ("logs", "security") if ent.get(k))
        out.append({"host": tok, "axes": axes})
    if not out:
        return {"hosts": [], "n": 0,
                "hint": "그 이름에 맞는 호스트가 없다. query 를 비우고 전체를 받아 보라"}
    return {"hosts": out[:100], "n": len(out)}


async def _tool_host_logs(args: dict, ctx: dict) -> dict:
    ent, err = _target(args, ctx)
    if err:
        return err
    label = ent.get("logs")
    if not label:
        return {"logs": [], "status": "disabled",
                "note": "이 호스트는 로그를 보내지 않는다. 없다는 뜻이 아니다"}
    ok, why = check_filter(args.get("contains") or "")
    if not ok:
        return _err(why)
    q = build_logql(label, args.get("contains") or "")
    # 로그도 보안 경보와 같은 상한을 쓴다. 하루로 자르면 사람이 이틀 구간을 보며
    # 물었을 때 앞 하루가 통째로 빠지고, 봇은 그 절반만 보고 답한다(2026-08-18 실측).
    # 결과 크기는 구간이 아니라 줄 수 상한이 정하므로 넓혀도 무겁지 않다.
    a, b, cut = window_bounds(args, int(ctx["now"]), WINDOW_MAX_WIDE_M,
                              default_span=ctx.get("panel_span"))
    # 상한 자체도 상한이 있다. 모델이 큰 값을 넣어도 여기서 잘린다.
    try:
        limit = max(1, min(int(args.get("limit") or LOG_LIMIT_DEFAULT), LOG_LIMIT_MAX))
    except (TypeError, ValueError):
        limit = LOG_LIMIT_DEFAULT
    out = note_if_capped(await ctx["fetch_logs"](q, a, b, limit), limit)
    return _add_cut(out, cut, WINDOW_MAX_WIDE_M, a, b, args, ctx.get("panel_span"))


async def _tool_security_alerts(args: dict, ctx: dict) -> dict:
    ent, err = _target(args, ctx)
    if err:
        return err
    agent = ent.get("security")
    if not agent:
        return {"alerts": [], "status": "disabled",
                "note": "이 호스트에는 보안 에이전트가 없다. 없다는 뜻이 아니다"}
    a, b, cut = window_bounds(args, int(ctx["now"]), WINDOW_MAX_WIDE_M,
                              default_span=ctx.get("panel_span"))
    grp = str(args.get("rule_group") or "").strip()
    if grp and not _LABEL_OK.match(grp):
        return _err("규칙 그룹 이름에 쓸 수 없는 글자가 있다: %r" % grp)
    body = build_wazuh_query(agent, a, b, args.get("min_level") or 0, grp)
    return _add_cut(await ctx["fetch_security"](body), cut, WINDOW_MAX_WIDE_M,
                    a, b, args, ctx.get("panel_span"))


async def _tool_past_judgments(args: dict, ctx: dict) -> dict:
    tok = str(args.get("host") or "").strip()
    ent = _lookup(tok, ctx) if tok else None
    if tok and not ent:
        return _err("알 수 없는 대상이다: %s. list_hosts 로 확인하라" % tok)
    try:
        days = int(args.get("days") or JUDGMENT_DAYS_DEFAULT)
    except (TypeError, ValueError):
        days = JUDGMENT_DAYS_DEFAULT
    days = max(1, min(days, JUDGMENT_DAYS_MAX))
    return await ctx["fetch_judgments"](ent.get("host") if ent else "", days)


async def _tool_host_metrics(args: dict, ctx: dict) -> dict:
    ent, err = _target(args, ctx)
    if err:
        return err
    a, b, cut = window_bounds(args, int(ctx["now"]), WINDOW_MAX_TREND_M,
                              default_span=ctx.get("panel_span"))
    out = note_if_no_points(
        await ctx["fetch_metrics"](ent, str(args.get("match") or ""), a, b))
    return _add_cut(out, cut, WINDOW_MAX_TREND_M, a, b, args, ctx.get("panel_span"))


async def _tool_open_problems(args: dict, ctx: dict) -> dict:
    tok = str(args.get("host") or "").strip()
    ent = _lookup(tok, ctx) if tok else None
    if tok and not ent:
        return _err("알 수 없는 대상이다: %s. list_hosts 로 확인하라" % tok)
    return await ctx["fetch_problems"](ent)


async def _tool_panel_image(args: dict, ctx: dict) -> dict:
    ent, err = _target(args, ctx)
    if err:
        return err
    a, b, _cut = window_bounds(args, int(ctx["now"]), WINDOW_MAX_WIDE_M,
                               default_span=ctx.get("panel_span"))
    ref = str(args.get("panel_ref") or "").strip()
    target = None
    if ref:
        target = (ctx.get("panel_refs") or {}).get(ref)
        if not target:
            return _err("%s 는 이번 대화에서 받은 패널 손잡이가 아니다. list_panels 를 "
                        "먼저 부르고 거기 적힌 ref 를 그대로 써라" % ref)
    return await ctx["fetch_panel"](ent, target, a, b)


async def _tool_list_panels(args: dict, ctx: dict) -> dict:
    raw = await ctx["list_panels"](str(args.get("dashboard") or ""))
    items = panel_refs(raw, ctx.setdefault("panel_refs", {}))
    if not items:
        return {"panels": [], "note": "그 조건에 맞는 패널이 없다. dashboard 를 비우고 "
                                      "전체 목록을 받아 보라"}
    note = "그림을 붙이려면 ref 를 panel_image 의 panel_ref 에 그대로 적어라"
    if len(raw) >= PANEL_REF_MAX:
        note += (" 목록이 %d개에서 잘렸다. dashboard 를 적어 좁혀야 나머지가 보인다"
                 % PANEL_REF_MAX)
    return {"panels": items, "n": len(items), "note": note}


_TOOLS = {
    "list_hosts": _tool_list_hosts,
    "panel_image": _tool_panel_image,
    "list_panels": _tool_list_panels,
    "host_metrics": _tool_host_metrics,
    "open_problems": _tool_open_problems,
    "host_logs": _tool_host_logs,
    "security_alerts": _tool_security_alerts,
    "past_judgments": _tool_past_judgments,
}
