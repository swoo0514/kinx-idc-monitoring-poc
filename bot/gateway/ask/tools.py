"""질의 도구의 질의문 조립과 검사. 설계는 bot/GATEWAY_GUIDE.md §27."""

import logging
import re

log = logging.getLogger("gateway.asktools")

# 조회 기간(분). 모델이 큰 값을 넣어도 여기서 잘린다.
WINDOW_DEFAULT_M = 60
WINDOW_MAX_M = 1440
# 건수 상한이 있어 구간을 넓혀도 무겁지 않은 조회 — 대시보드 구간이 7일인 일이 흔하다
WINDOW_MAX_WIDE_M = 10080
# 추세는 시간 단위 집계라 긴 구간도 가볍고 Zabbix 기본 보관도 이력보다 길다
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

# `.get` 이어도 이 목록 밖이면 거부한다 — 다 열면 사용자·설정 조회까지 나간다
ZBX_METHODS = frozenset((
    "host.get", "item.get", "history.get", "trend.get", "problem.get", "trigger.get",
    "event.get",
))


# 지표 표본을 얼마나 받아 얼마로 줄일지 — 최신순 상한이면 앞부분 스파이크를 못 본다
HISTORY_FETCH_MAX = 2000
HISTORY_BUCKETS = 60


def downsample(points: list, buckets: int = HISTORY_BUCKETS) -> list:
    """시계열을 구간별로 줄이되 **극단값을 살린다.**"""
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
    """시각 한 개를 유닉스 초로. 못 읽으면 None — 지어내지 않는다."""
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
    """질문 글에 적힌 구간 `(시작, 끝)`. 못 읽으면 None."""
    found = []
    for m in _ISO_RE.findall(str(text or "")):
        t = parse_when(m)
        if t:
            found.append(t)
    if len(found) < 2:
        return None
    a, b = min(found), max(found)
    return (a, b) if a < b else None


# 절대 구간을 잇는 글자. 사람도 모델도 물결표를 가장 많이 쓴다.
_SPAN_SEP = re.compile(r"\s*(?:~|\.\.|—|–|to)\s*")


def span_of(args: dict) -> tuple:
    """절대 구간 `(시작, 끝)`. 못 읽으면 `(None, None)`."""
    a = (args or {}).get("range")
    if a in (None, ""):
        # 예전 형태도 계속 읽는다. 스키마에는 없지만 이력이나 손 호출로 들어올 수 있다.
        return parse_when((args or {}).get("from")), parse_when((args or {}).get("to"))
    parts = [p for p in _SPAN_SEP.split(str(a).strip()) if p]
    if len(parts) != 2:
        return None, None
    return parse_when(parts[0]), parse_when(parts[1])


def window_bounds(args: dict, now: int, max_m: int = 0, default_span=None) -> tuple:
    """조회 구간 `(시작, 끝, 잘렸는가)`. 절대 구간이 있으면 그것을, 없으면 상대 창을."""
    cap = int(max_m or WINDOW_MAX_M) * 60
    a, b = span_of(args)
    # 화면이 넘긴 구간을 모델에게 받아 적으라고 시키지 않는다 — 모델이 직접 주면 그쪽이 이긴다
    if a is None and b is None and default_span and not (args or {}).get("window_m"):
        a, b = int(default_span[0]), int(default_span[1])
    if a is not None and b is not None:
        if a > b:
            a, b = b, a
        # 자를 때는 최신 쪽을 남긴다 — 조회가 최신순이라 앞을 남기면 화면 오른쪽 끝이 빠진다
        return max(a, b - cap), b, (b - a) > cap
    asked = raw_window_s((args or {}).get("window_m"))
    win = min(clamp_window((args or {}).get("window_m"), cap // 60) * 60, cap)
    # 상대 구간도 잘렸으면 잘렸다고 말한다 — 90일 요청이 조용히 하루가 된 적이 있다
    return now - win, now, asked > win


def raw_window_s(minutes) -> int:
    """사람이 실제로 요청한 창 길이(초). 상한을 적용하기 전 값이다."""
    try:
        m = int(minutes)
    except (TypeError, ValueError):
        return 0
    return max(0, m) * 60


def window_label(start: int, end: int) -> str:
    """실제로 본 구간을 사람이 읽는 형태로."""
    import datetime
    def fmt(t):
        return datetime.datetime.utcfromtimestamp(int(t)).strftime("%Y-%m-%d %H:%M")
    return "%s → %s UTC" % (fmt(start), fmt(end))


# 이름으로 아이템을 고를 때 몇 개까지 볼 것인가. 접두사가 캐시에 올라가 있어 여유가 있다.
ITEM_LIMIT = 8
# 한 번에 실을 호스트 수. 실환경은 사내 321대 + MSP 145대라 전부 실으면 접두사가 커진다.
HOST_LIST_MAX = 100

_WORD = re.compile(r"[A-Za-z0-9]+")


def rank_items(items: list, match: str) -> list:
    """이름 검색 결과를 관련도 순으로. 검색어가 없으면 순서를 안 바꾼다."""
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
    """이름 검색이 잘렸으면 몇 개를 못 봤고 그것이 무엇인지 결과에 적는다."""
    if not isinstance(out, dict) or int(total or 0) <= int(shown or 0):
        return out
    names = ", ".join(str(n) for n in (dropped or [])[:20])
    msg = ("이름이 맞는 아이템 %d개 중 %d개만 실었다. 안 실은 것: %s. 원하는 것이 없으면 "
           "match 를 더 좁혀서 다시 불러라." % (int(total), int(shown), names))
    out["note"] = (str(out.get("note") or "") + " " + msg).strip()
    return out


def note_if_no_points(out):
    """지표를 받았는데 점이 0개면 그 사실을 결과에 적는다."""
    if not isinstance(out, dict):
        return out
    items = out.get("metrics") or []
    if items and all(int(m.get("sampled_from") or 0) == 0 for m in items):
        msg = ("이 구간에는 값이 하나도 없다. 구간을 잘못 골랐을 수 있다. 긴 추이는 "
               "window_m 에 분으로 준다(90일이면 129600). last 는 현재값이라 추이가 아니다.")
        out["note"] = (str(out.get("note") or "") + " " + msg).strip()
    return out


def note_if_capped(out, limit: int = 0):
    """받을 수 있는 줄 수를 다 채웠으면 그 사실을 결과에 적는다."""
    if not isinstance(out, dict):
        return out
    from ..alerts import collector
    cap = int(limit or 0) or collector.LOKI_FETCH_LIMIT
    if int(out.get("fetched") or 0) >= cap:
        msg = ("받을 수 있는 줄 수를 다 채웠다. 최신 쪽만 실렸고 구간 앞부분은 안 들어왔다. "
               "구간을 좁히거나 contains 로 걸러서 다시 불러라.")
        out["note"] = (str(out.get("note") or "") + " " + msg).strip()
    return out


def bad_when(args: dict) -> list:
    """시각으로 읽지 못한 인자 이름들."""
    out = []
    for key in ("from", "to"):
        v = (args or {}).get(key)
        if v not in (None, "") and parse_when(v) is None:
            out.append(key)
    rng = (args or {}).get("range")
    if rng not in (None, "") and span_of(args) == (None, None):
        out.append("range")
    return out


def when_note(args: dict) -> str:
    """못 읽은 시각을 알리는 문장. 없으면 빈 문자열."""
    bad = bad_when(args)
    if not bad:
        return ""
    return ("%s 값을 시각으로 읽지 못해 무시했다. 절대 구간은 range 에 "
            "'2026-08-13T00:00Z ~ 2026-08-13T06:00Z' 처럼 물결표로 이어 준다. "
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
    """로그 문자열 필터가 쓸 만한가. 반환 `(가능 여부, 사유)`."""
    s = str(text or "")
    if len(s) > FILTER_MAX_CHARS:
        return False, "필터가 %d자를 넘는다" % FILTER_MAX_CHARS
    if _UNSAFE.search(s):
        # 무엇을 잘못했는지까지 적는다 — 안 적으면 모델이 같은 인자로 다시 부른다
        return False, ("질의문을 깨뜨리는 글자가 있다(따옴표·중괄호·역슬래시·줄바꿈). "
                       "contains 에는 찾을 낱말만 넣는다. 기간은 range 에, 대상은 host 에 "
                       "따로 넣어라")
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
    """Wazuh 질의 본문. 틀을 코드가 만들고 값만 끼운다."""
    try:
        lvl = max(0, min(15, int(min_level)))
    except (TypeError, ValueError):
        lvl = 0
    return {
        "size": 50,
        # 총 건수를 함께 받는다 — 50건만 받아 세면 그보다 많을 때 조용히 적게 센다
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


# 도구 목록과 실행 — 거부는 예외가 아니라 도구 결과로 돌려준다.
# 대상은 언제나 가명 토큰으로 받으므로 표에 없는 대상은 조회 자체가 불가능하다.

LOG_LIMIT_DEFAULT = 60
# 모델이 더 달라고 할 수 있는 최대. 알림 경로가 받는 줄 수와 같다(collector.LOKI_FETCH_LIMIT).
LOG_LIMIT_MAX = 300
JUDGMENT_DAYS_DEFAULT = 7
# 판정 이력은 90일까지 남는다 — 분 단위 상한을 쓰면 30일이 1일이 된다
JUDGMENT_DAYS_MAX = 90

# 값이 정해진 인자는 스키마로 묶는다 — 부탁과 달리 스키마는 표현 자체를 막는다
# 묶는 자리는 캐시가 정한다 — 요청 내내 안 바뀌는 값만 enum, 나머지는 코드가 검증한다

def _host_prop(desc: str, tokens=None, allow_all: bool = False) -> dict:
    """대상 호스트 인자. `allow_all` 이면 "전체" 를 뜻하는 빈 값도 고를 수 있다."""
    p = {"type": "string", "description": desc}
    if tokens:
        # 정렬은 필수다. 순서가 흔들리면 접두사 바이트가 달라져 캐시가 한 번도 안 걸린다.
        p["enum"] = ([""] if allow_all else []) + sorted(tokens)
    return p


_WINDOW_PROPS = {
    "window_m": {"type": "integer",
                 "description": ("지금부터 거슬러 볼 분. 90일이면 129600. 셋 다 비우면 "
                                 "사람이 화면에서 보고 있는 구간을 본다")},
    # 시작과 끝을 인자 두 개로 받지 않는다 — 정의가 커지면 API 가 모든 질의를 거부한다
    "range": {"type": "string",
              "description": ("절대 구간. '2026-08-13T00:00Z ~ 2026-08-13T06:00Z' 처럼 "
                              "물결표로 잇는다. 유닉스 초도 된다")},
}


# 엄격 모드에서 도구 정의 전체가 가질 수 있는 선택 인자 수. 넘기면 호출이 통째로 거부된다
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
              "사람에게 줄 최종 답. 조사가 끝나면 이 도구로 답한다. 산문에 그림 표시나 "
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
    """답 도구의 인자를 검증한다. 반환 `(통과 여부, 사유)`."""
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
    """보고 있는 패널. 반환 `(대시보드 uid, 패널 번호)`. 화면 맥락이 없으면 `(None, None)`."""
    p = panel or {}
    uid, pid = p.get("uid"), p.get("panelId")
    if not uid or pid in (None, ""):
        return None, None
    return uid, pid


PANEL_REF_MAX = 40


def panel_refs(items: list, refs: dict) -> list:
    """패널 목록에 번호를 붙여 모델에 줄 형태로. 대시보드 식별자는 안 나간다."""
    out = []
    for it in (items or [])[:PANEL_REF_MAX]:
        ref = "pnl-%d" % (len(refs) + 1)
        refs[ref] = (it.get("uid"), it.get("panel_id"), it.get("title") or "")
        row = {"ref": ref, "dashboard": it.get("dashboard") or "",
               "title": it.get("title") or ""}
        # 무엇을 조회하는 패널인지 함께 준다 — 제목만 주면 짐작하게 되고 짐작은 틀린다
        for key in ("source", "query"):
            if it.get(key):
                row[key] = it[key]
        out.append(row)
    return out


def query_count(trace) -> int:
    """조회 횟수. **답 도구는 안 센다.**"""
    return sum(1 for t in (trace or []) if (t or {}).get("tool") != "answer")


def _err(msg: str) -> dict:
    return {"error": msg}


def _lookup(tok: str, ctx: dict):
    """토큰 하나를 표에서 찾는다. **대상을 찾는 규칙은 한 곳에만 둔다.**"""
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


def tool_timeout_s() -> float:
    """도구 한 번의 시한(초)."""
    import os

    try:
        return max(1.0, float(os.environ.get("ASK_TOOL_TIMEOUT_S", "20")))
    except ValueError:
        return 20.0


async def run_tool(name: str, args: dict, ctx: dict) -> dict:
    """도구 하나를 실행한다. 어떤 실패도 예외로 던지지 않는다."""
    import asyncio

    fn = _TOOLS.get(name)
    if fn is None:
        return _err("그런 도구는 없다: %s. 쓸 수 있는 것은 %s"
                    % (name, ", ".join(sorted(_TOOLS))))
    try:
        out = await asyncio.wait_for(fn(args or {}, ctx), timeout=tool_timeout_s())
        return _hint_if_empty(name, out)
    except asyncio.TimeoutError:
        # 다른 조회 실패와 같은 형태로 돌려준다 — 비어 있다는 뜻이 아니라는 것도 함께 적는다
        from ..alerts import collector
        log.warning("도구 %s 시한 초과 (%.0f초)", name, tool_timeout_s())
        return {"status": collector.SOURCE_UNAVAILABLE,
                "note": ("조회가 %.0f초 안에 끝나지 않아 중단했다. 구간을 좁히거나 "
                         "대상을 지정해서 다시 불러라. 이 결과를 근거로 쓰지 마라"
                         % tool_timeout_s())}
    except ValueError as e:                      # 조립기가 막은 인자
        return _err(str(e))
    except Exception as e:                       # 조회 실패는 없음이 아니다
        log.warning("도구 %s 실패: %s", name, e)
        return _err("조회하지 못했다(%s). 이 결과를 '없음'으로 읽지 마라" % type(e).__name__)


# 빈 결과에 붙일 다음 수 — 그냥 비어 있으면 모델이 포기한다
_EMPTY_HINT = {
    "host_logs": "그 창에 로그가 없다. 기간을 넓히거나 contains 를 빼고 다시 보라",
    "host_metrics": "그 조건에 맞는 아이템이 없다. match 를 넓히거나 빼고 다시 보라",
    "security_alerts": "그 창에 경보가 없다. min_level 을 낮추거나 기간을 넓혀 보라",
    "open_problems": "지금 열린 문제가 없다. 지난 일을 보려면 past_judgments 를 써라",
    "past_judgments": "그 기간에 판정 기록이 없다. days 를 늘려 보라",
}
_LIST_KEYS = ("logs", "metrics", "alerts", "problems", "judgments", "hosts")


def _hint_if_empty(name: str, out):
    """비어 있는데 조회는 성공한 경우에만 다음 수를 붙인다."""
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
    """화면 구간이 있는데 다른 구간을 봤으면 그 사실과 되부르는 법을 알린다."""
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
    # 검색은 실명으로 맞춘다 — 실명은 여기서만 쓰이고 결과에는 토큰만 실린다
    q = str(args.get("query") or "").lower()
    out = []
    for tok, ent in (ctx.get("table") or {}).items():
        if q and q not in str(ent.get("host", "")).lower():
            continue
        # 표의 호스트는 전부 감시 서버에서 왔으므로 지표는 언제나 볼 수 있다
        axes = ["metrics"] + sorted(k for k in ("logs", "security") if ent.get(k))
        out.append({"host": tok, "axes": axes})
    if not out:
        return {"hosts": [], "n": 0,
                "hint": "그 이름에 맞는 호스트가 없다. query 를 비우고 전체를 받아 보라"}
    shown = out[:HOST_LIST_MAX]
    res = {"hosts": shown, "n": len(out)}
    if len(out) > len(shown):
        # 자르면 잘랐다고 말한다 — 안 알리면 모델이 "그런 호스트는 없다"로 답한다
        res["note"] = ("호스트 %d대 중 %d대만 실었다. query 에 이름 일부를 넣어 좁혀라"
                       % (len(out), len(shown)))
    return res


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
    # 로그도 보안 경보와 같은 상한 — 결과 크기는 구간이 아니라 줄 수 상한이 정한다
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
            return _err("%s 는 이번 대화에서 받은 패널 표시가 아니다. list_panels 를 "
                        "먼저 부르고 거기 적힌 ref 를 그대로 써라" % ref)
    return await ctx["fetch_panel"](ent, target, a, b)


async def _tool_list_panels(args: dict, ctx: dict) -> dict:
    raw, status = await ctx["list_panels"](str(args.get("dashboard") or ""))
    items = panel_refs(raw, ctx.setdefault("panel_refs", {}))
    if status != "ok":
        # **조회 실패를 "없음" 으로 바꾸지 않는다.** 다른 축과 같은 계약이다(§12).
        return {"panels": [], "status": status,
                "note": ("관측 화면 목록을 조회하지 못했다" if status == "unavailable"
                         else "관측 화면이 연결돼 있지 않다")}
    if not items:
        return {"panels": [], "status": status,
                "note": "그 조건에 맞는 패널이 없다. dashboard 를 비우고 전체 목록을 받아 보라"}
    note = "그림을 붙이려면 ref 를 panel_image 의 panel_ref 에 그대로 적어라"
    # 상태는 늘 싣는다. 있을 때만 실으면 모델이 없는 것을 "ok" 로 읽는다.
    if len(raw) >= PANEL_REF_MAX:
        note += (" 목록이 %d개에서 잘렸다. dashboard 를 적어 좁혀야 나머지가 보인다"
                 % PANEL_REF_MAX)
    return {"panels": items, "n": len(items), "status": status, "note": note}


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
