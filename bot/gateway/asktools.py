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

# 문자열 필터 상한. 길면 질의가 무거워지고, 정규식으로 쓰려는 시도이기도 하다.
FILTER_MAX_CHARS = 80
# LogQL 질의문을 깨뜨리는 글자. 하나라도 있으면 안 만든다.
_UNSAFE = re.compile(r'["{}\\\r\n]')
# 라벨 값은 호스트 이름이라 더 좁게 본다.
_LABEL_OK = re.compile(r"^[A-Za-z0-9._\-]+$")

# 도구가 쓰는 Zabbix 메서드. `.get` 이어도 이 목록 밖이면 거부한다 — 읽기 전용이라고
# 다 열어 주면 사용자·설정 조회까지 나간다.
ZBX_METHODS = frozenset((
    "host.get", "item.get", "history.get", "problem.get", "trigger.get", "event.get",
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


def window_bounds(args: dict, now: int) -> tuple:
    """조회 구간 `(시작, 끝)`. 절대 구간이 있으면 그것을, 없으면 상대 창을 쓴다.

    구간 길이는 상한 안으로 자른다. 뒤집혀 오면 바로잡는다 — 사람이 끌어 놓은 순서를
    모델이 그대로 옮기는 일이 있다.
    """
    a = parse_when((args or {}).get("from"))
    b = parse_when((args or {}).get("to"))
    if a is not None and b is not None:
        if a > b:
            a, b = b, a
        return a, min(b, a + WINDOW_MAX_M * 60)
    at = parse_when((args or {}).get("at"))
    win = clamp_window((args or {}).get("window_m")) * 60
    if at is not None:                     # 그 시각을 가운데 두고 앞뒤로
        return at - win // 2, at + win // 2
    return now - win, now


def clamp_window(minutes) -> int:
    """조회 기간을 상한 안으로. 0 이나 이상한 값은 기본값으로."""
    try:
        m = int(minutes)
    except (TypeError, ValueError):
        return WINDOW_DEFAULT_M
    if m <= 0:
        return WINDOW_DEFAULT_M
    return min(m, WINDOW_MAX_M)


def check_filter(text: str) -> tuple:
    """로그 문자열 필터가 쓸 만한가. 반환 `(가능 여부, 사유)`."""
    s = str(text or "")
    if len(s) > FILTER_MAX_CHARS:
        return False, "필터가 %d자를 넘는다" % FILTER_MAX_CHARS
    if _UNSAFE.search(s):
        return False, "질의문을 깨뜨리는 글자가 있다(따옴표·중괄호·역슬래시·줄바꿈)"
    return True, ""


def build_logql(label_value: str, contains: str = "") -> str:
    """라벨 등식 하나에 문자열 필터만 붙인다. 정규식은 만들지 않는다."""
    if not _LABEL_OK.match(str(label_value or "")):
        raise ValueError("라벨 값에 쓸 수 없는 글자가 있다: %r" % label_value)
    q = '{host="%s"}' % label_value
    if contains:
        ok, why = check_filter(contains)
        if not ok:
            raise ValueError(why)
        q += ' |= "%s"' % contains
    return q


def zbx_method_ok(method: str) -> bool:
    return str(method or "") in ZBX_METHODS


def build_wazuh_query(agent_name: str, start: int, end: int, min_level: int) -> dict:
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
        "sort": [{"@timestamp": {"order": "desc"}}],
        "_source": ["@timestamp", "rule.level", "rule.id", "rule.description",
                    "rule.groups", "agent.name", "syscheck.path", "syscheck.event"],
        "query": {"bool": {"filter": [
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
JUDGMENT_DAYS_DEFAULT = 7
# 판정 이력은 90일까지 남는다(store.KEEP_DAYS). **분 단위 상한을 쓰면 안 된다** —
# days 를 분 상한(1440)에 통과시켜 30일이 1일이 됐다(2026-08-18 실측).
JUDGMENT_DAYS_MAX = 90

TOOL_SPECS = [
    {
        "name": "list_hosts",
        "description": "질의할 수 있는 호스트 목록. 대상 토큰을 모를 때 먼저 부른다.",
        "input_schema": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "이름에 포함된 문자열로 좁힌다"},
            },
        },
    },
    {
        "name": "host_logs",
        "description": "그 호스트의 로그. 기간과 문자열 필터로 좁힌다. 정규식은 못 쓴다.",
        "input_schema": {
            "type": "object",
            "properties": {
                "host": {"type": "string", "description": "list_hosts 가 준 호스트 토큰"},
                "window_m": {"type": "integer", "description": "지금부터 거슬러 볼 분"},
                "from": {"type": "string",
                         "description": "절대 구간 시작. ISO8601 또는 유닉스 초"},
                "to": {"type": "string", "description": "절대 구간 끝"},
                "from": {"type": "string",
                         "description": "절대 구간 시작. ISO8601 또는 유닉스 초"},
                "to": {"type": "string", "description": "절대 구간 끝"},
                "from": {"type": "string",
                         "description": "절대 구간 시작. ISO8601 또는 유닉스 초"},
                "to": {"type": "string", "description": "절대 구간 끝"},
                "contains": {"type": "string", "description": "이 문자열이 든 줄만"},
            },
            "required": ["host"],
        },
    },
    {
        "name": "security_alerts",
        "description": "그 호스트의 보안 경보. 레벨 하한으로 좁힌다.",
        "input_schema": {
            "type": "object",
            "properties": {
                "host": {"type": "string"},
                "window_m": {"type": "integer"},
                "from": {"type": "string", "description": "절대 구간 시작"},
                "to": {"type": "string", "description": "절대 구간 끝"},
                "min_level": {"type": "integer", "description": "0~15"},
            },
            "required": ["host"],
        },
    },
    {
        "name": "host_metrics",
        "description": ("그 호스트의 Zabbix 지표. 이름 조각으로 아이템을 고르고 값의 "
                        "추이를 본다. 복제 지연·CPU·메모리처럼 수치로 보는 것은 여기서 본다."),
        "input_schema": {
            "type": "object",
            "properties": {
                "host": {"type": "string", "description": "list_hosts 가 준 호스트 토큰"},
                "match": {"type": "string",
                          "description": "아이템 이름·키에 든 문자열 (예: replication, cpu, memory)"},
                "window_m": {"type": "integer", "description": "지금부터 거슬러 볼 분"},
                "from": {"type": "string",
                         "description": "절대 구간 시작. ISO8601 또는 유닉스 초"},
                "to": {"type": "string", "description": "절대 구간 끝"},
                "from": {"type": "string",
                         "description": "절대 구간 시작. ISO8601 또는 유닉스 초"},
                "to": {"type": "string", "description": "절대 구간 끝"},
                "from": {"type": "string",
                         "description": "절대 구간 시작. ISO8601 또는 유닉스 초"},
                "to": {"type": "string", "description": "절대 구간 끝"},
                "at": {"type": "integer",
                       "description": "특정 시각을 볼 때 그 유닉스 초. 그 앞뒤 창을 본다"},
            },
            "required": ["host"],
        },
    },
    {
        "name": "open_problems",
        "description": "그 호스트에 지금 열려 있는 문제(Zabbix). 비우면 전체.",
        "input_schema": {
            "type": "object",
            "properties": {"host": {"type": "string"}},
        },
    },
    {
        "name": "panel_image",
        "description": ("그 호스트의 관측 화면(패널)을 그림으로 붙인다. 사람이 보고 있는 "
                        "그래프를 답과 함께 보여 줄 때 쓴다. 반환된 id 를 답에 적으면 "
                        "화면에 그림이 붙는다."),
        "input_schema": {
            "type": "object",
            "properties": {
                "host": {"type": "string"},
                "match": {"type": "string",
                          "description": "패널 제목에 든 문자열 (예: CPU, 복제, 로그)"},
                "from": {"type": "string"}, "to": {"type": "string"},
                "window_m": {"type": "integer"},
            },
            "required": ["host"],
        },
    },
    {
        "name": "past_judgments",
        "description": "봇이 전에 내린 판정 기록. 같은 일이 반복되는지 볼 때 쓴다.",
        "input_schema": {
            "type": "object",
            "properties": {
                "host": {"type": "string", "description": "비우면 전체"},
                "days": {"type": "integer"},
            },
        },
    },
]


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
    a, b = window_bounds(args, int(ctx["now"]))
    return await ctx["fetch_logs"](q, a, b, int(args.get("limit") or LOG_LIMIT_DEFAULT))


async def _tool_security_alerts(args: dict, ctx: dict) -> dict:
    ent, err = _target(args, ctx)
    if err:
        return err
    agent = ent.get("security")
    if not agent:
        return {"alerts": [], "status": "disabled",
                "note": "이 호스트에는 보안 에이전트가 없다. 없다는 뜻이 아니다"}
    a, b = window_bounds(args, int(ctx["now"]))
    body = build_wazuh_query(agent, a, b, args.get("min_level") or 0)
    return await ctx["fetch_security"](body)


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
    a, b = window_bounds(args, int(ctx["now"]))
    return await ctx["fetch_metrics"](ent, str(args.get("match") or ""), a, b)


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
    a, b = window_bounds(args, int(ctx["now"]))
    return await ctx["fetch_panel"](ent, str(args.get("match") or ""), a, b)


_TOOLS = {
    "list_hosts": _tool_list_hosts,
    "panel_image": _tool_panel_image,
    "host_metrics": _tool_host_metrics,
    "open_problems": _tool_open_problems,
    "host_logs": _tool_host_logs,
    "security_alerts": _tool_security_alerts,
    "past_judgments": _tool_past_judgments,
}
