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


def build_wazuh_query(agent_name: str, window_m: int, min_level: int, now: int) -> dict:
    """Wazuh 질의 본문. 틀을 코드가 만들고 값만 끼운다.

    에이전트명은 정확 일치(`term`)를 유지한다. 부분 일치로 바꾸면 이름이 비슷한 다른
    호스트의 경보가 섞인다.
    """
    win = clamp_window(window_m)
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
            {"range": {"@timestamp": {"gte": (now - win * 60) * 1000,
                                      "lte": now * 1000,
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


def _target(args: dict, ctx: dict) -> tuple:
    """인자의 호스트 토큰을 표에서 찾는다. 반환 `(항목, 오류)`."""
    tok = str((args or {}).get("host") or "").strip()
    if not tok:
        return None, _err("host 인자가 없다. list_hosts 로 대상 토큰을 먼저 확인하라")
    ent = (ctx.get("table") or {}).get(tok)
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
        return await fn(args or {}, ctx)
    except ValueError as e:                      # 조립기가 막은 인자
        return _err(str(e))
    except Exception as e:                       # 조회 실패는 없음이 아니다
        log.warning("도구 %s 실패: %s", name, e)
        return _err("조회하지 못했다(%s). 이 결과를 '없음'으로 읽지 마라" % type(e).__name__)


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
        out.append({"host": tok, "axes": sorted(k for k in ("logs", "security")
                                                if ent.get(k))})
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
    return await ctx["fetch_logs"](q, clamp_window(args.get("window_m")),
                                   int(args.get("limit") or LOG_LIMIT_DEFAULT))


async def _tool_security_alerts(args: dict, ctx: dict) -> dict:
    ent, err = _target(args, ctx)
    if err:
        return err
    agent = ent.get("security")
    if not agent:
        return {"alerts": [], "status": "disabled",
                "note": "이 호스트에는 보안 에이전트가 없다. 없다는 뜻이 아니다"}
    body = build_wazuh_query(agent, args.get("window_m"), args.get("min_level") or 0,
                             int(ctx["now"]))
    return await ctx["fetch_security"](body)


async def _tool_past_judgments(args: dict, ctx: dict) -> dict:
    tok = str(args.get("host") or "").strip()
    ent = (ctx.get("table") or {}).get(tok) if tok else None
    if tok and not ent:
        return _err("알 수 없는 대상이다: %s" % tok)
    days = clamp_window(int(args.get("days") or JUDGMENT_DAYS_DEFAULT) * 1440) // 1440
    return await ctx["fetch_judgments"](ent.get("host") if ent else "", max(days, 1))


async def _tool_host_metrics(args: dict, ctx: dict) -> dict:
    ent, err = _target(args, ctx)
    if err:
        return err
    return await ctx["fetch_metrics"](ent, str(args.get("match") or ""),
                                      clamp_window(args.get("window_m")),
                                      args.get("at"))


async def _tool_open_problems(args: dict, ctx: dict) -> dict:
    tok = str(args.get("host") or "").strip()
    ent = (ctx.get("table") or {}).get(tok) if tok else None
    if tok and not ent:
        return _err("알 수 없는 대상이다: %s" % tok)
    return await ctx["fetch_problems"](ent)


_TOOLS = {
    "list_hosts": _tool_list_hosts,
    "host_metrics": _tool_host_metrics,
    "open_problems": _tool_open_problems,
    "host_logs": _tool_host_logs,
    "security_alerts": _tool_security_alerts,
    "past_judgments": _tool_past_judgments,
}
