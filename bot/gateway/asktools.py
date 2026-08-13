"""질의 도구의 질의문 조립과 검사. 설계는 bot/GATEWAY_GUIDE.md §27.

`collector.ZabbixClient.call` 은 `.get` 아닌 메서드를 거부한다. Loki 와 Wazuh 에는
메서드 이름이 없어 같은 검사를 걸 수 없다. **두 축의 등가물은 호출자가 질의문을 못
주는 것이다.** 도구는 라벨·기간·문자열 필터만 받고 질의문은 여기서 만든다.
"""

import re

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
