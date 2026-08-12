"""외부 도구용 마스킹 수신 지점 — 도구와 모델 사이에서 이름을 가리고 되돌린다.

심층조사 도구는 받은 호스트명으로 감시 서버를 직접 조회하고 그 결과를 모델에 보낸다.
그 경계에 끼어들어야 통제가 성립한다. 설계·검증은 bot/GATEWAY_GUIDE.md §23.
"""

import hashlib
import json
import logging
import os
import re

import httpx

from . import egress, masking, nametable

log = logging.getLogger("gateway.proxy")

UPSTREAM = os.environ.get("LLM_UPSTREAM_URL", "https://api.anthropic.com")
API_VERSION = os.environ.get("LLM_API_VERSION", "2023-06-01")
TIMEOUT_S = float(os.environ.get("LLM_PROXY_TIMEOUT_S", "120"))
MAX_PER_HOUR = int(os.environ.get("LLM_PROXY_MAX_PER_HOUR", "2000"))

# 모델이 정확히 되받아야 하는 자리. 여기를 바꾸면 도구 호출이 깨진다.
PROTOCOL_KEYS = frozenset((
    "type", "role", "model", "name", "id", "tool_use_id", "stop_reason",
    "stop_sequence", "cache_control", "signature", "media_type", "encoding",
))
TOKEN_RE = re.compile(r"\[(?:host|ip|group)-[0-9a-z]+\]")


def token_for(kind: str, name: str) -> str:
    """이름에서 결정적으로 만든 토큰.

    번호를 매기면 표가 갱신될 때 순서가 밀려 같은 토큰이 다른 호스트를 가리킨다.
    조사 1회가 모델을 수십 번 부르는 동안 그 일이 나면 분석이 조용히 틀어진다.
    """
    h = hashlib.sha256(name.encode("utf-8")).hexdigest()[:6]
    return "[%s-%s]" % (kind, h)


def build_masker() -> masking.Masker:
    mk = masking.Masker()
    for name, kind in nametable.terms():
        if name not in mk._fwd:
            tok = token_for(kind, name)
            mk._fwd[name] = tok
            mk._rev[tok] = name
    mk._re = None
    return mk


def mask_json(obj, masker):
    return _walk(obj, masker.mask)


def unmask_json(obj, masker):
    return _walk(obj, masker.unmask)


def _walk(obj, fn, key: str = ""):
    if isinstance(obj, dict):
        return {k: _walk(v, fn, k) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_walk(v, fn, key) for v in obj]
    if isinstance(obj, str) and key not in PROTOCOL_KEYS:
        return fn(obj)
    return obj


def leftover_tokens(resp) -> list:
    """되돌리지 못한 토큰이 도구 인자에 남았는가.

    남은 채로 돌려주면 도구가 그 이름으로 조회해 빈 결과를 받고, 그것을
    "이상 없음" 으로 읽는다. 조용한 오답보다 시끄러운 실패가 낫다.
    """
    out = []
    for block in (resp.get("content") or []):
        if isinstance(block, dict) and block.get("type") == "tool_use":
            out += TOKEN_RE.findall(json.dumps(block.get("input") or {},
                                               ensure_ascii=False))
    return out


async def forward(body: dict, headers: dict) -> tuple:
    """상류로 중계한다. 반환 (상태코드, 응답 dict)."""
    async with httpx.AsyncClient() as c:      # TLS 검증은 켠 채로 둔다
        r = await c.post(UPSTREAM.rstrip("/") + "/v1/messages",
                         json=body, headers=headers, timeout=TIMEOUT_S)
    try:
        return r.status_code, r.json()
    except ValueError:
        return r.status_code, {"error": {"message": r.text[:300]}}


async def handle(body: dict, tenant_scoped: bool = False) -> tuple:
    """마스킹 → 중계 → 역치환. 반환 (상태코드, 응답 dict)."""
    if body.get("stream"):
        return 400, {"error": {"type": "unsupported",
                               "message": "이 수신 지점은 스트리밍을 중계하지 않는다. "
                                          "조각 사이에서 토큰이 갈라져 역치환이 깨진다."}}
    key = os.environ.get("ANTHROPIC_API_KEY", "")
    if not key:
        return 500, {"error": {"message": "상류 키가 없다(ANTHROPIC_API_KEY)"}}

    if not nametable.terms():
        log.error("이름 표가 비었다 — 가릴 대상을 모른다 (고객사 요청이면 거절)")
        if tenant_scoped:
            return 503, {"error": {"type": "masking_unavailable",
                                   "message": "이름 표가 비어 마스킹을 보장할 수 없다"}}

    mk = build_masker()
    masked = mask_json(body, mk)
    headers = {"x-api-key": key, "anthropic-version": API_VERSION,
               "content-type": "application/json"}
    try:
        with egress.guard("proxy", max_per_hour=MAX_PER_HOUR) as record:
            record()
            status, resp = await forward(masked, headers)
    except egress.Blocked as b:
        return 429, {"error": {"type": b.reason, "message": "게이트웨이 호출 제한"}}

    if status >= 300:
        return status, resp
    back = unmask_json(resp, mk)
    left = leftover_tokens(back)
    if left:
        log.error("역치환 못 한 토큰이 도구 인자에 남았다: %s", left[:3])
        return 502, {"error": {"type": "unmask_failed",
                               "message": "가명을 실명으로 되돌리지 못했다: %s" % left[:3]}}
    return status, back
