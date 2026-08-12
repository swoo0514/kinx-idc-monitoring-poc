"""외부 도구용 마스킹 수신 지점. 설계·검증은 bot/GATEWAY_GUIDE.md §23."""

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

# 치환 제외 — 근거 §23-3
PROTOCOL_KEYS = frozenset((
    "type", "role", "model", "name", "id", "tool_use_id", "stop_reason",
    "stop_sequence", "cache_control", "signature", "media_type", "encoding",
))
TOKEN_RE = re.compile(r"\[(?:host|ip|group)-[0-9a-z]+\]")


def token_for(kind: str, name: str) -> str:
    """이름에서 결정적으로 만든 토큰 (§23-4)."""
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


def substituted(before, after) -> int:
    """실제로 몇 개의 이름이 바뀌었는가 (§23-5)."""
    return len(TOKEN_RE.findall(json.dumps(after, ensure_ascii=False)))


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
    """되돌리지 못한 토큰이 도구 인자에 남았는가 (§23-5)."""
    out = []
    for block in (resp.get("content") or []):
        if isinstance(block, dict) and block.get("type") == "tool_use":
            out += TOKEN_RE.findall(json.dumps(block.get("input") or {},
                                               ensure_ascii=False))
    return out


async def forward(body: dict, headers: dict) -> tuple:
    """상류로 중계한다. 반환 (상태코드, 응답 dict)."""
    async with httpx.AsyncClient() as c:
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
                               "message": "스트리밍 미중계 — 조각 사이에서 토큰이 "
                                          "갈라져 역치환이 깨진다(§23-6)"}}
    key = os.environ.get("ANTHROPIC_API_KEY", "")
    if not key:
        return 500, {"error": {"message": "상류 키가 없다(ANTHROPIC_API_KEY)"}}

    if not nametable.terms():
        log.error("이름 표가 비었다 — 가릴 대상을 모른다 (§23-6)")
        if tenant_scoped:
            return 503, {"error": {"type": "masking_unavailable",
                                   "message": "이름 표가 비어 마스킹을 보장할 수 없다"}}

    mk = build_masker()
    masked = mask_json(body, mk)
    n = substituted(body, masked)
    if not n:
        log.warning("가린 이름이 0개다 — 표(%d개)에 없는 이름만 오간 것인지 확인한다",
                    len(nametable.terms()))
    else:
        log.info("이름 %d자리 가림 (표 %d개)", n, len(nametable.terms()))
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
