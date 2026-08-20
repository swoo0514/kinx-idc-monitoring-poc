"""축약 전용 어댑터 (GPT-5.6 Luna).

**판단하지 않는다.** 이 어댑터가 받는 것은 "이 축 결과에서 이 소목표에 답하라"뿐이고, 사건
서사도 다른 축도 가설도 안 받는다. 근거는 private/docs/deep_mode_design.md §3-5 —
논문 실측상 실행자 능력은 성능에 거의 영향이 없고(Żywot), 그래서 부피 큰 원문 읽기를 값싼
모델로 내려도 안전하다.

**`llm._adapters()` 에 넣지 않는다.** 그쪽은 등록부가 아니라 실행 폴백 체인이라, 넣으면
Claude 가 죽는 순간 트리아지 판단 프롬프트가 통째로 이리로 온다. 축약 전용 체인은
`deep/condense.py` 에 따로 있다.

전송 범위와 학습 미사용 근거는 private/docs/llm_data_spec.md.
"""

import logging
import os

log = logging.getLogger("gateway.openai_luna")

DEFAULT_MODEL = "gpt-5.6-luna"
DEFAULT_TIMEOUT_S = 60.0
MAX_TOKENS = 1024        # 축약 결과는 고정 형태 한 덩이라 길 이유가 없다


def map_usage(body: dict):
    """OpenAI 응답의 사용량을 우리 표 형식으로. 없으면 None — 추정하지 않는다.

    이름이 달라서 그대로 두면 **이 공급자만 조용히 무료로 보인다.**
    """
    u = (body or {}).get("usage") or {}
    if not u:
        return None
    cached = int(((u.get("prompt_tokens_details") or {}).get("cached_tokens")) or 0)
    return {"in": int(u.get("prompt_tokens") or 0),
            "out": int(u.get("completion_tokens") or 0),
            # OpenAI 는 캐시 쓰기를 따로 청구하지 않는다
            "cache_write": 0,
            "cache_read": cached,
            "model": (body or {}).get("model") or DEFAULT_MODEL}


class LunaAdapter:
    name = "luna"

    def __init__(self, model: str = "", kind: str = ""):
        from .. import llm

        self.model = model or llm.model_for(kind or "condense") or DEFAULT_MODEL
        self.timeout = float(os.environ.get("CONDENSE_TIMEOUT_S", DEFAULT_TIMEOUT_S))
        self.last_usage = None

    def available(self) -> bool:
        return bool(os.environ.get("OPENAI_API_KEY"))

    def complete(self, system: str, user: str) -> str:
        import openai

        client = openai.OpenAI(timeout=self.timeout, max_retries=0)
        resp = client.chat.completions.create(
            model=self.model, max_tokens=MAX_TOKENS,
            messages=[{"role": "system", "content": system},
                      {"role": "user", "content": user}])
        body = resp.model_dump()
        self.last_usage = map_usage(body)
        choices = body.get("choices") or [{}]
        return ((choices[0].get("message") or {}).get("content")) or ""
