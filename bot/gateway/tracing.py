"""질의 추적(랭스미스). 켜고 끄는 규칙과 무엇이 나가는지는 GATEWAY_GUIDE.md §33."""

import logging
import os

log = logging.getLogger("gateway.tracing")

DEFAULT_PROJECT = "kinx-gateway"


def _truthy(v) -> bool:
    return str(v or "").strip().lower() in ("1", "true", "yes", "on")


def enabled() -> bool:
    """지금 추적이 켜져 있는가. 두 값이 다 있어야 켜진 것으로 본다."""
    return _truthy(os.environ.get("LANGSMITH_TRACING")) and bool(
        os.environ.get("LANGSMITH_API_KEY", "").strip())


def setup() -> dict:
    """기동 때 한 번 부른다. 반환 `{"on": bool, "why": str, "project": str}`."""
    if not _truthy(os.environ.get("LANGSMITH_TRACING")):
        return {"on": False, "why": "미설정 (LANGSMITH_TRACING)", "project": ""}
    if not os.environ.get("LANGSMITH_API_KEY", "").strip():
        # 켜라고만 적고 키가 없으면 조용히 안 나간다 — 그 상태를 켜진 것으로 보고하면 안 된다
        log.warning("추적을 켜라고 적혀 있으나 키가 없다 — 끈 채로 돈다")
        return {"on": False, "why": "키 없음 (LANGSMITH_API_KEY)", "project": ""}
    project = os.environ.get("LANGSMITH_PROJECT", "").strip() or DEFAULT_PROJECT
    os.environ["LANGSMITH_PROJECT"] = project
    os.environ["LANGCHAIN_TRACING_V2"] = "true"
    os.environ["LANGCHAIN_PROJECT"] = project
    log.info("질의 추적 켜짐 — 프로젝트 %s. 그래프 질의 경로만 잡힌다"
             " (트리아지·리포트는 안 잡힘)", project)
    return {"on": True, "why": "", "project": project}


def status() -> dict:
    """지금 상태. `/healthz` 와 기록용."""
    return {"on": enabled(),
            "project": os.environ.get("LANGSMITH_PROJECT", "") if enabled() else ""}
