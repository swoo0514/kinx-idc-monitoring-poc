"""질의 추적(랭스미스). 켜고 끄는 규칙과 무엇이 나가는지는 GATEWAY_GUIDE.md §33.

**이것은 외부로 값이 한 벌 더 나가는 지점이다.** 그래서 기본은 꺼져 있고, 운영자가 파일에
두 값(`LANGSMITH_TRACING`·`LANGSMITH_API_KEY`)을 적었을 때만 켜진다. 하나만 적혀 있으면
켜지지 않는다 — 켜진 척하다가 아무 데도 안 보내는 상태가 가장 나쁘다.

나가는 것은 그래프 질의 경로의 노드 입출력이다. 시스템 문구, 도구 정의, 도구 결과, 모델
회신이며 **전부 이미 가명 처리된 값**이다(마스킹은 도구 결과를 조립할 때 끝난다). 역치환
표는 프로세스 메모리에만 있으므로 나가지 않는다.

트리아지·월간 리포트·`ASK_ENGINE=loop` 은 프레임워크를 지나지 않으므로 추적에 안 잡힌다.
화면에 보이는 것이 전부라고 읽으면 비용을 적게 센다.
"""

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
    """기동 때 한 번 부른다. 반환 `{"on": bool, "why": str, "project": str}`.

    라이브러리가 읽는 변수 이름이 판마다 달라서(`LANGCHAIN_TRACING_V2` 와
    `LANGSMITH_TRACING`) 켤 때 둘 다 맞춰 준다. 사람이 어느 쪽을 적든 동작하게 하려는
    것이지, 우리가 새 이름을 만드는 것이 아니다.
    """
    if not _truthy(os.environ.get("LANGSMITH_TRACING")):
        return {"on": False, "why": "미설정 (LANGSMITH_TRACING)", "project": ""}
    if not os.environ.get("LANGSMITH_API_KEY", "").strip():
        # 켜라고만 적고 키가 없으면 조용히 안 나간다. 그 상태를 켜진 것으로 보고하면
        # 사람이 추적 화면을 열어 놓고 왜 비었는지 찾게 된다.
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
