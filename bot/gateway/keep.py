"""Keep push 어댑터 — 봇 분석을 Keep 알림(enrichment)으로 전송.

환경변수: KEEP_URL(예: http://<keep>:8080), KEEP_API_KEY(no-auth 모드는 아무 값이나 통과).
KEEP_URL 없으면 skip(열화) — Keep 미배선 환경에서도 봇은 그대로 동작.
Keep generic webhook(/alerts/event/keep)로 네이티브 형식 알림 전송, analysis/prejudge를
커스텀 필드로 실어 운영자가 Keep 한 화면에서 분석을 보고 Run Workflow(승인)로 조치.
Keep은 온프렘 저장소라 실 호스트 전송 무방(외부 LLM 마스킹 경계와 별개)."""

import logging
import os

import httpx

log = logging.getLogger("gateway.keep")

_SEV = {"SEV1": "critical", "SEV2": "high", "SEV3": "warning", "SEV4": "info", "NONE": "low"}


def push_alert(name: str, sev: str, host: str, analysis: str,
               prejudge: str = "", service: str = "", source: str = "kinx-bot",
               fingerprint: str = "", playbook: str = "") -> dict:
    """분석 담은 알림을 Keep에 전송. 실패해도 예외를 던지지 않음(봇 흐름 보호).
    fingerprint 지정 시 Keep이 그 값으로 디듑 → 같은 사건은 한 행에 모임(홈즈 enrich 대상).
    source: 빠른 봇 분석=kinx-bot / HolmesGPT 심층조사=holmesgpt 로 구분.
    playbook: 조치 후보의 플레이북 논리명(데모 B). Keep 워크플로가 `{{ alert.playbook }}` 로
    읽어 실행 대상을 고른다 — host·service 도 같은 방식으로 참조하므로 별도 필드가 필요 없다.
    (근거: Keep 공식 문서 workflows/syntax/context — 임의 알림 속성을 템플릿으로 참조 가능)"""
    url = os.environ.get("KEEP_URL", "").rstrip("/")
    if not url:
        log.info("[keep skipped: no KEEP_URL] %s", name)
        return {"ok": False, "skipped": True}
    key = os.environ.get("KEEP_API_KEY", "") or "keep-noauth"
    payload = {"name": name, "status": "firing", "severity": _SEV.get(sev, "warning"),
               "source": [source], "host": host, "service": service,
               "analysis": analysis, "prejudge": prejudge}
    if fingerprint:
        payload["fingerprint"] = fingerprint
    if playbook:
        payload["playbook"] = playbook
    try:
        r = httpx.post(f"{url}/alerts/event/keep",
                       headers={"Content-Type": "application/json", "x-api-key": key},
                       json=payload, timeout=10)
        ok = r.status_code < 300
        if not ok:
            log.warning("keep push failed: %s %s", r.status_code, r.text[:200])
        return {"ok": ok, "status": r.status_code}
    except Exception as e:
        log.warning("keep push exception: %s", e)
        return {"ok": False, "error": str(e)}


def enrich_note(fingerprint: str, note: str) -> dict:
    """홈즈 심층분석을 원래 알림(fingerprint)의 Note로 첨부 — 별개 알림 생성 대신.
    Keep 한 화면에서 사건 1행 + Note에 심층분석. 실패해도 예외를 던지지 않음.
    엔드포인트: POST /alerts/enrich/note {fingerprint, note} (Keep openapi 실측)."""
    url = os.environ.get("KEEP_URL", "").rstrip("/")
    if not url or not fingerprint:
        return {"ok": False, "skipped": True}
    key = os.environ.get("KEEP_API_KEY", "") or "keep-noauth"
    try:
        r = httpx.post(f"{url}/alerts/enrich/note",
                       headers={"Content-Type": "application/json", "x-api-key": key},
                       json={"fingerprint": fingerprint, "note": note}, timeout=10)
        ok = r.status_code < 300
        if not ok:
            log.warning("keep enrich_note failed: %s %s", r.status_code, r.text[:200])
        return {"ok": ok, "status": r.status_code}
    except Exception as e:
        log.warning("keep enrich_note exception: %s", e)
        return {"ok": False, "error": str(e)}
