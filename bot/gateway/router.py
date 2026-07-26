"""태그 라우팅 — SEV·태그로 경로 결정.

경로: resolve(복구) / drop / dashboard_only(SEV4) / digest(SEV3) /
      triage(SEV1·2, 데모 C) / remediate(automate 태그, 데모 B).
"""

from . import severity

AUTOMATE_TAG = "automate"
SCOPE_TAG = "scope"        # MSP 계약: notify_only | remediate (customer.yml 상속)


def decide(sev: str, tags: list, event_value: int = 1) -> dict:
    tags = tags or []
    if event_value == 0:
        return {"route": "resolve", "playbook": None}
    if sev == severity.NONE:
        return {"route": "drop", "playbook": None}
    if sev == severity.SEV4:
        return {"route": "dashboard_only", "playbook": None}
    if sev == severity.SEV3:
        return {"route": "digest", "playbook": None}

    # SEV1/2: automate 태그 + 계약 허용이면 remediate, 아니면 triage. scope가 automate에 우선(A-6).
    playbook = _tag_value(tags, AUTOMATE_TAG)
    scope = _tag_value(tags, SCOPE_TAG)
    if playbook and scope != "notify_only":
        return {"route": "remediate", "playbook": playbook}
    return {"route": "triage", "playbook": None}


def _tag_value(tags: list, key: str):
    for t in tags:
        if isinstance(t, dict) and t.get("tag") == key:
            return t.get("value") or None
    return None
