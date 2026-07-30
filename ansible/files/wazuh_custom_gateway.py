#!/usr/bin/env python3
"""Wazuh 매니저 -> 게이트웨이 웹훅. 배선 근거와 절차는 ansible/DEPLOY_GUIDE.md."""

import json
import os
import sys
import urllib.error
import urllib.request

TOKEN_FILE = "/var/ossec/etc/gateway_token"
TIMEOUT_S = 5
MAX_LEVEL = 15


def log(msg):
    print("custom-gateway: %s" % msg, flush=True)


def read_token():
    try:
        with open(TOKEN_FILE, "r") as f:
            return f.read().strip()
    except OSError as e:
        log("token 파일 읽기 실패 %s: %s" % (TOKEN_FILE, e))
        return ""


def build_payload(alert):
    rule = alert.get("rule") or {}
    agent = alert.get("agent") or {}
    level = rule.get("level")
    try:
        level = int(level)
    except (TypeError, ValueError):
        log("rule.level 없음/비정상(%r) — 전송하지 않는다" % (level,))
        return None
    alert_id = alert.get("id") or "%s-%s" % (rule.get("id", "0"), alert.get("timestamp", ""))
    # rule.groups 는 게이트웨이 분류의 1차 신호다. 설명 문자열 추론보다 정확하므로
    # 반드시 함께 보낸다(리스트로 오는 것을 콤마 문자열로 평탄화 — 수집기와 같은 형태).
    groups = rule.get("groups") or []
    if not isinstance(groups, list):
        groups = [groups]
    return {
        "alert_id": str(alert_id),
        "rule_id": str(rule.get("id", "")),
        "rule_level": min(max(level, 0), MAX_LEVEL),
        "rule_description": rule.get("description", "") or "",
        "rule_groups": ",".join(str(g) for g in groups if g),
        "agent_name": agent.get("name", "") or "",
        "timestamp": alert.get("timestamp", "") or "",
    }


def main():
    if len(sys.argv) < 4:
        log("인자 부족 — argv[1]=alert file, argv[3]=hook_url 필요")
        return 1
    alert_path, hook_url = sys.argv[1], sys.argv[3]

    try:
        with open(alert_path, "r") as f:
            alert = json.load(f)
    except (OSError, ValueError) as e:
        log("알림 파일 파싱 실패 %s: %s" % (alert_path, e))
        return 1

    payload = build_payload(alert)
    if payload is None:
        return 1

    token = read_token()
    if not token:
        return 1

    req = urllib.request.Request(
        hook_url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", "X-Gateway-Token": token},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT_S) as res:
            log("sent rule=%s level=%s agent=%s -> HTTP %s"
                % (payload["rule_id"], payload["rule_level"],
                   payload["agent_name"], res.status))
    except urllib.error.HTTPError as e:
        log("게이트웨이 거부 rule=%s -> HTTP %s %s"
            % (payload["rule_id"], e.code, e.read()[:200]))
        return 1
    except (urllib.error.URLError, OSError) as e:
        log("게이트웨이 도달 실패 rule=%s: %s" % (payload["rule_id"], e))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
