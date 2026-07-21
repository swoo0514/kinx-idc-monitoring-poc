#!/usr/bin/env bash

set -uo pipefail

TARGET="${1:?사용법: $0 <대상_IP> [횟수=12] [계정=badguy]}"
COUNT="${2:-12}"
USER_NAME="${3:-badguy}"

echo "[chaos] SSH 브루트포스 시뮬 → ${TARGET} (없는 계정 '${USER_NAME}', ${COUNT}회)"
for i in $(seq 1 "${COUNT}"); do
  # BatchMode=yes  : 비밀번호 프롬프트 없이 즉시 인증 실패
  # StrictHostKeyChecking=no : 최초 호스트 키 확인 프롬프트 건너뜀
  # ConnectTimeout=3 : 응답 없을 때 3초 후 다음 시도
  ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=3 \
      "${USER_NAME}@${TARGET}" exit 2>/dev/null || true
  echo -n "${i} "
done
echo
echo "[chaos] 완료 — Wazuh Threat Hunting에서 rule.id:5712 (level 10) 발화 확인"
