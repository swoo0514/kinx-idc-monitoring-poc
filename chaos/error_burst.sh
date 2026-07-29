#!/usr/bin/env bash
# error_burst.sh — 감시 노드 로그에 ERROR 를 주입해 오류율을 급등시킨다. 사용법·원리는 chaos/README.md.
set -uo pipefail

COUNT="${1:-300}"
TAG="${2:-payment-api}"

echo "[chaos] ${TAG} 에러 로그 ${COUNT}건 주입..."
for i in $(seq 1 "$COUNT"); do
  logger -t "$TAG" -p user.err "ERROR request_id=${i} status=500 upstream_timeout"
done
echo "[chaos] 완료"
