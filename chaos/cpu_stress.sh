#!/usr/bin/env bash
#
# cpu_stress.sh — 감시 노드에 CPU 부하를 주입해 Zabbix CPU utilization 메트릭을 급등시킨다.
# 데모 A의 메트릭 축(브루트포스는 보안·로그 축만 흔든다). 실행 위치·원리는 chaos/README.md 참조.
#
set -uo pipefail

TARGET="${1:?사용법: $0 <ssh_대상> [지속초=60]}"
DURATION="${2:-60}"

echo "[chaos] ${TARGET} CPU 부하 ${DURATION}초 (전 코어 busy-loop)..."
# 대상의 코어 수만큼 busy-loop 워커를 timeout 로 띄운다(의존성 없이 CPU 100%).
ssh "$TARGET" "N=\$(nproc); echo \"  코어 \$N개에 부하\"; \
  for i in \$(seq 1 \$N); do timeout ${DURATION} bash -c 'while :; do :; done' >/dev/null 2>&1 & done; \
  wait"
echo "[chaos] 완료 — Grafana 메트릭 패널에서 CPU utilization 급등 확인"
