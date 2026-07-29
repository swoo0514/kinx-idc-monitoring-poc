#!/usr/bin/env bash
#
# service_down.sh — 대상 노드의 서비스를 정지시켜 데모 B(자가 치유)의 입력을 만든다.
# 정지 → Zabbix 서비스 트리거 발화 → 게이트웨이가 조치 후보를 Keep 승인 큐에 등록 →
# 사람이 승인(Run) → Ansible 재기동. 실행 위치·원리는 chaos/README.md 참조.
#
set -uo pipefail

TARGET="${1:?사용법: $0 <ssh_대상> [서비스=chronyd]}"
SERVICE="${2:-chronyd}"

echo "[chaos] ${TARGET} 의 ${SERVICE} 정지..."
ssh "$TARGET" "sudo systemctl stop ${SERVICE}; \
  echo \"  현재 상태: \$(systemctl is-active ${SERVICE} || true)\""

echo "[chaos] 완료 — Zabbix 서비스 트리거 발화를 기다린다(폴링 주기만큼 지연)."
echo "        복구는 Keep 승인 후 Ansible 이 수행한다."
echo "        수동 복구가 필요하면: ssh ${TARGET} sudo systemctl start ${SERVICE}"
