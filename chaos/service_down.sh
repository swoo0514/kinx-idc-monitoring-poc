#!/usr/bin/env bash
#
# service_down.sh — 대상 노드의 서비스를 정지시켜 데모 B(자가 치유)의 입력을 만든다.
# 정지 → Zabbix 서비스 트리거 발화 → 게이트웨이가 조치 후보를 Keep 승인 큐에 등록 →
# 사람이 승인(Run) → Ansible 재기동. 실행 위치·원리는 chaos/README.md 참조.
#
set -uo pipefail

TARGET="${1:?사용법: $0 <ssh_대상> [서비스=chronyd]   예) $0 vm-target-002 chronyd}"
SERVICE="${2:-chronyd}"

# SSH 별칭은 작업자 PC 의 ~/.ssh/config 에 있다. 관측 코어 VM 에는 없으므로 거기서 별칭을 쓰면
# Could not resolve hostname 이 난다. 대상 이름이 세 가지라 헷갈리기 쉽다 —
# SSH 별칭 vm-target-002 / Zabbix·Loki·Wazuh 라벨 vm-p3-target-002.novalocal / IP 192.168.20.16
if ! ssh -o BatchMode=yes -o ConnectTimeout=5 "$TARGET" true 2>/dev/null; then
    echo "[chaos] '${TARGET}' 에 SSH 로 붙지 못했다. 이름과 실행 위치를 확인할 것."
    echo "        작업자 PC 에서 SSH 별칭으로 실행한다: $0 vm-target-002 ${SERVICE}"
    exit 1
fi

echo "[chaos] ${TARGET} 의 ${SERVICE} 정지..."
ssh "$TARGET" "sudo systemctl stop ${SERVICE}; \
  echo \"  현재 상태: \$(systemctl is-active ${SERVICE} || true)\""

echo "[chaos] 완료 — Zabbix 서비스 트리거 발화를 기다린다(폴링 주기만큼 지연)."
echo "        복구는 Keep 승인 후 Ansible 이 수행한다."
echo "        수동 복구가 필요하면: ssh ${TARGET} sudo systemctl start ${SERVICE}"
