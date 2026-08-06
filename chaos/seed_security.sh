#!/usr/bin/env bash
# 고객사 월간 리포트 데모용 — 보안 소견을 대상 호스트에 심는다.
#
# 왜 필요한가: 리포트의 보안 절(준수율·파일 무결성·취약점)은 Wazuh 인덱서에서 읽어 온다.
# 아무 일도 없던 호스트로 리포트를 뽑으면 그 절이 "미산출"로만 채워져 고객에게 보여줄 게 없다.
# 그래서 실제로 탐지되는 변경을 심어 두고 리포트를 돌린다.
#
# 전제: 대상 호스트에 ansible/templates/ossec.conf.j2 가 적용돼 있어야 한다.
#   - /root/.ssh 와 /etc/cron.d 는 realtime, /etc/ssh 는 whodata → 변경이 수 초 안에 잡힌다.
#   - /etc 전체는 예약 스캔(12시간)이라 여기서 건드려도 데모 중에는 안 뜬다. 그래서 이 스크립트는
#     realtime/whodata 경로만 건드린다.
# 근거: ansible/templates/ossec.conf.j2, ansible/files/wazuh_local_rules.xml (룰 100201 = level 12)
#
# 되돌리기: 같은 스크립트에 revert 를 주면 심은 것을 전부 지운다.
#   ./seed_security.sh revert
#
# 실행 위치: 대상 호스트에서 직접(sudo 필요).
set -euo pipefail

MODE="${1:-seed}"
MARK="# kinx-demo-seed"
SSHD=/etc/ssh/sshd_config
AUTHKEYS=/root/.ssh/authorized_keys
CRONFILE=/etc/cron.d/kinx-demo-seed
STAMP="$(date +%Y%m%d-%H%M%S)"

need_root() {
  if [ "$(id -u)" -ne 0 ]; then
    echo "root 로 실행해야 합니다: sudo $0 $MODE" >&2
    exit 1
  fi
}

seed() {
  need_root
  echo "[1/4] SSH 설정 변경 — 룰 100201(level 12) 대상"
  # 원본을 남긴다. 되돌릴 때 이 파일로 복구한다.
  [ -f "$SSHD.kinx-demo.bak" ] || cp -p "$SSHD" "$SSHD.kinx-demo.bak"
  # 동작을 바꾸지 않는 주석만 덧붙인다 — 데모용이므로 실제 접속 정책은 건드리지 않는다.
  grep -q "$MARK" "$SSHD" || printf '\n%s %s\n' "$MARK" "$STAMP" >> "$SSHD"

  echo "[2/4] root 인증 키 추가 — 룰 100201(level 12) 대상"
  mkdir -p /root/.ssh && chmod 700 /root/.ssh
  [ -f "$AUTHKEYS" ] || { : > "$AUTHKEYS"; chmod 600 "$AUTHKEYS"; }
  # 실제로 로그인 가능한 키가 아니다. 형식만 갖춘 더미 문자열이라 이 키로는 접속되지 않는다.
  grep -q "$MARK" "$AUTHKEYS" || \
    echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDkinxDemoSeedNotARealKey$STAMP $MARK" >> "$AUTHKEYS"

  echo "[3/4] 예약 작업 추가 — 파일 무결성 이벤트(level 7) 대상"
  cat > "$CRONFILE" <<EOF
$MARK $STAMP
# 데모용. 아무 일도 하지 않는다.
*/30 * * * * root /bin/true
EOF
  chmod 644 "$CRONFILE"

  echo "[4/4] 심은 것 확인"
  grep -c "$MARK" "$SSHD" "$AUTHKEYS" "$CRONFILE" || true
  cat <<'EOS'

심었습니다. 확인 순서:
  1) Wazuh 대시보드 → Threat Hunting → rule.id:100201  (level 12 · 승격 룰)
  2) 같은 화면에서 rule.groups:syscheck                  (파일 무결성 일반)
  3) 인증 실패는 별도 — chaos/ssh_bruteforce.sh 를 관측 코어에서 대상 IP 로 실행

리포트는 그다음에 돌립니다. 절차는 docs/04-demo/runbook.md 를 봅니다.
EOS
}

revert() {
  need_root
  echo "[1/3] SSH 설정 복구"
  if [ -f "$SSHD.kinx-demo.bak" ]; then
    cp -p "$SSHD.kinx-demo.bak" "$SSHD" && rm -f "$SSHD.kinx-demo.bak"
  else
    sed -i "/$MARK/d" "$SSHD"
  fi
  echo "[2/3] root 인증 키 정리"
  [ -f "$AUTHKEYS" ] && sed -i "/$MARK/d" "$AUTHKEYS" || true
  echo "[3/3] 예약 작업 제거"
  rm -f "$CRONFILE"
  echo "되돌렸습니다. 이 변경들도 파일 무결성 이벤트로 한 번 더 잡힙니다(정상)."
}

case "$MODE" in
  seed)   seed ;;
  revert) revert ;;
  *) echo "사용: $0 [seed|revert]" >&2; exit 2 ;;
esac
