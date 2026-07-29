#!/usr/bin/env bash
# snmpsim 인터페이스 에러를 켰다 껐다 반복해 트리거 반복 발화(노이즈 폭주)를 재현. 원리·사용법은 chaos/README.md.
set -uo pipefail
cd "$(dirname "$0")/../lab"

CYCLES="${1:-6}"
DWELL="${2:-70}"
D=snmpsim/data

for i in $(seq 1 "$CYCLES"); do
  echo "[chaos] $i/$CYCLES 에러 ON"
  cp "$D/switch1.error.snmprec" "$D/switch1.snmprec"
  docker compose --profile chaos restart snmpsim >/dev/null
  sleep "$DWELL"
  echo "[chaos] $i/$CYCLES 에러 OFF"
  cp "$D/switch1.clean.snmprec" "$D/switch1.snmprec"
  docker compose --profile chaos restart snmpsim >/dev/null
  sleep "$DWELL"
done
echo "[chaos] 완료 — Monitoring > Problems 에 반복 발화가 쌓였는지 확인"
