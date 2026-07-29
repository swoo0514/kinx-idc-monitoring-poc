#!/usr/bin/env bash
#
# restart_gateway.sh — 게이트웨이를 안전하게 다시 띄운다.
#
# 코드를 고쳐도 이미 떠 있는 파이썬 프로세스는 다시 읽지 않는다. 그래서 재기동이 빠지면
# 옛 코드로 시험하게 되는데, healthz 는 옛 프로세스도 ok 로 답하기 때문에 정상으로 보인다.
# 2026-07-29 검증에서 이 함정에 세 번 걸려 순서를 코드로 굳혔다.
#
# 사용: bot/ 디렉토리에서 ./restart_gateway.sh
# 로그 위치를 바꾸려면 GATEWAY_LOG=/path/to/log ./restart_gateway.sh
#
set -uo pipefail

cd "$(dirname "$0")" || exit 1
LOG="${GATEWAY_LOG:-/tmp/gw-verify.log}"
PATTERN='uvicorn gateway.app'

echo "[1/4] 기존 프로세스 종료"
if pgrep -f "$PATTERN" >/dev/null; then
    pkill -f "$PATTERN"
    sleep 2
    if pgrep -f "$PATTERN" >/dev/null; then
        echo "      SIGTERM 으로 안 죽어 SIGKILL 사용"
        pkill -9 -f "$PATTERN"
        sleep 1
    fi
fi
if pgrep -f "$PATTERN" >/dev/null; then
    echo "      종료 실패. 아래 프로세스를 직접 확인할 것:"
    ps -ef | grep "$PATTERN" | grep -v grep
    exit 1
fi
echo "      종료 확인"

echo "[2/4] .env 로드"
if [ ! -f .env ]; then
    echo "      .env 가 없다. bot/ 디렉토리에서 실행할 것"
    exit 1
fi
set -a
. ./.env
set +a
echo "      완료"

echo "[3/4] 기동 (로그: $LOG)"
# --workers 를 붙이지 않는다. 워커마다 인시던트 버퍼가 따로 생겨 부모 카드가 여러 개 뜬다.
nohup python -m uvicorn gateway.app:app --host 0.0.0.0 --port 8800 > "$LOG" 2>&1 &
sleep 3

echo "[4/4] 기동 확인"
if grep -q 'Application startup complete' "$LOG"; then
    echo "      성공  pid=$(pgrep -f "$PATTERN" | tr '\n' ' ')"
    echo -n "      healthz: "; curl -s localhost:8800/healthz; echo
    echo
    echo "로그 보기:  tail -f $LOG"
    echo "검증용 필터: grep -E 'class=|gate |holmes|triage done' $LOG"
else
    echo "      실패. 로그 앞부분:"
    head -10 "$LOG"
    exit 1
fi
