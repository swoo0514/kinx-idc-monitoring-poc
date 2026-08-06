#!/usr/bin/env bash
# vm-target-002(슬레이브)에서 실행. 데모 C: "복제 고장이 아니라 자원 경합/과부하" 재현.
# lag 의 동력은 슬레이브 IO 가 아니라 master 쓰기량 = 슬레이브 단일 SQL 스레드가 대량 쓰기를
# 못 따라잡아 Seconds_Behind_Master 누적. 여기에 디스크 I/O 포화(백업성 dd)로 재생을 더 늦추고
# iowait 신호를 만든다 + syslog 백업 마커(Loki 교차신호). "야간 배치가 DB를 덮쳐 IO 포화 +
# 복제 백로그"라는 현실적 시나리오(복제 자체는 정상). 근거 docs/04-demo/scenario-c-replication.md,
# 절차 lab/mariadb/REPL_VM_GUIDE.md.
set -uo pipefail

DURATION="${DURATION:-180}"          # 부하 지속(초)
IO_WORKERS="${IO_WORKERS:-2}"        # 병렬 디스크 쓰기 개수
SCRATCH="${SCRATCH:-/var/tmp/kinx_chaos}"
MASTER_HOST="${MASTER_HOST:?예: MASTER_HOST=192.0.2.10}"
DB="${DEMO_REPL_DB:-demo_repl}"
WUSER="${DEMO_WRITER_USER:?}"
WPW="${DEMO_WRITER_PASSWORD:?}"

pids=()
cleanup() {
  echo "[chaos] 정리 중..."
  for p in "${pids[@]:-}"; do kill "$p" 2>/dev/null || true; done
  rm -rf "$SCRATCH"
  logger -t kinx-chaos "backup job finished (chaos cleanup)"
  echo "[chaos] 완료. lag 가 0 으로 회복하는지 관찰."
}
trap cleanup EXIT INT TERM

mkdir -p "$SCRATCH"
echo "[chaos] 자원 경합 주입 ${DURATION}s — I/O 워커 ${IO_WORKERS}개 + master 쓰기 + 백업 마커."
logger -t kinx-chaos "backup job started: dumping databases to ${SCRATCH} (nightly maintenance)"

# 1) 디스크 I/O 포화 — 백업성 대용량 쓰기(fdatasync 로 캐시 우회 효과)
for i in $(seq 1 "$IO_WORKERS"); do
  ( end=$((SECONDS+DURATION))
    while [ $SECONDS -lt $end ]; do
      dd if=/dev/zero of="$SCRATCH/blob_$i" bs=1M count=1024 conv=fdatasync status=none 2>/dev/null || true
    done ) &
  pids+=("$!")
done

# 2) 실제 백업 흉내 — 로컬 슬레이브 덤프 반복(디스크 read 부하 + Loki 로그 흔적)
( end=$((SECONDS+DURATION))
  while [ $SECONDS -lt $end ]; do
    sudo mariadb-dump --single-transaction --databases "$DB" > "$SCRATCH/backup.sql" 2>/dev/null || true
    logger -t kinx-chaos "backup snapshot written ($(wc -c < "$SCRATCH/backup.sql" 2>/dev/null || echo 0) bytes)"
    sleep 5
  done ) &
pids+=("$!")

# 3) master 대량 연속 쓰기 — lag 의 진짜 동력. load_gen 을 ~200k 행으로 시드한 뒤,
#    큰 INSERT...SELECT(MD5(RAND) → row 기반, 슬레이브가 행별 재생) + 같은 크기 DELETE 로
#    테이블은 유계 유지(디스크 안 채움)하며 쉼 없이 쓴다. 단일 SQL 스레드가 못 따라가 lag 누적.
m() { mariadb -h "$MASTER_HOST" -u "$WUSER" -p"$WPW" "$DB" "$@" 2>/dev/null; }
BATCH="${BATCH:-200000}"
echo "[chaos] load_gen 시드(~${BATCH} 행)..."
m -e "INSERT INTO load_gen(a,b) VALUES (MD5(RAND()),MD5(RAND()))" || true
for _ in $(seq 1 20); do
  n="$(m -N -e "SELECT COUNT(*) FROM load_gen" || echo 0)"
  [ "${n:-0}" -ge "$BATCH" ] && break
  m -e "INSERT INTO load_gen(a,b) SELECT MD5(RAND()),MD5(RAND()) FROM load_gen LIMIT ${BATCH}" || true
done
echo "[chaos] 시드 완료($(m -N -e 'SELECT COUNT(*) FROM load_gen' || echo '?') 행). 대량 쓰기 시작."
( end=$((SECONDS+DURATION))
  while [ $SECONDS -lt $end ]; do
    m -e "INSERT INTO load_gen(a,b) SELECT MD5(RAND()),MD5(RAND()) FROM load_gen LIMIT ${BATCH};
          DELETE FROM load_gen ORDER BY id LIMIT ${BATCH};" || true
  done ) &
pids+=("$!")

# 진행 관찰 — lag 를 주기적으로 출력
end=$((SECONDS+DURATION))
while [ $SECONDS -lt $end ]; do
  lag="$(sudo mariadb -N -e "SHOW SLAVE STATUS\G" 2>/dev/null \
        | grep -E 'Slave_SQL_Running:|Seconds_Behind_Master:' | paste -sd' ')"
  echo "  [$((end-SECONDS))s 남음] ${lag:-슬레이브 상태 조회 실패}"
  sleep 10
done
