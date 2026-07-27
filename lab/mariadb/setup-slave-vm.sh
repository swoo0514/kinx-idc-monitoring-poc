#!/usr/bin/env bash
# vm-target-002(슬레이브 VM)에서 sudo 로 실행. MariaDB 10.11 설치·복제 설정. 절차는 REPL_VM_GUIDE.md.
set -euo pipefail

MASTER_HOST="${MASTER_HOST:?예: MASTER_HOST=192.0.2.10}"
MASTER_PORT="${MASTER_PORT:-3306}"
DB="${DEMO_REPL_DB:-demo_repl}"
REPL_USER="${REPLICATION_USER:?}"
REPL_PW="${REPLICATION_PASSWORD:?}"
DUMP="${DUMP:-/tmp/kinx_demo_dump.sql}"
SERVER_ID="${SERVER_ID:-10}"
[[ -f "$DUMP" ]] || { echo "[!] 덤프 없음: $DUMP (prep-master 에서 scp)"; exit 1; }

echo "== 1/5 MariaDB 10.11 설치 (master 와 버전 일치 — 스큐 방지) =="
if ! rpm -q MariaDB-server >/dev/null 2>&1 && ! rpm -q mariadb-server >/dev/null 2>&1; then
  # MariaDB 10.11 은 liburing.so.2 요구(io_uring). Rocky 9 최소 이미지엔 없어 선설치.
  sudo dnf install -y liburing || sudo dnf install -y liburing --releasever=9
  curl -LsS https://r.mariadb.com/downloads/mariadb_repo_setup | sudo bash -s -- --mariadb-server-version=10.11
  sudo dnf install -y MariaDB-server MariaDB-client
fi

echo "== 2/5 서버 식별자 설정 (server-id=${SERVER_ID}, GTID) =="
sudo tee /etc/my.cnf.d/zz-slave.cnf >/dev/null <<EOF
[mariadb]
server-id=${SERVER_ID}
gtid-strict-mode=1
# 계정 관리 DDL(마스터의 CREATE/ALTER USER 등)은 슬레이브에 그 계정이 없어 적용 실패 →
# mysql 스키마는 복제 대상에서 제외 (demo_repl 데이터만 복제하면 충분)
replicate-wild-ignore-table=mysql.%
EOF
sudo systemctl enable --now mariadb
sudo systemctl restart mariadb

echo "== 3/5 스냅샷 적재 =="
sudo mariadb < "$DUMP"

echo "== 4/5 복제 시작 (스냅샷 GTID 명시) =="
GTID="$(grep -oE "gtid_slave_pos='[0-9-]+'" "$DUMP" | grep -oE "[0-9]+-[0-9]+-[0-9]+" | head -1)"
[[ -n "$GTID" ]] || { echo "[!] 덤프에서 GTID 추출 실패"; exit 1; }
sudo mariadb -e "
  STOP SLAVE;
  RESET SLAVE;
  SET GLOBAL gtid_slave_pos='${GTID}';
  CHANGE MASTER TO
    MASTER_HOST='${MASTER_HOST}', MASTER_PORT=${MASTER_PORT},
    MASTER_USER='${REPL_USER}', MASTER_PASSWORD='${REPL_PW}',
    MASTER_USE_GTID=slave_pos;
  START SLAVE;"

echo "== 5/5 복제 상태 =="
sleep 2
status="$(sudo mariadb -e 'SHOW SLAVE STATUS\G')"
echo "$status" | grep -E 'Slave_IO_Running:|Slave_SQL_Running:|Seconds_Behind_Master:|Last_IO_Error:|Last_SQL_Error:' || true
io="$(echo "$status"  | grep 'Slave_IO_Running:'  | awk '{print $2}')"
sql="$(echo "$status" | grep 'Slave_SQL_Running:' | awk '{print $2}')"
if [[ "$io" == "Yes" && "$sql" == "Yes" ]]; then
  echo "[OK] 복제 정상 (IO=Yes, SQL=Yes). 표준 MySQL 템플릿이 mysql.seconds_behind_master 로 지연 감시."
else
  echo "[!] 복제 비정상 (IO=$io, SQL=$sql). master 3306 도달·방화벽·GTID → REPL_VM_GUIDE.md §5"
  exit 1
fi
