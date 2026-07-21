#!/usr/bin/env bash
# 절차·근거·트러블슈팅: private/lab/docker-core/BUILD_GUIDE.md §9
set -euo pipefail
cd "$(dirname "$0")/.."

if [[ ! -f .env ]]; then echo "[!] lab/.env 가 없습니다. .env.example 참고해 생성하세요."; exit 1; fi
set -a; . ./.env; set +a

MASTER=mariadb
SLAVE=mariadb-slave
DB="${MYSQL_DATABASE:-zabbix}"

m() { docker compose exec -T -e MYSQL_PWD="$MYSQL_ROOT_PASSWORD" "$MASTER" "$@"; }
s() { docker compose exec -T -e MYSQL_PWD="$MYSQL_ROOT_PASSWORD" "$SLAVE"  "$@"; }

echo "== 1/5 마스터에 복제 계정 생성 (멱등) =="
m mariadb -uroot -e "
  CREATE USER IF NOT EXISTS '${REPLICATION_USER}'@'%' IDENTIFIED BY '${REPLICATION_PASSWORD}';
  GRANT REPLICATION SLAVE ON *.* TO '${REPLICATION_USER}'@'%';
  FLUSH PRIVILEGES;"

echo "== 2/5 마스터 스냅샷 덤프 (--gtid) =="
m mariadb-dump -uroot --single-transaction --gtid --databases "$DB" > /tmp/kinx_master_dump.sql
echo "   덤프 크기: $(wc -c < /tmp/kinx_master_dump.sql) bytes"

echo "== 3/5 슬레이브에 스냅샷 적재 =="
s mariadb -uroot < /tmp/kinx_master_dump.sql
rm -f /tmp/kinx_master_dump.sql

echo "== 4/5 슬레이브 복제 연결 후 시작 (GTID slave_pos) =="
s mariadb -uroot -e "
  STOP SLAVE;
  RESET SLAVE;
  CHANGE MASTER TO
    MASTER_HOST='${MASTER}',
    MASTER_PORT=3306,
    MASTER_USER='${REPLICATION_USER}',
    MASTER_PASSWORD='${REPLICATION_PASSWORD}',
    MASTER_USE_GTID=slave_pos;
  START SLAVE;"

echo "== 5/5 복제 상태 확인 =="
sleep 2
status="$(s mariadb -uroot -e 'SHOW SLAVE STATUS\G')"
echo "$status" | grep -E 'Slave_IO_Running:|Slave_SQL_Running:|Seconds_Behind_Master:|Last_IO_Error:|Last_SQL_Error:' || true

io="$(echo "$status"  | grep 'Slave_IO_Running:'  | awk '{print $2}')"
sql="$(echo "$status" | grep 'Slave_SQL_Running:' | awk '{print $2}')"
if [[ "$io" == "Yes" && "$sql" == "Yes" ]]; then
  echo "[OK] 복제 정상 (IO=Yes, SQL=Yes)."
else
  echo "[!] 복제 비정상 (IO=$io, SQL=$sql). 위 Last_*_Error → BUILD_GUIDE §9."
  exit 1
fi
