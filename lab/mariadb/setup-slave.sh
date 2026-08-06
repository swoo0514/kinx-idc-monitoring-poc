#!/usr/bin/env bash
# 절차·근거·트러블슈팅: docs/01-build/01-observability-core.md §9
set -euo pipefail
cd "$(dirname "$0")/.."

if [[ ! -f .env ]]; then echo "[!] lab/.env 가 없습니다. .env.example 참고해 생성하세요."; exit 1; fi
set -a; . ./.env; set +a

# 인자로 master/slave 컨테이너·DB 지정 가능(고객사별 재사용). 없으면 기본 랩 DB.
MASTER="${1:-mariadb}"
SLAVE="${2:-mariadb-slave}"
DB="${3:-${MYSQL_DATABASE:-zabbix}}"

m() { docker compose exec -T -e MYSQL_PWD="$MYSQL_ROOT_PASSWORD" "$MASTER" "$@"; }
s() { docker compose exec -T -e MYSQL_PWD="$MYSQL_ROOT_PASSWORD" "$SLAVE"  "$@"; }

echo "== 1/5 마스터에 대상 DB + 복제 계정 생성 (멱등) =="
m mariadb -uroot -e "
  CREATE DATABASE IF NOT EXISTS \`${DB}\`;
  CREATE USER IF NOT EXISTS '${REPLICATION_USER}'@'%' IDENTIFIED BY '${REPLICATION_PASSWORD}';
  GRANT REPLICATION SLAVE ON *.* TO '${REPLICATION_USER}'@'%';
  FLUSH PRIVILEGES;"

echo "== 2/5 마스터 스냅샷 덤프 (--gtid --master-data) =="
# --master-data=2 : 스냅샷 시점의 GTID 위치를 덤프에 (주석으로) 기록 — --gtid 단독으론 미포함.
# --add-drop-database : 재실행(멱등) 시 슬레이브 DB를 깨끗이 재적재(중복 INSERT 방지).
m mariadb-dump -uroot --single-transaction --gtid --master-data=2 --add-drop-database --databases "$DB" > /tmp/kinx_master_dump.sql
GTID="$(grep -oE "gtid_slave_pos='[0-9-]+'" /tmp/kinx_master_dump.sql | grep -oE "[0-9]+-[0-9]+-[0-9]+" | head -1)"
echo "   덤프 크기: $(wc -c < /tmp/kinx_master_dump.sql) bytes / 스냅샷 GTID: ${GTID:-추출실패}"
if [[ -z "$GTID" ]]; then echo "[!] 덤프에서 GTID 추출 실패 — 덤프 옵션 확인"; exit 1; fi

echo "== 3/5 슬레이브에 스냅샷 적재 =="
s mariadb -uroot < /tmp/kinx_master_dump.sql
rm -f /tmp/kinx_master_dump.sql

echo "== 4/5 슬레이브 복제 연결 후 시작 (GTID slave_pos, 스냅샷 위치 명시) =="
# 핵심: 스냅샷 시점 GTID(${GTID})를 gtid_slave_pos 로 명시 설정해야 그 지점부터 복제.
# 이 SET 이 없으면 slave 가 0-0-0 부터 재생 → 스냅샷에 이미 있는 행 재삽입 → Duplicate 오류.
s mariadb -uroot -e "
  STOP SLAVE;
  RESET SLAVE;
  SET GLOBAL gtid_slave_pos='${GTID}';
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
