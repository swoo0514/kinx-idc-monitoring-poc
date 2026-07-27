#!/usr/bin/env bash
# core VM(lab/)에서 실행. 데모 C 복제 대상 DB·계정 생성 + GTID 스냅샷 덤프. 절차는 REPL_VM_GUIDE.md.
set -euo pipefail
cd "$(dirname "$0")/.."
[[ -f .env ]] || { echo "[!] lab/.env 없음"; exit 1; }
set -a; . ./.env; set +a

DB="${DEMO_REPL_DB:-demo_repl}"
DUMP="/tmp/kinx_demo_dump.sql"
m() { docker compose exec -T -e MYSQL_PWD="$MYSQL_ROOT_PASSWORD" mariadb "$@"; }

echo "== 0/3 master 3306 노출 확인 =="
if ! docker compose port mariadb 3306 >/dev/null 2>&1; then
  echo "[!] master 3306 이 publish 안 됨. .env 에 MASTER_BIND_IP=<사설IP> 설정 후 'docker compose up -d mariadb' 재적용."
  echo "    (공인 IP 로 노출 금지 — REPL_VM_GUIDE.md)"; exit 1
fi
echo "   노출 바인딩: $(docker compose port mariadb 3306)"

echo "== 1/3 데모 DB + 복제/쓰기 계정 생성 (멱등) =="
m mariadb -uroot -e "
  CREATE DATABASE IF NOT EXISTS \`${DB}\`;
  CREATE TABLE IF NOT EXISTS \`${DB}\`.load_gen(
    id BIGINT AUTO_INCREMENT PRIMARY KEY, ts DATETIME DEFAULT NOW(), a CHAR(200), b CHAR(200));
  CREATE USER IF NOT EXISTS '${REPLICATION_USER}'@'%' IDENTIFIED BY '${REPLICATION_PASSWORD}';
  GRANT REPLICATION SLAVE ON *.* TO '${REPLICATION_USER}'@'%';
  CREATE USER IF NOT EXISTS '${DEMO_WRITER_USER}'@'%' IDENTIFIED BY '${DEMO_WRITER_PASSWORD}';
  GRANT INSERT,SELECT,DELETE ON \`${DB}\`.* TO '${DEMO_WRITER_USER}'@'%';
  FLUSH PRIVILEGES;"

echo "== 2/3 GTID 스냅샷 덤프 → ${DUMP} =="
m mariadb-dump -uroot --single-transaction --gtid --master-data=2 --add-drop-database \
  --databases "$DB" > "$DUMP"
GTID="$(grep -oE "gtid_slave_pos='[0-9-]+'" "$DUMP" | grep -oE "[0-9]+-[0-9]+-[0-9]+" | head -1)"
echo "   덤프 $(wc -c < "$DUMP") bytes / GTID ${GTID:-추출실패}"
[[ -n "$GTID" ]] || { echo "[!] GTID 추출 실패"; exit 1; }

echo "== 3/3 다음 단계 =="
echo "   이 덤프를 슬레이브 VM 으로 복사:"
echo "     scp ${DUMP} node2:/tmp/"
echo "   그 뒤 VM 에서 setup-slave-vm.sh 실행 (REPL_VM_GUIDE.md §3)."
