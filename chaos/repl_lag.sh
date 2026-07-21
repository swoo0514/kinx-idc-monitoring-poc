#!/usr/bin/env bash
#
# repl_lag.sh — master 대량 쓰기로 slave 복제 지연을 유발한다.
# 핵심: Slave_SQL_Running 은 Yes(복제 스레드는 살아있음)를 유지하면서 Seconds_Behind_Master(lag)가
#       급등하는 상황 = "상태 플래그만 보면 정상인데 실제로는 데이터가 뒤처진 것" (메트릭 깊이 §2-④).
# 실행 위치: 관측 코어 VM의 lab/ 디렉토리(docker compose 접근 필요). 원리는 chaos/README.md.
#
set -uo pipefail
cd "$(dirname "$0")/.."
[[ -f .env ]] || { echo "[!] lab/.env 없음"; exit 1; }
set -a; . ./.env; set +a

ROUNDS="${1:-14}"   # 테이블 행 수를 2배씩 늘리는 횟수(대략 2^ROUNDS 행). 클수록 lag 커짐.

m()   { docker compose exec -T -e MYSQL_PWD="$MYSQL_ROOT_PASSWORD" mariadb       mariadb -uroot "$@"; }
s()   { docker compose exec -T -e MYSQL_PWD="$MYSQL_ROOT_PASSWORD" mariadb-slave mariadb -uroot -N "$@"; }
lag() { s -e "SHOW SLAVE STATUS\G" | grep -E "Slave_SQL_Running:|Seconds_Behind_Master:" | paste -sd' '; }

echo "[chaos] 복제 지연 재현 — master 에 대량 쓰기(${ROUNDS} 배가). slave 는 SQL 스레드가 살아있는 채로 뒤처진다."
echo "  [주입 전] $(lag)"

m -e "CREATE TABLE IF NOT EXISTS zabbix.lag_test(id BIGINT AUTO_INCREMENT PRIMARY KEY, a CHAR(200), b CHAR(200));"
m -e "INSERT INTO zabbix.lag_test(a,b) VALUES (MD5(RAND()), MD5(RAND()));"
for r in $(seq 1 "$ROUNDS"); do
  m -e "INSERT INTO zabbix.lag_test(a,b) SELECT MD5(RAND()), MD5(RAND()) FROM zabbix.lag_test LIMIT 500000;"
  echo "  라운드 $r: $(lag)"
done

echo "[chaos] 대량 쓰기 완료. slave 가 따라잡는 동안 lag 가 올라갔다 0 으로 회복하는지 관찰."
echo "  Slave_SQL_Running 은 계속 Yes 인데 Seconds_Behind_Master 만 큰 값 → '상태 플래그로는 못 잡는 지연'(§2-④)."
echo
echo "  [정리] 테스트 테이블 삭제(복제로 slave 도 삭제됨):"
echo "    docker compose exec -T -e MYSQL_PWD=\"\$MYSQL_ROOT_PASSWORD\" mariadb mariadb -uroot -e 'DROP TABLE IF EXISTS zabbix.lag_test'"
