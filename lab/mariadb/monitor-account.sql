-- monitor-account.sql — Zabbix agent2 MySQL 플러그인이 복제 상태·지연을 읽기 위한 읽기 전용 계정.
--
-- 실행 위치: master(kinx-mariadb)에서 실행한다. slave 는 read-only 이므로 직접 만들지 않고,
--            master 에 만든 계정이 복제를 통해 slave 로 전파되게 한다.
--   docker compose exec -T -e MYSQL_PWD="$MYSQL_ROOT_PASSWORD" mariadb mariadb -uroot < mariadb/monitor-account.sql
--
-- 근거(공식 문서):
--   - Zabbix "Monitor MySQL with Zabbix agent 2":
--       GRANT REPLICATION CLIENT, PROCESS, SHOW DATABASES, SHOW VIEW ON *.* TO 'zbx_monitor'@'%'
--     https://www.zabbix.com/documentation/current/en/manual/guides/monitor_mysql
--   - MariaDB "SHOW REPLICA STATUS": 10.5+ 에서 SHOW SLAVE STATUS 는 REPLICA MONITOR 권한 필요.
--     https://mariadb.com/kb/en/show-replica-status/
--     ※ Zabbix 가이드는 MySQL 기준이라 REPLICATION CLIENT 만 안내한다. MariaDB 에서는 이 권한만으로는
--       복제 지연(Seconds_Behind_Master)을 못 읽어 지연 감시가 조용히 실패한다. REPLICA MONITOR 를
--       반드시 추가한다 — 실환경(MariaDB) 적용 시의 핵심 주의점.
--
-- <PASSWORD> 를 실제 값으로 교체하고, 같은 값을 Zabbix 호스트 매크로 {$MYSQL.PASSWORD} 에 넣는다.
-- 이 파일에는 실제 비밀번호를 넣지 말 것(플레이스홀더 상태로만 커밋).

CREATE USER IF NOT EXISTS 'zbx_monitor'@'%' IDENTIFIED BY '<PASSWORD>';
GRANT REPLICATION CLIENT, PROCESS, SHOW DATABASES, SHOW VIEW, REPLICA MONITOR ON *.* TO 'zbx_monitor'@'%';
FLUSH PRIVILEGES;
