#!/usr/bin/env bash
# 인증서 만료 사슬 — "포트는 열려 있는데 사용자는 못 붙는" 사건을 만든다.
# 쓰는 법과 배경은 chaos/README.md "인증서 만료 사슬" 참고.
set -euo pipefail

DOMAIN=${DOMAIN:-$(hostname -f)}
PORT=${PORT:-8443}
DIR=${DIR:-/etc/lab-webapp}
EXPIRED_FROM=${EXPIRED_FROM:-20250101000000Z}
EXPIRED_TO=${EXPIRED_TO:-20250401000000Z}

need_root() { [ "$(id -u)" -eq 0 ] || { echo "root 로 실행하라"; exit 1; }; }
need_root

echo "== 대상 ${DOMAIN}:${PORT} · 인증서 유효기간 ${EXPIRED_FROM} ~ ${EXPIRED_TO}"

install -d -m 755 "$DIR" "$DIR/ca"
cd "$DIR"

# ── 내부 CA. 발급 시각을 과거로 박으려면 openssl ca 가 필요하다 — OpenSSL 3.0 의
#    `openssl req -x509` 에는 not_before/not_after 옵션이 없다(3.5 에서 추가).
if [ ! -f ca/ca.crt ]; then
  openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
    -keyout ca/ca.key -out ca/ca.crt -subj "/CN=lab-internal-ca" 2>/dev/null
  : > ca/index.txt
  echo 1000 > ca/serial
  cat > ca/ca.cnf <<CNF
[ ca ]
default_ca = lab
[ lab ]
dir = $DIR/ca
database = \$dir/index.txt
serial = \$dir/serial
new_certs_dir = \$dir
certificate = \$dir/ca.crt
private_key = \$dir/ca.key
default_md = sha256
policy = anything
email_in_dn = no
unique_subject = no
[ anything ]
commonName = optional
CNF
fi

# ── 서버 인증서를 **이미 만료된 기간**으로 발급한다
openssl req -newkey rsa:2048 -nodes -keyout server.key -out server.csr \
  -subj "/CN=${DOMAIN}" 2>/dev/null
openssl ca -config ca/ca.cnf -batch -notext -md sha256 \
  -startdate "$EXPIRED_FROM" -enddate "$EXPIRED_TO" \
  -in server.csr -out server.crt >/dev/null 2>&1
chmod 640 server.key
openssl x509 -in server.crt -noout -subject -dates

# ── CA 를 신뢰시킨다. 이게 없으면 실패 사유가 "만료"가 아니라 "발급자 불명"으로 나와
#    사건의 성격이 달라진다.
cp -f ca/ca.crt /etc/pki/ca-trust/source/anchors/lab-internal-ca.crt
update-ca-trust extract

# ── 서비스. 로그가 저널로 가야 Alloy 가 Loki 로 옮긴다.
cat > "$DIR/serve.py" <<'PY'
import http.server, os, ssl, sys

port = int(os.environ.get("PORT", "8443"))
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain("/etc/lab-webapp/server.crt", "/etc/lab-webapp/server.key")


class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", "3")
        self.end_headers()
        self.wfile.write(b"ok\n")

    def do_HEAD(self):
        self.send_response(200)
        self.end_headers()

    def log_message(self, fmt, *a):
        sys.stderr.write("lab-webapp %s\n" % (fmt % a))


srv = http.server.HTTPServer(("0.0.0.0", port), H)
srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
sys.stderr.write("lab-webapp listening on %d\n" % port)
srv.serve_forever()
PY

cat > /etc/systemd/system/lab-webapp.service <<UNIT
[Unit]
Description=lab webapp (만료 인증서로 HTTPS 제공)
[Service]
Environment=PORT=${PORT}
ExecStart=/usr/bin/python3 ${DIR}/serve.py
Restart=always
[Install]
WantedBy=multi-user.target
UNIT

# ── 사용자 쪽. 접속이 실패하는 것을 저널에 남긴다.
cat > /etc/systemd/system/lab-webapp-client.service <<UNIT
[Unit]
Description=lab webapp 접속 확인 (사용자 시점)
[Service]
ExecStart=/bin/bash -c 'while true; do \
  out=\$(curl -sS --max-time 5 https://${DOMAIN}:${PORT}/ 2>&1) \
    && echo "lab-webapp-client OK" \
    || echo "lab-webapp-client FAILED: \$out"; \
  sleep 20; done'
Restart=always
[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable --now lab-webapp.service lab-webapp-client.service >/dev/null
sleep 3

echo
echo "== 서비스 상태"
systemctl is-active lab-webapp.service lab-webapp-client.service

echo
echo "== 사용자 시점 (실패해야 정상)"
curl -sS --max-time 5 "https://${DOMAIN}:${PORT}/" 2>&1 | head -2 || true

echo
echo "== 포트는 열려 있다 (Zabbix https 체크가 초록으로 남는 이유)"
echo -n "  net.tcp.service[https,,${PORT}] 상당: "
curl -ksS -o /dev/null -I --max-time 5 "https://${DOMAIN}:${PORT}/" && echo "통과(1)" || echo "실패(0)"
