#!/usr/bin/env bash
# TLS server scenario (host-orchestrated). Generates a self-signed CA + server
# cert (CN=depot) + client cert (CN=principal) on depot, propagates the CA +
# client material to principal, runs `pgbackrust server` as a daemon on depot
# listening on tls-server-port (8432), then drives stanza-create + check +
# full backup from principal over the TLS transport (repo-host-type=tls).
# Stops the daemon at end. Run from the integration/vagrant dir on the host.
set -uo pipefail
export PATH="/c/Program Files/Oracle/VirtualBox:$PATH"
export MSYS_NO_PATHCONV=1
PGV=${PGBR_PG_VERSION:-18}
PRI=/var/lib/postgresql/$PGV/principal
BIN=/usr/lib/postgresql/$PGV/bin
CD=/etc/pgbackrust/certs
fails=0

echo "=== TLS server: cert generation on depot (X.509 v3 + SAN, rustls compatible) ==="
# Three layers of shell make embedded newlines hellish; instead, write the cert
# gen script to stdin of a single `sudo bash` on depot via heredoc. Outer
# heredoc terminator is quoted ('REMOTE') so the host shell does no expansion;
# we just splice $CD literally where needed via the parent shell first.
timeout 90 vagrant ssh depot -c "sudo bash -s" <<REMOTE 2>&1 | grep -vE 'Connection to|^[\.+]+\*?$|^\.\.\.+|writing new private key' | tail -25
set -e
CD=$CD
install -d -o postgres -g postgres -m 0700 \$CD
cd \$CD
rm -f ca.key ca.crt ca.srl server.key server.crt server.csr client.key client.crt client.csr srv-ext.cnf cli-ext.cnf 2>/dev/null
openssl req -x509 -nodes -newkey rsa:2048 -days 365 -keyout ca.key -out ca.crt \\
  -subj /CN=pgbr-test-ca \\
  -addext basicConstraints=critical,CA:TRUE,pathlen:0 \\
  -addext keyUsage=critical,keyCertSign,cRLSign
cat > srv-ext.cnf <<'EXT_SRV'
subjectAltName=DNS:depot,IP:192.168.56.10
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
EXT_SRV
openssl req -new -nodes -newkey rsa:2048 -keyout server.key -out server.csr -subj /CN=depot
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days 365 -out server.crt -extfile srv-ext.cnf
cat > cli-ext.cnf <<'EXT_CLI'
subjectAltName=DNS:principal,IP:192.168.56.11
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=clientAuth
EXT_CLI
openssl req -new -nodes -newkey rsa:2048 -keyout client.key -out client.csr -subj /CN=principal
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days 365 -out client.crt -extfile cli-ext.cnf
chown postgres:postgres \$CD/ca.key \$CD/ca.crt \$CD/server.key \$CD/server.crt \$CD/client.key \$CD/client.crt
chmod 600 \$CD/*.key
echo --- final cert listing ---
ls -l \$CD/
REMOTE

echo "=== TLS server: copy CA + client cert/key to principal via host ==="
TMPD=$(mktemp -d)
# vagrant on Windows wants a Windows-style path for upload source; convert
# /c/Users/... -> C:/Users/...
TMPDW=$(printf '%s' "$TMPD" | sed -E 's@^/([a-zA-Z])/@\U\1:/@')
timeout 30 vagrant ssh depot -c "sudo cat $CD/ca.crt" > "$TMPD/ca.crt" 2>/dev/null
timeout 30 vagrant ssh depot -c "sudo cat $CD/client.crt" > "$TMPD/client.crt" 2>/dev/null
timeout 30 vagrant ssh depot -c "sudo cat $CD/client.key" > "$TMPD/client.key" 2>/dev/null
echo "  fetched: ca.crt=$(wc -c<$TMPD/ca.crt)B client.crt=$(wc -c<$TMPD/client.crt)B client.key=$(wc -c<$TMPD/client.key)B"
echo "  upload from: $TMPDW"
timeout 30 vagrant ssh principal -c "sudo install -d -o postgres -g postgres -m 0700 $CD" >/dev/null 2>&1
timeout 60 vagrant upload "$TMPDW/ca.crt" /tmp/ca.crt principal 2>&1 | grep -viE 'Uploading|complete|Connection to'
timeout 60 vagrant upload "$TMPDW/client.crt" /tmp/client.crt principal 2>&1 | grep -viE 'Uploading|complete|Connection to'
timeout 60 vagrant upload "$TMPDW/client.key" /tmp/client.key principal 2>&1 | grep -viE 'Uploading|complete|Connection to'
timeout 30 vagrant ssh principal -c "sudo bash -c 'mv /tmp/ca.crt /tmp/client.crt /tmp/client.key $CD/ && chown postgres:postgres $CD/ca.crt $CD/client.crt $CD/client.key && chmod 600 $CD/client.key && ls -l $CD/'" 2>&1 | grep -vE 'Connection to' | tail -5

echo "=== reset principal + write configs ==="
timeout 30 vagrant upload provision/reset-cluster.sh /tmp/reset-cluster.sh principal >/dev/null 2>&1
timeout 90 vagrant ssh principal -c "sudo PGBR_PG_VERSION=$PGV bash /tmp/reset-cluster.sh" >/dev/null 2>&1
# depot: server-side config + tls-server settings
timeout 30 vagrant ssh depot -c "
# Run rm via sudo bash -c so the glob is expanded by a privileged shell —
# 0750 perms on the parent dir prevent the calling user from listing it.
sudo bash -c 'rm -rf /var/lib/pgbackrust/* /var/lib/pgbackrust/.[!.]* /tmp/pgbackrust/*.stop 2>/dev/null; true'
sudo install -d -o postgres -g postgres -m 0750 /var/lib/pgbackrust /var/log/pgbackrust
sudo tee /etc/pgbackrust/pgbackrust.conf >/dev/null <<EOF
[global]
repo1-path=/var/lib/pgbackrust
log-level-console=info
log-level-file=detail
log-path=/var/log/pgbackrust
start-fast=y
tls-server-address=0.0.0.0
tls-server-cert-file=$CD/server.crt
tls-server-key-file=$CD/server.key
tls-server-ca-file=$CD/ca.crt
tls-server-auth=principal=demo

[demo]
pg1-host=principal
pg1-host-user=postgres
pg1-path=$PRI
pg1-port=5433
EOF
sudo chmod 0644 /etc/pgbackrust/pgbackrust.conf
" 2>&1 | grep -vE 'Connection to' | tail -3
# principal: client-side TLS config
timeout 30 vagrant ssh principal -c "
sudo tee /etc/pgbackrust/pgbackrust.conf >/dev/null <<EOF
[global]
repo1-host=depot
repo1-host-type=tls
repo1-host-ca-file=$CD/ca.crt
repo1-host-cert-file=$CD/client.crt
repo1-host-key-file=$CD/client.key
repo1-path=/var/lib/pgbackrust
log-level-console=info
log-level-file=detail
log-path=/var/log/pgbackrust

[demo]
pg1-path=$PRI
pg1-port=5433
EOF
sudo chmod 0644 /etc/pgbackrust/pgbackrust.conf
sudo install -d -o postgres -g postgres -m 0750 /var/log/pgbackrust
" 2>&1 | grep -vE 'Connection to' | tail -3

echo "=== start pgbackrust server daemon on depot (systemd transient unit) ==="
# Daemon lifecycle delegated to systemd as a transient unit. `systemctl stop`
# is reliable + idempotent + kills the full cgroup, so we never end up with
# a stale daemon holding stale certs across test cycles (which was the
# BadSignature root cause). We also verify the port is actually free before
# starting and after stopping, failing loudly if not.
timeout 30 vagrant ssh depot -c "sudo systemctl stop pgbr-tls-test.service 2>/dev/null; sudo systemctl reset-failed pgbr-tls-test.service 2>/dev/null; true" >/dev/null 2>&1
timeout 30 vagrant ssh depot -c "
  for _ in \$(seq 1 30); do
    sudo ss -ltnp 2>/dev/null | grep -q ':8432 ' || { echo 'port 8432 free'; exit 0; }
    sleep 0.5
  done
  echo 'ERROR: port 8432 still bound after stop' >&2
  sudo ss -ltnp | grep 8432 >&2
  exit 1
" 2>&1 | grep -vE 'Connection to'
# systemd-run with --unit creates a transient service unit running as postgres.
# StandardOutput=append:<file> captures logs to a known location on depot. The
# wait pattern below confirms the daemon is actually listening before tests run.
timeout 30 vagrant ssh depot -c "sudo systemd-run --unit=pgbr-tls-test --uid=postgres --gid=postgres \
  --property=StandardOutput=append:/tmp/pgbr-srv-host.log \
  --property=StandardError=append:/tmp/pgbr-srv-host.log \
  /usr/bin/pgbackrust server" 2>&1 | grep -vE 'Connection to'
timeout 30 vagrant ssh depot -c "
  for _ in \$(seq 1 30); do
    sudo ss -ltnp 2>/dev/null | grep -q ':8432 ' && break
    sleep 0.5
  done
  sudo ss -ltnp 2>/dev/null | grep ':8432' | head
  ps -eo pid,cmd | grep '[p]gbackrest server' | head
" 2>&1 | grep -vE 'Connection to' | head -5

echo "=== from principal: stanza-create over TLS ==="
out=$(timeout 60 vagrant ssh principal -c "sudo -u postgres pgbackrust --stanza=demo stanza-create 2>&1")
rc=$?
echo "  stanza-create exit=$rc"
printf '%s\n' "$out" | grep -vE 'Connection to' | tail -6
[ "$rc" = "0" ] || fails=$((fails+1))

echo "=== from principal: check over TLS ==="
out=$(timeout 120 vagrant ssh principal -c "sudo -u postgres pgbackrust --stanza=demo check 2>&1")
rc=$?
echo "  check exit=$rc"
printf '%s\n' "$out" | grep -vE 'Connection to' | tail -3
[ "$rc" = "0" ] || fails=$((fails+1))

echo "=== from principal: full backup over TLS ==="
timeout 30 vagrant ssh principal -c "sudo -u postgres /usr/lib/postgresql/$PGV/bin/psql -p5433 -c 'CREATE TABLE t(i int); INSERT INTO t SELECT generate_series(1,500)'" >/dev/null 2>&1
out=$(timeout 600 vagrant ssh principal -c "sudo -u postgres pgbackrust --stanza=demo --type=full backup 2>&1")
rc=$?
echo "  backup exit=$rc"
printf '%s\n' "$out" | grep -vE 'Connection to' | tail -5
[ "$rc" = "0" ] || fails=$((fails+1))

echo "=== stop daemon + cleanup ==="
# Stop the transient unit. systemctl tears down the full cgroup so no
# pgbackrust worker children survive. Verify the port is actually free.
timeout 30 vagrant ssh depot -c "
  sudo systemctl stop pgbr-tls-test.service 2>/dev/null || true
  sudo systemctl reset-failed pgbr-tls-test.service 2>/dev/null || true
  for _ in \$(seq 1 20); do
    sudo ss -ltnp 2>/dev/null | grep -q ':8432 ' || { echo 'port 8432 released'; exit 0; }
    sleep 0.5
  done
  echo 'ERROR: port 8432 still bound after systemctl stop' >&2
  sudo ss -ltnp | grep 8432 >&2
  exit 1
" 2>&1 | grep -vE 'Connection to'
rm -rf "$TMPD"

echo "TLS_SERVER_FAILS=$fails"
