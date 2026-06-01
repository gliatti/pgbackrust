#!/usr/bin/env bash
# Capture strace on the archive-push process spawned by PG's archive_command,
# which is the actual context where the hang reproduces.
#
# Strategy: replace PG's archive_command with a strace wrapper that captures
# every fork. PG calls archive_command synchronously per WAL; strace -f catches
# the whole tree. Daemon also stays under strace via systemd-run.
set -uo pipefail
export PATH="/c/Program Files/Oracle/VirtualBox:$PATH"
export MSYS_NO_PATHCONV=1
PGV=${PGBR_PG_VERSION:-18}
PRI=/var/lib/postgresql/$PGV/principal
OUT_DIR="diag-out-pg"
mkdir -p "$OUT_DIR"

echo "=== stop any prior daemon ==="
timeout 30 vagrant ssh depot -c "
  sudo systemctl stop pgbr-tls-test.service 2>/dev/null || true
  sudo systemctl reset-failed pgbr-tls-test.service 2>/dev/null || true
  PIDS=\$(pgrep -f '/usr/bin/pgbackrust' 2>/dev/null)
  [ -n \"\$PIDS\" ] && sudo kill -9 \$PIDS 2>/dev/null
  sudo rm -f /tmp/strace-srv.out /tmp/pgbr-srv-host.log 2>/dev/null
" 2>&1 | grep -vE 'Connection to' >/dev/null

echo "=== start daemon under strace ==="
timeout 30 vagrant ssh depot -c "sudo systemd-run --unit=pgbr-tls-test --uid=postgres --gid=postgres \
  --property=StandardOutput=append:/tmp/pgbr-srv-host.log \
  --property=StandardError=append:/tmp/pgbr-srv-host.log \
  /usr/bin/strace -f -tt -y -s 256 -o /tmp/strace-srv.out /usr/bin/pgbackrust server" 2>&1 | grep -vE 'Connection to'
sleep 3

echo "=== install archive_command strace wrapper on principal ==="
timeout 60 vagrant ssh principal -c "
  sudo tee /usr/local/bin/pgbr-traced-push > /dev/null <<'WRAPPER'
#!/bin/bash
exec /usr/bin/strace -f -tt -y -s 256 -o /tmp/strace-archive-cmd.out \\
  /usr/bin/pgbackrust --stanza=demo archive-push \"\$1\"
WRAPPER
  sudo chmod 0755 /usr/local/bin/pgbr-traced-push
  sudo rm -f /tmp/strace-archive-cmd.out
  echo wrapper installed
" 2>&1 | grep -vE 'Connection to'

echo "=== reset principal cluster + wipe repo (so stanza matches new system-id) ==="
timeout 30 vagrant upload provision/reset-cluster.sh /tmp/reset-cluster.sh principal >/dev/null 2>&1
timeout 90 vagrant ssh principal -c "sudo PGBR_PG_VERSION=$PGV bash /tmp/reset-cluster.sh" 2>&1 | grep -vE 'Connection to' | tail -3
# Wipe depot's repo so stanza-create regenerates archive.info with the new system-id.
timeout 30 vagrant ssh depot -c "sudo bash -c 'rm -rf /var/lib/pgbackrust/* /var/lib/pgbackrust/.[!.]* /tmp/pgbackrust/*.stop 2>/dev/null; install -d -o postgres -g postgres -m 0750 /var/lib/pgbackrust /var/log/pgbackrust'" 2>&1 | grep -vE 'Connection to' | tail -3
# Write principal pgbackrust.conf (TLS client) — same as test-tls-server.sh
CD=/etc/pgbackrust/certs
timeout 30 vagrant ssh principal -c "
sudo tee /etc/pgbackrest/pgbackrest.conf >/dev/null <<EOF
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
sudo chmod 0644 /etc/pgbackrest/pgbackrest.conf
# Override PG's archive_command to use our traced wrapper.
sudo -u postgres /usr/lib/postgresql/$PGV/bin/psql -p5433 -c \"ALTER SYSTEM SET archive_command = '/usr/local/bin/pgbr-traced-push %p'\"
sudo -u postgres /usr/lib/postgresql/$PGV/bin/psql -p5433 -c \"SELECT pg_reload_conf()\"
sudo -u postgres /usr/lib/postgresql/$PGV/bin/psql -p5433 -tc \"SELECT setting FROM pg_settings WHERE name='archive_command'\"
" 2>&1 | grep -vE 'Connection to' | tail -8

echo "=== stanza-create ==="
timeout 60 vagrant ssh principal -c "sudo -u postgres pgbackrust --stanza=demo stanza-create 2>&1" 2>&1 | grep -vE 'Connection to' | tail -3

echo "=== TWO WAL switches to force first-success + second-fail pattern ==="
for i in 1 2 3; do
  timeout 30 vagrant ssh principal -c "sudo -u postgres /usr/lib/postgresql/$PGV/bin/psql -p5433 -tc \"SELECT pg_walfile_name(pg_switch_wal())\"" 2>&1 | grep -vE 'Connection to'
  sleep 5
done

echo "=== wait 30s more for archiver retries ==="
sleep 30

echo "=== pg_stat_archiver snapshot ==="
timeout 30 vagrant ssh principal -c "sudo -u postgres /usr/lib/postgresql/$PGV/bin/psql -p5433 -c 'SELECT * FROM pg_stat_archiver'" 2>&1 | grep -vE 'Connection to'

echo "=== alive pgbackrust processes on principal ==="
timeout 30 vagrant ssh principal -c "pgrep -af pgbackrust || echo none; sudo ls -la /tmp/strace-archive-cmd.out 2>&1" 2>&1 | grep -vE 'Connection to'

echo "=== copy artifacts ==="
timeout 30 vagrant ssh principal -c "sudo cat /tmp/strace-archive-cmd.out 2>/dev/null" > "$OUT_DIR/principal-strace-archive-cmd.out" 2>/dev/null
timeout 30 vagrant ssh depot -c "sudo cat /tmp/strace-srv.out 2>/dev/null" > "$OUT_DIR/depot-strace-srv.out" 2>/dev/null
timeout 30 vagrant ssh depot -c "sudo cat /tmp/pgbr-srv-host.log 2>/dev/null" > "$OUT_DIR/depot-srv.log" 2>/dev/null
timeout 30 vagrant ssh principal -c "sudo bash -c 'cat /var/log/pgbackrust/demo-archive-push*.log 2>/dev/null'" > "$OUT_DIR/principal-pgbackrust.log" 2>/dev/null
echo "  principal-strace-archive-cmd.out: $(wc -c < "$OUT_DIR/principal-strace-archive-cmd.out" 2>/dev/null) bytes"
echo "  depot-strace-srv.out: $(wc -c < "$OUT_DIR/depot-strace-srv.out" 2>/dev/null) bytes"
echo "  depot-srv.log: $(wc -c < "$OUT_DIR/depot-srv.log" 2>/dev/null) bytes"
echo "  principal-pgbackrust.log: $(wc -c < "$OUT_DIR/principal-pgbackrust.log" 2>/dev/null) bytes"

echo "=== cleanup ==="
timeout 30 vagrant ssh principal -c "
  PIDS=\$(pgrep -f pgbr-traced-push 2>/dev/null; pgrep -f '/usr/bin/pgbackrust' 2>/dev/null)
  [ -n \"\$PIDS\" ] && sudo kill -9 \$PIDS 2>/dev/null
  sudo -u postgres /usr/lib/postgresql/$PGV/bin/psql -p5433 -c \"ALTER SYSTEM RESET archive_command\" 2>/dev/null
  sudo -u postgres /usr/lib/postgresql/$PGV/bin/psql -p5433 -c \"SELECT pg_reload_conf()\" 2>/dev/null
  true
" 2>&1 | grep -vE 'Connection to' >/dev/null
timeout 30 vagrant ssh depot -c "sudo systemctl stop pgbr-tls-test.service 2>/dev/null; sudo systemctl reset-failed pgbr-tls-test.service 2>/dev/null; true" 2>&1 | grep -vE 'Connection to' >/dev/null
