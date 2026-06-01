#!/usr/bin/env bash
# Diagnostic capture for the archive-async hang against the TLS server.
# Captures: strace on the depot daemon (under systemd-run), strace on the
# principal archive-push call, daemon log, and (if the push hangs) gdb bts
# on every alive pgbackrust process on both VMs after a 30s wait.
#
# Output artifacts on the HOST under integration/vagrant/diag-out/.
set -uo pipefail
export PATH="/c/Program Files/Oracle/VirtualBox:$PATH"
export MSYS_NO_PATHCONV=1
PGV=${PGBR_PG_VERSION:-18}
PRI=/var/lib/postgresql/$PGV/principal
OUT_DIR="diag-out"
mkdir -p "$OUT_DIR"

echo "=== ensure principal cluster + stanza exist (idempotent) ==="
# Skip the full reset; rely on the previous test cycle's stanza-create. If
# something is wrong we'll see it in the strace.
timeout 30 vagrant ssh principal -c "sudo systemctl is-active postgresql@${PGV}-principal" 2>&1 | grep -vE 'Connection to' | head -1

echo "=== stop any prior daemon ==="
timeout 30 vagrant ssh depot -c "
  sudo systemctl stop pgbr-tls-test.service 2>/dev/null || true
  sudo systemctl reset-failed pgbr-tls-test.service 2>/dev/null || true
  PIDS=\$(pgrep -f '/usr/bin/pgbackrust' 2>/dev/null)
  [ -n \"\$PIDS\" ] && sudo kill -9 \$PIDS 2>/dev/null
  for _ in \$(seq 1 20); do
    sudo ss -ltnp 2>/dev/null | grep -q ':8432 ' || break
    sleep 0.5
  done
  sudo rm -f /tmp/strace-srv.out /tmp/pgbr-srv-host.log 2>/dev/null
  echo 'depot clean'
" 2>&1 | grep -vE 'Connection to'

echo "=== install strace + gdb on both VMs (idempotent) ==="
for vm in depot principal; do
  timeout 60 vagrant ssh "$vm" -c "
    dpkg -s strace >/dev/null 2>&1 || sudo apt-get install -y strace >/dev/null 2>&1
    dpkg -s gdb    >/dev/null 2>&1 || sudo apt-get install -y gdb    >/dev/null 2>&1
    echo \"$vm: strace=\$(command -v strace) gdb=\$(command -v gdb)\"
  " 2>&1 | grep -vE 'Connection to'
done

echo "=== start daemon under strace (transient unit) ==="
# systemd-run wraps strace which wraps pgbackrust. -f follows forks/clones,
# -tt absolute timestamps, -y decodes fds → paths/sockets, -s 256 captures
# enough of each buffer to read protocol traffic, -e trace=!nanosleep,clock_*
# trims noise.
timeout 30 vagrant ssh depot -c "sudo systemd-run --unit=pgbr-tls-test --uid=postgres --gid=postgres \
  --property=StandardOutput=append:/tmp/pgbr-srv-host.log \
  --property=StandardError=append:/tmp/pgbr-srv-host.log \
  /usr/bin/strace -f -tt -y -s 256 -o /tmp/strace-srv.out /usr/bin/pgbackrust server" 2>&1 | grep -vE 'Connection to'
sleep 3
timeout 30 vagrant ssh depot -c "sudo ss -ltnp 2>/dev/null | grep ':8432' | head; pgrep -af pgbackrust" 2>&1 | grep -vE 'Connection to' | head -10

echo "=== resolve a WAL to push ==="
WAL_PATH=$(timeout 15 vagrant ssh principal -c "sudo bash -c 'ls -1 ${PRI}/pg_wal/0000* 2>/dev/null | grep -v partial | head -1'" 2>&1 | grep -vE 'Connection to' | tr -d '\r' | tail -1)
echo "  WAL_PATH=$WAL_PATH"
if [ -z "$WAL_PATH" ]; then
  echo "FATAL: no WAL found on principal; aborting"; exit 1
fi

echo "=== run archive-push under strace from principal (timeout 30s) ==="
timeout 45 vagrant ssh principal -c "
  sudo rm -f /tmp/strace-push.out /tmp/push.log 2>/dev/null
  sudo -u postgres bash -c '
    set +e
    timeout 30 /usr/bin/strace -f -tt -y -s 256 -o /tmp/strace-push.out \
      /usr/bin/pgbackrust --stanza=demo --archive-async=y --log-level-console=detail \
      archive-push ${WAL_PATH} > /tmp/push.log 2>&1
    echo \"exit=\$?\"
    sleep 1
    echo --- pgrep snapshot ---
    pgrep -af pgbackrust || echo none
  '
" 2>&1 | grep -vE 'Connection to' | head -20

echo "=== gdb bt on any hung pgbackrust (depot then principal) ==="
for vm in depot principal; do
  timeout 60 vagrant ssh "$vm" -c "
    PIDS=\$(pgrep -f '/usr/bin/pgbackrust' 2>/dev/null)
    if [ -z \"\$PIDS\" ]; then
      echo \"$vm: no live pgbackrust processes\"
    else
      for PID in \$PIDS; do
        echo --- $vm PID \$PID ---
        sudo cat /proc/\$PID/cmdline | tr '\0' ' '; echo
        sudo cat /proc/\$PID/status 2>/dev/null | grep -E 'State:|Threads:'
        sudo gdb -batch -p \$PID -ex 'set pagination off' -ex 'thread apply all bt' 2>&1 | tail -80 || true
      done
    fi
  " 2>&1 | grep -vE 'Connection to' > "$OUT_DIR/gdb-$vm.txt"
  echo "  $vm: $(wc -l < "$OUT_DIR/gdb-$vm.txt") lines -> $OUT_DIR/gdb-$vm.txt"
done

echo "=== copy strace + log artifacts to host ==="
TMPD=$(mktemp -d)
TMPDW=$(printf '%s' "$TMPD" | sed -E 's@^/([a-zA-Z])/@\U\1:/@')
for f in strace-srv.out pgbr-srv-host.log; do
  timeout 30 vagrant ssh depot -c "sudo cat /tmp/$f 2>/dev/null" > "$OUT_DIR/depot-$f" 2>/dev/null
  echo "  depot $f: $(wc -c < "$OUT_DIR/depot-$f" 2>/dev/null || echo 0) bytes"
done
for f in strace-push.out push.log; do
  timeout 30 vagrant ssh principal -c "sudo cat /tmp/$f 2>/dev/null" > "$OUT_DIR/principal-$f" 2>/dev/null
  echo "  principal $f: $(wc -c < "$OUT_DIR/principal-$f" 2>/dev/null || echo 0) bytes"
done

echo "=== final daemon stop ==="
timeout 30 vagrant ssh depot -c "sudo systemctl stop pgbr-tls-test.service 2>/dev/null; sudo systemctl reset-failed pgbr-tls-test.service 2>/dev/null; true" 2>&1 | grep -vE 'Connection to'
rm -rf "$TMPD"

echo "=== SUMMARY ==="
ls -la "$OUT_DIR/"
echo "--- principal push.log (last 30) ---"
tail -30 "$OUT_DIR/principal-push.log" 2>/dev/null
echo "--- principal strace tail (last 60) ---"
tail -60 "$OUT_DIR/principal-strace-push.out" 2>/dev/null
echo "--- depot strace tail (last 60) ---"
tail -60 "$OUT_DIR/depot-strace-srv.out" 2>/dev/null
