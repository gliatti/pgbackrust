#!/usr/bin/env bash
# End-to-end validation of the Rust pgbackrest binary against the live
# PostgreSQL clusters provisioned in the Vagrant/VirtualBox topology
# (principal / secondaire / depot). Run AFTER `vagrant up` (and after
# ../build-binary.sh has produced the binary). Drives the KB scenarios over
# `vagrant ssh`.
#
#   cd integration/vagrant && PATH="/c/Program Files/Oracle/VirtualBox:$PATH" ./run-validation.sh
set -uo pipefail

PGV="${PGBR_PG_VERSION:-18}"
PASS=0
FAIL=0

pass() { printf '  \033[32mPASS\033[0m %s\n' "$*"; PASS=$((PASS+1)); }
fail() { printf '  \033[31mFAIL\033[0m %s\n' "$*" >&2; FAIL=$((FAIL+1)); }
hd()   { printf '\n=== %s ===\n' "$*"; }

# Run a command on a node. The command is base64-encoded on the host and decoded
# on the VM, then piped to a login shell — so SQL/config containing single quotes,
# double quotes, $, or newlines passes through intact (a bash -lc '...' wrapper
# would otherwise mangle embedded single quotes, e.g. pg_create_restore_point('x')).
# The remote command's exit status propagates as the pipeline's status.
on() { local n="$1"; shift; local b64; b64=$(printf '%s' "$*" | base64 | tr -d '\n'); vagrant ssh "$n" -c "echo $b64 | base64 -d | sudo bash -l" 2>&1; }
# As `on` but as the postgres user; `-H` sets HOME so ssh (~/.ssh/config) and
# pgbackrest find their per-user state.
pg() { local n="$1"; shift; local b64; b64=$(printf '%s' "$*" | base64 | tr -d '\n'); vagrant ssh "$n" -c "echo $b64 | base64 -d | sudo -u postgres -H bash -l" 2>&1; }
# psql on a node/port as postgres.
psql_on() { local n="$1" port="$2"; shift 2; pg "$n" "/usr/lib/postgresql/$PGV/bin/psql -p $port -X -A -t -c \"$*\""; }

assert_contains() {
  local out="$1" needle="$2" what="$3"
  if printf '%s' "$out" | grep -qF -- "$needle"; then pass "$what"; else printf '%s\n' "$out" | tail -5 >&2; fail "$what (missing '$needle')"; fi
}

# Run a pgbackrest (or any) command as postgres on a node; PASS on exit 0.
# Usage: ok "<description>" <node> "<command...>"
ok() {
  local desc="$1" node="$2"; shift 2
  local out rc
  # Hard 600s cap per command so a hang (e.g. a stuck pg_backup_stop waiting on
  # a never-archived WAL) fails the step instead of blocking the whole run.
  out=$(pg "$node" "timeout 600 $*"); rc=$?
  if [ "$rc" -eq 0 ]; then pass "$desc"; else printf '%s\n' "$out" | grep -v 'Connection to' | tail -5 >&2; fail "$desc (exit $rc)"; fi
}

PRI=/var/lib/postgresql/$PGV/principal
BIN=/usr/lib/postgresql/$PGV/bin

# Reset the principal cluster + repository to a clean baseline and create a fresh
# stanza, so each scenario is self-contained and re-runnable regardless of the
# state a prior scenario left behind. Asserts the reset and stanza-create.
# Re-initdb the principal cluster to a clean, running PG18 primary (archiving on).
reset_principal_cluster() {
  vagrant upload provision/reset-cluster.sh /tmp/reset-cluster.sh principal >/dev/null 2>&1
  local reset_out reset_rc
  reset_out=$(on principal "PGBR_PG_VERSION=$PGV bash /tmp/reset-cluster.sh"); reset_rc=$?
  if [ "$reset_rc" -eq 0 ]; then pass "reset principal cluster (clean initdb + start)"
  else printf '%s\n' "$reset_out" | tail -6 >&2; fail "reset principal cluster (exit $reset_rc)"; fi
}

# Reset cluster + local repo, write a [global] whose extra lines are $1 (e.g.
# cipher / compress / retention knobs), then stanza-create. $1 may be multi-line.
prepare_principal_cfg() {
  local extra="$1"
  reset_principal_cluster
  on principal "rm -rf /var/lib/pgbackrest/* 2>/dev/null; true"
  on principal "cat > /etc/pgbackrest/pgbackrest.conf <<EOF
[global]
repo1-path=/var/lib/pgbackrest
$extra
log-level-console=info
log-path=/var/log/pgbackrest
start-fast=y
[demo]
pg1-path=$PRI
pg1-port=5433
EOF
chmod 0644 /etc/pgbackrest/pgbackrest.conf
install -d -o postgres -g postgres -m 0750 /var/lib/pgbackrest /var/log/pgbackrest"

  ok "stanza-create" principal "pgbackrest --stanza=demo stanza-create"
}

# The KB Exemple 1 minimal config (local repo, retention-full=2).
prepare_principal() { prepare_principal_cfg "repo1-retention-full=2"; }

############################################################################
hd "Sanity: binary runs on each node"
for node in depot principal secondaire; do
  out=$(pg "$node" "pgbackrest version")
  assert_contains "$out" "pgBackRest" "$node: pgbackrest version"
done

############################################################################
hd "Scenario 1 — local minimal backup on principal (KB Exemple 1)"
# Clean baseline (cluster + repo + fresh stanza), then the live WAL round-trip.
prepare_principal
ok "check (live WAL archive round-trip)" principal "pgbackrest --stanza=demo check"

# Seed data BEFORE the full backup so the restore can prove it survived.
psql_on principal 5433 "CREATE TABLE IF NOT EXISTS t(i int)" >/dev/null
psql_on principal 5433 "INSERT INTO t SELECT generate_series(1,1000)" >/dev/null
psql_on principal 5433 "SELECT pg_switch_wal()" >/dev/null

ok "full backup" principal "pgbackrest --stanza=demo --type=full backup"

# More WAL + an incremental backup.
psql_on principal 5433 "INSERT INTO t SELECT generate_series(1,500)" >/dev/null
psql_on principal 5433 "SELECT pg_switch_wal()" >/dev/null
ok "incr backup" principal "pgbackrest --stanza=demo --type=incr backup"

# info shows both.
out=$(pg principal "pgbackrest --stanza=demo info")
assert_contains "$out" "status: ok" "info status ok"
assert_contains "$out" "full backup" "info shows full"
assert_contains "$out" "incr backup" "info shows incr"

# Restore (KB style: options before the command): stop, --delta restore, start,
# verify the rows survived (1000 + 500 = 1500).
pg principal "$BIN/pg_ctl -D $PRI -w stop" >/dev/null 2>&1
ok "delta restore (--delta restore, options before command)" principal "pgbackrest --stanza=demo --delta restore"
# `-w` waits for the cluster to finish recovery and accept connections; a
# recovery failure makes pg_ctl return non-zero after its timeout.
pg principal "$BIN/pg_ctl -D $PRI -l $PRI/server.log -w -t 60 start" >/dev/null 2>&1
sleep 4
rows=$(psql_on principal 5433 "SELECT count(*) FROM t")
if printf '%s' "$rows" | grep -qF -- "1500"; then
  pass "restored data (1500 rows)"
else
  # Surface the recovery log so a failure is diagnosable from the run output.
  pg principal "tail -25 $PRI/server.log" 2>&1 | grep -vE 'Connection to' >&2
  fail "restored data (1500 rows) (got: $(printf '%s' "$rows" | tr -d '\n'))"
fi

############################################################################
hd "Scenario 2 — PITR to a named restore point (pgstef PITR walkthrough)"
# Self-contained: fresh promoted primary (archiving active), full backup, then a
# named restore point as the PITR target with "future" rows after it that must
# NOT survive a point-in-time restore to that target.
# The base full backup MUST be taken BEFORE the recovery target so recovery can
# replay forward to it. (Taking another backup AFTER the restore point would make
# it the "latest" backup that --type=name restores, and recovery would start
# after the target and never reach it — a classic PITR ordering mistake.)
prepare_principal
ok "PITR full backup (pre-target base)" principal "pgbackrest --stanza=demo --type=full backup"

# Data AFTER the base backup: 1000 rows committed before the restore point (the
# PITR target), then 500 "future" rows that must NOT survive the restore.
psql_on principal 5433 "CREATE TABLE t(i int)" >/dev/null
psql_on principal 5433 "INSERT INTO t SELECT generate_series(1,1000)" >/dev/null
psql_on principal 5433 "SELECT pg_create_restore_point('pitr_target')" >/dev/null
psql_on principal 5433 "INSERT INTO t SELECT generate_series(1001,1500)" >/dev/null
before=$(psql_on principal 5433 "SELECT count(*) FROM t")  # 1500

# Complete + archive the segment holding the restore point WITHOUT a new backup,
# so recovery can fetch it: capture the current segment, force a switch, then poll
# the repo until that segment lands (deterministic; no async-archiver race).
target_seg=$(psql_on principal 5433 "SELECT pg_walfile_name(pg_current_wal_lsn())" | grep -oE '[0-9A-F]{24}' | head -1)
psql_on principal 5433 "SELECT pg_switch_wal()" >/dev/null
# Poll directly via pg (not ok: ok prepends `timeout 600`, which cannot wrap a
# `for` loop). The loop is self-bounded to ~60s.
poll_rc=0
pg principal "for i in \$(seq 1 60); do ls /var/lib/pgbackrest/archive/demo/18-1/ 2>/dev/null | grep -q \"^${target_seg}\" && exit 0; sleep 1; done; exit 1" >/dev/null 2>&1 || poll_rc=$?
if [ "$poll_rc" -eq 0 ]; then pass "restore-point WAL ($target_seg) archived to repo"
else fail "restore-point WAL ($target_seg) not archived within 60s"; fi

pg principal "$BIN/pg_ctl -D $PRI -w stop" >/dev/null 2>&1
ok "PITR restore (--type=name --target=pitr_target --target-action=promote)" principal \
  "pgbackrest --stanza=demo --delta --type=name --target=pitr_target --target-action=promote restore"
pg principal "$BIN/pg_ctl -D $PRI -l $PRI/server.log -w -t 120 start" >/dev/null 2>&1
sleep 5
after=$(psql_on principal 5433 "SELECT count(*) FROM t" | grep -oE '^[0-9]+$' | head -1)
future=$(psql_on principal 5433 "SELECT count(*) FROM t WHERE i>1000" | grep -oE '^[0-9]+$' | head -1)
# Recovery stops at the restore point: the 1000 base rows survive, the 500
# "future" rows do not — expect 1000 rows total and 0 future rows.
if [ "$after" = "1000" ] && [ "$future" = "0" ]; then
  pass "PITR recovered to named target (1000 base rows kept, future rows dropped)"
else
  pg principal "tail -30 $PRI/server.log" 2>&1 | grep -vE 'Connection to' >&2
  fail "PITR to named target (before=$before after=$after future=$future, want after=1000 future=0)"
fi

############################################################################
hd "Scenario 3 — backup to a dedicated remote repository over SSH (depot)"
# pgBackRest topology: the backup runs ON the PG host (principal) and writes the
# repository to a dedicated host (depot) over SSH (repo1-host=depot). The DB
# connection is local; only repository I/O + archive-push go over the SSH worker.
reset_principal_cluster
on depot "rm -rf /var/lib/pgbackrest/* 2>/dev/null; install -d -o postgres -g postgres -m 0750 /var/lib/pgbackrest /var/log/pgbackrest"
# Also clear principal's LOCAL repo so the placement check reflects only this
# scenario (the remote backup must put NOTHING in principal's local repo).
on principal "rm -rf /var/lib/pgbackrest/* 2>/dev/null; install -d -o postgres -g postgres -m 0750 /var/lib/pgbackrest /var/log/pgbackrest"
on principal "cat > /etc/pgbackrest/pgbackrest.conf <<EOF
[global]
repo1-host=depot
repo1-host-user=postgres
repo1-path=/var/lib/pgbackrest
repo1-retention-full=2
log-level-console=info
log-path=/var/log/pgbackrest
start-fast=y
[demo]
pg1-path=$PRI
pg1-port=5433
EOF
chmod 0644 /etc/pgbackrest/pgbackrest.conf"

ok "stanza-create (remote repo on depot)" principal "pgbackrest --stanza=demo stanza-create"
ok "check (remote repo write + WAL archive over SSH)" principal "pgbackrest --stanza=demo check"

psql_on principal 5433 "CREATE TABLE t(i int)" >/dev/null
psql_on principal 5433 "INSERT INTO t SELECT generate_series(1,1500)" >/dev/null
psql_on principal 5433 "SELECT pg_switch_wal()" >/dev/null
ok "full backup (files pushed to depot over SSH)" principal "pgbackrest --stanza=demo --type=full backup"

# The repository must live on depot, not principal.
dep_has=$(on depot "ls /var/lib/pgbackrest/backup/demo/ 2>/dev/null | grep -c 'F\$'")
pri_has=$(on principal "ls /var/lib/pgbackrest/backup/demo/ 2>/dev/null | grep -c 'F\$' || true")
if printf '%s' "$dep_has" | grep -qE '[1-9]' && printf '%s' "${pri_has:-0}" | grep -qxE '0'; then
  pass "backup stored on depot (not principal)"
else
  fail "backup placement (depot=$dep_has principal=$pri_has, want depot>=1 principal=0)"
fi

out=$(pg principal "pgbackrest --stanza=demo info")
assert_contains "$out" "status: ok" "remote-repo info status ok"
assert_contains "$out" "full backup" "remote-repo info shows full"

# Restore reads the backup back FROM depot over SSH into principal's PGDATA.
pg principal "$BIN/pg_ctl -D $PRI -w stop" >/dev/null 2>&1
ok "delta restore (reads remote repo on depot over SSH)" principal "pgbackrest --stanza=demo --delta restore"
pg principal "$BIN/pg_ctl -D $PRI -l $PRI/server.log -w -t 90 start" >/dev/null 2>&1
sleep 4
rows=$(psql_on principal 5433 "SELECT count(*) FROM t" | grep -oE '^[0-9]+$' | head -1)
if [ "$rows" = "1500" ]; then pass "remote-repo restored data (1500 rows)"
else pg principal "tail -20 $PRI/server.log" 2>&1 | grep -vE 'Connection to' >&2; fail "remote-repo restored data (got: $rows)"; fi

############################################################################
hd "Scenario 4 — encrypted repository (repo1-cipher-type=aes-256-cbc)"
prepare_principal_cfg "repo1-retention-full=2
repo1-cipher-type=aes-256-cbc
repo1-cipher-pass=demo-cipher-passphrase"
ok "check (encrypted repo)" principal "pgbackrest --stanza=demo check"
psql_on principal 5433 "CREATE TABLE t(i int)" >/dev/null
psql_on principal 5433 "INSERT INTO t SELECT generate_series(1,1500)" >/dev/null
psql_on principal 5433 "SELECT pg_switch_wal()" >/dev/null
ok "full backup (encrypted)" principal "pgbackrest --stanza=demo --type=full backup"
# Stored repo files must be OpenSSL-encrypted (the "Salted__" magic), not plaintext.
hdr=$(on principal "f=\$(find /var/lib/pgbackrest/backup/demo -name 'pg_control*' | head -1); head -c6 \"\$f\" 2>/dev/null")
assert_contains "$hdr" "Salted" "backup files encrypted (OpenSSL Salted__ header)"
pg principal "$BIN/pg_ctl -D $PRI -w stop" >/dev/null 2>&1
ok "delta restore (encrypted repo)" principal "pgbackrest --stanza=demo --delta restore"
pg principal "$BIN/pg_ctl -D $PRI -l $PRI/server.log -w -t 90 start" >/dev/null 2>&1
sleep 4
rows=$(psql_on principal 5433 "SELECT count(*) FROM t" | grep -oE '^[0-9]+$' | head -1)
if [ "$rows" = "1500" ]; then pass "encrypted restore data (1500 rows)"
else pg principal "tail -20 $PRI/server.log" 2>&1 | grep -vE 'Connection to' >&2; fail "encrypted restore data (got: $rows)"; fi

############################################################################
hd "Scenario 5 — zstd compression + differential backup + retention/expire"
prepare_principal_cfg "repo1-retention-full=2
compress-type=zst
compress-level=3"
ok "check (zstd repo)" principal "pgbackrest --stanza=demo check"
psql_on principal 5433 "CREATE TABLE t(i int)" >/dev/null
psql_on principal 5433 "INSERT INTO t SELECT generate_series(1,1000)" >/dev/null
psql_on principal 5433 "SELECT pg_switch_wal()" >/dev/null
ok "full backup #1 (zstd)" principal "pgbackrest --stanza=demo --type=full backup"
zst=$(on principal "ls /var/lib/pgbackrest/backup/demo/*F/global/pg_control* 2>/dev/null")
assert_contains "$zst" ".zst" "backup files zstd-compressed (.zst suffix)"
psql_on principal 5433 "INSERT INTO t SELECT generate_series(1001,1500)" >/dev/null
psql_on principal 5433 "SELECT pg_switch_wal()" >/dev/null
ok "differential backup (zstd)" principal "pgbackrest --stanza=demo --type=diff backup"
ok "full backup #2 (zstd)" principal "pgbackrest --stanza=demo --type=full backup"
fulls_before=$(on principal "ls /var/lib/pgbackrest/backup/demo/ 2>/dev/null | grep -cE 'F\$'")
ok "expire (--repo1-retention-full=1)" principal "pgbackrest --stanza=demo expire --repo1-retention-full=1"
fulls_after=$(on principal "ls /var/lib/pgbackrest/backup/demo/ 2>/dev/null | grep -cE 'F\$'")
if [ "${fulls_before:-0}" = "2" ] && [ "${fulls_after:-0}" = "1" ]; then pass "expire kept newest full only ($fulls_before -> $fulls_after)"
else fail "expire retention (full dirs before=$fulls_before after=$fulls_after, want 2 -> 1)"; fi

############################################################################
hd "Scenario 6 — block-incremental + file bundling (repo-block, repo-bundle)"
prepare_principal_cfg "repo1-retention-full=2
repo1-block=y
repo1-bundle=y"
ok "check (block+bundle repo)" principal "pgbackrest --stanza=demo check"
psql_on principal 5433 "CREATE TABLE t(i int)" >/dev/null
psql_on principal 5433 "INSERT INTO t SELECT generate_series(1,2000)" >/dev/null
psql_on principal 5433 "SELECT pg_switch_wal()" >/dev/null
ok "full backup (block+bundle)" principal "pgbackrest --stanza=demo --type=full backup"
psql_on principal 5433 "INSERT INTO t SELECT generate_series(2001,2500)" >/dev/null
psql_on principal 5433 "SELECT pg_switch_wal()" >/dev/null
ok "incr backup (block+bundle)" principal "pgbackrest --stanza=demo --type=incr backup"
pg principal "$BIN/pg_ctl -D $PRI -w stop" >/dev/null 2>&1
ok "delta restore (block+bundle)" principal "pgbackrest --stanza=demo --delta restore"
pg principal "$BIN/pg_ctl -D $PRI -l $PRI/server.log -w -t 90 start" >/dev/null 2>&1
sleep 4
rows=$(psql_on principal 5433 "SELECT count(*) FROM t" | grep -oE '^[0-9]+$' | head -1)
if [ "$rows" = "2500" ]; then pass "block+bundle restored data (2500 rows)"
else pg principal "tail -20 $PRI/server.log" 2>&1 | grep -vE 'Connection to' >&2; fail "block+bundle restored data (got: $rows)"; fi

############################################################################
hd "Scenario 7 — create a streaming standby on secondaire (restore --type=standby)"
# Repo on depot (shared); principal is the primary backing up to depot. The
# secondaire node restores that backup as a hot standby and streams from principal.
# (KB Exemple 3 / Dalibo Ex.4: a backup-fed streaming replica.)
SEC=/var/lib/postgresql/$PGV/secondaire
reset_principal_cluster
on depot "rm -rf /var/lib/pgbackrest/* 2>/dev/null; install -d -o postgres -g postgres -m 0750 /var/lib/pgbackrest /var/log/pgbackrest"
on principal "cat > /etc/pgbackrest/pgbackrest.conf <<EOF
[global]
repo1-host=depot
repo1-host-user=postgres
repo1-path=/var/lib/pgbackrest
repo1-retention-full=2
log-level-console=info
log-path=/var/log/pgbackrest
start-fast=y
[demo]
pg1-path=$PRI
pg1-port=5433
EOF
chmod 0644 /etc/pgbackrest/pgbackrest.conf"
ok "stanza-create (standby scenario)" principal "pgbackrest --stanza=demo stanza-create"
ok "check (standby scenario)" principal "pgbackrest --stanza=demo check"
# Replication role the standby connects as (reset-cluster's pg_hba allows the
# 192.168.56.0/24 subnet via scram-sha-256).
psql_on principal 5433 "CREATE ROLE replicator WITH REPLICATION LOGIN PASSWORD 'replicator'" >/dev/null
psql_on principal 5433 "CREATE TABLE t(i int)" >/dev/null
psql_on principal 5433 "INSERT INTO t SELECT generate_series(1,1500)" >/dev/null
psql_on principal 5433 "SELECT pg_switch_wal()" >/dev/null
ok "full backup (for standby)" principal "pgbackrest --stanza=demo --type=full backup"

# Configure pgbackrest on secondaire (same remote repo on depot, its own data dir).
on secondaire "cat > /etc/pgbackrest/pgbackrest.conf <<EOF
[global]
repo1-host=depot
repo1-host-user=postgres
repo1-path=/var/lib/pgbackrest
log-level-console=info
log-path=/var/log/pgbackrest
[demo]
pg1-path=$SEC
pg1-port=5433
EOF
chmod 0644 /etc/pgbackrest/pgbackrest.conf
install -d -o postgres -g postgres -m 0750 /var/log/pgbackrest"
# Stop any prior standby + wipe its data dir, then restore as a standby from depot.
on secondaire "sudo -u postgres $BIN/pg_ctl -D $SEC -m immediate -w stop >/dev/null 2>&1 || true; rm -rf $SEC; install -d -o postgres -g postgres -m 0700 $SEC"
ok "restore --type=standby (on secondaire, from depot)" secondaire \
  "pgbackrest --stanza=demo --type=standby --recovery-option=primary_conninfo='host=principal port=5433 user=replicator password=replicator' --delta restore"
sig=$(on secondaire "ls $SEC/standby.signal 2>&1")
assert_contains "$sig" "standby.signal" "restore wrote standby.signal"

pg secondaire "$BIN/pg_ctl -D $SEC -l $SEC/server.log -w -t 90 start" >/dev/null 2>&1
sleep 5
in_rec=$(psql_on secondaire 5433 "SELECT pg_is_in_recovery()" | grep -oE '^[tf]$' | head -1)
srows=$(psql_on secondaire 5433 "SELECT count(*) FROM t" | grep -oE '^[0-9]+$' | head -1)
if [ "$in_rec" = "t" ] && [ "$srows" = "1500" ]; then
  pass "standby is a hot replica with the restored data (1500 rows)"
else
  pg secondaire "tail -25 $SEC/server.log" 2>&1 | grep -vE 'Connection to' >&2
  fail "standby state (in_recovery=$in_rec rows=$srows, want t/1500)"
fi
# Streaming: an insert on the primary must replicate to the standby.
psql_on principal 5433 "INSERT INTO t SELECT generate_series(1501,1600)" >/dev/null
psql_on principal 5433 "SELECT pg_switch_wal()" >/dev/null
sleep 6
srows2=$(psql_on secondaire 5433 "SELECT count(*) FROM t" | grep -oE '^[0-9]+$' | head -1)
if [ "$srows2" = "1600" ]; then pass "streaming replication primary -> standby (1600 rows)"
else pg secondaire "tail -15 $SEC/server.log" 2>&1 | grep -vE 'Connection to' >&2; fail "streaming replication (standby rows=$srows2, want 1600)"; fi

############################################################################
hd "Scenario 8 — PITR to a timestamp (--type=time)"
prepare_principal
ok "PITR(time) full backup (pre-target base)" principal "pgbackrest --stanza=demo --type=full backup"
psql_on principal 5433 "CREATE TABLE t(i int)" >/dev/null
psql_on principal 5433 "INSERT INTO t SELECT generate_series(1,1000)" >/dev/null
# Capture a recovery target time AFTER the 1000 base rows committed; the 500
# "future" rows are committed >2s later so they fall strictly after the target.
target_time=$(psql_on principal 5433 "SELECT now()" | grep -oE '^[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9:.+-]+' | head -1)
sleep 3
psql_on principal 5433 "INSERT INTO t SELECT generate_series(1001,1500)" >/dev/null
target_seg=$(psql_on principal 5433 "SELECT pg_walfile_name(pg_current_wal_lsn())" | grep -oE '[0-9A-F]{24}' | head -1)
psql_on principal 5433 "SELECT pg_switch_wal()" >/dev/null
poll_rc=0
pg principal "for i in \$(seq 1 60); do ls /var/lib/pgbackrest/archive/demo/18-1/ 2>/dev/null | grep -q \"^${target_seg}\" && exit 0; sleep 1; done; exit 1" >/dev/null 2>&1 || poll_rc=$?
[ "$poll_rc" -eq 0 ] && pass "target WAL ($target_seg) archived" || fail "target WAL not archived in 60s"
pg principal "$BIN/pg_ctl -D $PRI -w stop" >/dev/null 2>&1
ok "PITR restore (--type=time --target='$target_time' --target-action=promote)" principal \
  "pgbackrest --stanza=demo --delta --type=time --target='$target_time' --target-action=promote restore"
pg principal "$BIN/pg_ctl -D $PRI -l $PRI/server.log -w -t 120 start" >/dev/null 2>&1
sleep 5
after=$(psql_on principal 5433 "SELECT count(*) FROM t" | grep -oE '^[0-9]+$' | head -1)
future=$(psql_on principal 5433 "SELECT count(*) FROM t WHERE i>1000" | grep -oE '^[0-9]+$' | head -1)
if [ "$after" = "1000" ] && [ "$future" = "0" ]; then pass "PITR(time) recovered to target (1000 rows, future dropped)"
else pg principal "tail -25 $PRI/server.log" 2>&1 | grep -vE 'Connection to' >&2; fail "PITR(time) (after=$after future=$future, want 1000/0)"; fi

############################################################################
hd "Scenario 9 — multiple repositories (repo1 + repo2, both local on principal)"
reset_principal_cluster
on principal "rm -rf /var/lib/pgbackrest/* /var/lib/pgbackrest2/* 2>/dev/null; install -d -o postgres -g postgres -m 0750 /var/lib/pgbackrest /var/lib/pgbackrest2 /var/log/pgbackrest"
on principal "cat > /etc/pgbackrest/pgbackrest.conf <<EOF
[global]
repo1-path=/var/lib/pgbackrest
repo1-retention-full=2
repo2-path=/var/lib/pgbackrest2
repo2-retention-full=2
log-level-console=info
log-path=/var/log/pgbackrest
start-fast=y
[demo]
pg1-path=$PRI
pg1-port=5433
EOF
chmod 0644 /etc/pgbackrest/pgbackrest.conf"
ok "stanza-create (2 repos)" principal "pgbackrest --stanza=demo stanza-create"
ok "check (2 repos)" principal "pgbackrest --stanza=demo check"
psql_on principal 5433 "CREATE TABLE t(i int)" >/dev/null
psql_on principal 5433 "INSERT INTO t SELECT generate_series(1,1500)" >/dev/null
psql_on principal 5433 "SELECT pg_switch_wal()" >/dev/null
ok "full backup to repo1 (default)" principal "pgbackrest --stanza=demo --repo=1 --type=full backup"
ok "full backup to repo2" principal "pgbackrest --stanza=demo --repo=2 --type=full backup"
r1=$(on principal "ls /var/lib/pgbackrest/backup/demo/ 2>/dev/null | grep -cE 'F\$'")
r2=$(on principal "ls /var/lib/pgbackrest2/backup/demo/ 2>/dev/null | grep -cE 'F\$'")
if printf '%s' "$r1" | grep -qE '[1-9]' && printf '%s' "$r2" | grep -qE '[1-9]'; then pass "both repos hold a full backup (repo1=$r1 repo2=$r2)"
else fail "multi-repo backup placement (repo1=$r1 repo2=$r2, want both >=1)"; fi
out=$(pg principal "pgbackrest --stanza=demo --repo=2 info")
assert_contains "$out" "full backup" "repo2 info shows full"
# Restore explicitly from repo2.
pg principal "$BIN/pg_ctl -D $PRI -w stop" >/dev/null 2>&1
ok "delta restore from repo2" principal "pgbackrest --stanza=demo --repo=2 --delta restore"
pg principal "$BIN/pg_ctl -D $PRI -l $PRI/server.log -w -t 90 start" >/dev/null 2>&1
sleep 4
rows=$(psql_on principal 5433 "SELECT count(*) FROM t" | grep -oE '^[0-9]+$' | head -1)
if [ "$rows" = "1500" ]; then pass "restore from repo2 (1500 rows)"
else pg principal "tail -20 $PRI/server.log" 2>&1 | grep -vE 'Connection to' >&2; fail "restore from repo2 (got: $rows)"; fi

############################################################################
hd "Scenario 10 — pull backup from a dedicated repo host (KB Exemple 2: depot runs backup, pg1-host=principal)"
# The backup/stanza/check commands run ON depot with the PG host remote
# (pg1-host=principal): the control connection (pg_backup_start/stop, version,
# WAL switch) runs on an SSH worker on principal (local libpq, peer/trust). The
# repository is local to depot; principal archives WAL to depot.
reset_principal_cluster
on depot "rm -rf /var/lib/pgbackrest/* 2>/dev/null; install -d -o postgres -g postgres -m 0750 /var/lib/pgbackrest /var/log/pgbackrest"
on depot "cat > /etc/pgbackrest/pgbackrest.conf <<EOF
[global]
repo1-path=/var/lib/pgbackrest
repo1-retention-full=2
log-level-console=info
log-path=/var/log/pgbackrest
start-fast=y
[demo]
pg1-host=principal
pg1-host-user=postgres
pg1-path=$PRI
pg1-port=5433
EOF
chmod 0644 /etc/pgbackrest/pgbackrest.conf"
on principal "cat > /etc/pgbackrest/pgbackrest.conf <<EOF
[global]
repo1-host=depot
repo1-host-user=postgres
repo1-path=/var/lib/pgbackrest
log-level-console=info
log-path=/var/log/pgbackrest
[demo]
pg1-path=$PRI
pg1-port=5433
EOF
chmod 0644 /etc/pgbackrest/pgbackrest.conf"
ok "pull stanza-create (on depot, pg1-host=principal via SSH worker)" depot "pgbackrest --stanza=demo stanza-create"
ok "pull check (on depot, control connection on principal worker)" depot "pgbackrest --stanza=demo check"
psql_on principal 5433 "CREATE TABLE t(i int)" >/dev/null
psql_on principal 5433 "INSERT INTO t SELECT generate_series(1,1500)" >/dev/null
psql_on principal 5433 "SELECT pg_switch_wal()" >/dev/null
ok "pull full backup (on depot, pg_backup_start/stop on worker; files pulled over SSH)" depot "pgbackrest --stanza=demo --type=full backup"
out=$(pg depot "pgbackrest --stanza=demo info")
assert_contains "$out" "full backup" "pull backup: info shows full"
# Cross-validate the pull backup is restorable: principal (repo on depot) restores it.
pg principal "$BIN/pg_ctl -D $PRI -w stop" >/dev/null 2>&1
ok "restore the pull backup (on principal, repo on depot)" principal "pgbackrest --stanza=demo --delta restore"
pg principal "$BIN/pg_ctl -D $PRI -l $PRI/server.log -w -t 90 start" >/dev/null 2>&1
sleep 4
rows=$(psql_on principal 5433 "SELECT count(*) FROM t" | grep -oE '^[0-9]+$' | head -1)
if [ "$rows" = "1500" ]; then pass "pull backup restored (1500 rows)"
else pg principal "tail -20 $PRI/server.log" 2>&1 | grep -vE 'Connection to' >&2; fail "pull backup restore (got: $rows)"; fi

############################################################################
hd "Scenario 11 — compression variants bz2 + lz4 (configuration.html compress-type)"
# Scenario 5 proved zstd; this proves the remaining real codecs are usable
# end-to-end: each does a full backup whose repo files carry the codec's suffix
# (.bz2 / .lz4), then a delta restore that brings back all 1500 rows. The suffix
# is asserted via `ls ... pg_control*` (the same idiom Scenario 5 uses) rather
# than `find | grep -q`, which trips set -o pipefail (grep -q closes the pipe,
# find dies on SIGPIPE, pipefail reports the pipeline as failed despite a match).
for CT in bz2 lz4; do
  prepare_principal_cfg "compress-type=$CT"
  ok "check ($CT repo)" principal "pgbackrest --stanza=demo check"
  psql_on principal 5433 "CREATE TABLE t(i int)" >/dev/null
  psql_on principal 5433 "INSERT INTO t SELECT generate_series(1,1500)" >/dev/null
  psql_on principal 5433 "SELECT pg_switch_wal()" >/dev/null
  ok "full backup ($CT)" principal "pgbackrest --stanza=demo --type=full backup"
  sfx=$(on principal "ls /var/lib/pgbackrest/backup/demo/*F/global/pg_control* 2>/dev/null")
  assert_contains "$sfx" ".$CT" "backup files $CT-compressed (.$CT suffix)"
  pg principal "$BIN/pg_ctl -D $PRI -w stop" >/dev/null 2>&1
  ok "delta restore ($CT)" principal "pgbackrest --stanza=demo --delta restore"
  pg principal "$BIN/pg_ctl -D $PRI -l $PRI/server.log -w -t 90 start" >/dev/null 2>&1
  sleep 4
  rows=$(psql_on principal 5433 "SELECT count(*) FROM t" | grep -oE '^[0-9]+$' | head -1)
  if [ "$rows" = "1500" ]; then pass "$CT restored data (1500 rows)"
  else pg principal "tail -20 $PRI/server.log" 2>&1 | grep -vE 'Connection to' >&2; fail "$CT restored data (got: $rows)"; fi
done

############################################################################
hd "Scenario 12 — asynchronous WAL archiving (archive-async=y + spool-path)"
# Async mode stages each WAL into <spool>/archive/<stanza>/out/ and the foreground
# call drains the spool into the repo before returning. A 'check' archive
# round-trip + a full backup (whose pg_backup_stop waits for the stop WAL via
# archive-check) are the deterministic proof that staged segments actually reach
# the repo within archive-timeout, not pile up in the spool unread.
prepare_principal_cfg "archive-async=y
spool-path=/var/spool/pgbackrest
repo1-retention-full=2"
on principal "install -d -o postgres -g postgres -m 0750 /var/spool/pgbackrest; rm -rf /var/spool/pgbackrest/* 2>/dev/null; true"
ok "check (async archive round-trip)" principal "pgbackrest --stanza=demo check"
psql_on principal 5433 "CREATE TABLE t(i int)" >/dev/null
psql_on principal 5433 "INSERT INTO t SELECT generate_series(1,1500)" >/dev/null
for _ in 1 2 3; do psql_on principal 5433 "SELECT pg_switch_wal()" >/dev/null; done
ok "full backup (async; archive-check waits for stop WAL)" principal "pgbackrest --stanza=demo --type=full backup"
arch=$(on principal "ls /var/lib/pgbackrest/archive/demo/*/0000* 2>/dev/null | wc -l" | tr -d ' ')
if [ "${arch:-0}" -ge 1 ]; then pass "WAL segments reached the repo archive ($arch present)"
else fail "no WAL in repo archive (got: $arch) — async drain regression"; fi
pg principal "$BIN/pg_ctl -D $PRI -w stop" >/dev/null 2>&1
ok "delta restore (async repo)" principal "pgbackrest --stanza=demo --delta restore"
pg principal "$BIN/pg_ctl -D $PRI -l $PRI/server.log -w -t 90 start" >/dev/null 2>&1
sleep 4
rows=$(psql_on principal 5433 "SELECT count(*) FROM t" | grep -oE '^[0-9]+$' | head -1)
if [ "$rows" = "1500" ]; then pass "async repo restored data (1500 rows)"
else pg principal "tail -20 $PRI/server.log" 2>&1 | grep -vE 'Connection to' >&2; fail "async repo restored data (got: $rows)"; fi

############################################################################
hd "Scenario 13 — restore to an alternate datadir (--pg1-path=<other>)"
# pgBackRest's restore can target a different PGDATA directory via --pg1-path
# (command.html). The restored cluster must start on its own port and serve
# the backed-up data; recovery requires that PG's restore_command — which runs
# `pgbackrest archive-get %f "%p"` with cwd=PGDATA — actually delivers the
# fetched WAL to the cwd-relative %p (not under pg1-path). This scenario
# regression-guards that contract, fixed in c4ef0bb30.
ALT=/var/lib/postgresql/$PGV/alt-restore
prepare_principal
psql_on principal 5433 "CREATE TABLE t(i int)" >/dev/null
psql_on principal 5433 "INSERT INTO t SELECT generate_series(1,1500)" >/dev/null
psql_on principal 5433 "SELECT pg_switch_wal()" >/dev/null
ok "full backup (for alt restore)" principal "pgbackrest --stanza=demo --type=full backup"
pg principal "$BIN/pg_ctl -D $ALT -m fast -w stop" >/dev/null 2>&1 || true
on principal "rm -rf $ALT; install -d -o postgres -g postgres -m 0700 $ALT"
pg principal "$BIN/pg_ctl -D $PRI -w stop" >/dev/null 2>&1
ok "restore --pg1-path=$ALT (alternate datadir)" principal "pgbackrest --stanza=demo --pg1-path=$ALT --delta restore"
pv=$(on principal "test -f $ALT/PG_VERSION && cat $ALT/PG_VERSION || echo MISSING")
assert_contains "$pv" "$PGV" "alt-restore PG_VERSION present"
pg principal "$BIN/pg_ctl -D $ALT -o '-p 5434' -l $ALT/server.log -w -t 90 start" >/dev/null 2>&1
sleep 4
rows=$(psql_on principal 5434 "SELECT count(*) FROM t" | grep -oE '^[0-9]+$' | head -1)
if [ "$rows" = "1500" ]; then pass "alt cluster recovered + serves 1500 rows on port 5434"
else pg principal "tail -25 $ALT/server.log" 2>&1 | grep -vE 'Connection to' >&2; fail "alt cluster rows (got: $rows)"; fi
pg principal "$BIN/pg_ctl -D $ALT -m fast -w stop" >/dev/null 2>&1
pg principal "$BIN/pg_ctl -D $PRI -l $PRI/server.log -w start" >/dev/null 2>&1

############################################################################
hd "Scenario 14 — backup-standby=y (KB Exemple 8: backup runs on repo host, files pulled from standby)"
# Topology: depot=repo host (orchestrator), principal=primary, secondaire=standby
# streaming from principal. Config on depot has pg1=principal + pg2=secondaire +
# backup-standby=y. The backup runs pg_backup_start/stop on pg1 (primary) but
# reads PGDATA files from pg2 (standby) — offloading I/O from the primary while
# keeping consistency. Exercises gap-B (DB control over a worker) AND the
# pull-backup file-copy path (read source through a remote pg_storage worker).
SEC=/var/lib/postgresql/$PGV/secondaire
reset_principal_cluster
on depot "rm -rf /var/lib/pgbackrest/* 2>/dev/null; install -d -o postgres -g postgres -m 0750 /var/lib/pgbackrest /var/log/pgbackrest"
# Step 1: initial config on depot (pg1 only) so we can take a base backup that
# the standby will restore from. backup-standby is enabled later, once the
# standby is up; turning it on now would make `check` fail (no pg2 yet).
on depot "cat > /etc/pgbackrest/pgbackrest.conf <<EOF
[global]
repo1-path=/var/lib/pgbackrest
log-level-console=info
log-path=/var/log/pgbackrest
start-fast=y
[demo]
pg1-host=principal
pg1-host-user=postgres
pg1-path=$PRI
pg1-port=5433
EOF
chmod 0644 /etc/pgbackrest/pgbackrest.conf"
# principal also needs a pgbackrest.conf so PG's archive_command (set by
# reset-cluster) actually pushes WAL to depot, mirroring Scenario 10's setup.
on principal "cat > /etc/pgbackrest/pgbackrest.conf <<EOF
[global]
repo1-host=depot
repo1-host-user=postgres
repo1-path=/var/lib/pgbackrest
log-level-console=info
log-path=/var/log/pgbackrest
[demo]
pg1-path=$PRI
pg1-port=5433
EOF
chmod 0644 /etc/pgbackrest/pgbackrest.conf"
ok "stanza-create (backup-standby setup, on depot)" depot "pgbackrest --stanza=demo stanza-create"
ok "check (initial, no standby)" depot "pgbackrest --stanza=demo check"
psql_on principal 5433 "CREATE ROLE replicator WITH REPLICATION LOGIN PASSWORD 'replicator'" >/dev/null
psql_on principal 5433 "CREATE TABLE t(i int)" >/dev/null
psql_on principal 5433 "INSERT INTO t SELECT generate_series(1,1500)" >/dev/null
psql_on principal 5433 "SELECT pg_switch_wal()" >/dev/null
ok "initial full backup (primary, no standby yet)" depot "pgbackrest --stanza=demo --type=full backup"
# Step 2: restore secondaire as a streaming standby from the depot repo.
on secondaire "sudo -u postgres $BIN/pg_ctl -D $SEC -m immediate -w stop >/dev/null 2>&1 || true; rm -rf $SEC; install -d -o postgres -g postgres -m 0700 $SEC"
on secondaire "cat > /etc/pgbackrest/pgbackrest.conf <<EOF
[global]
repo1-host=depot
repo1-host-user=postgres
repo1-path=/var/lib/pgbackrest
log-level-console=info
log-path=/var/log/pgbackrest
[demo]
pg1-path=$SEC
pg1-port=5433
EOF
chmod 0644 /etc/pgbackrest/pgbackrest.conf
install -d -o postgres -g postgres -m 0750 /var/log/pgbackrest"
ok "restore --type=standby (on secondaire, from depot)" secondaire \
  "pgbackrest --stanza=demo --type=standby --recovery-option=primary_conninfo='host=principal port=5433 user=replicator password=replicator' --delta restore"
pg secondaire "$BIN/pg_ctl -D $SEC -l $SEC/server.log -w -t 90 start" >/dev/null 2>&1
sleep 5
in_rec=$(psql_on secondaire 5433 "SELECT pg_is_in_recovery()" | grep -oE '^[tf]$' | head -1)
if [ "$in_rec" = "t" ]; then pass "standby is in recovery (streaming from principal)"
else pg secondaire "tail -25 $SEC/server.log" 2>&1 | grep -vE 'Connection to' >&2; fail "standby setup (in_recovery=$in_rec)"; fi
# More data on primary so the standby backup captures something new (>= 2000 rows).
psql_on principal 5433 "INSERT INTO t SELECT generate_series(1501,2000)" >/dev/null
psql_on principal 5433 "SELECT pg_switch_wal()" >/dev/null
sleep 4
prows=$(psql_on principal 5433 "SELECT count(*) FROM t" | grep -oE '^[0-9]+$' | head -1)
srows=$(psql_on secondaire 5433 "SELECT count(*) FROM t" | grep -oE '^[0-9]+$' | head -1)
if [ "$prows" = "2000" ] && [ "$srows" = "2000" ]; then pass "primary + standby caught up (2000 rows each)"
else fail "replication mismatch (primary=$prows standby=$srows, want 2000/2000)"; fi
# Step 3: re-config depot with pg1+pg2 + backup-standby=y and take the standby backup.
on depot "cat > /etc/pgbackrest/pgbackrest.conf <<EOF
[global]
repo1-path=/var/lib/pgbackrest
backup-standby=y
log-level-console=info
log-path=/var/log/pgbackrest
start-fast=y
[demo]
pg1-host=principal
pg1-host-user=postgres
pg1-path=$PRI
pg1-port=5433
pg2-host=secondaire
pg2-host-user=postgres
pg2-path=$SEC
pg2-port=5433
EOF
chmod 0644 /etc/pgbackrest/pgbackrest.conf"
ok "full backup --backup-standby=y (start/stop on pg1, files from pg2)" depot "pgbackrest --stanza=demo --type=full backup"
out=$(pg depot "pgbackrest --stanza=demo info")
fulls=$(printf '%s' "$out" | grep -cE 'full backup')
if [ "$fulls" -ge 2 ]; then pass "info shows $fulls full backups (initial + standby)"
else fail "info doesn't show >=2 full backups (got $fulls)"; fi
# Cross-validate: restore the latest (standby) backup on principal, verify 2000 rows.
pg secondaire "$BIN/pg_ctl -D $SEC -m fast -w stop" >/dev/null 2>&1
pg principal "$BIN/pg_ctl -D $PRI -w stop" >/dev/null 2>&1
on principal "cat > /etc/pgbackrest/pgbackrest.conf <<EOF
[global]
repo1-host=depot
repo1-host-user=postgres
repo1-path=/var/lib/pgbackrest
log-level-console=info
log-path=/var/log/pgbackrest
[demo]
pg1-path=$PRI
pg1-port=5433
EOF
chmod 0644 /etc/pgbackrest/pgbackrest.conf"
ok "restore the standby backup (on principal, repo on depot)" principal "pgbackrest --stanza=demo --delta restore"
pg principal "$BIN/pg_ctl -D $PRI -l $PRI/server.log -w -t 90 start" >/dev/null 2>&1
sleep 4
rows=$(psql_on principal 5433 "SELECT count(*) FROM t" | grep -oE '^[0-9]+$' | head -1)
if [ "$rows" = "2000" ]; then pass "standby backup restored data (2000 rows)"
else pg principal "tail -20 $PRI/server.log" 2>&1 | grep -vE 'Connection to' >&2; fail "standby backup restore (got: $rows)"; fi

############################################################################
hd "Scenario 15 — PITR to a transaction id (--type=xid + --target-action=promote)"
# Scenarios 2 + 8 covered --type=name and --type=time; this covers --type=xid
# (command.html). Backup with 1000 rows in place, capture an xid via
# pg_current_xact_id(), insert 1000 future rows, stop, restore --type=xid to
# the captured xid, start (which promotes), assert <= 1000 rows + not in
# recovery.
prepare_principal
psql_on principal 5433 "CREATE TABLE t(i int)" >/dev/null
psql_on principal 5433 "INSERT INTO t SELECT generate_series(1,1000)" >/dev/null
psql_on principal 5433 "SELECT pg_switch_wal()" >/dev/null
ok "PITR(xid) full backup (pre-target base)" principal "pgbackrest --stanza=demo --type=full backup"
psql_on principal 5433 "CHECKPOINT" >/dev/null
TGT_XID=$(psql_on principal 5433 "SELECT pg_current_xact_id()::text" | grep -oE '^[0-9]+$' | head -1)
if [ -n "$TGT_XID" ]; then pass "captured target xid ($TGT_XID)"
else fail "could not capture target xid"; fi
psql_on principal 5433 "INSERT INTO t SELECT generate_series(1001,2000)" >/dev/null
psql_on principal 5433 "SELECT pg_switch_wal()" >/dev/null
sleep 5
pg principal "$BIN/pg_ctl -D $PRI -m fast -w stop" >/dev/null 2>&1
ok "PITR restore (--type=xid --target=$TGT_XID --target-action=promote)" principal \
  "pgbackrest --stanza=demo --type=xid --target=$TGT_XID --target-action=promote --delta restore"
pg principal "$BIN/pg_ctl -D $PRI -l $PRI/server.log -w -t 90 start" >/dev/null 2>&1
sleep 10
in_rec=$(psql_on principal 5433 "SELECT pg_is_in_recovery()" | grep -oE '^[tf]$' | head -1)
rows=$(psql_on principal 5433 "SELECT count(*) FROM t" | grep -oE '^[0-9]+$' | head -1)
if [ "$in_rec" = "f" ] && [ -n "$rows" ] && [ "$rows" -le 1000 ]; then pass "PITR(xid) recovered to target + promoted ($rows rows, future dropped)"
else pg principal "tail -25 $PRI/server.log" 2>&1 | grep -vE 'Connection to' >&2; fail "PITR(xid) outcome (in_recovery=$in_rec rows=$rows, want f / <=1000)"; fi

############################################################################
hd "Scenario 16 — PITR to a WAL LSN (--type=lsn + --target-action=promote)"
# Completes the PITR target-type matrix: --type=name (S2), --type=time (S8),
# --type=xid (S15), --type=lsn here (command.html). Backup with 1000 rows,
# capture pg_current_wal_lsn(), insert 1000 future rows, restore --type=lsn to
# that LSN, assert in_recovery=f and rows<=1000.
prepare_principal
psql_on principal 5433 "CREATE TABLE t(i int)" >/dev/null
psql_on principal 5433 "INSERT INTO t SELECT generate_series(1,1000)" >/dev/null
psql_on principal 5433 "SELECT pg_switch_wal()" >/dev/null
ok "PITR(lsn) full backup (pre-target base)" principal "pgbackrest --stanza=demo --type=full backup"
psql_on principal 5433 "CHECKPOINT" >/dev/null
TGT_LSN=$(psql_on principal 5433 "SELECT pg_current_wal_lsn()::text" | grep -oE '^[0-9A-Fa-f]+/[0-9A-Fa-f]+$' | head -1)
if [ -n "$TGT_LSN" ]; then pass "captured target lsn ($TGT_LSN)"
else fail "could not capture target lsn"; fi
psql_on principal 5433 "INSERT INTO t SELECT generate_series(1001,2000)" >/dev/null
psql_on principal 5433 "SELECT pg_switch_wal()" >/dev/null
sleep 5
pg principal "$BIN/pg_ctl -D $PRI -m fast -w stop" >/dev/null 2>&1
ok "PITR restore (--type=lsn --target=$TGT_LSN --target-action=promote)" principal \
  "pgbackrest --stanza=demo --type=lsn --target=$TGT_LSN --target-action=promote --delta restore"
pg principal "$BIN/pg_ctl -D $PRI -l $PRI/server.log -w -t 90 start" >/dev/null 2>&1
sleep 10
in_rec=$(psql_on principal 5433 "SELECT pg_is_in_recovery()" | grep -oE '^[tf]$' | head -1)
rows=$(psql_on principal 5433 "SELECT count(*) FROM t" | grep -oE '^[0-9]+$' | head -1)
if [ "$in_rec" = "f" ] && [ -n "$rows" ] && [ "$rows" -le 1000 ]; then pass "PITR(lsn) recovered to target + promoted ($rows rows, future dropped)"
else pg principal "tail -25 $PRI/server.log" 2>&1 | grep -vE 'Connection to' >&2; fail "PITR(lsn) outcome (in_recovery=$in_rec rows=$rows, want f / <=1000)"; fi

############################################################################
hd "Scenario 17 — info --output=json (machine-parsable) + expire --set=<label> (targeted)"
# Two distinct documented features that combine naturally: the JSON output is
# the canonical way for tooling to drive expire --set. Asserts (a) the JSON
# output starts with `[` and ends with `]` (smoke-tests well-formed structure
# without needing python on the MSYS host), (b) two backups appear as two
# `"label" : "..."` entries in the JSON, (c) expire --set=<label1> removes
# ONLY that backup. Labels are extracted with grep/sed (pgbackrest formats
# labels as <YYYYMMDD>-<HHMMSS>{F,D,I}), so the harness stays bash-only.
extract_labels_from_json() {
  # echo each label in the JSON on its own line, in order. Empty if none.
  printf '%s' "$1" | grep -oE '"label"[[:space:]]*:[[:space:]]*"[^"]+"' | sed -E 's/.*"([^"]+)"$/\1/'
}
prepare_principal
out=$(pg principal "pgbackrest --stanza=demo info --output=json")
first_nonblank=$(printf '%s' "$out" | sed -n '/[^[:space:]]/{p;q}')
last_nonblank=$(printf '%s' "$out" | awk 'NF{l=$0}END{print l}')
if [ "$first_nonblank" = "[" ] && [ "$last_nonblank" = "]" ]; then pass "info --output=json (empty repo) is a well-formed JSON array"
else printf '%s\n' "$out" | tail -4 >&2; fail "info --output=json (empty) not bracketed (first=$first_nonblank last=$last_nonblank)"; fi
psql_on principal 5433 "CREATE TABLE t(i int)" >/dev/null
psql_on principal 5433 "INSERT INTO t SELECT generate_series(1,1000)" >/dev/null
ok "full backup #1 (for expire --set)" principal "pgbackrest --stanza=demo --type=full backup"
psql_on principal 5433 "INSERT INTO t SELECT generate_series(1001,1500)" >/dev/null
ok "full backup #2 (for expire --set)" principal "pgbackrest --stanza=demo --type=full backup"
json=$(pg principal "pgbackrest --stanza=demo info --output=json")
mapfile -t LABELS < <(extract_labels_from_json "$json")
if [ "${#LABELS[@]}" = "2" ]; then pass "info --output=json shows both backups (${LABELS[0]}, ${LABELS[1]})"
else fail "info --output=json missed backups (got ${#LABELS[@]}: ${LABELS[*]})"; fi
LABEL1="${LABELS[0]:-}"
LABEL2="${LABELS[1]:-}"
ok "expire --set=$LABEL1 (targeted deletion)" principal "pgbackrest --stanza=demo expire --set=$LABEL1"
post=$(pg principal "pgbackrest --stanza=demo info --output=json")
mapfile -t REMAINING < <(extract_labels_from_json "$post")
if [ "${#REMAINING[@]}" = "1" ] && [ "${REMAINING[0]}" = "$LABEL2" ]; then pass "expire --set removed only the targeted backup ($LABEL1 gone, $LABEL2 kept)"
else fail "expire --set wrong outcome (remaining ${#REMAINING[@]}: ${REMAINING[*]}, want only $LABEL2)"; fi

############################################################################
hd "Scenario 18 — annotate command (set / update / delete key=value metadata)"
# annotate attaches arbitrary user-supplied key/value labels to a backup's
# metadata (command.html). The annotation is persisted in backup.info under
# "backup-annotation":{...} and surfaced by `info --output=json` per backup.
# Companion to 01e5eae1f (fix(info): surface backup-annotation in info text +
# JSON), which wired the previously-missing rendering. Asserts the three
# documented operations: add a new annotation, update an existing key's
# value, and remove an annotation by setting it to an empty value.
prepare_principal
psql_on principal 5433 "CREATE TABLE t(i int); INSERT INTO t SELECT generate_series(1,500)" >/dev/null
ok "full backup (for annotate)" principal "pgbackrest --stanza=demo --type=full backup"
LABEL=$(pg principal "pgbackrest --stanza=demo info --output=json" | grep -oE '"label"[[:space:]]*:[[:space:]]*"[^"]+"' | sed -E 's/.*"([^"]+)"$/\1/' | head -1)
ok "annotate --set=$LABEL --annotation=note=hello" principal "pgbackrest --stanza=demo annotate --set=$LABEL --annotation=note=hello"
js1=$(pg principal "pgbackrest --stanza=demo info --output=json")
if printf '%s' "$js1" | grep -qE '"note"[[:space:]]*:[[:space:]]*"hello"'; then pass "info --output=json renders annotation note=hello"
else fail "annotation note=hello not visible in info json"; fi
ok "annotate update (note=updated, same key)" principal "pgbackrest --stanza=demo annotate --set=$LABEL --annotation=note=updated"
js2=$(pg principal "pgbackrest --stanza=demo info --output=json")
if printf '%s' "$js2" | grep -qE '"note"[[:space:]]*:[[:space:]]*"updated"' && ! printf '%s' "$js2" | grep -qE '"note"[[:space:]]*:[[:space:]]*"hello"'; then pass "annotation value updated (hello -> updated)"
else fail "annotation update failed"; fi
ok "annotate delete (--annotation=note= empty)" principal "pgbackrest --stanza=demo annotate --set=$LABEL --annotation=note="
js3=$(pg principal "pgbackrest --stanza=demo info --output=json")
if ! printf '%s' "$js3" | grep -qE '"note"[[:space:]]*:[[:space:]]*"'; then pass "annotation removed (empty value deletes the key)"
else fail "annotation NOT removed"; fi

############################################################################
hd "Scenario 19 — PITR --target-action=pause (cluster stays in recovery until promoted)"
# Scenarios 2/8/15/16 covered --target-action=promote (the default). pause is
# the alternative: when recovery reaches the target the cluster STAYS in
# recovery (paused), allowing an operator to inspect the state before
# committing to a promotion. pg_promote() then exits recovery normally.
prepare_principal
psql_on principal 5433 "CREATE TABLE t(i int); INSERT INTO t SELECT generate_series(1,1000)" >/dev/null
psql_on principal 5433 "SELECT pg_switch_wal()" >/dev/null
ok "PITR(pause) full backup (pre-target base)" principal "pgbackrest --stanza=demo --type=full backup"
psql_on principal 5433 "CHECKPOINT" >/dev/null
TGT_LSN=$(psql_on principal 5433 "SELECT pg_current_wal_lsn()::text" | grep -oE '^[0-9A-Fa-f]+/[0-9A-Fa-f]+$' | head -1)
psql_on principal 5433 "INSERT INTO t SELECT generate_series(1001,2000)" >/dev/null
psql_on principal 5433 "SELECT pg_switch_wal()" >/dev/null
sleep 5
pg principal "$BIN/pg_ctl -D $PRI -m fast -w stop" >/dev/null 2>&1
ok "PITR restore --type=lsn --target-action=pause" principal \
  "pgbackrest --stanza=demo --type=lsn --target=$TGT_LSN --target-action=pause --delta restore"
pg principal "$BIN/pg_ctl -D $PRI -l $PRI/server.log -w -t 90 start" >/dev/null 2>&1
sleep 8
in_rec=$(psql_on principal 5433 "SELECT pg_is_in_recovery()" | grep -oE '^[tf]$' | head -1)
if [ "$in_rec" = "t" ]; then pass "cluster stays in recovery (paused) after reaching the target"
else pg principal "tail -20 $PRI/server.log" 2>&1 | grep -vE 'Connection to' >&2; fail "cluster did not pause (in_recovery=$in_rec)"; fi
psql_on principal 5433 "SELECT pg_promote()" >/dev/null
sleep 6
in_rec2=$(psql_on principal 5433 "SELECT pg_is_in_recovery()" | grep -oE '^[tf]$' | head -1)
rows=$(psql_on principal 5433 "SELECT count(*) FROM t" | grep -oE '^[0-9]+$' | head -1)
if [ "$in_rec2" = "f" ] && [ -n "$rows" ] && [ "$rows" -le 1000 ]; then pass "pg_promote() exits recovery + data matches pause-target ($rows rows)"
else pg principal "tail -20 $PRI/server.log" 2>&1 | grep -vE 'Connection to' >&2; fail "post-promote state (in_recovery=$in_rec2 rows=$rows, want f / <=1000)"; fi

############################################################################
hd "Scenario 20 — checksum-page detects a corrupted relation page (page-validation)"
# data_checksums=on (reset-cluster passes --data-checksums). pgbackrest's
# default checksum-page now resolves dynamically from pg_control, so a corrupt
# page IS detected even without --checksum-page on the CLI. Companion to
# d57cc86b9 (default --checksum-page from pg_control and record invalid
# blocks), which fixed the previously-silent corruption pass-through. Asserts
# the backup completes (warning, not abort) AND logs an invalid-page warning.
prepare_principal
dch=$(psql_on principal 5433 "SHOW data_checksums" | grep -oE 'on|off' | head -1)
assert_contains "$dch" "on" "cluster has data_checksums=on (reset-cluster default)"
psql_on principal 5433 "CREATE TABLE t(i int, s text)" >/dev/null
psql_on principal 5433 "INSERT INTO t SELECT g, repeat('x',1000) FROM generate_series(1,200) g" >/dev/null
psql_on principal 5433 "CHECKPOINT" >/dev/null
RELP=$(psql_on principal 5433 "SELECT pg_relation_filepath('t')" | grep -oE '^base/[0-9]+/[0-9]+' | head -1)
ok "clean full backup (baseline)" principal "pgbackrest --stanza=demo --type=full backup"
pg principal "$BIN/pg_ctl -D $PRI -m fast -w stop" >/dev/null 2>&1
# Corrupt 100 bytes of page 0 of the relation (not touching the stored
# checksum at offset 8 — the checksum is computed over the whole page so any
# change in the data area invalidates it).
on principal "dd if=/dev/urandom of=$PRI/$RELP bs=1 count=100 seek=100 conv=notrunc 2>/dev/null"
pass "corrupted 100 bytes at offset 100 of \$PGDATA/$RELP"
pg principal "$BIN/pg_ctl -D $PRI -l $PRI/server.log -w -t 60 start" >/dev/null 2>&1
out=$(pg principal "pgbackrest --stanza=demo --type=full backup" 2>&1)
rc=$?
if [ "$rc" = "0" ]; then pass "backup completed despite corruption (warn, not abort)"
else printf '%s\n' "$out" | tail -6 >&2; fail "backup did not complete on corruption (exit $rc)"; fi
if printf '%s' "$out" | grep -qiE '(invalid|mismatch).*(page checksum|page header)|page.*checksum.*(invalid|mismatch)'; then pass "backup log warns about invalid page checksum"
else printf '%s\n' "$out" | tail -6 >&2; fail "no invalid-page warning emitted"; fi

############################################################################
hd "Scenario 21 — verify command (repo-side integrity check, clean + corruption)"
# verify walks the repo and re-validates each backup file (reverse-chains then
# SHA-1s the bytes, mirroring the writer's plaintext checksum) and each WAL
# segment. A clean repo verifies cleanly; corrupting a backup file makes the
# verify exit non-zero with a clear corruption hint (either a checksum-class
# message or a decompress-class one — bytes mangled mid-stream fail the gz
# inflate step before SHA-1 can be taken, which is itself a real corruption
# detection signal). Companion to bfb275403 (verify: honour per-holder
# compress suffix + reverse-hash to plaintext), which fixed the previously-
# broken clean-repo path that flagged every compressed file as "missing".
prepare_principal
psql_on principal 5433 "CREATE TABLE t(i int); INSERT INTO t SELECT generate_series(1,500)" >/dev/null
ok "full backup (for verify)" principal "pgbackrest --stanza=demo --type=full backup"
ok "verify on clean repo" principal "pgbackrest --stanza=demo verify"
# Corrupt one of the backed-up files. Avoid backup.manifest* and backup.info*
# (those have their own per-file checksums and would trip a different code
# path); aim for a real bundled / compressed payload.
LABEL_DIR=$(on principal "ls -d /var/lib/pgbackrest/backup/demo/*F | head -1")
TARGET=$(on principal "find $LABEL_DIR -type f ! -name 'backup.manifest*' ! -name 'backup.info*' -size +1k | head -1")
on principal "dd if=/dev/urandom of=$TARGET bs=128 count=4 seek=2 conv=notrunc 2>/dev/null"
pass "corrupted 512 bytes of $TARGET"
out=$(pg principal "pgbackrest --stanza=demo verify" 2>&1)
rc=$?
if [ "$rc" != "0" ]; then pass "verify exited non-zero on corruption (exit $rc)"
else printf '%s\n' "$out" | tail -6 >&2; fail "verify did not detect corruption"; fi
# Accept ANY corruption indicator: a checksum mismatch, an explicit "invalid"
# wording, or a decompression-stage error (gz/zst/bz2/lz4 inflate failures
# are themselves real corruption detections — the bytes were unreadable).
if printf '%s' "$out" | grep -qiE 'checksum|invalid|mismatch|corrupt|inflate|decompress|zlib'; then pass "verify log surfaces a corruption signal"
else printf '%s\n' "$out" | tail -8 >&2; fail "verify log surfaces no corruption signal"; fi

############################################################################
hd "Scenario 22 — start / stop commands (pause/resume archiving + backups)"
# `stop` creates <lock-path>/<stanza>.stop locally; backup + archive-push then
# refuse with "stop file exists for stanza <name>" until `start` removes it.
# Companion to 44dd361c4 (control: write stop file locally + gate backup +
# archive on stop file), which fixed the previously-noop pair.
LOCK=/tmp/pgbackrest
prepare_principal
# Ensure no stale stop file from a prior run / scenario.
on principal "rm -f $LOCK/*.stop 2>/dev/null; true"
psql_on principal 5433 "CREATE TABLE t(i int); INSERT INTO t SELECT generate_series(1,500)" >/dev/null
ok "baseline backup (before stop)" principal "pgbackrest --stanza=demo --type=full backup"
ok "stop command" principal "pgbackrest --stanza=demo stop"
sf=$(on principal "ls $LOCK/demo.stop 2>/dev/null")
assert_contains "$sf" "demo.stop" "stop file created at $LOCK/demo.stop"
out=$(pg principal "pgbackrest --stanza=demo --type=full backup" 2>&1)
rc=$?
if [ "$rc" != "0" ]; then pass "backup is blocked while stopped (exit $rc)"
else printf '%s\n' "$out" | tail -4 >&2; fail "backup ran despite stop file"; fi
if printf '%s' "$out" | grep -qiE 'stop file exists'; then pass "refusal message names the stop file"
else printf '%s\n' "$out" | tail -4 >&2; fail "refusal message lacks 'stop file exists'"; fi
ok "start command" principal "pgbackrest --stanza=demo start"
nostf=$(on principal "ls $LOCK/demo.stop 2>/dev/null; true")
if [ -z "$nostf" ]; then pass "stop file removed by start"
else fail "stop file still present after start ($nostf)"; fi
ok "backup after start (resumed)" principal "pgbackrest --stanza=demo --type=full backup"

############################################################################
hd "Scenario 23 — stanza-delete (gated on stop file, repo cleared)"
# Stock pgBackRest requires `stop` before `stanza-delete` (the operator must
# explicitly confirm the stanza is offline before any wipe). Companion to
# af0f497ff (stanza: gate stanza-delete on stop file). Asserts (a) delete
# without stop refuses with a clear error, (b) after stop the delete clears
# archive/<stanza> + backup/<stanza>, (c) a clean stanza-create succeeds
# afterwards proving no residue.
LOCK=/tmp/pgbackrest
prepare_principal
on principal "rm -f $LOCK/*.stop 2>/dev/null; true"
psql_on principal 5433 "CREATE TABLE t(i int); INSERT INTO t SELECT generate_series(1,300)" >/dev/null
ok "full backup (so the stanza has something to delete)" principal "pgbackrest --stanza=demo --type=full backup"
exists=$(on principal "test -d /var/lib/pgbackrest/backup/demo && echo yes || echo no")
assert_contains "$exists" "yes" "backup/demo present before delete"
out=$(pg principal "pgbackrest --stanza=demo stanza-delete" 2>&1)
rc=$?
if [ "$rc" != "0" ]; then pass "stanza-delete refused without stop file (exit $rc)"
else printf '%s\n' "$out" | tail -3 >&2; fail "stanza-delete ran without stop file"; fi
if printf '%s' "$out" | grep -qiE 'stop file'; then pass "refusal message mentions 'stop file'"
else printf '%s\n' "$out" | tail -3 >&2; fail "refusal message lacks 'stop file' hint"; fi
ok "stop (to authorise the delete)" principal "pgbackrest --stanza=demo stop"
ok "stanza-delete (after stop)" principal "pgbackrest --stanza=demo stanza-delete"
gone_b=$(on principal "test -d /var/lib/pgbackrest/backup/demo && echo yes || echo no")
gone_a=$(on principal "test -d /var/lib/pgbackrest/archive/demo && echo yes || echo no")
if [ "$gone_b" = "no" ] && [ "$gone_a" = "no" ]; then pass "archive/demo + backup/demo both removed"
else fail "stanza dirs remain after delete (backup=$gone_b archive=$gone_a)"; fi
# Cleanup: start to remove stop file so the rest of the suite is unaffected.
pg principal "pgbackrest --stanza=demo start" >/dev/null 2>&1 || true
# Fresh stanza-create proves no residue prevents reuse of the name.
ok "stanza-create after delete (no residue)" principal "pgbackrest --stanza=demo stanza-create"

############################################################################
hd "Scenario 24 — repo-put / repo-ls / repo-get / repo-rm (low-level repo cmds)"
# The four low-level repository commands (command.html). repo-put behaves
# like unix `tee` (does NOT create parent directories), so use a top-level
# path. End-to-end: write, list, read-back, remove, verify gone.
prepare_principal
PAYLOAD="hello-pgbackrest-repo-put-$(date +%s)"
ok "repo-put hello.txt (stdin -> repo)" principal "printf '%s' '$PAYLOAD' | pgbackrest repo-put hello.txt"
ls_out=$(pg principal "pgbackrest repo-ls")
if printf '%s' "$ls_out" | grep -qE '^hello\.txt$'; then pass "repo-ls lists hello.txt"
else printf '%s\n' "$ls_out" | head -5 >&2; fail "repo-ls did not list hello.txt"; fi
got=$(pg principal "pgbackrest repo-get hello.txt")
if [ "$got" = "$PAYLOAD" ]; then pass "repo-get round-trips bytes byte-for-byte"
else fail "repo-get bytes mismatch (want '$PAYLOAD' got '$got')"; fi
ok "repo-rm hello.txt" principal "pgbackrest repo-rm hello.txt"
ls_after=$(pg principal "pgbackrest repo-ls")
if ! printf '%s' "$ls_after" | grep -qE '^hello\.txt$'; then pass "hello.txt absent after repo-rm"
else fail "hello.txt still listed after repo-rm"; fi

############################################################################
printf '\n==================================================\n'
printf 'VALIDATION SUMMARY: %d passed, %d failed\n' "$PASS" "$FAIL"
printf '==================================================\n'
[ "$FAIL" -eq 0 ]
