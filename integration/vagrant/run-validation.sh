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

prepare_principal() {
  reset_principal_cluster
  on principal "rm -rf /var/lib/pgbackrest/* 2>/dev/null; true"
  on principal "cat > /etc/pgbackrest/pgbackrest.conf <<EOF
[global]
repo1-path=/var/lib/pgbackrest
repo1-retention-full=2
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
printf '\n==================================================\n'
printf 'VALIDATION SUMMARY: %d passed, %d failed\n' "$PASS" "$FAIL"
printf '==================================================\n'
[ "$FAIL" -eq 0 ]
