#!/usr/bin/env bash
# End-to-end validation of the Rust pgbackrest binary against the live
# PostgreSQL clusters provisioned in the Vagrant/VirtualBox topology
# (principal / secondaire / depot). Run AFTER `vagrant up` (and after
# ../build-binary.sh has produced the binary). Drives the KB scenarios over
# `vagrant ssh`.
#
#   cd integration/vagrant && PATH="/c/Program Files/Oracle/VirtualBox:$PATH" ./run-validation.sh
set -uo pipefail

PGV="${PGBR_PG_VERSION:-16}"
PASS=0
FAIL=0

pass() { printf '  \033[32mPASS\033[0m %s\n' "$*"; PASS=$((PASS+1)); }
fail() { printf '  \033[31mFAIL\033[0m %s\n' "$*" >&2; FAIL=$((FAIL+1)); }
hd()   { printf '\n=== %s ===\n' "$*"; }

# Run a command as root on a node.
on() { local n="$1"; shift; vagrant ssh "$n" -c "sudo bash -lc '$*'" 2>&1; }
# Run a command as the postgres user on a node. `-H` sets HOME to postgres's
# home so ssh (~/.ssh/config) and pgbackrest find their per-user state.
pg() { local n="$1"; shift; vagrant ssh "$n" -c "sudo -u postgres -H bash -lc '$*'" 2>&1; }
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
  out=$(pg "$node" "$*"); rc=$?
  if [ "$rc" -eq 0 ]; then pass "$desc"; else printf '%s\n' "$out" | grep -v 'Connection to' | tail -5 >&2; fail "$desc (exit $rc)"; fi
}

PRI=/var/lib/postgresql/$PGV/principal
BIN=/usr/lib/postgresql/$PGV/bin

############################################################################
hd "Sanity: binary runs on each node"
for node in depot principal secondaire; do
  out=$(pg "$node" "pgbackrest version")
  assert_contains "$out" "pgBackRest" "$node: pgbackrest version"
done

############################################################################
hd "Scenario 1 — local minimal backup on principal (KB Exemple 1)"
# Reset the repository so the run is deterministic (stanza-create is fresh).
on principal "rm -rf /var/lib/pgbackrest/* 2>/dev/null; true"

# principal is its own repo host (local repo). Write the minimal config to the
# binary's default path (/etc/pgbackrest/pgbackrest.conf).
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

# archive_command on principal already points at pgbackrest (provisioning); the
# cluster is up on 5433. Create + check the stanza.
ok "stanza-create" principal "pgbackrest --stanza=demo stanza-create"
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
pg principal "$BIN/pg_ctl -D $PRI -l $PRI/server.log -w start" >/dev/null 2>&1
sleep 4
rows=$(psql_on principal 5433 "SELECT count(*) FROM t")
assert_contains "$rows" "1500" "restored data (1500 rows)"

############################################################################
printf '\n==================================================\n'
printf 'VALIDATION SUMMARY: %d passed, %d failed\n' "$PASS" "$FAIL"
printf '==================================================\n'
[ "$FAIL" -eq 0 ]
