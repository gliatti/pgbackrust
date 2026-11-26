#!/usr/bin/env bash
# Port of Vagrant Scenario 13 — "restore to an alternate datadir
# (--pg1-path=<other>)".
#
# A full backup of principal's normal cluster is restored into a DIFFERENT data
# directory via --pg1-path, and that copy is started on its own port (5434)
# inside the principal container. Recovery only succeeds if PG's
# restore_command — `pgbackrust archive-get %f "%p"`, run with cwd=PGDATA —
# delivers the fetched WAL to the cwd-relative %p and not under pg1-path.
# Regression guard for that contract (fixed in c4ef0bb30).
set -euo pipefail
. "$(dirname "$0")/_lib.sh"

STANZA=demo
DATADIR=/var/lib/postgresql/$PGV/principal
ALT=/var/lib/postgresql/$PGV/alt-restore
REPO=/srv/depot/pgbackrust
BIN=/usr/lib/postgresql/$PGV/bin

info "21 alt-datadir: principal is its own repo host (local repo1-path)"
node principal bash -c "install -d -o postgres -g postgres -m 0750 $REPO"
node principal bash -c "cat > /etc/pgbackrust/pgbackrust.conf <<EOF
[global]
repo1-path=$REPO
repo1-retention-full=2
log-level-console=info
start-fast=y
[$STANZA]
pg1-path=$DATADIR
pg1-port=5433
EOF
chown postgres:postgres /etc/pgbackrust/pgbackrust.conf"

reset_principal "$DATADIR" "$BIN" "$STANZA"
node principal bash -c "install -d -o postgres -g postgres -m 0750 $REPO"

info "stanza-create + check"
pg_as principal pgbackrust --stanza=$STANZA stanza-create
pg_as principal pgbackrust --stanza=$STANZA check

info "seed 1500 rows + full backup (for the alt restore)"
psql_on principal 5433 -c "CREATE TABLE t(i int);" >/dev/null
psql_on principal 5433 -c "INSERT INTO t SELECT generate_series(1,1500);" >/dev/null
psql_on principal 5433 -c "SELECT pg_switch_wal();" >/dev/null
pg_as principal pgbackrust --stanza=$STANZA --type=full backup

info "prepare an empty alternate datadir $ALT"
pg_as principal bash -c "$BIN/pg_ctl -D $ALT -m fast -w stop >/dev/null 2>&1 || true"
node principal bash -c "rm -rf $ALT; install -d -o postgres -g postgres -m 0700 $ALT"

info "stop the original cluster, restore --pg1-path=$ALT"
pg_as principal bash -c "$BIN/pg_ctl -D $DATADIR -w stop" || true
pg_as principal pgbackrust --stanza=$STANZA --pg1-path=$ALT --delta restore

pv=$(node principal bash -c "test -f $ALT/PG_VERSION && cat $ALT/PG_VERSION || echo MISSING" | tr -d '\r')
assert_contains "$pv" "$PGV" "alt-restore PG_VERSION"

info "start the alt cluster on port 5434 inside principal"
pg_as principal bash -c "chmod 0700 $ALT; $BIN/pg_ctl -D $ALT -o '-p 5434' -l $ALT/server.log -w -t 90 start" || true
wait_for "alt cluster accepts connections on 5434" 60 1 \
  bash -c "$COMPOSE exec -T -u postgres principal $BIN/pg_isready -p 5434 -q" || {
  pg_as principal tail -25 "$ALT/server.log" >&2 || true
  fail "alt cluster did not come up on 5434"
}

rows=$(psql_on principal 5434 -c "SELECT count(*) FROM t;" | tr -d '\r')
if [ "$rows" = "1500" ]; then
  pass "alt cluster recovered + serves 1500 rows on port 5434"
else
  pg_as principal tail -25 "$ALT/server.log" >&2 || true
  fail "alt cluster rows (got: $rows, want 1500)"
fi

info "stop the alt cluster, restart the original cluster"
pg_as principal bash -c "$BIN/pg_ctl -D $ALT -m fast -w stop" || true
pg_as principal bash -c "$BIN/pg_ctl -D $DATADIR -l $DATADIR/server.log -w start"
pg_ready principal 5433 "$BIN"

pass "21 alt-datadir complete"
