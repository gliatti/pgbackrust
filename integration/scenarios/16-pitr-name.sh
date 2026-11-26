#!/usr/bin/env bash
# PITR to a named restore point (--type=name). Port of Vagrant Scenario 2
# (integration/vagrant/run-validation.sh, "PITR to a named restore point").
#
# Takes the full backup FIRST (the base for recovery must precede the target:
# a backup taken after the restore point would be the one restored, recovery
# would start past the target and never reach it). Then seeds 1000 rows,
# creates the restore point `pitr_target`, inserts 500 "future" rows, waits
# until the WAL segment holding the restore point lands in the repo, and
# restores with --type=name --target=pitr_target --target-action=promote.
# Proves the 1000 base rows survive, the 500 future rows do not, and the
# cluster is promoted out of recovery.
set -euo pipefail
. "$(dirname "$0")/_lib.sh"

STANZA=demo
DATADIR=/var/lib/postgresql/$PGV/principal
REPO=/srv/depot/pgbackrust
BIN=/usr/lib/postgresql/$PGV/bin

dump_log() { node principal bash -c "tail -25 $DATADIR/server.log" >&2 || true; }

info "16 pitr-name: self-provision principal as its own repo host"
node principal bash -c "install -d -o postgres -g postgres -m 0750 $REPO"
node principal bash -c "cat > /etc/pgbackrust/pgbackrust.conf <<EOF
[global]
repo1-path=$REPO
repo1-retention-full=2
log-level-console=info
log-path=/var/log/pgbackrust
start-fast=y
[$STANZA]
pg1-path=$DATADIR
pg1-port=5433
EOF
chown postgres:postgres /etc/pgbackrust/pgbackrust.conf"

reset_principal "$DATADIR" "$BIN" "$STANZA"

info "stanza-create + full backup (pre-target base)"
pg_as principal pgbackrust --stanza=$STANZA stanza-create
pg_as principal pgbackrust --stanza=$STANZA check
pg_as principal pgbackrust --stanza=$STANZA --type=full backup

info "seed 1000 base rows, restore point, then 500 future rows"
psql_on principal 5433 -c "CREATE TABLE t(i int);" >/dev/null
psql_on principal 5433 -c "INSERT INTO t SELECT generate_series(1,1000);" >/dev/null
psql_on principal 5433 -c "SELECT pg_create_restore_point('pitr_target');" >/dev/null
psql_on principal 5433 -c "INSERT INTO t SELECT generate_series(1001,1500);" >/dev/null

info "complete + archive the segment holding the restore point"
SEG=$(psql_on principal 5433 -c "SELECT pg_walfile_name(pg_current_wal_lsn());" \
  | tr -d '\r' | grep -oE '[0-9A-F]{24}' | head -1)
[ -n "$SEG" ] || fail "could not capture the restore-point WAL segment name"
psql_on principal 5433 -c "SELECT pg_switch_wal();" >/dev/null
# Archived segments are stored flat as archive/<stanza>/<archive-id>/<seg>[.gz]
# (see crates/pgbr-command/src/archive.rs repo_segment_path) — no -<sha> suffix.
if node principal bash -c "for i in \$(seq 1 60); do find $REPO/archive/$STANZA -type f -name '${SEG}*' 2>/dev/null | grep -q . && exit 0; sleep 1; done; exit 1"; then
  pass "restore-point WAL ($SEG) archived to repo"
else
  fail "restore-point WAL ($SEG) not archived within 60s"
fi

info "stop, PITR restore to the named restore point"
pg_as principal bash -c "$BIN/pg_ctl -D $DATADIR -m fast -w stop" || true
pg_as principal pgbackrust --stanza=$STANZA --delta \
  --type=name --target=pitr_target --target-action=promote restore

auto=$(node principal bash -c "cat $DATADIR/postgresql.auto.conf")
assert_contains "$auto" "recovery_target_name" "postgresql.auto.conf"

info "start + let recovery reach the target and promote"
pg_as principal bash -c "$BIN/pg_ctl -D $DATADIR -l $DATADIR/server.log -w -t 120 start" || true
not_in_recovery() {
  [ "$(psql_on principal 5433 -c "SELECT pg_is_in_recovery();" 2>/dev/null | tr -d '\r')" = "f" ]
}
if ! wait_for "principal promoted after PITR" 120 1 not_in_recovery; then
  dump_log; exit 1
fi

rows=$(psql_on principal 5433 -c "SELECT count(*) FROM t;" | tr -d '\r')
future=$(psql_on principal 5433 -c "SELECT count(*) FROM t WHERE i>1000;" | tr -d '\r')
if [ "$rows" = "1000" ] && [ "$future" = "0" ]; then
  pass "PITR recovered to named target (1000 base rows kept, future rows dropped)"
else
  dump_log
  fail "PITR to named target (rows=$rows future=$future, want rows=1000 future=0)"
fi

pass "16 pitr-name complete"
