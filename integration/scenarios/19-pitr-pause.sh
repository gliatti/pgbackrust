#!/usr/bin/env bash
# PITR with --target-action=pause. Port of Vagrant Scenario 19
# (integration/vagrant/run-validation.sh, "PITR --target-action=pause").
#
# The sibling PITR scenarios use --target-action=promote. With pause, once
# recovery reaches the target the cluster STAYS in recovery (replay paused) so
# an operator can inspect the state before committing to a promotion. Seeds
# 1000 rows + full backup, captures a target LSN, inserts 1000 "future" rows,
# restores --type=lsn --target-action=pause, then proves: replay pauses at the
# target with pg_is_in_recovery() = t, and pg_promote() exits recovery with
# the 1000 base rows present and the future rows gone.
set -euo pipefail
. "$(dirname "$0")/_lib.sh"

STANZA=demo
DATADIR=/var/lib/postgresql/$PGV/principal
REPO=/srv/depot/pgbackrust
BIN=/usr/lib/postgresql/$PGV/bin

dump_log() { node principal bash -c "tail -25 $DATADIR/server.log" >&2 || true; }

info "19 pitr-pause: self-provision principal as its own repo host"
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

info "stanza-create + seed 1000 base rows + full backup (pre-target base)"
pg_as principal pgbackrust --stanza=$STANZA stanza-create
pg_as principal pgbackrust --stanza=$STANZA check
psql_on principal 5433 -c "CREATE TABLE t(i int); INSERT INTO t SELECT generate_series(1,1000);" >/dev/null
psql_on principal 5433 -c "SELECT pg_switch_wal();" >/dev/null
pg_as principal pgbackrust --stanza=$STANZA --type=full backup

info "capture target lsn, then 1000 future rows"
psql_on principal 5433 -c "CHECKPOINT;" >/dev/null
TGT_LSN=$(psql_on principal 5433 -c "SELECT pg_current_wal_lsn()::text;" \
  | tr -d '\r' | grep -oE '^[0-9A-Fa-f]+/[0-9A-Fa-f]+$' | head -1)
if [ -n "$TGT_LSN" ]; then pass "captured target lsn ($TGT_LSN)"
else fail "could not capture target lsn"; fi
psql_on principal 5433 -c "INSERT INTO t SELECT generate_series(1001,2000);" >/dev/null
psql_on principal 5433 -c "SELECT pg_switch_wal();" >/dev/null
sleep 5

info "stop, PITR restore to lsn $TGT_LSN with --target-action=pause"
pg_as principal bash -c "$BIN/pg_ctl -D $DATADIR -m fast -w stop" || true
pg_as principal pgbackrust --stanza=$STANZA --delta \
  --type=lsn --target="$TGT_LSN" --target-action=pause restore

auto=$(node principal bash -c "cat $DATADIR/postgresql.auto.conf")
assert_contains "$auto" "recovery_target_lsn" "postgresql.auto.conf"

info "start + wait for replay to pause at the target"
pg_as principal bash -c "$BIN/pg_ctl -D $DATADIR -l $DATADIR/server.log -w -t 90 start" || true
replay_paused() {
  [ "$(psql_on principal 5433 -c "SELECT pg_is_wal_replay_paused();" 2>/dev/null | tr -d '\r')" = "t" ]
}
if ! wait_for "WAL replay paused at the target" 90 1 replay_paused; then
  dump_log; exit 1
fi

in_rec=$(psql_on principal 5433 -c "SELECT pg_is_in_recovery();" | tr -d '\r')
if [ "$in_rec" = "t" ]; then
  pass "cluster stays in recovery (paused) after reaching the target"
else
  dump_log
  fail "cluster did not pause (in_recovery=$in_rec, want t)"
fi

info "pg_promote() exits recovery"
psql_on principal 5433 -c "SELECT pg_promote();" >/dev/null
not_in_recovery() {
  [ "$(psql_on principal 5433 -c "SELECT pg_is_in_recovery();" 2>/dev/null | tr -d '\r')" = "f" ]
}
if ! wait_for "principal promoted by pg_promote()" 60 1 not_in_recovery; then
  dump_log; exit 1
fi

in_rec2=$(psql_on principal 5433 -c "SELECT pg_is_in_recovery();" | tr -d '\r')
rows=$(psql_on principal 5433 -c "SELECT count(*) FROM t;" | tr -d '\r')
future=$(psql_on principal 5433 -c "SELECT count(*) FROM t WHERE i>1000;" | tr -d '\r')
if [ "$in_rec2" = "f" ] && [ "$rows" = "1000" ] && [ "$future" = "0" ]; then
  pass "pg_promote() exits recovery + data matches pause target (1000 base rows kept, future rows dropped)"
else
  dump_log
  fail "post-promote state (in_recovery=$in_rec2 rows=$rows future=$future, want f / 1000 / 0)"
fi

pass "19 pitr-pause complete"
