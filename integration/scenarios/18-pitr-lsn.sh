#!/usr/bin/env bash
# PITR to a WAL LSN (--type=lsn). Port of Vagrant Scenario 16
# (integration/vagrant/run-validation.sh, "PITR to a WAL LSN").
#
# Seeds 1000 rows and takes the full backup (pre-target base), then captures a
# target LSN via pg_current_wal_lsn(), inserts 1000 "future" rows, restores
# with --type=lsn --target=<lsn> --target-action=promote, and proves recovery
# stopped at the target: the cluster is promoted out of recovery, the 1000
# base rows are present and the future rows are gone.
set -euo pipefail
. "$(dirname "$0")/_lib.sh"

STANZA=demo
DATADIR=/var/lib/postgresql/$PGV/principal
REPO=/srv/depot/pgbackrust
BIN=/usr/lib/postgresql/$PGV/bin

dump_log() { node principal bash -c "tail -25 $DATADIR/server.log" >&2 || true; }

info "18 pitr-lsn: self-provision principal as its own repo host"
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
psql_on principal 5433 -c "CREATE TABLE t(i int);" >/dev/null
psql_on principal 5433 -c "INSERT INTO t SELECT generate_series(1,1000);" >/dev/null
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

info "stop, PITR restore to lsn $TGT_LSN"
pg_as principal bash -c "$BIN/pg_ctl -D $DATADIR -m fast -w stop" || true
pg_as principal pgbackrust --stanza=$STANZA --delta \
  --type=lsn --target="$TGT_LSN" --target-action=promote restore

auto=$(node principal bash -c "cat $DATADIR/postgresql.auto.conf")
assert_contains "$auto" "recovery_target_lsn" "postgresql.auto.conf"

info "start + let recovery reach the target and promote"
pg_as principal bash -c "$BIN/pg_ctl -D $DATADIR -l $DATADIR/server.log -w -t 90 start" || true
not_in_recovery() {
  [ "$(psql_on principal 5433 -c "SELECT pg_is_in_recovery();" 2>/dev/null | tr -d '\r')" = "f" ]
}
if ! wait_for "principal promoted after PITR" 90 1 not_in_recovery; then
  dump_log; exit 1
fi

in_rec=$(psql_on principal 5433 -c "SELECT pg_is_in_recovery();" | tr -d '\r')
rows=$(psql_on principal 5433 -c "SELECT count(*) FROM t;" | tr -d '\r')
future=$(psql_on principal 5433 -c "SELECT count(*) FROM t WHERE i>1000;" | tr -d '\r')
if [ "$in_rec" = "f" ] && [ "$rows" = "1000" ] && [ "$future" = "0" ]; then
  pass "PITR(lsn) recovered to target + promoted (1000 base rows kept, future rows dropped)"
else
  dump_log
  fail "PITR(lsn) outcome (in_recovery=$in_rec rows=$rows future=$future, want f / 1000 / 0)"
fi

pass "18 pitr-lsn complete"
