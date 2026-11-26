#!/usr/bin/env bash
# Port of Vagrant Scenario 20: checksum-page detects a corrupted relation page.
#
# The cluster is initdb'd with --data-checksums (reset_principal), so the
# default checksum-page resolves dynamically from pg_control to "on" and a
# corrupt page IS detected even without --checksum-page on the CLI. This
# scenario takes a clean baseline full backup, corrupts 100 bytes of page 0 of
# a user relation while PG is stopped, then asserts the next full backup
# COMPLETES (exit 0: a warning, not an abort) AND logs an invalid-page warning.
set -euo pipefail
. "$(dirname "$0")/_lib.sh"

STANZA=demo
DATADIR=/var/lib/postgresql/$PGV/principal
REPO=/srv/depot/pgbackrust
BIN=/usr/lib/postgresql/$PGV/bin

info "25 checksum-page: configure principal as its own repo host"
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

info "stanza-create"
pg_as principal pgbackrust --stanza=$STANZA stanza-create

info "cluster must have data_checksums=on (reset_principal initdbs --data-checksums)"
dch=$(psql_on principal 5433 -c "SHOW data_checksums" | tr -d '\r' | grep -oE 'on|off' | head -1 || true)
assert_contains "$dch" "on" "cluster has data_checksums=on"

info "seed a relation with ~200 wide rows + CHECKPOINT"
psql_on principal 5433 -c "CREATE TABLE t(i int, s text)" >/dev/null
psql_on principal 5433 -c "INSERT INTO t SELECT g, repeat('x',1000) FROM generate_series(1,200) g" >/dev/null
psql_on principal 5433 -c "CHECKPOINT" >/dev/null
RELP=$(psql_on principal 5433 -c "SELECT pg_relation_filepath('t')" | tr -d '\r' | grep -oE '^base/[0-9]+/[0-9]+' | head -1 || true)
[ -n "$RELP" ] || fail "could not resolve relation file path of t"
info "relation file: \$PGDATA/$RELP"

info "clean full backup (baseline)"
pg_as principal pgbackrust --stanza=$STANZA --type=full backup

info "stop PG and corrupt page 0 of the relation"
pg_as principal bash -c "$BIN/pg_ctl -D $DATADIR -m fast -w stop"
# Corrupt 100 bytes at offset 100 of page 0 (not touching the stored checksum
# at offset 8 — the checksum covers the whole page so any data-area change
# invalidates it).
pg_as principal bash -c "dd if=/dev/urandom of=$DATADIR/$RELP bs=1 count=100 seek=100 conv=notrunc status=none"
pass "corrupted 100 bytes at offset 100 of \$PGDATA/$RELP"
pg_as principal bash -c "$BIN/pg_ctl -D $DATADIR -l $DATADIR/server.log -w -t 60 start"
pg_ready principal 5433 "$BIN"

info "full backup over the corrupted page must complete AND warn"
set +e
out=$(pg_as principal pgbackrust --stanza=$STANZA --type=full backup 2>&1)
rc=$?
set -e
printf '%s\n' "$out"
if [ "$rc" -eq 0 ]; then
  pass "backup completed despite corruption (warn, not abort)"
else
  fail "backup did not complete on corruption (exit $rc)"
fi
if printf '%s' "$out" | grep -qiE '(invalid|mismatch).*(page checksum|page header)|page.*checksum.*(invalid|mismatch)'; then
  pass "backup log warns about invalid page checksum"
else
  fail "no invalid-page warning emitted"
fi

pass "25 checksum-page complete"
