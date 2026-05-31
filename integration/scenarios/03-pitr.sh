#!/usr/bin/env bash
# KB "Restauration avec retour en arrière (PITR)".
#
# Takes a full backup, records a target time, makes further changes, then
# restores with --type=time --target=<time> and verifies the post-target
# changes are absent while pre-target data is present. Validates the recovery
# config pgBackRest writes (recovery_target_time + restore_command +
# recovery.signal).
set -euo pipefail
. "$(dirname "$0")/_lib.sh"

STANZA=demo
DATADIR=/var/lib/postgresql/$PGV/principal
BIN=/usr/lib/postgresql/$PGV/bin

info "03 pitr: assumes stanza=$STANZA already initialized (run 01 first)"
pg_as principal pgbackrest --stanza=$STANZA --type=full backup

info "seed pre-target data + capture target time"
psql_on principal 5433 -c "CREATE TABLE IF NOT EXISTS pitr(label text);"
psql_on principal 5433 -c "INSERT INTO pitr VALUES ('before');"
psql_on principal 5433 -c "SELECT pg_switch_wal();" >/dev/null
sleep 2
TARGET=$(psql_on principal 5433 -c "SELECT now();" | tr -d '\r')
info "target time = $TARGET"
sleep 2

info "post-target change that must be rolled back"
psql_on principal 5433 -c "INSERT INTO pitr VALUES ('after');"
psql_on principal 5433 -c "SELECT pg_switch_wal();" >/dev/null

info "stop, PITR restore to target time"
pg_as principal bash -c "$BIN/pg_ctl -D $DATADIR -w stop" || true
pg_as principal pgbackrest --stanza=$STANZA --delta \
  --type=time --target="$TARGET" --target-action=promote restore

info "recovery config written by pgBackRest"
auto=$(node principal bash -c "cat $DATADIR/postgresql.auto.conf")
assert_contains "$auto" "recovery_target_time" "postgresql.auto.conf"
assert_contains "$auto" "restore_command" "postgresql.auto.conf"
node principal bash -c "test -f $DATADIR/recovery.signal" && pass "recovery.signal present"

info "start + let recovery reach the target"
pg_as principal bash -c "$BIN/pg_ctl -D $DATADIR -l $DATADIR/server.log -w start" || true
wait_for "principal accepts connections after PITR" 60 1 \
  bash -c "$COMPOSE exec -T -u postgres principal $BIN/pg_isready -p 5433 -q"

before=$(psql_on principal 5433 -c "SELECT count(*) FROM pitr WHERE label='before';")
after=$(psql_on principal 5433 -c "SELECT count(*) FROM pitr WHERE label='after';")
assert_contains "$before" "1" "pre-target row present"
assert_contains "$after" "0" "post-target row rolled back"

pass "03 pitr complete"
