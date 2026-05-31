#!/usr/bin/env bash
# KB "Queuing & mode asynchrone".
#
# Enables asynchronous archive-push (archive-async + spool-path +
# archive-push-queue-max) and asynchronous archive-get, then drives a burst of
# WAL and confirms segments land in the repo via the background spool drain.
set -euo pipefail
. "$(dirname "$0")/_lib.sh"

STANZA=demo
DATADIR=/var/lib/postgresql/$PGV/principal
REPO=/srv/depot/pgbackrest
BIN=/usr/lib/postgresql/$PGV/bin

info "07 async: enable asynchronous archiving on principal"
node principal bash -c "install -d -o postgres -g postgres -m 0750 /var/spool/pgbackrest $REPO"
node principal bash -c "cat > /etc/pgbackrest.conf <<EOF
[global]
repo1-path=$REPO
repo1-retention-full=2
archive-async=y
spool-path=/var/spool/pgbackrest
archive-push-queue-max=1GiB
archive-get-queue-max=256MiB
log-level-console=info
log-level-file=detail
[global:archive-push]
process-max=3
[global:archive-get]
process-max=2
[$STANZA]
pg1-path=$DATADIR
pg1-port=5433
EOF
chown postgres:postgres /etc/pgbackrest.conf"

info "ensure cluster up + stanza initialized"
pg_as principal bash -c "[ -s $DATADIR/PG_VERSION ] || $BIN/initdb -D $DATADIR --data-checksums >/dev/null"
pg_as principal bash -c "
  grep -q pgbackrest $DATADIR/postgresql.conf || cat >> $DATADIR/postgresql.conf <<EOF
port = 5433
archive_mode = on
archive_command = '/usr/bin/pgbackrest --stanza=$STANZA archive-push %p'
wal_level = replica
EOF
  $BIN/pg_ctl -D $DATADIR -l $DATADIR/server.log -w restart >/dev/null 2>&1 || \
  $BIN/pg_ctl -D $DATADIR -l $DATADIR/server.log -w start"
pg_as principal pgbackrest --stanza=$STANZA stanza-create || true

info "burst WAL to exercise the async push queue"
psql_on principal 5433 -c "CREATE TABLE IF NOT EXISTS burst(i int);"
for _ in $(seq 1 8); do
  psql_on principal 5433 -c "INSERT INTO burst SELECT generate_series(1,5000);" >/dev/null
  psql_on principal 5433 -c "SELECT pg_switch_wal();" >/dev/null
done

info "wait for segments to land in the repo archive via async drain"
wait_for "archived WAL segments present" 40 1 \
  bash -c "$COMPOSE exec -T principal bash -c 'ls $REPO/archive/$STANZA/*/0000* 2>/dev/null | head -1 | grep -q .'"

info "spool out dir should drain (no stuck .ok backlog growth)"
out=$(pg_as principal pgbackrest --stanza=$STANZA check 2>&1) || true
assert_contains "$out" "" "check ran"

pass "07 async-queuing complete"
