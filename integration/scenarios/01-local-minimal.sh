#!/usr/bin/env bash
# KB "Exemple 1 : sauvegarde en local, minimaliste".
#
# One PostgreSQL server, repository on the same host, backup taken locally.
# Exercises: stanza-create, check, archive-push (via archive_command),
# backup --type=full / diff / incr, info, and restore --delta.
#
# Runs against the `principal` node which here doubles as its own repo host
# (repo1-path local), matching the KB minimal /etc/pgbackrest.conf.
set -euo pipefail
. "$(dirname "$0")/_lib.sh"

STANZA=demo
DATADIR=/var/lib/postgresql/$PGV/principal
BIN=/usr/lib/postgresql/$PGV/bin

info "01 local-minimal: configure principal as its own repo host"
node principal bash -c "install -d -o postgres -g postgres -m 0750 /srv/depot/pgbackrest"
node principal bash -c "cat > /etc/pgbackrest.conf <<EOF
[global]
repo1-path=/srv/depot/pgbackrest
repo1-retention-full=2
log-level-console=info
log-path=/var/log/pgbackrest
start-fast=y
[$STANZA]
pg1-path=$DATADIR
pg1-port=5433
EOF
chown postgres:postgres /etc/pgbackrest.conf"

info "initdb + start principal (port 5433) with pgbackrest archiving"
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

info "stanza-create"
pg_as principal pgbackrest --stanza=$STANZA stanza-create

info "check (repo + live archive round-trip)"
pg_as principal pgbackrest --stanza=$STANZA check

info "full backup"
pg_as principal pgbackrest --stanza=$STANZA --type=full backup

info "generate WAL + incr backup"
psql_on principal 5433 -c "CREATE TABLE IF NOT EXISTS t(i int); INSERT INTO t SELECT generate_series(1,1000);"
psql_on principal 5433 -c "SELECT pg_switch_wal();" >/dev/null
pg_as principal pgbackrest --stanza=$STANZA --type=incr backup

info "info"
out=$(pg_as principal pgbackrest --stanza=$STANZA info)
assert_contains "$out" "status: ok" "info"
assert_contains "$out" "full backup" "info"
assert_contains "$out" "incr backup" "info"

info "restore --delta to original path after stop"
pg_as principal bash -c "$BIN/pg_ctl -D $DATADIR -w stop" || true
pg_as principal pgbackrest --stanza=$STANZA --delta restore
pg_as principal bash -c "$BIN/pg_ctl -D $DATADIR -l $DATADIR/server.log -w start"
wait_for "principal accepts connections after restore" 30 1 \
  bash -c "$COMPOSE exec -T -u postgres principal $BIN/pg_isready -p 5433 -q"
rows=$(psql_on principal 5433 -c "SELECT count(*) FROM t;")
assert_contains "$rows" "1000" "restored table row count"

pass "01 local-minimal complete"
