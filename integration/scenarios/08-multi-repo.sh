#!/usr/bin/env bash
# KB "Dépôts multiples".
#
# Two repositories with different retention. WAL is archived to both repos
# simultaneously; backups are taken per-repo with --repo=N; info --repo=N shows
# each independently.
set -euo pipefail
. "$(dirname "$0")/_lib.sh"

STANZA=erp
DATADIR=/var/lib/postgresql/$PGV/principal
R1=/srv/depot/repo1
R2=/srv/depot/repo2
BIN=/usr/lib/postgresql/$PGV/bin

info "08 multi-repo: two local repos with different retention"
node principal bash -c "install -d -o postgres -g postgres -m 0750 $R1 $R2"
node principal bash -c "cat > /etc/pgbackrest.conf <<EOF
[global]
repo1-path=$R1
repo1-retention-full=1
repo2-path=$R2
repo2-retention-full=5
log-level-console=info
start-fast=y
[$STANZA]
pg1-path=$DATADIR
pg1-port=5433
EOF
chown postgres:postgres /etc/pgbackrest.conf"

info "ensure cluster up with archiving for stanza=$STANZA"
pg_as principal bash -c "[ -s $DATADIR/PG_VERSION ] || $BIN/initdb -D $DATADIR --data-checksums >/dev/null"
pg_as principal bash -c "
  grep -q \"stanza=$STANZA\" $DATADIR/postgresql.conf || cat >> $DATADIR/postgresql.conf <<EOF
port = 5433
archive_mode = on
archive_command = '/usr/bin/pgbackrest --stanza=$STANZA archive-push %p'
wal_level = replica
EOF
  $BIN/pg_ctl -D $DATADIR -l $DATADIR/server.log -w restart >/dev/null 2>&1 || \
  $BIN/pg_ctl -D $DATADIR -l $DATADIR/server.log -w start"

info "stanza-create initializes BOTH repos"
pg_as principal pgbackrest --stanza=$STANZA stanza-create
node principal bash -c "test -f $R1/backup/$STANZA/backup.info && test -f $R2/backup/$STANZA/backup.info" \
  && pass "both repos initialized"

info "WAL is archived to both repos simultaneously"
psql_on principal 5433 -c "SELECT pg_switch_wal();" >/dev/null
wait_for "WAL on repo1" 30 1 bash -c "$COMPOSE exec -T principal bash -c 'ls $R1/archive/$STANZA/*/0000* 2>/dev/null | grep -q .'"
wait_for "WAL on repo2" 30 1 bash -c "$COMPOSE exec -T principal bash -c 'ls $R2/archive/$STANZA/*/0000* 2>/dev/null | grep -q .'"

info "backups are taken per-repo with --repo=N"
pg_as principal pgbackrest --stanza=$STANZA --repo=1 backup
pg_as principal pgbackrest --stanza=$STANZA --repo=2 backup

i1=$(pg_as principal pgbackrest --stanza=$STANZA --repo=1 info)
i2=$(pg_as principal pgbackrest --stanza=$STANZA --repo=2 info)
assert_contains "$i1" "full backup" "repo1 info"
assert_contains "$i2" "full backup" "repo2 info"

pass "08 multi-repo complete"
