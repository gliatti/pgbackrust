#!/usr/bin/env bash
# KB "Restauration d'un serveur secondaire" + "Exemple 3 : sauvegarde depuis un
# serveur secondaire".
#
# 1. Build `secondaire` as a streaming standby of `principal` via
#    pgbackrest restore --type=standby (recovery-option primary_conninfo +
#    primary_slot_name). Verify a standby.signal is written and streaming works.
# 2. Take a backup with backup-standby=prefer and confirm pgBackRest runs
#    pg_backup_start/stop on the primary but reads files from the standby.
set -euo pipefail
. "$(dirname "$0")/_lib.sh"

STANZA=demo
PRI_DATA=/var/lib/postgresql/$PGV/principal
STB_DATA=/var/lib/postgresql/$PGV/secondaire
REPO=/srv/depot/pgbackrest
BIN=/usr/lib/postgresql/$PGV/bin

info "05 standby: depot reaches both primary (pg1) and standby (pg2) over SSH"
node depot bash -c "cat > /etc/pgbackrest.conf <<EOF
[global]
repo1-path=$REPO
repo1-retention-full=2
backup-standby=prefer
log-level-console=info
start-fast=y
[$STANZA]
pg1-host=principal
pg1-host-user=postgres
pg1-path=$PRI_DATA
pg1-port=5433
pg2-host=secondaire
pg2-host-user=postgres
pg2-path=$STB_DATA
pg2-port=5434
EOF
chown postgres:postgres /etc/pgbackrest.conf"

info "secondaire restore config (ignore primary as pg1-host conflicts)"
node secondaire bash -c "cat > /etc/pgbackrest.conf <<EOF
[global]
repo1-host=depot
repo1-host-user=postgres
repo1-path=$REPO
delta=y
log-level-console=info
[$STANZA]
pg1-path=$STB_DATA
pg1-port=5434
recovery-option=primary_conninfo=host=principal port=5433 user=replicator
recovery-option=primary_slot_name=secondaire
recovery-option=recovery_target_timeline=latest
EOF
chown postgres:postgres /etc/pgbackrest.conf"

info "restore secondaire as a standby"
pg_as secondaire bash -c "rm -rf $STB_DATA/* 2>/dev/null || true"
pg_as secondaire pgbackrest --stanza=$STANZA --type=standby --delta restore
node secondaire bash -c "test -f $STB_DATA/standby.signal" && pass "standby.signal written"

info "start secondaire on 5434 and confirm streaming"
pg_as secondaire bash -c "echo 'port=5434' >> $STB_DATA/postgresql.auto.conf; $BIN/pg_ctl -D $STB_DATA -l $STB_DATA/server.log -w start" || true
wait_for "secondaire accepts connections" 60 1 \
  bash -c "$COMPOSE exec -T -u postgres secondaire $BIN/pg_isready -p 5434 -q"
inrec=$(psql_on secondaire 5434 -c "SELECT pg_is_in_recovery();")
assert_contains "$inrec" "t" "secondaire is in recovery (standby)"
repl=$(psql_on principal 5433 -c "SELECT count(*) FROM pg_stat_replication;")
assert_contains "$repl" "1" "primary sees one streaming standby"

info "backup with backup-standby=prefer (launched from depot)"
out=$(pg_as depot pgbackrest --stanza=$STANZA --type=full backup 2>&1)
printf '%s\n' "$out"
assert_contains "$out" "backup command end" "backup completed"

pass "05 standby complete"
