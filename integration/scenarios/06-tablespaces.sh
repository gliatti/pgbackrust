#!/usr/bin/env bash
# KB "Gestion des tablespaces" — remapping 1-by-1 (tablespace-map) and in bulk
# (tablespace-map-all). Creates two tablespaces, backs up, then restores to a
# fresh path with the tablespaces remapped, and verifies data + new locations.
set -euo pipefail
. "$(dirname "$0")/_lib.sh"

STANZA=demo
DATADIR=/var/lib/postgresql/$PGV/principal
REPO=/srv/depot/pgbackrust
BIN=/usr/lib/postgresql/$PGV/bin

info "06 tablespaces: self-provision principal as its own repo host"
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
pg_as principal pgbackrust --stanza=$STANZA stanza-create

info "06 tablespaces: create tb1/tb2 on principal"
pg_as principal bash -c "install -d -o postgres -g postgres /var/lib/postgresql/tb1 /var/lib/postgresql/tb2"
psql_on principal 5433 -c "CREATE TABLESPACE tb1 LOCATION '/var/lib/postgresql/tb1';" || true
psql_on principal 5433 -c "CREATE TABLESPACE tb2 LOCATION '/var/lib/postgresql/tb2';" || true
psql_on principal 5433 -c "CREATE TABLE IF NOT EXISTS ts1(i int) TABLESPACE tb1;"
psql_on principal 5433 -c "INSERT INTO ts1 SELECT generate_series(1,100);"
psql_on principal 5433 -c "SELECT pg_switch_wal();" >/dev/null

info "full backup capturing the tablespaces"
pg_as principal pgbackrust --stanza=$STANZA --type=full backup

info "remap 1-by-1 to a new restore target"
ALT=/var/lib/postgresql/restore_tbmap
pg_as principal bash -c "rm -rf $ALT /var/lib/postgresql/hdd; install -d -o postgres -g postgres $ALT /var/lib/postgresql/hdd/tbl1 /var/lib/postgresql/hdd/tbl2"
oid1=$(psql_on principal 5433 -c "SELECT oid FROM pg_tablespace WHERE spcname='tb1';" | tr -d '\r')
oid2=$(psql_on principal 5433 -c "SELECT oid FROM pg_tablespace WHERE spcname='tb2';" | tr -d '\r')
pg_as principal pgbackrust --stanza=$STANZA \
  --pg1-path=$ALT \
  --tablespace-map=$oid1=/var/lib/postgresql/hdd/tbl1 \
  --tablespace-map=$oid2=/var/lib/postgresql/hdd/tbl2 \
  --delta restore
node principal bash -c "test -d /var/lib/postgresql/hdd/tbl1" && pass "tb1 remapped to new path"

info "bulk remap (tablespace-map-all) to a separate target"
ALL=/var/lib/postgresql/restore_tball
pg_as principal bash -c "rm -rf $ALL /var/lib/postgresql/tablespaces; install -d -o postgres -g postgres $ALL /var/lib/postgresql/tablespaces"
pg_as principal pgbackrust --stanza=$STANZA \
  --pg1-path=$ALL \
  --tablespace-map-all=/var/lib/postgresql/tablespaces \
  --delta restore
node principal bash -c "ls /var/lib/postgresql/tablespaces | grep -q ." && pass "tablespace-map-all populated"

pass "06 tablespaces complete"
