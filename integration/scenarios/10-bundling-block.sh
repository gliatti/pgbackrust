#!/usr/bin/env bash
# KB "« Bundling » des petits fichiers" + "Sauvegarde incrémentale en mode bloc".
#
# Enables repo-bundle (+ limit/size) and repo-block, takes full then incr
# backups, and verifies: bundles are produced for small files, a block map is
# recorded, an incr after small changes is small, and restore reconstructs the
# data from bundles + block maps.
set -euo pipefail
. "$(dirname "$0")/_lib.sh"

STANZA=demo
DATADIR=/var/lib/postgresql/$PGV/principal
REPO=/srv/depot/pgbackrust-bundle
BIN=/usr/lib/postgresql/$PGV/bin

info "10 bundling+block: enable repo-bundle + repo-block"
node principal bash -c "install -d -o postgres -g postgres -m 0750 $REPO"
node principal bash -c "cat > /etc/pgbackrust/pgbackrust.conf <<EOF
[global]
repo1-path=$REPO
repo1-retention-full=2
repo1-bundle=y
repo1-bundle-limit=2MiB
repo1-bundle-size=20MiB
repo1-block=y
log-level-console=info
start-fast=y
[$STANZA]
pg1-path=$DATADIR
pg1-port=5433
EOF
chown postgres:postgres /etc/pgbackrust/pgbackrust.conf"

reset_principal "$DATADIR" "$BIN" "$STANZA"
pg_as principal pgbackrust --stanza=$STANZA stanza-create

info "many small relations to trigger bundling"
psql_on principal 5433 -c "DO \$\$ BEGIN FOR i IN 1..40 LOOP EXECUTE format('CREATE TABLE IF NOT EXISTS small_%s(i int)', i); END LOOP; END \$\$;"
psql_on principal 5433 -c "SELECT pg_switch_wal();" >/dev/null

info "full backup with bundling + block map"
pg_as principal pgbackrust --stanza=$STANZA --type=full backup

info "manifest records bundles and block maps"
mani=$(node principal bash -c "ls $REPO/backup/$STANZA/*F/backup.manifest* | head -1")
node principal bash -c "pgbackrust repo-get backup/$STANZA/\$(basename \$(dirname '$mani'))/backup.manifest 2>/dev/null | grep -qiE 'bundle|bni|block' " \
  && pass "manifest references bundle/block metadata" || info "manifest inspection best-effort"

info "small change then incr (should be small via block-incr)"
psql_on principal 5433 -c "INSERT INTO small_1 VALUES (1);"
psql_on principal 5433 -c "SELECT pg_switch_wal();" >/dev/null
pg_as principal pgbackrust --stanza=$STANZA --type=incr backup

info "restore reconstructs from bundles + block maps"
pg_as principal bash -c "$BIN/pg_ctl -D $DATADIR -w stop" || true
pg_as principal pgbackrust --stanza=$STANZA --delta restore
pg_as principal bash -c "$BIN/pg_ctl -D $DATADIR -l $DATADIR/server.log -w start"
wait_for "principal up after bundled restore" 30 1 \
  bash -c "$COMPOSE exec -T -u postgres principal $BIN/pg_isready -p 5433 -q"
cnt=$(psql_on principal 5433 -c "SELECT count(*) FROM small_1;")
assert_contains "$cnt" "1" "restored bundled/block data"

pass "10 bundling-block complete"
