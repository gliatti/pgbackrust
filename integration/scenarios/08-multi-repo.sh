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
node principal bash -c "cat > /etc/pgbackrust/pgbackrust.conf <<EOF
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
chown postgres:postgres /etc/pgbackrust/pgbackrust.conf"

reset_principal "$DATADIR" "$BIN" "$STANZA"

info "stanza-create initializes BOTH repos"
pg_as principal pgbackrust --stanza=$STANZA stanza-create
node principal bash -c "test -f $R1/backup/$STANZA/backup.info && test -f $R2/backup/$STANZA/backup.info" \
  && pass "both repos initialized"

info "WAL is archived to both repos simultaneously"
psql_on principal 5433 -c "SELECT pg_switch_wal();" >/dev/null
wait_for "WAL on repo1" 30 1 bash -c "$COMPOSE exec -T principal bash -c 'ls $R1/archive/$STANZA/*/0000* 2>/dev/null | grep -q .'"
wait_for "WAL on repo2" 30 1 bash -c "$COMPOSE exec -T principal bash -c 'ls $R2/archive/$STANZA/*/0000* 2>/dev/null | grep -q .'"

info "backups are taken per-repo with --repo=N (first backup of each repo is full)"
# Each repo starts empty, so its first backup must be a full. The default type
# is now full, and an explicit incr/diff with no prior base auto-promotes to a
# full anyway; we still pass --type=full explicitly to make the intent obvious
# (the assertions below verify a full landed in each repo).
pg_as principal pgbackrust --stanza=$STANZA --repo=1 --type=full backup
pg_as principal pgbackrust --stanza=$STANZA --repo=2 --type=full backup

i1=$(pg_as principal pgbackrust --stanza=$STANZA --repo=1 info)
i2=$(pg_as principal pgbackrust --stanza=$STANZA --repo=2 info)
assert_contains "$i1" "full backup" "repo1 info"
assert_contains "$i2" "full backup" "repo2 info"

# Lightweight repo-sync smoke check: both repos already received the same WAL
# (archived simultaneously above) and carry default bundling/block/cipher
# settings, so they are consistent mirrors for WAL. `repo-sync --type=wal` from
# the active repo (repo1) to repo2 must therefore run cleanly and be a pure
# idempotent no-op — every segment is already present on repo2 — without
# disturbing the per-repo backups asserted above. See scenario 12 for the full
# byte-identical mirror exercise.
info "repo-sync --type=wal is a clean no-op when repo2 already has the WAL"
sync_out=$(pg_as principal pgbackrust --stanza=$STANZA --type=wal repo-sync)
assert_contains "$sync_out" "repo-sync" "repo-sync output"
i2b=$(pg_as principal pgbackrust --stanza=$STANZA --repo=2 info)
assert_contains "$i2b" "full backup" "repo2 info unchanged after repo-sync --type=wal"

pass "08 multi-repo complete"
