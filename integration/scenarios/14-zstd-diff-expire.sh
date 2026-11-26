#!/usr/bin/env bash
# Port of Vagrant Scenario 5 — zstd compression + differential backup +
# retention/expire (integration/vagrant/run-validation.sh).
#
# Proves that a repo configured with compress-type=zst / compress-level=3
# stores backup files with the .zst suffix, that a differential backup can be
# taken on top of a zstd full, and that `expire --repo1-retention-full=1`
# removes the older of two full backups (full dirs 2 -> 1).
set -euo pipefail
. "$(dirname "$0")/_lib.sh"

STANZA=demo
DATADIR=/var/lib/postgresql/$PGV/principal
REPO=/srv/depot/pgbackrust
BIN=/usr/lib/postgresql/$PGV/bin

info "14 zstd-diff-expire: local repo with compress-type=zst, compress-level=3"
node principal bash -c "install -d -o postgres -g postgres -m 0750 $REPO"
node principal bash -c "cat > /etc/pgbackrust/pgbackrust.conf <<EOF
[global]
repo1-path=$REPO
repo1-retention-full=2
compress-type=zst
compress-level=3
log-level-console=info
log-path=/var/log/pgbackrust
start-fast=y
[$STANZA]
pg1-path=$DATADIR
pg1-port=5433
EOF
chown postgres:postgres /etc/pgbackrust/pgbackrust.conf"

reset_principal "$DATADIR" "$BIN" "$STANZA"
node principal bash -c "install -d -o postgres -g postgres -m 0750 $REPO"

info "stanza-create + check (zstd repo)"
pg_as principal pgbackrust --stanza=$STANZA stanza-create
pg_as principal pgbackrust --stanza=$STANZA check

info "seed data + full backup #1 (zstd)"
psql_on principal 5433 -c "CREATE TABLE t(i int)" >/dev/null
psql_on principal 5433 -c "INSERT INTO t SELECT generate_series(1,1000)" >/dev/null
psql_on principal 5433 -c "SELECT pg_switch_wal()" >/dev/null
pg_as principal pgbackrust --stanza=$STANZA --type=full backup

info "stored backup files must carry the .zst suffix"
zst=$(node principal bash -c "ls $REPO/backup/$STANZA/*F/global/pg_control* 2>/dev/null" | tr -d '\r' || true)
assert_contains "$zst" ".zst" "backup files zstd-compressed (.zst suffix)"

info "more data + differential backup (zstd)"
psql_on principal 5433 -c "INSERT INTO t SELECT generate_series(1001,1500)" >/dev/null
psql_on principal 5433 -c "SELECT pg_switch_wal()" >/dev/null
pg_as principal pgbackrust --stanza=$STANZA --type=diff backup

info "full backup #2 (zstd)"
pg_as principal pgbackrust --stanza=$STANZA --type=full backup

info "expire --repo1-retention-full=1 must keep only the newest full"
fulls_before=$(node principal bash -c "ls $REPO/backup/$STANZA/ 2>/dev/null | grep -cE 'F\$' || true" | tr -d '\r')
pg_as principal pgbackrust --stanza=$STANZA expire --repo1-retention-full=1
fulls_after=$(node principal bash -c "ls $REPO/backup/$STANZA/ 2>/dev/null | grep -cE 'F\$' || true" | tr -d '\r')
if [ "${fulls_before:-0}" = "2" ] && [ "${fulls_after:-0}" = "1" ]; then
  pass "expire kept newest full only ($fulls_before -> $fulls_after)"
else
  node principal bash -c "ls -l $REPO/backup/$STANZA/" >&2 || true
  fail "expire retention (full dirs before=$fulls_before after=$fulls_after, want 2 -> 1)"
fi

pass "14 zstd-diff-expire complete"
