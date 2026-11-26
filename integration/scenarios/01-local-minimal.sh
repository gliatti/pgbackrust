#!/usr/bin/env bash
# KB "Exemple 1 : sauvegarde en local, minimaliste".
#
# One PostgreSQL server, repository on the same host, backup taken locally.
# Exercises: stanza-create, check, archive-push (via archive_command),
# backup --type=full / diff / incr, info, and restore --delta.
#
# Runs against the `principal` node which here doubles as its own repo host
# (repo1-path local), matching the KB minimal /etc/pgbackrust/pgbackrust.conf.
set -euo pipefail
. "$(dirname "$0")/_lib.sh"

STANZA=demo
DATADIR=/var/lib/postgresql/$PGV/principal
BIN=/usr/lib/postgresql/$PGV/bin

info "01 local-minimal: configure principal as its own repo host"
node principal bash -c "install -d -o postgres -g postgres -m 0750 /srv/depot/pgbackrust"
node principal bash -c "cat > /etc/pgbackrust/pgbackrust.conf <<EOF
[global]
repo1-path=/srv/depot/pgbackrust
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

info "stanza-create"
pg_as principal pgbackrust --stanza=$STANZA stanza-create

info "check (repo + live archive round-trip)"
pg_as principal pgbackrust --stanza=$STANZA check

info "full backup"
pg_as principal pgbackrust --stanza=$STANZA --type=full backup

info "repository modes (GHSA-5qj2-9x5v-7c87: files 0640, dirs 0750)"
assert_mode principal /srv/depot/pgbackrust/backup/$STANZA 750 "repo backup dir"
assert_mode principal /srv/depot/pgbackrust/backup/$STANZA/backup.info 640 "backup.info"
assert_mode principal /srv/depot/pgbackrust/archive/$STANZA 750 "repo archive dir"
wal=$(node principal bash -c "find /srv/depot/pgbackrust/archive/$STANZA -type f ! -name 'archive.info*' | head -1")
assert_mode principal "$wal" 640 "archived WAL file"

info "generate WAL + incr backup"
psql_on principal 5433 -c "CREATE TABLE IF NOT EXISTS t(i int); INSERT INTO t SELECT generate_series(1,1000);"
psql_on principal 5433 -c "SELECT pg_switch_wal();" >/dev/null
pg_as principal pgbackrust --stanza=$STANZA --type=incr backup

info "info"
out=$(pg_as principal pgbackrust --stanza=$STANZA info)
assert_contains "$out" "status: ok" "info"
assert_contains "$out" "full backup" "info"
assert_contains "$out" "incr backup" "info"

info "repo-* path confinement (GHSA-vq5g-8277-5pwc: CWE-22)"
# The victim is owned by postgres (the user running pgbackrust): a root-owned
# file in sticky /tmp could not be removed by postgres anyway, which would make
# the repo-rm assertion pass even with the vulnerable code.
pg_as principal bash -c "echo outside > /tmp/outside-repo"
if pg_as principal pgbackrust --stanza=$STANZA repo-ls / >/dev/null 2>&1; then
  fail "repo-ls / must be rejected (host root is outside the repository)"
fi
if pg_as principal pgbackrust --stanza=$STANZA repo-get /etc/hostname >/dev/null 2>&1; then
  fail "repo-get /etc/hostname must be rejected"
fi
if pg_as principal pgbackrust --stanza=$STANZA repo-get ../../../../etc/hostname >/dev/null 2>&1; then
  fail "repo-get with ..-escape must be rejected"
fi
if pg_as principal pgbackrust --stanza=$STANZA repo-rm /tmp/outside-repo >/dev/null 2>&1; then
  fail "repo-rm /tmp/outside-repo must be rejected"
fi
node principal test -f /tmp/outside-repo || fail "repo-rm must not delete outside the repository"
pass "repo-ls / , repo-get /etc/hostname, repo-get ..-escape, repo-rm /tmp/outside-repo all rejected"
node principal rm -f /tmp/outside-repo
# repo1-path is /srv/depot/pgbackrust, local to principal (see pgbackrust.conf above).
out=$(pg_as principal pgbackrust --stanza=$STANZA repo-ls /srv/depot/pgbackrust)
assert_contains "$out" "backup" "repo-ls absolute path under repo root is accepted"
out=$(pg_as principal pgbackrust --stanza=$STANZA repo-ls)
assert_contains "$out" "archive" "repo-ls default still lists the repo root"

info "restore --delta to original path after stop"
pg_as principal bash -c "$BIN/pg_ctl -D $DATADIR -w stop" || true
pg_as principal pgbackrust --stanza=$STANZA --delta restore

info "restored modes (GHSA-5qj2-9x5v-7c87: new files 0600, dirs per manifest)"
assert_mode principal $DATADIR/backup_label 600 "backup_label"
assert_mode principal $DATADIR/base 700 "restored base dir"
if node principal test -e $DATADIR/recovery.signal; then
  assert_mode principal $DATADIR/recovery.signal 600 "recovery.signal"
fi

pg_as principal bash -c "$BIN/pg_ctl -D $DATADIR -l $DATADIR/server.log -w start"
wait_for "principal accepts connections after restore" 30 1 \
  bash -c "$COMPOSE exec -T -u postgres principal $BIN/pg_isready -p 5433 -q"
rows=$(psql_on principal 5433 -c "SELECT count(*) FROM t;")
assert_contains "$rows" "1000" "restored table row count"

pass "01 local-minimal complete"
