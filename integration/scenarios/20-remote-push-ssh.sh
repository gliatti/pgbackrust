#!/usr/bin/env bash
# Port of Vagrant Scenario 3 — "backup to a dedicated remote repository over SSH
# (depot)", the PUSH topology.
#
# The inverse of 02-remote-pull-ssh: here the backup runs ON `principal` (local
# DB connection) and the repository lives on `depot`, reached over SSH via
# repo1-host=depot. Only repository I/O + archive-push go over the SSH worker.
# Proves: stanza-create / check / backup / info / --delta restore all work with
# a remote repo, and the backup lands on depot (none on principal's filesystem).
set -euo pipefail
. "$(dirname "$0")/_lib.sh"

STANZA=demo
DATADIR=/var/lib/postgresql/$PGV/principal
REPO=/srv/depot/pgbackrust
BIN=/usr/lib/postgresql/$PGV/bin

info "20 remote-push: depot is a plain repository host"
node depot bash -c "install -d -o postgres -g postgres -m 0750 $REPO"
node depot bash -c "cat > /etc/pgbackrust/pgbackrust.conf <<EOF
[global]
repo1-path=$REPO
log-level-console=info
EOF
chown postgres:postgres /etc/pgbackrust/pgbackrust.conf"

info "principal config: repository remote on depot over SSH (repo1-host)"
node principal bash -c "cat > /etc/pgbackrust/pgbackrust.conf <<EOF
[global]
repo1-host=depot
repo1-host-user=postgres
repo1-path=$REPO
repo1-retention-full=2
log-level-console=info
start-fast=y
[$STANZA]
pg1-path=$DATADIR
pg1-port=5433
EOF
chown postgres:postgres /etc/pgbackrust/pgbackrust.conf"

reset_principal "$DATADIR" "$BIN" "$STANZA"

# reset_principal wipes /srv/depot/* on both nodes: recreate the repo dir on
# depot, and an EMPTY same-named dir on principal so the placement check below
# would catch a backup mistakenly written to principal's local filesystem.
node depot bash -c "install -d -o postgres -g postgres -m 0750 $REPO"
node principal bash -c "install -d -o postgres -g postgres -m 0750 $REPO"

info "verify SSH reachability postgres@principal -> postgres@depot"
pg_as principal ssh -o BatchMode=yes depot true && pass "principal->depot ssh"

info "stanza-create from principal (remote repo on depot)"
pg_as principal pgbackrust --stanza=$STANZA stanza-create

info "check from principal (remote repo write + WAL archive over SSH)"
pg_as principal pgbackrust --stanza=$STANZA check

info "seed 1500 rows"
psql_on principal 5433 -c "CREATE TABLE t(i int);" >/dev/null
psql_on principal 5433 -c "INSERT INTO t SELECT generate_series(1,1500);" >/dev/null
psql_on principal 5433 -c "SELECT pg_switch_wal();" >/dev/null

info "full backup launched from principal (push to depot)"
pg_as principal pgbackrust --stanza=$STANZA --type=full backup

info "placement: backup must live on depot, not principal"
count_full() {
  node "$1" bash -c "find $REPO/backup/$STANZA -mindepth 1 -maxdepth 1 -type d -name '*F' 2>/dev/null | wc -l" \
    | tr -d '[:space:]'
}
dep_has=$(count_full depot || true)
pri_has=$(count_full principal || true)
dep_has=${dep_has:-0}
pri_has=${pri_has:-0}
if [ "$dep_has" -ge 1 ] && [ "$pri_has" -eq 0 ]; then
  pass "backup stored on depot (depot=$dep_has principal=$pri_has)"
else
  fail "backup placement (depot=$dep_has principal=$pri_has, want depot>=1 principal=0)"
fi

out=$(pg_as principal pgbackrust --stanza=$STANZA info)
assert_contains "$out" "status: ok" "info from principal"
assert_contains "$out" "full backup" "info from principal"

info "stop, --delta restore (reads the remote repo on depot over SSH)"
pg_as principal bash -c "$BIN/pg_ctl -D $DATADIR -w stop" || true
pg_as principal pgbackrust --stanza=$STANZA --delta restore
pg_as principal bash -c "chmod 0700 $DATADIR; $BIN/pg_ctl -D $DATADIR -l $DATADIR/server.log -w -t 90 start"
wait_for "principal accepts connections after restore" 60 1 \
  bash -c "$COMPOSE exec -T -u postgres principal $BIN/pg_isready -p 5433 -q"

rows=$(psql_on principal 5433 -c "SELECT count(*) FROM t;" | tr -d '\r')
if [ "$rows" = "1500" ]; then
  pass "remote-repo restored data (1500 rows)"
else
  pg_as principal tail -25 "$DATADIR/server.log" >&2 || true
  fail "remote-repo restored data (got: $rows, want 1500)"
fi

pass "20 remote-push-ssh complete"
