#!/usr/bin/env bash
# Port of Vagrant Scenario 22: start / stop commands.
#
# `stop` creates <lock-path>/<stanza>.stop locally (lock path /tmp/pgbackrust);
# backup then refuses with "stop file exists for stanza <name>" until `start`
# removes it. Proves: stop file written by stop, backup blocked (non-zero exit,
# message names the stop file), stop file removed by start, backup resumes.
set -euo pipefail
. "$(dirname "$0")/_lib.sh"

STANZA=demo
DATADIR=/var/lib/postgresql/$PGV/principal
REPO=/srv/depot/pgbackrust
BIN=/usr/lib/postgresql/$PGV/bin
LOCK=/tmp/pgbackrust

info "27 start-stop: configure principal as its own repo host"
node principal bash -c "install -d -o postgres -g postgres -m 0750 $REPO"
node principal bash -c "cat > /etc/pgbackrust/pgbackrust.conf <<EOF
[global]
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

info "clear any stale stop file"
node principal bash -c "rm -f $LOCK/*.stop 2>/dev/null; true"

info "stanza-create + seed + baseline backup (before stop)"
pg_as principal pgbackrust --stanza=$STANZA stanza-create
psql_on principal 5433 -c "CREATE TABLE t(i int); INSERT INTO t SELECT generate_series(1,500)" >/dev/null
pg_as principal pgbackrust --stanza=$STANZA --type=full backup

info "stop"
pg_as principal pgbackrust --stanza=$STANZA stop
if node principal test -f $LOCK/$STANZA.stop; then
  pass "stop file created at $LOCK/$STANZA.stop"
else
  fail "stop file missing at $LOCK/$STANZA.stop after stop"
fi

info "backup MUST be refused while stopped"
set +e
out=$(pg_as principal pgbackrust --stanza=$STANZA --type=full backup 2>&1)
rc=$?
set -e
printf '%s\n' "$out"
if [ "$rc" -ne 0 ]; then
  pass "backup is blocked while stopped (exit $rc)"
else
  fail "backup ran despite stop file"
fi
if printf '%s' "$out" | grep -qiE 'stop file exists'; then
  pass "refusal message names the stop file"
else
  fail "refusal message lacks 'stop file exists'"
fi

info "start"
pg_as principal pgbackrust --stanza=$STANZA start
if node principal test -e $LOCK/$STANZA.stop; then
  fail "stop file still present after start"
else
  pass "stop file removed by start"
fi

info "backup after start (resumed)"
pg_as principal pgbackrust --stanza=$STANZA --type=full backup
pass "backup succeeded after start"

pass "27 start-stop complete"
