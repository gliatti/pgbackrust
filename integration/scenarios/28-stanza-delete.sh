#!/usr/bin/env bash
# Port of Vagrant Scenario 23: stanza-delete (gated on stop file, repo cleared).
#
# Stock pgBackRest requires `stop` before `stanza-delete` (the operator must
# explicitly confirm the stanza is offline before any wipe). Proves:
#   (a) stanza-delete without stop refuses (non-zero) mentioning the stop file;
#   (b) after stop, stanza-delete clears archive/<stanza> + backup/<stanza>;
#   (c) a fresh stanza-create succeeds afterwards (no residue).
set -euo pipefail
. "$(dirname "$0")/_lib.sh"

STANZA=demo
DATADIR=/var/lib/postgresql/$PGV/principal
REPO=/srv/depot/pgbackrust
BIN=/usr/lib/postgresql/$PGV/bin
LOCK=/tmp/pgbackrust

info "28 stanza-delete: configure principal as its own repo host"
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

info "stanza-create + seed + full backup (so the stanza has something to delete)"
pg_as principal pgbackrust --stanza=$STANZA stanza-create
psql_on principal 5433 -c "CREATE TABLE t(i int); INSERT INTO t SELECT generate_series(1,300)" >/dev/null
pg_as principal pgbackrust --stanza=$STANZA --type=full backup
if node principal test -d $REPO/backup/$STANZA; then
  pass "backup/$STANZA present before delete"
else
  fail "backup/$STANZA missing before delete"
fi

info "stanza-delete WITHOUT stop MUST be refused"
set +e
out=$(pg_as principal pgbackrust --stanza=$STANZA stanza-delete 2>&1)
rc=$?
set -e
printf '%s\n' "$out"
if [ "$rc" -ne 0 ]; then
  pass "stanza-delete refused without stop file (exit $rc)"
else
  fail "stanza-delete ran without stop file"
fi
if printf '%s' "$out" | grep -qiE 'stop file'; then
  pass "refusal message mentions 'stop file'"
else
  fail "refusal message lacks 'stop file' hint"
fi

info "stop (to authorise the delete) + stanza-delete"
pg_as principal pgbackrust --stanza=$STANZA stop
pg_as principal pgbackrust --stanza=$STANZA stanza-delete
gone_b=$(node principal bash -c "test -d $REPO/backup/$STANZA && echo yes || echo no" | tr -d '\r')
gone_a=$(node principal bash -c "test -d $REPO/archive/$STANZA && echo yes || echo no" | tr -d '\r')
if [ "$gone_b" = "no" ] && [ "$gone_a" = "no" ]; then
  pass "archive/$STANZA + backup/$STANZA both removed"
else
  fail "stanza dirs remain after delete (backup=$gone_b archive=$gone_a)"
fi

info "start (remove stop file) + fresh stanza-create (no residue)"
pg_as principal pgbackrust --stanza=$STANZA start
pg_as principal pgbackrust --stanza=$STANZA stanza-create
pass "stanza-create after delete succeeded (no residue)"

pass "28 stanza-delete complete"
