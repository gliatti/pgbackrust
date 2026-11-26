#!/usr/bin/env bash
# Port of Vagrant Scenario 24: repo-put / repo-ls / repo-get / repo-rm.
#
# The four low-level repository commands, end to end: write (repo-put reads
# stdin and behaves like unix `tee` — it does NOT create parent directories,
# so a top-level path is used), list, read back byte-for-byte, remove, and
# verify the file is gone.
set -euo pipefail
. "$(dirname "$0")/_lib.sh"

STANZA=demo
DATADIR=/var/lib/postgresql/$PGV/principal
REPO=/srv/depot/pgbackrust
BIN=/usr/lib/postgresql/$PGV/bin

info "29 repo-cmds: configure principal as its own repo host"
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

info "stanza-create"
pg_as principal pgbackrust --stanza=$STANZA stanza-create

PAYLOAD="hello-pgbackrust-repo-put-$(date +%s)"

info "repo-put hello.txt (stdin -> repo)"
pg_as principal bash -c "printf '%s' '$PAYLOAD' | pgbackrust repo-put hello.txt"
pass "repo-put hello.txt"

info "repo-ls must list hello.txt"
ls_out=$(pg_as principal pgbackrust repo-ls | tr -d '\r')
if printf '%s\n' "$ls_out" | grep -qE '^hello\.txt$'; then
  pass "repo-ls lists hello.txt"
else
  printf '%s\n' "$ls_out" >&2
  fail "repo-ls did not list hello.txt"
fi

info "repo-get must round-trip the payload"
got=$(pg_as principal pgbackrust repo-get hello.txt | tr -d '\r')
if [ "$got" = "$PAYLOAD" ]; then
  pass "repo-get round-trips bytes byte-for-byte"
else
  fail "repo-get bytes mismatch (want '$PAYLOAD' got '$got')"
fi

info "repo-rm hello.txt"
pg_as principal pgbackrust repo-rm hello.txt
ls_after=$(pg_as principal pgbackrust repo-ls | tr -d '\r')
if printf '%s\n' "$ls_after" | grep -qE '^hello\.txt$'; then
  fail "hello.txt still listed after repo-rm"
else
  pass "hello.txt absent after repo-rm"
fi

pass "29 repo-cmds complete"
