#!/usr/bin/env bash
# KB "Exemple 2 : sauvegarde depuis un serveur distant (pull)".
#
# The backup is launched from `depot`, which reaches the PostgreSQL cluster on
# `principal` over SSH (pg1-host). Archiving runs on `principal` and ships WAL
# to `depot` over SSH (repo1-host). Exercises the inter-host worker transport
# in both directions.
set -euo pipefail
. "$(dirname "$0")/_lib.sh"

STANZA=demo
DATADIR=/var/lib/postgresql/$PGV/principal
REPO=/srv/depot/pgbackrust
BIN=/usr/lib/postgresql/$PGV/bin

info "02 remote-pull: depot config reaches principal over SSH"
node depot bash -c "install -d -o postgres -g postgres -m 0750 $REPO"
node depot bash -c "cat > /etc/pgbackrust/pgbackrust.conf <<EOF
[global]
repo1-path=$REPO
repo1-retention-full=2
log-level-console=info
process-max=2
start-fast=y
[$STANZA]
pg1-host=principal
pg1-host-user=postgres
pg1-path=$DATADIR
pg1-port=5433
pg1-user=postgres
EOF
chown postgres:postgres /etc/pgbackrust/pgbackrust.conf"

info "principal config: archive WAL to depot over SSH (repo1-host)"
node principal bash -c "cat > /etc/pgbackrust/pgbackrust.conf <<EOF
[global]
repo1-host=depot
repo1-host-user=postgres
repo1-path=$REPO
compress-type=gz
compress-level=1
[$STANZA]
pg1-path=$DATADIR
pg1-port=5433
EOF
chown postgres:postgres /etc/pgbackrust/pgbackrust.conf"

reset_principal "$DATADIR" "$BIN" "$STANZA"

info "verify SSH reachability postgres@principal <-> postgres@depot"
pg_as depot ssh -o BatchMode=yes principal true && pass "depot->principal ssh"
pg_as principal ssh -o BatchMode=yes depot true && pass "principal->depot ssh"

info "stanza-create from depot (over SSH to principal)"
pg_as depot pgbackrust --stanza=$STANZA stanza-create

info "check from depot"
pg_as depot pgbackrust --stanza=$STANZA check

info "full backup launched from depot (pull)"
pg_as depot pgbackrust --stanza=$STANZA --type=full backup

out=$(pg_as depot pgbackrust --stanza=$STANZA info)
assert_contains "$out" "status: ok" "info from depot"
assert_contains "$out" "full backup" "info from depot"

pass "02 remote-pull-ssh complete"
