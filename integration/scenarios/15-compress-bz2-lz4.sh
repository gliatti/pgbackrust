#!/usr/bin/env bash
# Port of Vagrant Scenario 11 — compression variants bz2 + lz4
# (integration/vagrant/run-validation.sh; configuration.html compress-type).
#
# Scenario 14 proves zstd; this proves the remaining real codecs are usable end
# to end. For each codec: fresh config with compress-type=<codec>, clean
# cluster + repo, stanza-create, check, full backup whose stored files carry
# the codec suffix (.bz2 / .lz4), then a --delta restore that brings back all
# 1500 rows. The suffix is asserted via `ls ... pg_control*` rather than
# `find | grep -q`, which trips pipefail (SIGPIPE on early grep exit).
set -euo pipefail
. "$(dirname "$0")/_lib.sh"

STANZA=demo
DATADIR=/var/lib/postgresql/$PGV/principal
REPO=/srv/depot/pgbackrust
BIN=/usr/lib/postgresql/$PGV/bin

for CT in bz2 lz4; do
  info "15 compress-bz2-lz4: local repo with compress-type=$CT"
  node principal bash -c "install -d -o postgres -g postgres -m 0750 $REPO"
  node principal bash -c "cat > /etc/pgbackrust/pgbackrust.conf <<EOF
[global]
repo1-path=$REPO
compress-type=$CT
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

  info "stanza-create + check ($CT repo)"
  pg_as principal pgbackrust --stanza=$STANZA stanza-create
  pg_as principal pgbackrust --stanza=$STANZA check

  info "seed 1500 rows + full backup ($CT)"
  psql_on principal 5433 -c "CREATE TABLE t(i int)" >/dev/null
  psql_on principal 5433 -c "INSERT INTO t SELECT generate_series(1,1500)" >/dev/null
  psql_on principal 5433 -c "SELECT pg_switch_wal()" >/dev/null
  pg_as principal pgbackrust --stanza=$STANZA --type=full backup

  info "stored backup files must carry the .$CT suffix"
  sfx=$(node principal bash -c "ls $REPO/backup/$STANZA/*F/global/pg_control* 2>/dev/null" | tr -d '\r' || true)
  assert_contains "$sfx" ".$CT" "backup files $CT-compressed (.$CT suffix)"

  info "delta restore ($CT)"
  pg_as principal bash -c "$BIN/pg_ctl -D $DATADIR -w stop" >/dev/null 2>&1 || true
  pg_as principal pgbackrust --stanza=$STANZA --delta restore
  pg_as principal bash -c "$BIN/pg_ctl -D $DATADIR -l $DATADIR/server.log -w -t 90 start"
  pg_ready principal 5433 "$BIN"

  rows=$(psql_on principal 5433 -c "SELECT count(*) FROM t" | tr -d '\r' | grep -oE '^[0-9]+$' | head -1 || true)
  if [ "$rows" = "1500" ]; then
    pass "$CT restored data (1500 rows)"
  else
    node principal bash -c "tail -20 $DATADIR/server.log" >&2 || true
    fail "$CT restored data (got: $rows)"
  fi
done

pass "15 compress-bz2-lz4 complete"
