#!/usr/bin/env bash
# Port of Vagrant Scenario 14 — "backup-standby=y" (KB Exemple 8: backup runs on
# the repo host with a standby configured).
#
# Topology: depot = repo host (orchestrator), principal = primary, secondaire =
# streaming standby of principal. Depot's phase-2 config lists pg1=principal +
# pg2=secondaire with STRICT backup-standby=y (05-standby.sh only covers
# `prefer`).
#
# What this proves: strict backup-standby=y is accepted with a live streaming
# standby configured as pg2, and the backup completes (pg_backup_start/stop on
# pg1). It does NOT prove that PGDATA files are read from pg2: the binary
# currently reads them from the primary, as it logs:
#   backup-standby: standby is remote; reading files from the primary data
#   directory (consistent; remote-standby read offload not yet plumbed)
# The resulting backup is then restored on principal and must carry the rows
# inserted after the standby was built.
set -euo pipefail
. "$(dirname "$0")/_lib.sh"

STANZA=demo
PRI_DATA=/var/lib/postgresql/$PGV/principal
STB_DATA=/var/lib/postgresql/$PGV/secondaire
REPO=/srv/depot/pgbackrust
BIN=/usr/lib/postgresql/$PGV/bin

info "22 backup-standby: depot phase 1 — pg1 (primary) only"
# pg2 + backup-standby=y are added only once the standby is streaming: with
# them configured now, check/backup would fail trying to reach a not-yet-running
# secondaire (and strict mode refuses to run without a standby).
node depot bash -c "cat > /etc/pgbackrust/pgbackrust.conf <<EOF
[global]
repo1-path=$REPO
log-level-console=info
start-fast=y
[$STANZA]
pg1-host=principal
pg1-host-user=postgres
pg1-path=$PRI_DATA
pg1-port=5433
EOF
chown postgres:postgres /etc/pgbackrust/pgbackrust.conf"

info "secondaire restore config (repo on depot, streaming recovery options)"
node secondaire bash -c "cat > /etc/pgbackrust/pgbackrust.conf <<EOF
[global]
repo1-host=depot
repo1-host-user=postgres
repo1-path=$REPO
delta=y
log-level-console=info
[$STANZA]
pg1-path=$STB_DATA
pg1-port=5434
recovery-option=primary_conninfo=host=principal port=5433 user=replicator
recovery-option=primary_slot_name=secondaire
recovery-option=recovery_target_timeline=latest
EOF
chown postgres:postgres /etc/pgbackrust/pgbackrust.conf"

info "principal config: archive WAL to depot over SSH (repo1-host)"
node principal bash -c "cat > /etc/pgbackrust/pgbackrust.conf <<EOF
[global]
repo1-host=depot
repo1-host-user=postgres
repo1-path=$REPO
log-level-console=info
[$STANZA]
pg1-path=$PRI_DATA
pg1-port=5433
EOF
chown postgres:postgres /etc/pgbackrust/pgbackrust.conf"

node depot bash -c "install -d -o postgres -g postgres -m 0750 $REPO"

reset_principal "$PRI_DATA" "$BIN" "$STANZA"
reset_secondaire "$STB_DATA" "$BIN"
node depot bash -c "install -d -o postgres -g postgres -m 0750 $REPO"

info "create replication role + slot on principal for the standby"
psql_on principal 5433 -c "DO \$\$ BEGIN IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='replicator') THEN CREATE ROLE replicator WITH REPLICATION LOGIN; END IF; END \$\$;"
psql_on principal 5433 -c "SELECT pg_create_physical_replication_slot('secondaire') WHERE NOT EXISTS (SELECT 1 FROM pg_replication_slots WHERE slot_name='secondaire');" >/dev/null
pg_as principal bash -c "grep -q 'replicator.*replication' $PRI_DATA/pg_hba.conf || echo 'host replication replicator all trust' >> $PRI_DATA/pg_hba.conf"
pg_as principal bash -c "$BIN/pg_ctl -D $PRI_DATA -w reload >/dev/null 2>&1 || true"

info "stanza-create + check from depot (no standby yet)"
pg_as depot pgbackrust --stanza=$STANZA stanza-create
pg_as depot pgbackrust --stanza=$STANZA check

info "seed 1500 rows + initial full backup (primary only)"
psql_on principal 5433 -c "CREATE TABLE t(i int);" >/dev/null
psql_on principal 5433 -c "INSERT INTO t SELECT generate_series(1,1500);" >/dev/null
psql_on principal 5433 -c "SELECT pg_switch_wal();" >/dev/null
pg_as depot pgbackrust --stanza=$STANZA --type=full backup

info "restore secondaire as a streaming standby from the depot repo"
pg_as secondaire bash -c "rm -rf $STB_DATA/* 2>/dev/null || true"
pg_as secondaire pgbackrust --stanza=$STANZA --type=standby --delta restore
if node secondaire bash -c "test -f $STB_DATA/standby.signal"; then
  pass "standby.signal written"
else
  node secondaire bash -c "tail -25 $STB_DATA/server.log" >&2 || true
  fail "standby.signal missing after restore --type=standby"
fi

info "start secondaire on 5434 and confirm it is a streaming standby"
pg_as secondaire bash -c "chmod 0700 $STB_DATA; echo 'port=5434' >> $STB_DATA/postgresql.auto.conf; $BIN/pg_ctl -D $STB_DATA -l $STB_DATA/server.log -w -t 90 start" || true
wait_for "secondaire accepts connections" 60 1 \
  bash -c "$COMPOSE exec -T -u postgres secondaire $BIN/pg_isready -p 5434 -q"
inrec=$(psql_on secondaire 5434 -c "SELECT pg_is_in_recovery();" | tr -d '\r')
if [ "$inrec" = "t" ]; then
  pass "standby is in recovery"
else
  pg_as secondaire tail -25 "$STB_DATA/server.log" >&2 || true
  fail "standby setup (in_recovery=$inrec)"
fi

info "more rows on the primary; wait for the standby to catch up (2000 rows)"
psql_on principal 5433 -c "INSERT INTO t SELECT generate_series(1501,2000);" >/dev/null
psql_on principal 5433 -c "SELECT pg_switch_wal();" >/dev/null
psql_on principal 5433 -c "CHECKPOINT;" >/dev/null
psql_on principal 5433 -c "SELECT pg_switch_wal();" >/dev/null
wait_for "standby has replayed 2000 rows" 60 2 \
  bash -c "[ \"\$($COMPOSE exec -T -u postgres secondaire $BIN/psql -p 5434 -X -A -t -c \"SELECT count(*) FROM t\" 2>/dev/null | tr -d '\r')\" = 2000 ]"
prows=$(psql_on principal 5433 -c "SELECT count(*) FROM t;" | tr -d '\r')
srows=$(psql_on secondaire 5434 -c "SELECT count(*) FROM t;" | tr -d '\r')
if [ "$prows" = "2000" ] && [ "$srows" = "2000" ]; then
  pass "primary + standby caught up (2000 rows each)"
else
  fail "replication mismatch (primary=$prows standby=$srows, want 2000/2000)"
fi

# backup-standby needs the standby to reach the backup-start LSN: assert real
# streaming (primary_conninfo handoff), not just archive replay.
wait_for "primary sees the standby streaming (pg_stat_replication=1)" 60 1 \
  bash -c "[ \"\$($COMPOSE exec -T -u postgres principal $BIN/psql -p 5433 -X -A -t -c \"SELECT count(*) FROM pg_stat_replication\" 2>/dev/null | tr -d '\r')\" = 1 ]"

info "depot phase 2: add pg2 (standby) + STRICT backup-standby=y"
node depot bash -c "cat > /etc/pgbackrust/pgbackrust.conf <<EOF
[global]
repo1-path=$REPO
backup-standby=y
log-level-console=info
start-fast=y
[$STANZA]
pg1-host=principal
pg1-host-user=postgres
pg1-path=$PRI_DATA
pg1-port=5433
pg2-host=secondaire
pg2-host-user=postgres
pg2-path=$STB_DATA
pg2-port=5434
EOF
chown postgres:postgres /etc/pgbackrust/pgbackrust.conf"

info "full backup with backup-standby=y + streaming pg2 (start/stop on pg1; files currently read from the primary, remote-standby read offload not yet plumbed)"
out=$(pg_as depot bash -c "timeout -s KILL 300 pgbackrust --stanza=$STANZA --type=full backup 2>&1") || true
printf '%s\n' "$out" | tail -8
# Completion marker emitted by the product is "backup <label> complete: ...".
assert_contains "$out" "complete:" "backup-standby=y backup completed"

out=$(pg_as depot pgbackrust --stanza=$STANZA info)
fulls=$(printf '%s\n' "$out" | grep -cE 'full backup' || true)
fulls=${fulls:-0}
if [ "$fulls" -ge 2 ]; then
  pass "info shows $fulls full backups (initial + standby)"
else
  printf '%s\n' "$out" >&2
  fail "info doesn't show >=2 full backups (got $fulls)"
fi

info "cross-validate: restore the latest (standby) backup on principal"
pg_as secondaire bash -c "$BIN/pg_ctl -D $STB_DATA -m fast -w stop" || true
pg_as principal bash -c "$BIN/pg_ctl -D $PRI_DATA -w stop" || true
# principal's conf (repo1-host=depot) from the top of the scenario is already
# what this restore needs, so it is not rewritten here.
pg_as principal pgbackrust --stanza=$STANZA --delta restore
pg_as principal bash -c "chmod 0700 $PRI_DATA; $BIN/pg_ctl -D $PRI_DATA -l $PRI_DATA/server.log -w -t 90 start" || true
if ! wait_for "principal accepts connections after restore" 60 1 \
  bash -c "$COMPOSE exec -T -u postgres principal $BIN/pg_isready -p 5433 -q"; then
  node principal bash -c "tail -40 $PRI_DATA/server.log" >&2 || true
  fail "principal did not come up after restoring the standby backup"
fi

rows=$(psql_on principal 5433 -c "SELECT count(*) FROM t;" | tr -d '\r')
if [ "$rows" = "2000" ]; then
  pass "standby backup restored data (2000 rows)"
else
  pg_as principal tail -25 "$PRI_DATA/server.log" >&2 || true
  fail "standby backup restore (got: $rows, want 2000)"
fi

pass "22 backup-standby complete (strict backup-standby=y + restore of the standby backup)"
