#!/usr/bin/env bash
# KB "Gestion des tablespaces" — remapping 1-by-1 (tablespace-map) and in bulk
# (tablespace-map-all), plus a symlinked pg_wal (link-map).
#
# Creates two tablespaces with data, backs up, then restores to fresh paths with
# the tablespaces remapped and STARTS each restored cluster (port 5434 inside
# principal) to prove the tablespace contents really made it into the backup
# (regression guard for issue #11: the old scenario never started the restored
# cluster, so an empty pg_tblspc/<oid> went unnoticed). Also checks:
#   - the repo holds files under pg_tblspc/
#   - pg_tblspc/<oid> symlinks point at the remapped locations
#   - tablespace_map.old is written, never a live tablespace_map
#   - a --delta re-restore onto the same target (links already present) passes
#   - a symlinked pg_wal is recorded as a link and recreated via
#     --link-map pg_wal=<path>, with its target directory created
#
# Restored clusters run with archive_mode=off so they never push a new timeline
# into the shared stanza (that would derail recovery of later restores).
set -euo pipefail
. "$(dirname "$0")/_lib.sh"

STANZA=demo
DATADIR=/var/lib/postgresql/$PGV/principal
REPO=/srv/depot/pgbackrust
BIN=/usr/lib/postgresql/$PGV/bin

ALT=/var/lib/postgresql/restore_tbmap
ALL=/var/lib/postgresql/restore_tball
ALTW=/var/lib/postgresql/restore_tbwal
HDD=/var/lib/postgresql/hdd
HDDW=/var/lib/postgresql/hdd_w
TSALL=/var/lib/postgresql/tablespaces
WALEXT=/var/lib/postgresql/wal_ext
WALRES=/var/lib/postgresql/wal_restored

# start_alt <datadir>: start a restored cluster on 5434 (archiving off) and wait.
start_alt() {
  local dir="$1"
  info "start restored cluster $dir on port 5434"
  pg_as principal bash -c "chmod 0700 $dir; $BIN/pg_ctl -D $dir -o '-p 5434 -c archive_mode=off' -l $dir.log -w -t 90 start" || true
  wait_for "restored cluster $dir accepts connections on 5434" 60 1 \
    bash -c "$COMPOSE exec -T -u postgres principal $BIN/pg_isready -p 5434 -q" || {
    pg_as principal tail -40 "$dir.log" >&2 || true
    fail "restored cluster $dir did not come up on 5434"
  }
}

# stop_alt <datadir>: stop the restored cluster (must succeed: a stale
# postmaster.pid would make the next --delta restore refuse to run).
stop_alt() {
  local dir="$1"
  info "stop restored cluster $dir"
  pg_as principal bash -c "$BIN/pg_ctl -D $dir -m fast -w -t 90 stop" \
    || fail "could not stop restored cluster $dir"
}

# assert_rows <table> <want> <what>: count(*) on the 5434 cluster.
assert_rows() {
  local table="$1" want="$2" what="$3" rows
  rows=$(psql_on principal 5434 -c "SELECT count(*) FROM $table;" 2>&1 | tr -d '\r') || true
  if [ "$rows" = "$want" ]; then
    pass "$what: $table has $want rows"
  else
    fail "$what: $table rows (got: '$rows', want $want)"
  fi
}

# assert_link <link> <want-target> <what>
assert_link() {
  local link="$1" want="$2" what="$3" got
  got=$(node principal readlink "$link" 2>&1 | tr -d '\r') || true
  if [ "$got" = "$want" ]; then
    pass "$what: $link -> $want"
  else
    fail "$what: $link -> '$got' (want $want)"
  fi
}

# assert_node <description> <shell predicate run in principal as root>
assert_node() {
  local what="$1" pred="$2"
  if node principal bash -c "$pred"; then
    pass "$what"
  else
    fail "$what (predicate failed: $pred)"
  fi
}

info "06 tablespaces: self-provision principal as its own repo host"
node principal bash -c "install -d -o postgres -g postgres -m 0750 $REPO"
node principal bash -c "cat > /etc/pgbackrust/pgbackrust.conf <<EOF
[global]
repo1-path=$REPO
repo1-retention-full=2
log-level-console=info
log-path=/var/log/pgbackrust
start-fast=y
[$STANZA]
pg1-path=$DATADIR
pg1-port=5433
EOF
chown postgres:postgres /etc/pgbackrust/pgbackrust.conf"

# Defensive: no restored cluster from a previous run may still hold port 5434.
for d in $ALT $ALL $ALTW; do
  pg_as principal bash -c "$BIN/pg_ctl -D $d -m immediate -w stop >/dev/null 2>&1 || true"
done

reset_principal "$DATADIR" "$BIN" "$STANZA"
pg_as principal pgbackrust --stanza=$STANZA stanza-create

info "06 tablespaces: create tb1/tb2 on principal"
pg_as principal bash -c "rm -rf /var/lib/postgresql/tb1 /var/lib/postgresql/tb2; install -d -o postgres -g postgres /var/lib/postgresql/tb1 /var/lib/postgresql/tb2"
psql_on principal 5433 -c "CREATE TABLESPACE tb1 LOCATION '/var/lib/postgresql/tb1';" || true
psql_on principal 5433 -c "CREATE TABLESPACE tb2 LOCATION '/var/lib/postgresql/tb2';" || true
psql_on principal 5433 -c "CREATE TABLE IF NOT EXISTS ts1(i int) TABLESPACE tb1;"
psql_on principal 5433 -c "INSERT INTO ts1 SELECT generate_series(1,100);"
psql_on principal 5433 -c "CREATE TABLE IF NOT EXISTS ts2(i int) TABLESPACE tb2;"
psql_on principal 5433 -c "INSERT INTO ts2 SELECT generate_series(1,50);"
psql_on principal 5433 -c "CHECKPOINT;" >/dev/null
psql_on principal 5433 -c "SELECT pg_switch_wal();" >/dev/null

oid1=$(psql_on principal 5433 -c "SELECT oid FROM pg_tablespace WHERE spcname='tb1';" | tr -d '\r')
oid2=$(psql_on principal 5433 -c "SELECT oid FROM pg_tablespace WHERE spcname='tb2';" | tr -d '\r')
[ -n "$oid1" ] && [ -n "$oid2" ] || fail "could not resolve tablespace oids (tb1='$oid1', tb2='$oid2')"
info "tablespace oids: tb1=$oid1 tb2=$oid2"

info "full backup capturing the tablespaces"
pg_as principal pgbackrust --stanza=$STANZA --type=full backup
assert_node "repo holds files under pg_tblspc/" \
  "find $REPO/backup/$STANZA -path '*pg_tblspc/*' -type f | grep -q ."
assert_node "repo holds tb1 ($oid1) files" \
  "find $REPO/backup/$STANZA -path '*pg_tblspc/$oid1/*' -type f | grep -q ."
assert_node "repo holds tb2 ($oid2) files" \
  "find $REPO/backup/$STANZA -path '*pg_tblspc/$oid2/*' -type f | grep -q ."

# ---------------------------------------------------------------------------
info "remap 1-by-1 (--tablespace-map) to $ALT"
pg_as principal bash -c "rm -rf $ALT $ALT.log $HDD; install -d -o postgres -g postgres $ALT $HDD/tbl1 $HDD/tbl2"
pg_as principal pgbackrust --stanza=$STANZA \
  --pg1-path=$ALT \
  --tablespace-map=$oid1=$HDD/tbl1 \
  --tablespace-map=$oid2=$HDD/tbl2 \
  --delta restore

assert_link "$ALT/pg_tblspc/$oid1" "$HDD/tbl1" "tb1 remapped"
assert_link "$ALT/pg_tblspc/$oid2" "$HDD/tbl2" "tb2 remapped"
assert_node "tablespace_map.old written in $ALT" "test -f $ALT/tablespace_map.old"
assert_node "no live tablespace_map in $ALT" "test ! -e $ALT/tablespace_map"
assert_node "tb1 data files physically under $HDD/tbl1" "find $HDD/tbl1 -type f | grep -q ."
assert_node "tb2 data files physically under $HDD/tbl2" "find $HDD/tbl2 -type f | grep -q ."

start_alt "$ALT"
assert_rows ts1 100 "1-by-1 remap"
assert_rows ts2 50 "1-by-1 remap"
stop_alt "$ALT"

# ---------------------------------------------------------------------------
info "re-restore --delta onto the same $ALT (tablespace links already present)"
pg_as principal pgbackrust --stanza=$STANZA \
  --pg1-path=$ALT \
  --tablespace-map=$oid1=$HDD/tbl1 \
  --tablespace-map=$oid2=$HDD/tbl2 \
  --delta restore
assert_link "$ALT/pg_tblspc/$oid1" "$HDD/tbl1" "tb1 after delta re-restore"
assert_link "$ALT/pg_tblspc/$oid2" "$HDD/tbl2" "tb2 after delta re-restore"

start_alt "$ALT"
assert_rows ts1 100 "delta re-restore"
assert_rows ts2 50 "delta re-restore"
stop_alt "$ALT"

# ---------------------------------------------------------------------------
info "bulk remap (--tablespace-map-all) to $ALL"
pg_as principal bash -c "rm -rf $ALL $ALL.log $TSALL; install -d -o postgres -g postgres $ALL $TSALL"
pg_as principal pgbackrust --stanza=$STANZA \
  --pg1-path=$ALL \
  --tablespace-map-all=$TSALL \
  --delta restore
assert_node "tablespace-map-all populated $TSALL with data files" "find $TSALL -type f | grep -q ."
for o in $oid1 $oid2; do
  tgt=$(node principal readlink "$ALL/pg_tblspc/$o" 2>&1 | tr -d '\r') || true
  case "$tgt" in
    "$TSALL"/*) pass "map-all: $ALL/pg_tblspc/$o -> $tgt" ;;
    *) fail "map-all: $ALL/pg_tblspc/$o -> '$tgt' (want under $TSALL/)" ;;
  esac
done
assert_node "no live tablespace_map in $ALL" "test ! -e $ALL/tablespace_map"

start_alt "$ALL"
assert_rows ts1 100 "map-all"
assert_rows ts2 50 "map-all"
stop_alt "$ALL"

# ---------------------------------------------------------------------------
info "symlinked pg_wal: move principal's pg_wal to $WALEXT"
pg_as principal bash -c "$BIN/pg_ctl -D $DATADIR -m fast -w -t 90 stop"
pg_as principal bash -c "rm -rf $WALEXT && mv $DATADIR/pg_wal $WALEXT && ln -s $WALEXT $DATADIR/pg_wal"
assert_link "$DATADIR/pg_wal" "$WALEXT" "principal pg_wal symlinked"
pg_as principal bash -c "$BIN/pg_ctl -D $DATADIR -l $DATADIR/server.log -w -t 90 start"
pg_ready principal 5433 "$BIN"
psql_on principal 5433 -c "SELECT pg_switch_wal();" >/dev/null

info "full backup with a symlinked pg_wal"
pg_as principal pgbackrust --stanza=$STANZA --type=full backup
assert_node "manifest records the pg_wal link destination $WALEXT" \
  "find $REPO/backup/$STANZA -name backup.manifest -exec grep -l '$WALEXT' {} + | grep -q ."

info "restore to $ALTW with --tablespace-map + --link-map pg_wal=$WALRES"
# Neither the tablespace targets nor the pg_wal target are pre-created: the
# restore must create them.
pg_as principal bash -c "rm -rf $ALTW $ALTW.log $HDDW $WALRES; install -d -o postgres -g postgres $ALTW"
pg_as principal pgbackrust --stanza=$STANZA \
  --pg1-path=$ALTW \
  --tablespace-map=$oid1=$HDDW/tbl1 \
  --tablespace-map=$oid2=$HDDW/tbl2 \
  --link-map=pg_wal=$WALRES \
  --delta restore

assert_link "$ALTW/pg_wal" "$WALRES" "pg_wal link-mapped"
assert_node "pg_wal link target $WALRES created" "test -d $WALRES"
assert_node "pg_wal/archive_status reachable through the link" "test -d $ALTW/pg_wal/archive_status"
assert_link "$ALTW/pg_tblspc/$oid1" "$HDDW/tbl1" "tb1 remapped (pg_wal backup)"
assert_link "$ALTW/pg_tblspc/$oid2" "$HDDW/tbl2" "tb2 remapped (pg_wal backup)"
assert_node "tb1 data files physically under $HDDW/tbl1" "find $HDDW/tbl1 -type f | grep -q ."

start_alt "$ALTW"
assert_rows ts1 100 "pg_wal link-map"
assert_rows ts2 50 "pg_wal link-map"
assert_node "restored cluster writes WAL into $WALRES" "find $WALRES -type f | grep -q ."
stop_alt "$ALTW"

# principal is still running (restarted above with its symlinked pg_wal).
pg_ready principal 5433 "$BIN"

pass "06 tablespaces complete"
