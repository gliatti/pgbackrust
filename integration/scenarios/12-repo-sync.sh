#!/usr/bin/env bash
# repo-sync (Layer 1): byte-identical mirroring of backups + WAL between repos.
#
# Models the intended topology: the primary archives to repo1 ONLY (repo1 is the
# only repository in pgbackrust.conf, so archive_command targets just it), and
# repo1 then SYNCHRONISES backups + WAL to repo2. repo2 is the sync TARGET — it
# is supplied on the CLI (R2OPTS) only to the commands that must see it
# (stanza-create, repo-sync, info, restore), never to the archive path. Because
# the repos are configured as byte-identical mirrors (compression global;
# identical bundling, block-incremental, and cipher-type; and — for an encrypted
# mirror — a SHARED cipher sub-key, which repo-sync establishes by aligning the
# fresh, empty target's sub-key to the source's on the first sync) syncing is a
# PURE RAW BYTE COPY of the stored objects at the SAME repo paths.
#
# Asserts:
#   - repo2 starts empty (the primary never archived to it)
#   - repo-sync aligns repo2's sub-key and mirrors WAL + the full backup
#   - a synced bundle object is BYTE-IDENTICAL across repos (raw copy, no re-encode)
#   - repo-sync --type=wal is idempotent (a rerun changes nothing)
#   - a diff backup + repo-sync mirrors the whole dependency chain (ancestor backfill)
#   - restore --repo=2 reconstructs the data from the mirrored, encrypted repo
#   - the inline `backup --repo-sync` option mirrors a just-completed backup directly
set -euo pipefail
. "$(dirname "$0")/_lib.sh"

STANZA=mirror
DATADIR=/var/lib/postgresql/$PGV/principal
R1=/srv/depot/repo1
R2=/srv/depot/repo2
BIN=/usr/lib/postgresql/$PGV/bin
# A single shared user passphrase. Each repo still gets its OWN random sub-key at
# stanza-create; repo-sync aligns repo2's sub-key to repo1's on the first sync
# (repo2 is empty at that point), after which the stored bytes are identical.
PASS="aiZ4eewiethoh4boWaiTeiDie0oonaibaewahSi8uh6iXai1nu9aijohGhex9aefae6Arahqu1au3mee5ohXipiiHvohphiGoa7e"

# repo2 is supplied on the CLI so it exists only for the sync/info/restore
# commands, never for the primary's archive_command. Two sets, because not every
# command accepts every option:
#   R2_BASE  — storage + cipher only; valid for stanza-create / info / restore.
#   R2OPTS   — adds the bundling/block toggles; valid for repo-sync / backup and
#              REQUIRED there so repo-sync sees repo2 as a byte-identical mirror
#              of repo1 (its consistency check compares these per-repo options).
R2_BASE="--repo2-path=$R2 --repo2-cipher-type=aes-256-cbc --repo2-cipher-pass=$PASS"
R2OPTS="$R2_BASE --repo2-bundle=y --repo2-bundle-limit=2MiB --repo2-bundle-size=20MiB --repo2-block=y"

info "12 repo-sync: archive to repo1 only; repo1 mirrors backups+WAL to repo2 (bundle+block+cipher)"
node principal bash -c "install -d -o postgres -g postgres -m 0750 $R1 $R2"
node principal bash -c "cat > /etc/pgbackrust/pgbackrust.conf <<EOF
[global]
repo1-path=$R1
repo1-retention-full=5
repo1-bundle=y
repo1-bundle-limit=2MiB
repo1-bundle-size=20MiB
repo1-block=y
repo1-cipher-type=aes-256-cbc
repo1-cipher-pass=$PASS
compress-type=gz
compress-level=1
log-level-console=info
start-fast=y
[$STANZA]
pg1-path=$DATADIR
pg1-port=5433
EOF
chown postgres:postgres /etc/pgbackrust/pgbackrust.conf"

reset_principal "$DATADIR" "$BIN" "$STANZA"

info "stanza-create initializes repo1 (conf) AND repo2 (CLI) — each gets its own sub-key"
pg_as principal pgbackrust --stanza=$STANZA $R2_BASE stanza-create
node principal bash -c "test -f $R1/backup/$STANZA/backup.info && test -f $R2/backup/$STANZA/backup.info" \
  && pass "both repos initialized"

info "seed data + full backup on repo1 ONLY (archive_command targets repo1)"
psql_on principal 5433 -c "CREATE TABLE m(i int); INSERT INTO m SELECT generate_series(1,1000);"
psql_on principal 5433 -c "SELECT pg_switch_wal();" >/dev/null
wait_for "WAL on repo1" 30 1 \
  bash -c "$COMPOSE exec -T principal bash -c 'ls $R1/archive/$STANZA/*/0000* 2>/dev/null | grep -q .'"
pg_as principal pgbackrust --stanza=$STANZA --repo=1 --type=full backup

FULL=$(node principal bash -c "ls $R1/backup/$STANZA | grep -E 'F\$' | head -1")
[ -n "$FULL" ] || fail "could not determine full backup label on repo1"
info "full backup label = $FULL"

info "repo2 is empty before repo-sync (the primary never archived to it)"
node principal bash -c "test ! -d $R2/backup/$STANZA/$FULL" \
  && pass "repo2 has no backup before repo-sync"
node principal bash -c "! ls $R2/archive/$STANZA/*/0000* >/dev/null 2>&1" \
  && pass "repo2 has no WAL before repo-sync"

info "repo-sync (repo1 -> repo2): align repo2 sub-key, then mirror WAL + the full backup"
out=$(pg_as principal pgbackrust --stanza=$STANZA $R2OPTS repo-sync)
assert_contains "$out" "repo-sync" "repo-sync output"

info "repo2 now carries the mirrored WAL and the full backup"
node principal bash -c "ls $R2/archive/$STANZA/*/0000* >/dev/null 2>&1" \
  && pass "repo-sync mirrored WAL to repo2"
node principal bash -c "test -d $R2/backup/$STANZA/$FULL && test -f $R2/backup/$STANZA/$FULL/backup.manifest" \
  && pass "repo2 has the synced full backup"
node principal bash -c "ls $R2/backup/$STANZA/$FULL/bundle/* >/dev/null 2>&1" \
  && pass "repo2 has a synced bundle file"
b2=$(pg_as principal pgbackrust --stanza=$STANZA $R2_BASE --repo=2 info)
assert_contains "$b2" "full backup" "repo2 info after repo-sync"

info "the synced stored object is BYTE-IDENTICAL (raw copy under the shared sub-key)"
OBJ=$(node principal bash -c "cd $R1/backup/$STANZA/$FULL && ls bundle/* 2>/dev/null | head -1")
[ -n "$OBJ" ] || OBJ=backup.manifest
h1=$(node principal bash -c "sha256sum $R1/backup/$STANZA/$FULL/$OBJ | awk '{print \$1}'")
h2=$(node principal bash -c "sha256sum $R2/backup/$STANZA/$FULL/$OBJ | awk '{print \$1}'")
if [ -n "$h1" ] && [ "$h1" = "$h2" ]; then
  pass "stored object $OBJ is byte-identical across repos ($h1)"
else
  fail "stored object $OBJ differs across repos (repo1=$h1 repo2=$h2)"
fi

info "repo-sync --type=wal rerun is an idempotent no-op (present segments skipped)"
seg_before=$(node principal bash -c "cd $R2/archive/$STANZA && find . -type f | sort | sha256sum")
pg_as principal pgbackrust --stanza=$STANZA $R2OPTS --type=wal repo-sync >/dev/null
seg_after=$(node principal bash -c "cd $R2/archive/$STANZA && find . -type f | sort | sha256sum")
if [ "$seg_before" = "$seg_after" ]; then
  pass "repo-sync --type=wal rerun left repo2 unchanged (idempotent)"
else
  fail "repo-sync --type=wal rerun changed repo2 (not idempotent)"
fi

info "diff backup on repo1, then repo-sync mirrors the whole dependency chain to repo2"
psql_on principal 5433 -c "INSERT INTO m SELECT generate_series(1001,2000);"
psql_on principal 5433 -c "SELECT pg_switch_wal();" >/dev/null
pg_as principal pgbackrust --stanza=$STANZA --repo=1 --type=diff backup
DIFF=$(node principal bash -c "ls $R1/backup/$STANZA | grep -E 'D\$' | head -1")
[ -n "$DIFF" ] || fail "could not determine diff backup label on repo1"
info "diff backup label = $DIFF (depends on $FULL)"
pg_as principal pgbackrust --stanza=$STANZA $R2OPTS --type=backup repo-sync
node principal bash -c "test -d $R2/backup/$STANZA/$DIFF && test -f $R2/backup/$STANZA/$DIFF/backup.manifest" \
  && pass "repo2 has the synced diff backup"
node principal bash -c "test -d $R2/backup/$STANZA/$FULL" \
  && pass "repo2 retains the full ancestor (chain intact)"
b2=$(pg_as principal pgbackrust --stanza=$STANZA $R2_BASE --repo=2 info)
assert_contains "$b2" "diff backup" "repo2 info chain (diff)"

info "restore --repo=2 reconstructs the data from the MIRRORED encrypted repo"
pg_as principal bash -c "$BIN/pg_ctl -D $DATADIR -w stop" || true
pg_as principal pgbackrust --stanza=$STANZA $R2_BASE --repo=2 --delta restore
pg_as principal bash -c "$BIN/pg_ctl -D $DATADIR -l $DATADIR/server.log -w start"
wait_for "principal up after restore from repo2" 30 1 \
  bash -c "$COMPOSE exec -T -u postgres principal $BIN/pg_isready -p 5433 -q"
rows=$(psql_on principal 5433 -c "SELECT count(*) FROM m;")
assert_contains "$rows" "2000" "restored row count from mirrored repo2"

info "inline option: backup --repo-sync mirrors the just-completed backup to repo2 directly"
psql_on principal 5433 -c "INSERT INTO m SELECT generate_series(2001,3000);"
psql_on principal 5433 -c "SELECT pg_switch_wal();" >/dev/null
out=$(pg_as principal pgbackrust --stanza=$STANZA $R2OPTS --repo=1 --type=incr --repo-sync backup)
assert_contains "$out" "repo-sync" "inline repo-sync log"
INCR=$(node principal bash -c "ls $R1/backup/$STANZA | grep -E 'I\$' | head -1")
[ -n "$INCR" ] || fail "could not determine incr backup label on repo1"
info "incr backup label = $INCR"
node principal bash -c "test -d $R2/backup/$STANZA/$INCR && test -f $R2/backup/$STANZA/$INCR/backup.manifest" \
  && pass "inline --repo-sync populated repo2 with the incr backup directly"
b2=$(pg_as principal pgbackrust --stanza=$STANZA $R2_BASE --repo=2 info)
assert_contains "$b2" "incr backup" "repo2 info after inline --repo-sync"

pass "12 repo-sync complete"
