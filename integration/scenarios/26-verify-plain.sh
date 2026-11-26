#!/usr/bin/env bash
# Port of Vagrant Scenario 21: `verify` on a PLAIN (unencrypted) repository.
#
# Companion to 13-verify-encrypted.sh (which covers the encrypted variant).
# verify walks the repo and re-validates each backup file (reverse-chains then
# SHA-1s the bytes, mirroring the writer's plaintext checksum) and each WAL
# segment. This scenario proves:
#   1. a clean plain repo verifies cleanly (exit 0);
#   2. corrupting a real stored payload file makes verify exit non-zero with a
#      corruption signal — either checksum-class wording or a decompress-class
#      error (bytes mangled mid-stream fail the gz inflate step before SHA-1
#      can be taken, which is itself a real corruption detection).
set -euo pipefail
. "$(dirname "$0")/_lib.sh"

STANZA=demo
DATADIR=/var/lib/postgresql/$PGV/principal
REPO=/srv/depot/pgbackrust
BIN=/usr/lib/postgresql/$PGV/bin

info "26 verify-plain: configure principal as its own (unencrypted) repo host"
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

info "stanza-create + seed + full backup"
pg_as principal pgbackrust --stanza=$STANZA stanza-create
psql_on principal 5433 -c "CREATE TABLE t(i int); INSERT INTO t SELECT generate_series(1,500)" >/dev/null
pg_as principal pgbackrust --stanza=$STANZA --type=full backup

info "verify MUST succeed on the clean plain repo"
pg_as principal pgbackrust --stanza=$STANZA verify
pass "verify succeeded on the clean repo"

info "corrupt a real stored payload file of the full backup"
# Avoid backup.manifest* and backup.info* (they have their own per-file
# checksums and would trip a different code path); aim for a real
# bundled / compressed payload.
LABEL_DIR=$(node principal bash -c "ls -d $REPO/backup/$STANZA/*F | head -1" | tr -d '\r')
[ -n "$LABEL_DIR" ] || fail "no full-backup label directory found under $REPO/backup/$STANZA"
TARGET=$(node principal bash -c "find $LABEL_DIR -type f \
  ! -name 'backup.manifest*' ! -name 'backup.info*' -size +1k | head -n1" | tr -d '\r')
[ -n "$TARGET" ] || fail "no stored payload file (>1k) found to corrupt"
node principal bash -c "dd if=/dev/urandom of='$TARGET' bs=128 count=4 seek=2 conv=notrunc status=none"
pass "corrupted 512 bytes of $TARGET"

info "verify MUST fail and surface a corruption signal"
set +e
corrupt_out=$(pg_as principal pgbackrust --stanza=$STANZA verify 2>&1)
corrupt_rc=$?
set -e
printf '%s\n' "$corrupt_out"
if [ "$corrupt_rc" -ne 0 ]; then
  pass "verify exited non-zero on corruption (exit $corrupt_rc)"
else
  fail "verify did not detect corruption"
fi
if printf '%s' "$corrupt_out" | grep -qiE 'checksum|invalid|mismatch|corrupt|inflate|decompress|zlib'; then
  pass "verify log surfaces a corruption signal"
else
  fail "verify log surfaces no corruption signal"
fi

pass "26 verify-plain complete"
