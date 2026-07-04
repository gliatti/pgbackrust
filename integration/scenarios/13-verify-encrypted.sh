#!/usr/bin/env bash
# `verify` on an ENCRYPTED repository.
#
# Regression guard for the verify-cannot-decrypt bug: verify used to re-read and
# hash the on-disk CIPHERTEXT (it never injected the repository sub-key the way
# restore does), so a perfectly healthy encrypted repo was reported CORRUPT.
#
# This scenario builds an encrypted repo (repo1-cipher-type=aes-256-cbc + a
# passphrase), stanza-creates, seeds data + a full backup, then:
#   1. runs `verify` and asserts it SUCCEEDS (zero problems) on the encrypted
#      repo — i.e. the sub-key is resolved and the plaintext SHA-1s match;
#   2. corrupts one byte of a stored backup file and asserts `verify` DETECTS
#      the damage (non-zero exit), proving it is really checking bytes and not
#      trivially returning success.
set -euo pipefail
. "$(dirname "$0")/_lib.sh"

STANZA=securverify
DATADIR=/var/lib/postgresql/$PGV/principal
REPO=/srv/depot/pgbackrust-venc
BIN=/usr/lib/postgresql/$PGV/bin
PASS="Ohgh8aopeishaeGhfaSh6uk4iu8ohNguChei8oohiequ2iu8oaNgeiwohjaiP4iewaikaeToghai7Aigh0aiy4Ahb9choo6Aegh"

info "13 verify-encrypted: encrypted repo config (cipher set at stanza-create)"
node principal bash -c "install -d -o postgres -g postgres -m 0750 $REPO"
node principal bash -c "cat > /etc/pgbackrust/pgbackrust.conf <<EOF
[global]
repo1-path=$REPO
repo1-retention-full=2
repo1-cipher-type=aes-256-cbc
repo1-cipher-pass=$PASS
log-level-console=info
start-fast=y
[$STANZA]
pg1-path=$DATADIR
pg1-port=5433
EOF
chown postgres:postgres /etc/pgbackrust/pgbackrust.conf"

reset_principal "$DATADIR" "$BIN" "$STANZA"

info "stanza-create on encrypted repo"
pg_as principal pgbackrust --stanza=$STANZA stanza-create

info "the [cipher] section must be present in archive.info / backup.info"
node principal bash -c "grep -l cipher $REPO/archive/$STANZA/archive.info $REPO/backup/$STANZA/backup.info" \
  && pass "cipher section stored in info files"

info "check + seed + full backup on encrypted repo"
pg_as principal pgbackrust --stanza=$STANZA check
psql_on principal 5433 -c "CREATE TABLE IF NOT EXISTS v(i int); INSERT INTO v SELECT generate_series(1,1000);"
pg_as principal pgbackrust --stanza=$STANZA --type=full backup

info "the stored backup files must actually be encrypted (Salted__ framing)"
if node principal bash -c "grep -rqa 'Salted__' $REPO/backup/$STANZA"; then
  pass "encrypted blobs carry the Salted__ cipher framing"
else
  fail "no Salted__ cipher framing found; repo may be plaintext"
fi

info "verify MUST succeed on the healthy encrypted repo (was reporting it corrupt)"
# This is the core assertion: verify resolves the repo sub-key, decrypts every
# manifest + data file, hashes the PLAINTEXT, and finds zero problems. Before the
# fix verify hashed ciphertext and exited non-zero on a clean repo.
out=$(pg_as principal pgbackrust --stanza=$STANZA verify 2>&1)
printf '%s\n' "$out"
assert_contains "$out" "0 problem(s)" "verify reports zero problems on clean encrypted repo"
pass "verify succeeded (0 problems) on the encrypted repo"

info "verify MUST detect a corrupted encrypted backup file"
# Pick one real (non-info, non-manifest) stored file under the backup dir and
# flip its last byte in place. The recomputed plaintext SHA-1 (or the decrypt
# itself) then no longer matches, so verify must exit non-zero.
TARGET=$(node principal bash -c "find $REPO/backup/$STANZA -type f \
  ! -name 'backup.manifest*' ! -name 'backup.info*' | head -n1")
[ -n "$TARGET" ] || fail "no stored backup file found to corrupt"
info "corrupting one byte of: $TARGET"
node principal bash -c "sz=\$(stat -c%s '$TARGET'); \
  printf '\\xff' | dd of='$TARGET' bs=1 seek=\$((sz-1)) count=1 conv=notrunc status=none"

# Verify must now FAIL (non-zero exit). Capture the status without tripping set -e.
set +e
corrupt_out=$(pg_as principal pgbackrust --stanza=$STANZA verify 2>&1)
corrupt_rc=$?
set -e
printf '%s\n' "$corrupt_out"
if [ "$corrupt_rc" -ne 0 ]; then
  pass "verify detected the corrupted encrypted backup file (exit $corrupt_rc)"
else
  fail "verify passed on a corrupted encrypted repo; corruption went undetected"
fi

pass "13 verify-encrypted complete"
