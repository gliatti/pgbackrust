#!/usr/bin/env bash
# KB "Options avancées : Chiffrement de la sauvegarde".
#
# Encryption is configured on the repo (repo1-cipher-type / repo1-cipher-pass)
# and MUST be in place from stanza-create. Verifies that an encrypted repo
# round-trips: backup, info reports the cipher, repo bytes are not plaintext,
# and restore recovers the data.
set -euo pipefail
. "$(dirname "$0")/_lib.sh"

STANZA=secure
DATADIR=/var/lib/postgresql/$PGV/principal
REPO=/srv/depot/pgbackrust-enc
BIN=/usr/lib/postgresql/$PGV/bin
PASS="vohphiGoa7eiZ4eewiethoh4boWaiTeiDie0oonaibaewahSi8uh6iXai1nu9aijohGhex9aefae6Arahqu1au3mee5ohXipiiH"

info "04 encryption: encrypted repo config (cipher set at stanza-create)"
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

info "check + full backup on encrypted repo"
pg_as principal pgbackrust --stanza=$STANZA check
psql_on principal 5433 -c "CREATE TABLE IF NOT EXISTS s(i int); INSERT INTO s SELECT generate_series(1,500);"
pg_as principal pgbackrust --stanza=$STANZA --type=full backup

info "info must report the cipher type"
out=$(pg_as principal pgbackrust --stanza=$STANZA info)
assert_contains "$out" "cipher: aes-256-cbc" "info cipher line"

info "stored backup files must carry the cipher framing (not plaintext)"
# pgBackRust frames every encrypted blob with the OpenSSL "Salted__" magic
# (CIPHER_BLOCK_MAGIC; AES-256-CBC with a per-blob salt). Its presence in the
# repo is the on-disk proof the bytes are encrypted rather than plaintext.
if node principal bash -c "grep -rqa 'Salted__' $REPO/backup/$STANZA"; then
  pass "encrypted blobs carry the Salted__ cipher framing"
else
  fail "no Salted__ cipher framing found; repo may be plaintext"
fi

info "backup_label in the backup root must be encrypted (GHSA-8265-5345-wr5g)"
# The label is stored as backup_label<transform suffix> in the backup root.
# Under a cipher it must start with the Salted__ magic, and its plaintext
# content ("START WAL LOCATION: ...") must appear nowhere in the backup tree.
last_backup=$(node principal bash -c "ls -1d $REPO/backup/$STANZA/2*/ 2>/dev/null | sort | tail -n1" || true)
[ -n "$last_backup" ] || fail "no backup directory found under $REPO/backup/$STANZA"
label_file=$(node principal bash -c "ls -1 ${last_backup}backup_label* 2>/dev/null | head -n1" || true)
[ -n "$label_file" ] || fail "no backup_label* file in $last_backup"
label_magic=$(node principal head -c8 "$label_file")
if [ "$label_magic" = "Salted__" ]; then
  pass "backup_label stored encrypted ($(basename "$label_file") starts with Salted__)"
else
  fail "backup_label $label_file is not encrypted (magic '$label_magic')"
fi
if node principal bash -c "grep -rqa 'START WAL LOCATION' $REPO/backup/$STANZA"; then
  fail "backup_label content found in cleartext under $REPO/backup/$STANZA"
else
  pass "no cleartext backup_label content in the backup tree"
fi

info "archived WAL in the encrypted repo must carry the cipher framing"
# Every regular file below the archive-id directories (segments, .history,
# .backup) must start with Salted__. check + backup normally pushed at least
# one segment; force a switch and wait if none is present yet.
wal_count() { node principal bash -c "find $REPO/archive/$STANZA -mindepth 2 -type f | wc -l" | tr -d '[:space:]'; }
wal_present() { [ "$(wal_count)" -gt 0 ]; }
if ! wal_present; then
  psql_on principal 5433 -c "SELECT pg_switch_wal();" >/dev/null
  wait_for "a WAL segment archived to the encrypted repo" 30 1 wal_present
fi
plain_wal=$(node principal bash -c "find $REPO/archive/$STANZA -mindepth 2 -type f -print0 \
  | while IFS= read -r -d '' f; do [ \"\$(head -c8 \"\$f\")\" = Salted__ ] || printf '%s\n' \"\$f\"; done")
if [ -z "$plain_wal" ]; then
  pass "all $(wal_count) archived WAL file(s) start with Salted__"
else
  printf '%s\n' "$plain_wal" >&2
  fail "archived WAL file(s) without cipher framing (plaintext)"
fi

info "restore from encrypted repo"
pg_as principal bash -c "$BIN/pg_ctl -D $DATADIR -w stop" || true
pg_as principal pgbackrust --stanza=$STANZA --delta restore
pg_as principal bash -c "$BIN/pg_ctl -D $DATADIR -l $DATADIR/server.log -w start"
wait_for "principal up after encrypted restore" 30 1 \
  bash -c "$COMPOSE exec -T -u postgres principal $BIN/pg_isready -p 5433 -q"
rows=$(psql_on principal 5433 -c "SELECT count(*) FROM s;")
assert_contains "$rows" "500" "restored row count from encrypted repo"

info "repo-put on an encrypted repo must store ciphertext (GHSA-8265-5345-wr5g)"
pg_as principal bash -c "echo cleartext-canary | pgbackrust --stanza=$STANZA repo-put adv-test.txt"
put_file=$(node principal bash -c "ls -1 $REPO/adv-test.txt* 2>/dev/null | head -n1" || true)
[ -n "$put_file" ] || fail "repo-put stored no adv-test.txt* file under $REPO"
put_magic=$(node principal head -c8 "$put_file")
if [ "$put_magic" = "Salted__" ]; then
  pass "repo-put stored $(basename "$put_file") encrypted (Salted__)"
else
  fail "repo-put stored $put_file without cipher framing (magic '$put_magic')"
fi
if node principal bash -c "grep -rqa 'cleartext-canary' $REPO"; then
  fail "repo-put canary found in cleartext under $REPO"
else
  pass "repo-put canary not present in cleartext anywhere in the repo"
fi
got=$(pg_as principal pgbackrust --stanza=$STANZA repo-get adv-test.txt)
assert_contains "$got" "cleartext-canary" "repo-get of the encrypted repo-put file"

# Kept LAST: it temporarily adds an uninitialised repo2 to the config, which
# makes PostgreSQL's archive_command fail until repo2 is removed again.
info "archive-push must refuse a configured repo without stanza-create (GHSA-8265-5345-wr5g)"
REPO2=/srv/depot/pgbackrust-enc2
node principal bash -c "install -d -o postgres -g postgres -m 0750 $REPO2"
# Pick a completed segment already archived to repo1 (.done marker): re-pushing
# it with identical content is accepted, so the positive control below isolates
# the refusal to repo2.
done_seg() {
  pg_as principal bash -c "ls -1 $DATADIR/pg_wal/archive_status/ 2>/dev/null \
    | sed -n 's/^\([0-9A-F]\{24\}\)\.done\$/\1/p' | sort | tail -n1" || true
}
done_seg_present() { [ -n "$(done_seg)" ]; }
# After the restore + promotion pg_wal may hold only the .partial/.history of
# the timeline switch: force a complete segment out through archive_command.
if ! done_seg_present; then
  psql_on principal 5433 -c "SELECT pg_switch_wal();" >/dev/null
  wait_for "a completed WAL segment archived to repo1" 30 1 done_seg_present
fi
seg=$(done_seg)
[ -n "$seg" ] || fail "no archived WAL segment (.done) found in $DATADIR/pg_wal"
pg_as principal pgbackrust --stanza=$STANZA archive-push "$DATADIR/pg_wal/$seg"
pass "control: archive-push of $seg succeeds with only the initialised repo1"
node principal bash -c "sed -i \
  -e '/^\[global\]\$/a repo2-cipher-pass=$PASS' \
  -e '/^\[global\]\$/a repo2-cipher-type=aes-256-cbc' \
  -e '/^\[global\]\$/a repo2-path=$REPO2' \
  /etc/pgbackrust/pgbackrust.conf && chown postgres:postgres /etc/pgbackrust/pgbackrust.conf"
node principal grep -q '^repo2-path=' /etc/pgbackrust/pgbackrust.conf \
  || fail "repo2 was not added to pgbackrust.conf"
if pg_as principal pgbackrust --stanza=$STANZA archive-push "$DATADIR/pg_wal/$seg"; then
  fail "archive-push succeeded although repo2 has no stanza (no archive.info)"
else
  pass "archive-push refused: repo2 is configured but not initialised"
fi
repo2_files=$(node principal bash -c "find $REPO2 -type f")
if [ -z "$repo2_files" ]; then
  pass "nothing was written to uninitialised repo2"
else
  printf '%s\n' "$repo2_files" >&2
  fail "archive-push wrote to uninitialised repo2"
fi
node principal bash -c "sed -i '/^repo2-/d' /etc/pgbackrust/pgbackrust.conf && chown postgres:postgres /etc/pgbackrust/pgbackrust.conf"
pg_as principal pgbackrust --stanza=$STANZA archive-push "$DATADIR/pg_wal/$seg"
pass "repo2 removed from config: archive-push works again"

pass "04 encryption complete"
