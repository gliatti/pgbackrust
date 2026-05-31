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
node principal bash -c "cat > /etc/pgbackrust.conf <<EOF
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
chown postgres:postgres /etc/pgbackrust.conf"

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

info "restore from encrypted repo"
pg_as principal bash -c "$BIN/pg_ctl -D $DATADIR -w stop" || true
pg_as principal pgbackrust --stanza=$STANZA --delta restore
pg_as principal bash -c "$BIN/pg_ctl -D $DATADIR -l $DATADIR/server.log -w start"
wait_for "principal up after encrypted restore" 30 1 \
  bash -c "$COMPOSE exec -T -u postgres principal $BIN/pg_isready -p 5433 -q"
rows=$(psql_on principal 5433 -c "SELECT count(*) FROM s;")
assert_contains "$rows" "500" "restored row count from encrypted repo"

pass "04 encryption complete"
