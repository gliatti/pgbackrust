#!/usr/bin/env bash
# KB "Sauvegarde vers un dépôt S3".
#
# Uses the MinIO service as an S3-compatible endpoint (repo1-type=s3,
# path-style addressing). Creates the bucket, stanza-create, backup, info.
set -euo pipefail
. "$(dirname "$0")/_lib.sh"

STANZA=demo
DATADIR=/var/lib/postgresql/$PGV/principal
BIN=/usr/lib/postgresql/$PGV/bin
S3_KEY=pgbackrust
S3_SECRET=pgbackrust-secret
BUCKET=depot

info "11 s3: create the bucket via the MinIO client"
$COMPOSE exec -T minio sh -c "
  mc alias set local http://localhost:9000 $S3_KEY $S3_SECRET >/dev/null 2>&1 || true
  mc mb -p local/$BUCKET >/dev/null 2>&1 || true
" || info "bucket create best-effort (mc may differ); pgBackRust will create keys under the prefix"

info "principal: S3 repo config (path-style, verify-tls off for the test endpoint)"
node principal bash -c "cat > /etc/pgbackrest/pgbackrest.conf <<EOF
[global]
repo1-type=s3
repo1-s3-uri-style=path
repo1-s3-endpoint=http://minio:9000
repo1-s3-region=us-east-1
repo1-s3-bucket=$BUCKET
repo1-path=/pgbackrust
repo1-s3-verify-tls=n
repo1-s3-key=$S3_KEY
repo1-s3-key-secret=$S3_SECRET
repo1-retention-full=2
log-level-console=info
log-level-file=debug
start-fast=y
[$STANZA]
pg1-path=$DATADIR
pg1-port=5433
EOF
chown postgres:postgres /etc/pgbackrest/pgbackrest.conf"
# pgBackRust talks plain HTTP to a :9000 endpoint only if scheme handling allows
# it; this scenario documents the KB S3 config and is the acceptance check for
# the s3 backend against a real endpoint.

reset_principal "$DATADIR" "$BIN" "$STANZA"

info "stanza-create against S3 (writes archive.info / backup.info objects + SigV4 auth)"
pg_as principal pgbackrust --stanza=$STANZA stanza-create
pass "S3 stanza-create succeeded"

info "check against S3 (archive round-trip + repo read over the S3 HTTP transport)"
chk=$(pg_as principal pgbackrust --stanza=$STANZA check 2>&1)
assert_contains "$chk" "check ok" "S3 check"

out=$(pg_as principal pgbackrust --stanza=$STANZA info)
assert_contains "$out" "status: ok" "S3 info"

info "full backup against S3 (the is_local backup-label guard makes this complete)"
# The S3 backend's early backup-label-directory existence check used to fail a
# backup with `not found: backup/<stanza>/<label>` (S3 has no real directories /
# empty prefixes), but the non-local repo HEAD guard skips that check for S3, so
# a full backup now completes over the S3 HTTP/SigV4 transport just like POSIX.
out=$(pg_as principal pgbackrust --stanza=$STANZA --type=full backup 2>&1)
printf '%s\n' "$out" | tail -6
assert_contains "$out" "complete:" "S3 backup completed"
info2=$(pg_as principal pgbackrust --stanza=$STANZA info)
assert_contains "$info2" "full backup" "S3 info shows a full backup"

pass "11 s3 complete (S3 stanza-create + check + a full backup over HTTP/SigV4)"
