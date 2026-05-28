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
S3_KEY=pgbackrest
S3_SECRET=pgbackrest-secret
BUCKET=depot

info "11 s3: create the bucket via the MinIO client"
$COMPOSE exec -T minio sh -c "
  mc alias set local http://localhost:9000 $S3_KEY $S3_SECRET >/dev/null 2>&1 || true
  mc mb -p local/$BUCKET >/dev/null 2>&1 || true
" || info "bucket create best-effort (mc may differ); pgBackRest will create keys under the prefix"

info "principal: S3 repo config (path-style, verify-tls off for the test endpoint)"
node principal bash -c "cat > /etc/pgbackrest.conf <<EOF
[global]
repo1-type=s3
repo1-s3-uri-style=path
repo1-s3-endpoint=minio:9000
repo1-s3-region=us-east-1
repo1-s3-bucket=$BUCKET
repo1-path=/pgbackrest
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
chown postgres:postgres /etc/pgbackrest.conf"
# pgBackRest talks plain HTTP to a :9000 endpoint only if scheme handling allows
# it; this scenario documents the KB S3 config and is the acceptance check for
# the s3 backend against a real endpoint.

info "ensure cluster up + archiving"
pg_as principal bash -c "[ -s $DATADIR/PG_VERSION ] || $BIN/initdb -D $DATADIR --data-checksums >/dev/null"
pg_as principal bash -c "
  grep -q pgbackrest $DATADIR/postgresql.conf || cat >> $DATADIR/postgresql.conf <<EOF
port = 5433
archive_mode = on
archive_command = '/usr/bin/pgbackrest --stanza=$STANZA archive-push %p'
wal_level = replica
EOF
  $BIN/pg_ctl -D $DATADIR -l $DATADIR/server.log -w restart >/dev/null 2>&1 || \
  $BIN/pg_ctl -D $DATADIR -l $DATADIR/server.log -w start"

info "stanza-create + check + backup against S3"
pg_as principal pgbackrest --stanza=$STANZA stanza-create
pg_as principal pgbackrest --stanza=$STANZA check
pg_as principal pgbackrest --stanza=$STANZA --type=full backup

out=$(pg_as principal pgbackrest --stanza=$STANZA info)
assert_contains "$out" "status: ok" "S3 info"
assert_contains "$out" "full backup" "S3 info"

pass "11 s3 complete"
