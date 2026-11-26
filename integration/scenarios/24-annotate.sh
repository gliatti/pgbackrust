#!/usr/bin/env bash
# Port of Vagrant Scenario 18 — annotate command (set / update / delete
# key=value metadata) (integration/vagrant/run-validation.sh).
#
# annotate attaches arbitrary user-supplied key/value labels to a backup's
# metadata. The annotation is persisted in backup.info under
# "backup-annotation" and surfaced by `info --output=json` per backup. Proves
# the three documented operations: add a new annotation, update an existing
# key's value, and remove an annotation by setting it to an empty value.
set -euo pipefail
. "$(dirname "$0")/_lib.sh"

STANZA=demo
DATADIR=/var/lib/postgresql/$PGV/principal
REPO=/srv/depot/pgbackrust
BIN=/usr/lib/postgresql/$PGV/bin

info "24 annotate: minimal local repo"
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

reset_principal "$DATADIR" "$BIN" "$STANZA"
node principal bash -c "install -d -o postgres -g postgres -m 0750 $REPO"

info "stanza-create + full backup"
pg_as principal pgbackrust --stanza=$STANZA stanza-create
psql_on principal 5433 -c "CREATE TABLE t(i int); INSERT INTO t SELECT generate_series(1,500)" >/dev/null
pg_as principal pgbackrust --stanza=$STANZA --type=full backup

json=$(pg_as principal pgbackrust --stanza=$STANZA info --output=json | tr -d '\r')
LABEL=$(grep -oE '"label"[[:space:]]*:[[:space:]]*"[^"]+"' <<<"$json" | sed -E 's/.*"([^"]+)"$/\1/' | head -1 || true)
if [ -n "$LABEL" ]; then
  pass "full backup label from info --output=json: $LABEL"
else
  printf '%s\n' "$json" >&2
  fail "no backup label found in info --output=json"
fi

info "annotate add (note=hello)"
pg_as principal pgbackrust --stanza=$STANZA annotate --set="$LABEL" --annotation=note=hello
js1=$(pg_as principal pgbackrust --stanza=$STANZA info --output=json | tr -d '\r')
if grep -qE '"note"[[:space:]]*:[[:space:]]*"hello"' <<<"$js1"; then
  pass "info --output=json renders annotation note=hello"
else
  printf '%s\n' "$js1" >&2
  fail "annotation note=hello not visible in info json"
fi

info "annotate update (note=updated, same key)"
pg_as principal pgbackrust --stanza=$STANZA annotate --set="$LABEL" --annotation=note=updated
js2=$(pg_as principal pgbackrust --stanza=$STANZA info --output=json | tr -d '\r')
if grep -qE '"note"[[:space:]]*:[[:space:]]*"updated"' <<<"$js2" \
  && ! grep -qE '"note"[[:space:]]*:[[:space:]]*"hello"' <<<"$js2"; then
  pass "annotation value updated (hello -> updated)"
else
  printf '%s\n' "$js2" >&2
  fail "annotation update failed"
fi

info "annotate delete (--annotation=note= empty value)"
pg_as principal pgbackrust --stanza=$STANZA annotate --set="$LABEL" --annotation=note=
js3=$(pg_as principal pgbackrust --stanza=$STANZA info --output=json | tr -d '\r')
if ! grep -qE '"note"[[:space:]]*:[[:space:]]*"' <<<"$js3"; then
  pass "annotation removed (empty value deletes the key)"
else
  printf '%s\n' "$js3" >&2
  fail "annotation NOT removed"
fi

pass "24 annotate complete"
