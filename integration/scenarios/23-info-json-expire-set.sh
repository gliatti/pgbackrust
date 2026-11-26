#!/usr/bin/env bash
# Port of Vagrant Scenario 17 — info --output=json (machine-parsable) +
# expire --set=<label> (targeted) (integration/vagrant/run-validation.sh).
#
# Two documented features that combine naturally: the JSON output is the
# canonical way for tooling to drive expire --set. Proves (a) info
# --output=json on an empty repo has `[` alone on its first non-blank line and
# `]` alone on its last (well-formed structure smoke test, no python needed), (b) two full backups
# appear as two `"label" : "..."` entries, (c) expire --set=<label1> removes
# ONLY that backup. Labels (<YYYYMMDD>-<HHMMSS>{F,D,I}) are extracted with
# grep/sed so the harness stays bash-only.
set -euo pipefail
. "$(dirname "$0")/_lib.sh"

STANZA=demo
DATADIR=/var/lib/postgresql/$PGV/principal
REPO=/srv/depot/pgbackrust
BIN=/usr/lib/postgresql/$PGV/bin

extract_labels_from_json() {
  # echo each label in the JSON on its own line, in order. Empty if none.
  printf '%s' "$1" | grep -oE '"label"[[:space:]]*:[[:space:]]*"[^"]+"' | sed -E 's/.*"([^"]+)"$/\1/'
}

info "23 info-json-expire-set: minimal local repo"
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

info "stanza-create"
pg_as principal pgbackrust --stanza=$STANZA stanza-create

info "info --output=json on an empty repo must be a bracketed JSON array"
out=$(pg_as principal pgbackrust --stanza=$STANZA info --output=json | tr -d '\r')
# Vagrant semantics: the whole first non-blank line must be exactly `[` and the
# whole last non-blank line exactly `]` (surrounding whitespace trimmed).
first_nonblank=$(printf '%s' "$out" | sed -n '/[^[:space:]]/{p;q}' | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//')
last_nonblank=$(printf '%s' "$out" | awk 'NF{l=$0}END{print l}' | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//')
if [ "$first_nonblank" = "[" ] && [ "$last_nonblank" = "]" ]; then
  pass "info --output=json (empty repo) is a well-formed JSON array"
else
  printf '%s\n' "$out" | tail -4 >&2
  fail "info --output=json (empty) not bracketed (first=$first_nonblank last=$last_nonblank)"
fi

info "two full backups"
psql_on principal 5433 -c "CREATE TABLE t(i int)" >/dev/null
psql_on principal 5433 -c "INSERT INTO t SELECT generate_series(1,1000)" >/dev/null
pg_as principal pgbackrust --stanza=$STANZA --type=full backup
# Labels have second resolution: make sure the two fulls cannot collide.
sleep 1
psql_on principal 5433 -c "INSERT INTO t SELECT generate_series(1001,1500)" >/dev/null
pg_as principal pgbackrust --stanza=$STANZA --type=full backup

info "info --output=json must list both backups"
json=$(pg_as principal pgbackrust --stanza=$STANZA info --output=json | tr -d '\r')
mapfile -t LABELS < <(extract_labels_from_json "$json" || true)
if [ "${#LABELS[@]}" = "2" ]; then
  pass "info --output=json shows both backups (${LABELS[0]}, ${LABELS[1]})"
else
  fail "info --output=json missed backups (got ${#LABELS[@]}: ${LABELS[*]})"
fi
LABEL1="${LABELS[0]}"
LABEL2="${LABELS[1]}"

info "expire --set=$LABEL1 must remove only that backup"
pg_as principal pgbackrust --stanza=$STANZA expire --set="$LABEL1"
post=$(pg_as principal pgbackrust --stanza=$STANZA info --output=json | tr -d '\r')
mapfile -t REMAINING < <(extract_labels_from_json "$post" || true)
if [ "${#REMAINING[@]}" = "1" ] && [ "${REMAINING[0]}" = "$LABEL2" ]; then
  pass "expire --set removed only the targeted backup ($LABEL1 gone, $LABEL2 kept)"
else
  fail "expire --set wrong outcome (remaining ${#REMAINING[@]}: ${REMAINING[*]}, want only $LABEL2)"
fi

pass "23 info-json-expire-set complete"
