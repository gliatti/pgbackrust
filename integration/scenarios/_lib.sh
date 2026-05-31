#!/usr/bin/env bash
# Shared helpers for the pgBackRest integration scenarios. Sourced by each
# scenario script and by run-all.sh.
set -euo pipefail

COMPOSE="docker compose -f $(cd "$(dirname "${BASH_SOURCE[0]}")/../docker" && pwd)/docker-compose.yml"
PGV="${PGBR_PG_VERSION:-16}"

# colour-free status helpers
pass() { printf 'PASS  %s\n' "$*"; }
fail() { printf 'FAIL  %s\n' "$*" >&2; return 1; }
info() { printf '----  %s\n' "$*"; }

# run a command in a node container as root
node() { local n="$1"; shift; $COMPOSE exec -T "$n" "$@"; }

# run a command in a node container as the postgres user
pg_as() { local n="$1"; shift; $COMPOSE exec -T -u postgres "$n" "$@"; }

# psql on a PG node (principal:5433 / secondaire:5434)
psql_on() {
  local n="$1" port="$2"; shift 2
  pg_as "$n" /usr/lib/postgresql/$PGV/bin/psql -p "$port" -X -A -t "$@"
}

# assert that a string appears in command output
assert_contains() {
  local haystack="$1" needle="$2" what="${3:-output}"
  if printf '%s' "$haystack" | grep -qF -- "$needle"; then
    pass "$what contains '$needle'"
  else
    printf '%s\n' "$haystack" >&2
    fail "$what missing '$needle'"
  fi
}

# wait until a shell predicate succeeds (bounded)
wait_for() {
  local desc="$1" tries="${2:-30}" sleep_s="${3:-1}"; shift 3 || true
  local i=0
  until "$@"; do
    i=$((i+1))
    [ "$i" -ge "$tries" ] && { fail "timeout waiting for $desc"; return 1; }
    sleep "$sleep_s"
  done
  pass "ready: $desc"
}
