#!/usr/bin/env bash
# Shared helpers for the pgBackRust integration scenarios. Sourced by each
# scenario script and by run-all.sh.
set -euo pipefail

# When sourced from Git-for-Windows / MSYS2 bash, absolute container paths passed
# to `docker ... exec` (e.g. /usr/lib/postgresql/16/bin/psql) are rewritten to
# host paths (C:/Program Files/Git/...), breaking the exec. Disable MSYS path
# conversion so the scenarios run unchanged on a Windows host as well as Linux CI.
export MSYS_NO_PATHCONV=1

_compose_file="$(cd "$(dirname "${BASH_SOURCE[0]}")/../docker" && pwd)/docker-compose.yml"
# MSYS path conversion is disabled above (for container paths), so hand the
# native docker client a Windows-style path for `-f` explicitly on Git-for-Windows.
if command -v cygpath >/dev/null 2>&1; then
  _compose_file="$(cygpath -m "$_compose_file")"
fi
COMPOSE="docker compose -f $_compose_file"
PGV="${PGBR_PG_VERSION:-16}"

# colour-free status helpers
pass() { printf 'PASS  %s\n' "$*"; }
fail() { printf 'FAIL  %s\n' "$*" >&2; return 1; }
info() { printf '%s\n' "----  $*"; }

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

# wait until a PG node accepts connections on a given port
pg_ready() {
  local n="$1" port="$2" bin="$3"
  wait_for "$n accepts connections on $port" 60 1 \
    bash -c "$COMPOSE exec -T -u postgres $n $bin/pg_isready -p $port -q"
}

# reset_principal <datadir> <bin> <stanza>
#
# Bring the `principal` cluster to a known-clean state for a self-contained
# scenario, regardless of what a prior scenario left behind:
#   - stop the cluster if running (ignore errors)
#   - wipe the data directory (the persistent volume is reused across `down`s,
#     so a fresh `initdb` is what guarantees a clean timeline / no stale WAL)
#   - initdb --data-checksums
#   - write a FRESH postgresql.conf by OVERWRITE (never append): port 5433,
#     archive_mode=on, archive_command pinned to THIS scenario's stanza,
#     wal_level=replica, listen_addresses='*'. Overwriting is the crux of the
#     cumulative-append contamination fix — no stale archive_command for a
#     prior stanza can survive.
#   - start + wait for ready
reset_principal() {
  local datadir="$1" bin="$2" stanza="$3"
  info "reset principal cluster (fresh initdb, clean postgresql.conf for stanza=$stanza)"
  pg_as principal bash -c "$bin/pg_ctl -D $datadir -m immediate -w stop >/dev/null 2>&1 || true"
  pg_as principal bash -c "rm -rf $datadir/* $datadir/.[!.]* 2>/dev/null || true"
  pg_as principal bash -c "$bin/initdb -D $datadir --data-checksums >/dev/null"
  pg_as principal bash -c "cat > $datadir/postgresql.conf <<EOF
listen_addresses = '*'
port = 5433
archive_mode = on
archive_command = '/usr/bin/pgbackrest --stanza=$stanza archive-push %p'
wal_level = replica
max_wal_senders = 10
max_replication_slots = 10
hot_standby = on
EOF"
  pg_as principal bash -c "$bin/pg_ctl -D $datadir -l $datadir/server.log -w start"
  pg_ready principal 5433 "$bin"
}

# reset_secondaire <datadir> <bin>
#
# Wipe the `secondaire` data directory and ensure no cluster is running there,
# so a standby restore (scenario 05) starts from clean ground.
reset_secondaire() {
  local datadir="$1" bin="$2"
  info "reset secondaire cluster (stop + wipe data dir)"
  pg_as secondaire bash -c "$bin/pg_ctl -D $datadir -m immediate -w stop >/dev/null 2>&1 || true"
  pg_as secondaire bash -c "rm -rf $datadir/* $datadir/.[!.]* 2>/dev/null || true"
}
