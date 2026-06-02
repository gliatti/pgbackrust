#!/usr/bin/env bash
# Orchestrates the Docker integration topology and runs every scenario.
#
#   ./integration/scenarios/run-all.sh            # all scenarios
#   ./integration/scenarios/run-all.sh 01 03      # only matching scenarios
#
# Steps: build the binary if missing, mint the shared SSH key, build the node
# image, then for EACH scenario reset the topology (down -v / up) so it runs in
# full isolation, run it, record pass/fail (a failure never aborts the loop),
# print a summary, and tear down on exit.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
. "$HERE/_lib.sh"

cd "$ROOT"

# Docker Desktop's buildx "bake" path builds all compose services in parallel
# and races when several of them export the SAME image tag — the three nodes
# share pgbr-node:latest — failing with `image ... already exists`. Default to
# the classic sequential builder so a plain run works out of the box; callers
# can still override (e.g. COMPOSE_BAKE=true) on engines without the race.
export COMPOSE_BAKE="${COMPOSE_BAKE:-false}"

# 1. binary artifact
if [ ! -x integration/artifacts/pgbackrust ]; then
  info "building pgbackrust binary"
  ./integration/build-binary.sh
fi

# 2. shared SSH key for postgres-user cross-node access
if [ ! -f integration/artifacts/ssh/id_ed25519 ]; then
  info "minting shared integration SSH key"
  mkdir -p integration/artifacts/ssh
  ssh-keygen -t ed25519 -N "" -C pgbr-integration -f integration/artifacts/ssh/id_ed25519
fi

# 3. build image (topology is brought up fresh per-scenario below)
info "building node image"
$COMPOSE build
trap '$COMPOSE down -v >/dev/null 2>&1 || true' EXIT

# 4. run scenarios (filtered by optional args)
#
# The numbered scenarios (auto-discovered by the glob below) are:
#   01-local-minimal      02-remote-pull-ssh   03-pitr            04-encryption
#   05-standby            06-tablespaces       07-async-queuing   08-multi-repo
#   09-tls                10-bundling-block    11-s3              12-repo-sync
#
# Each scenario runs against a freshly reset topology: `down -v` wipes every
# volume (principal-data, secondaire-data, depot-repo, minio-data) so no
# cross-scenario state (leftover timelines, stale WAL, cumulatively-appended
# postgresql.conf, prior repo contents) can leak into the next scenario. Each
# scenario then self-provisions its own cluster + stanza via the _lib.sh
# helpers. A failing scenario records the failure and continues; it never
# aborts the loop.
filters=("$@")
rc=0
declare -a results=()
for s in "$HERE"/[0-9][0-9]-*.sh; do
  name="$(basename "$s")"
  if [ "${#filters[@]}" -gt 0 ]; then
    match=0
    for f in "${filters[@]}"; do [[ "$name" == *"$f"* ]] && match=1; done
    [ "$match" -eq 1 ] || continue
  fi

  info "resetting topology for $name"
  $COMPOSE down -v >/dev/null 2>&1 || true
  sleep 2
  $COMPOSE up -d >/dev/null
  # Wait for every node to actually be running before launching the scenario —
  # a fixed sleep can race with container (re)creation and the scenario's first
  # `docker compose exec` then fails with "container ... is not running".
  for _ in $(seq 1 30); do
    up=$($COMPOSE ps --status running --services 2>/dev/null | grep -c .)
    [ "${up:-0}" -ge 4 ] && break
    sleep 1
  done
  sleep 2

  printf '\n========== %s ==========\n' "$name"
  # `if bash "$s"` already neutralises the scenario's exit status for `set -e`,
  # but make the bookkeeping explicit and resilient regardless.
  if bash "$s"; then
    pass "$name"
    results+=("PASS  $name")
  else
    printf 'FAIL  %s\n' "$name" >&2
    rc=1
    results+=("FAIL  $name")
  fi
done

printf '\n========== SUMMARY ==========\n'
n_pass=0; n_fail=0
for r in "${results[@]}"; do
  printf '%s\n' "$r"
  case "$r" in PASS*) n_pass=$((n_pass+1));; FAIL*) n_fail=$((n_fail+1));; esac
done
printf '%d passed / %d failed (of %d run)\n' "$n_pass" "$n_fail" "$((n_pass+n_fail))"

exit "$rc"
