#!/usr/bin/env bash
# Orchestrates the Docker integration topology and runs every scenario.
#
#   ./integration/scenarios/run-all.sh            # all scenarios
#   ./integration/scenarios/run-all.sh 01 03      # only matching scenarios
#
# Steps: build the binary if missing, mint the shared SSH key, build the node
# image, bring the 3 nodes up, run scenarios, then tear down.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
. "$HERE/_lib.sh"

cd "$ROOT"

# 1. binary artifact
if [ ! -x integration/artifacts/pgbackrest ]; then
  info "building pgbackrest binary"
  ./integration/build-binary.sh
fi

# 2. shared SSH key for postgres-user cross-node access
if [ ! -f integration/artifacts/ssh/id_ed25519 ]; then
  info "minting shared integration SSH key"
  mkdir -p integration/artifacts/ssh
  ssh-keygen -t ed25519 -N "" -C pgbr-integration -f integration/artifacts/ssh/id_ed25519
fi

# 3. build image + bring up topology
info "building node image"
$COMPOSE build
info "starting topology"
$COMPOSE up -d
trap '$COMPOSE down -v' EXIT

# give sshd a moment
sleep 3

# 4. run scenarios (filtered by optional args)
filters=("$@")
rc=0
for s in "$HERE"/[0-9][0-9]-*.sh; do
  name="$(basename "$s")"
  if [ "${#filters[@]}" -gt 0 ]; then
    match=0
    for f in "${filters[@]}"; do [[ "$name" == *"$f"* ]] && match=1; done
    [ "$match" -eq 1 ] || continue
  fi
  printf '\n========== %s ==========\n' "$name"
  if bash "$s"; then pass "$name"; else fail "$name"; rc=1; fi
done

exit "$rc"
