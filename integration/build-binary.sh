#!/usr/bin/env bash
# Build the release `pgbackrest` binary in the Docker dev image and copy it to
# integration/artifacts/pgbackrest, where the Vagrant and Docker harnesses pick
# it up. Run from the repo root:  ./integration/build-binary.sh
set -euo pipefail

cd "$(dirname "$0")/.."

echo "[build] cargo build --release -p pgbr-cli (in Docker dev image)"
docker compose run --rm dev bash -c '
  set -e
  cargo build --release -p pgbr-cli
  # /work/pgbackrust is the synced repo root on the host; landing the binary
  # here makes it visible outside the container.
  cp /work/target/release/pgbackrest /work/pgbackrust/integration/artifacts/pgbackrest
'

chmod +x integration/artifacts/pgbackrest
echo "[build] artifact: integration/artifacts/pgbackrest"
integration/artifacts/pgbackrest version 2>/dev/null || \
  echo "[build] (binary is a Linux ELF; run it inside a VM/container, not the host)"
