#!/usr/bin/env bash
# Build the release `pgbackrust` binary in the Docker dev image and copy it to
# integration/artifacts/pgbackrust, where the Vagrant and Docker harnesses pick
# it up. Run from the repo root:  ./integration/build-binary.sh
set -euo pipefail

cd "$(dirname "$0")/.."

echo "[build] cargo build --release -p pgbr-cli (in Docker dev image)"
docker compose run --rm dev bash -c '
  set -e
  cargo build --release -p pgbr-cli
  # The pgbr-cli crate names its binary `pgbackrest` (the historical spelling;
  # see crates/pgbr-cli/Cargo.toml `[[bin]] name = "pgbackrest"`), so cargo emits
  # target/release/pgbackrest — NOT `pgbackrust`. Copying the wrong name silently
  # shipped a stale leftover binary and masked landed fixes. /work/pgbackrust is
  # the synced repo root on the host; landing the artifact (named `pgbackrust`,
  # which docker-compose bind-mounts) here makes it visible outside the container.
  cp "${CARGO_TARGET_DIR:-/work/pgbackrust/target}/release/pgbackrest" /work/pgbackrust/integration/artifacts/pgbackrust
'

chmod +x integration/artifacts/pgbackrust
echo "[build] artifact: integration/artifacts/pgbackrust"
integration/artifacts/pgbackrust version 2>/dev/null || \
  echo "[build] (binary is a Linux ELF; run it inside a VM/container, not the host)"
