#!/usr/bin/env bash
# Build the release `pgbackrust` binary and copy it to integration/artifacts/
# pgbackrust, where the Vagrant and Docker harnesses pick it up. Run from the
# repo root:  ./integration/build-binary.sh
#
# IMPORTANT: builds in the `build` service (Debian 12 bookworm, glibc 2.36), NOT
# the `dev` service (Debian 13 trixie, glibc 2.41). glibc is backward- but not
# forward-compatible, so a trixie-built binary requires GLIBC_2.39 and dies on
# the bookworm Vagrant VMs (`version GLIBC_2.39 not found`). Building on the
# lowest supported glibc yields ONE artifact that runs everywhere: bookworm VMs
# AND trixie Docker nodes. See Dockerfile.build for the full rationale.
set -euo pipefail

cd "$(dirname "$0")/.."

echo "[build] cargo build --release -p pgbr-cli (in bookworm 'build' image, glibc 2.36)"
docker compose run --rm build bash -c '
  set -e
  cargo build --release -p pgbr-cli
  # The pgbr-cli crate names its binary `pgbackrest` (the historical spelling;
  # see crates/pgbr-cli/Cargo.toml `[[bin]] name = "pgbackrest"`), so cargo emits
  # target/release/pgbackrest — NOT `pgbackrust`. Copying the wrong name silently
  # shipped a stale leftover binary and masked landed fixes. /work/pgbackrust is
  # the synced repo root on the host; landing the artifact (named `pgbackrust`)
  # here makes it visible outside the container. CARGO_TARGET_DIR=/work/target in
  # the build service, so release artifacts live there.
  cp "${CARGO_TARGET_DIR:-/work/pgbackrust/target}/release/pgbackrest" /work/pgbackrust/integration/artifacts/pgbackrust
'

chmod +x integration/artifacts/pgbackrust
echo "[build] artifact: integration/artifacts/pgbackrust"
integration/artifacts/pgbackrust version 2>/dev/null || \
  echo "[build] (binary is a Linux ELF; run it inside a VM/container, not the host)"
