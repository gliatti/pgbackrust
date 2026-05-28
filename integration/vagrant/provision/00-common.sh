#!/usr/bin/env bash
# Common provisioning for every node: base packages, PGDG repo, the Rust
# pgbackrest binary, and the pgBackRest runtime directories from the KB
# (spool / log / config). Idempotent — safe to re-run with `vagrant provision`.
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive

echo "[common] base packages"
apt-get update -qq
apt-get install -y -qq ca-certificates curl gnupg lsb-release rsync openssh-client openssl acl >/dev/null

# --- PGDG apt repository (PostgreSQL + matching libpq for the binary) -------
if [ ! -f /etc/apt/sources.list.d/pgdg.list ]; then
  echo "[common] add PGDG repository"
  install -d /usr/share/postgresql-common/pgdg
  curl -fsSL https://www.postgresql.org/media/keys/ACCC4CF8.asc \
    -o /usr/share/postgresql-common/pgdg/apt.postgresql.org.asc
  echo "deb [signed-by=/usr/share/postgresql-common/pgdg/apt.postgresql.org.asc] http://apt.postgresql.org/pub/repos/apt $(lsb_release -cs)-pgdg main" \
    > /etc/apt/sources.list.d/pgdg.list
  apt-get update -qq
fi

# libpq is required at runtime by the pgbr-db crate.
apt-get install -y -qq libpq5 >/dev/null || true

# --- pgBackRest runtime directories (KB layout) ----------------------------
echo "[common] runtime directories"
install -d -o postgres -g postgres -m 0750 /var/log/pgbackrest 2>/dev/null || install -d -m 0750 /var/log/pgbackrest
install -d -m 0750 /var/spool/pgbackrest
install -d -m 0750 /etc/pgbackrest /etc/pgbackrest/conf.d
install -d -m 0750 /etc/certs

# --- install the Rust pgbackrest binary ------------------------------------
ARTIFACT=/vagrant_repo/integration/artifacts/pgbackrest
if [ -x "$ARTIFACT" ]; then
  echo "[common] installing prebuilt pgbackrest binary"
  install -m 0755 "$ARTIFACT" /usr/bin/pgbackrest
else
  echo "[common] prebuilt binary missing; building in-VM with rustup (slow)"
  if ! command -v cargo >/dev/null 2>&1; then
    curl -fsSL https://sh.rustup.rs | sh -s -- -y --default-toolchain 1.95.0
    # shellcheck disable=SC1090
    source "$HOME/.cargo/env"
  fi
  apt-get install -y -qq build-essential pkg-config libpq-dev libssl-dev \
    zlib1g-dev libbz2-dev liblz4-dev libzstd-dev libssh2-1-dev >/dev/null
  ( cd /vagrant_repo && cargo build --release -p pgbr-cli )
  install -m 0755 /vagrant_repo/target/release/pgbackrest /usr/bin/pgbackrest
fi

pgbackrest version || true
echo "[common] done on role=${PGBR_ROLE}"
