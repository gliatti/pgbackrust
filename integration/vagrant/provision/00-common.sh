#!/usr/bin/env bash
# Common provisioning for every node: base packages, PGDG repo, the Rust
# pgbackrust binary, and the pgBackRust runtime directories from the KB
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

# Runtime shared libraries the pgbackrust binary links (readelf NEEDED):
# libpq (pgbr-db), libbz2 (bz2 compress), libssl/libcrypto, libz (gz). All but
# libpq are part of the Debian base, but install them explicitly to be safe.
apt-get install -y -qq libpq5 libbz2-1.0 libssl3 zlib1g >/dev/null || true

# --- pgBackRust runtime directories (KB layout) ----------------------------
echo "[common] runtime directories"
install -d -o postgres -g postgres -m 0750 /var/log/pgbackrust 2>/dev/null || install -d -m 0750 /var/log/pgbackrust
install -d -m 0750 /var/spool/pgbackrust
# Config dir uses the 'e' spelling the current binary reads by default
# (/etc/pgbackrest/pgbackrest.conf, conf.d at /etc/pgbackrest/conf.d).
install -d -m 0755 /etc/pgbackrest /etc/pgbackrest/conf.d
install -d -m 0750 /etc/certs

# --- install the Rust pgbackrust binary (uploaded to /tmp by Vagrant) -------
# The current binary reads its default config from the 'e' path
# (/etc/pgbackrest/pgbackrest.conf) and resolves the worker spawn command from
# its own executable path (std::env::current_exe → cmd/pg-host-cmd/repo-host-cmd
# defaults). The `check` command also requires the cluster's archive_command to
# contain the substring "pgbackrest". So install the binary at the 'e' path
# /usr/bin/pgbackrest and add a /usr/bin/pgbackrust symlink so the harness's
# bare-name `pgbackrust ...` invocations still resolve on PATH.
ARTIFACT=/tmp/pgbackrust.bin
if [ -s "$ARTIFACT" ]; then
  echo "[common] installing prebuilt pgbackrest binary"
  install -m 0755 "$ARTIFACT" /usr/bin/pgbackrest
  ln -sf /usr/bin/pgbackrest /usr/bin/pgbackrust
else
  echo "[common] ERROR: prebuilt binary /tmp/pgbackrust.bin missing — run ../build-binary.sh on the host first" >&2
  exit 1
fi

pgbackrest version || true
echo "[common] done on role=${PGBR_ROLE}"
