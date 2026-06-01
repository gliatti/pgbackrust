#!/usr/bin/env bash
# Passwordless SSH between nodes for the `postgres` OS user. The KB's pull and
# remote-restore scenarios require `postgres@<host>` SSH without a password
# (repo1-host / pg1-host over the default ssh transport).
#
# A single throwaway keypair is minted on the host (by run-vagrant.sh) and
# uploaded to every node at /tmp/pgbr_ssh_key{,.pub} via a Vagrant `file`
# provisioner. This script installs it for the postgres user.
set -euo pipefail

KEY=/tmp/pgbr_ssh_key
PUB=/tmp/pgbr_ssh_key.pub

# Ensure the postgres user exists; match the PGDG convention (home in
# /var/lib/postgresql) so it lines up with the data directories.
id -u postgres >/dev/null 2>&1 || useradd -m -d /var/lib/postgresql -s /bin/bash postgres

# Install the key into the postgres user's ACTUAL home (it may be /home/postgres
# if useradd created it before the postgresql package, or /var/lib/postgresql).
PGHOME=$(getent passwd postgres | cut -d: -f6)
PGHOME=${PGHOME:-/var/lib/postgresql}
SSHDIR="$PGHOME/.ssh"

if [ ! -s "$KEY" ] || [ ! -s "$PUB" ]; then
  echo "[ssh] ERROR: uploaded key $KEY / $PUB missing — was it minted on the host before vagrant up?" >&2
  exit 1
fi

install -d -o postgres -g postgres -m 0700 "$SSHDIR"
install -o postgres -g postgres -m 0600 "$KEY" "$SSHDIR/id_ed25519"
install -o postgres -g postgres -m 0644 "$PUB" "$SSHDIR/id_ed25519.pub"
install -o postgres -g postgres -m 0600 /dev/null "$SSHDIR/authorized_keys"
cat "$PUB" >> "$SSHDIR/authorized_keys"
chown postgres:postgres "$SSHDIR/authorized_keys"

cat > "$SSHDIR/config" <<'EOF'
Host principal secondaire depot
    User postgres
    StrictHostKeyChecking no
    UserKnownHostsFile /dev/null
EOF
chown postgres:postgres "$SSHDIR/config"
chmod 0600 "$SSHDIR/config"

# A locked password ("L") can make some sshd setups reject the account even for
# pubkey auth; set a non-login usable password field so key auth is accepted.
usermod -p '*' postgres 2>/dev/null || true

# System-wide client config: pgbackrust spawns `ssh <host> pgbackrust ...` as
# the postgres OS user, but sudo may not set HOME, so the per-user config above
# can be missed. A drop-in applies regardless of HOME.
install -d -m 0755 /etc/ssh/ssh_config.d
cat > /etc/ssh/ssh_config.d/00-pgbr-integration.conf <<'EOF'
Host principal secondaire depot
    StrictHostKeyChecking no
    UserKnownHostsFile /dev/null
EOF
grep -q 'ssh_config.d/\*.conf' /etc/ssh/ssh_config 2>/dev/null || echo 'Include /etc/ssh/ssh_config.d/*.conf' >> /etc/ssh/ssh_config

echo "[ssh] installed key into $SSHDIR; done"
