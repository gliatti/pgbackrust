#!/usr/bin/env bash
# Passwordless SSH between nodes for the `postgres` OS user. The KB's pull and
# remote-restore scenarios require `postgres@<host>` SSH without a password
# (repo1-host / pg1-host over the default ssh transport).
#
# A single throwaway keypair is minted on the host (by run-vagrant.sh) and
# uploaded to every node at /tmp/pgbr_ssh_key{,.pub} via a Vagrant `file`
# provisioner. This script installs it for the postgres user (private key +
# authorized_keys) so every node trusts the same key.
set -euo pipefail

KEY=/tmp/pgbr_ssh_key
PUB=/tmp/pgbr_ssh_key.pub

id -u postgres >/dev/null 2>&1 || useradd -m -s /bin/bash postgres
install -d -o postgres -g postgres -m 0700 /var/lib/postgresql/.ssh

if [ ! -s "$KEY" ] || [ ! -s "$PUB" ]; then
  echo "[ssh] ERROR: uploaded key $KEY / $PUB missing — was it minted on the host before vagrant up?" >&2
  exit 1
fi

install -o postgres -g postgres -m 0600 "$KEY" /var/lib/postgresql/.ssh/id_ed25519
install -o postgres -g postgres -m 0644 "$PUB" /var/lib/postgresql/.ssh/id_ed25519.pub
install -o postgres -g postgres -m 0600 /dev/null /var/lib/postgresql/.ssh/authorized_keys
cat "$PUB" >> /var/lib/postgresql/.ssh/authorized_keys
chown postgres:postgres /var/lib/postgresql/.ssh/authorized_keys

# Trust the other nodes' host keys without prompting (integration network).
cat > /var/lib/postgresql/.ssh/config <<'EOF'
Host principal secondaire depot
    User postgres
    StrictHostKeyChecking no
    UserKnownHostsFile /dev/null
EOF
chown postgres:postgres /var/lib/postgresql/.ssh/config
chmod 0600 /var/lib/postgresql/.ssh/config

echo "[ssh] done"
