#!/usr/bin/env bash
# Passwordless SSH between nodes for the `postgres` OS user. The KB's pull and
# remote-restore scenarios require `postgres@<host>` SSH without a password
# (repo1-host / pg1-host over the default ssh transport).
#
# A single shared keypair is generated deterministically on `depot` and copied
# to every node via the synced repo folder (a throwaway key, integration-only).
set -euo pipefail

KEYDIR=/vagrant_repo/integration/artifacts/ssh
SHARED_KEY="$KEYDIR/id_ed25519"

id -u postgres >/dev/null 2>&1 || useradd -m -s /bin/bash postgres
install -d -o postgres -g postgres -m 0700 /var/lib/postgresql/.ssh

if [ "$(hostname)" = "depot" ] && [ ! -f "$SHARED_KEY" ]; then
  echo "[ssh] generating shared integration keypair on depot"
  install -d -m 0700 "$KEYDIR"
  ssh-keygen -t ed25519 -N "" -C "pgbr-integration" -f "$SHARED_KEY"
fi

# Wait for the key to exist (depot provisions first by convention; if a PG node
# runs before depot, re-run `vagrant provision` after depot is up).
if [ -f "$SHARED_KEY" ]; then
  install -o postgres -g postgres -m 0600 "$SHARED_KEY"     /var/lib/postgresql/.ssh/id_ed25519
  install -o postgres -g postgres -m 0644 "$SHARED_KEY.pub" /var/lib/postgresql/.ssh/id_ed25519.pub
  install -o postgres -g postgres -m 0600 /dev/null         /var/lib/postgresql/.ssh/authorized_keys
  cat "$SHARED_KEY.pub" >> /var/lib/postgresql/.ssh/authorized_keys
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
else
  echo "[ssh] shared key not present yet; bring up 'depot' first, then re-provision"
fi
echo "[ssh] done"
