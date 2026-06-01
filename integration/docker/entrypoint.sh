#!/usr/bin/env bash
# Integration node entrypoint. Sets up passwordless SSH for the postgres user
# across nodes, starts sshd, and (for PG nodes) keeps PGDATA ready. The actual
# pgBackRust scenarios are driven externally via `docker compose exec`.
set -euo pipefail

ROLE="${PGBR_ROLE:-repo}"

# --- shared SSH key (mounted from integration/artifacts/ssh) ---------------
SSHDIR=/var/lib/postgresql/.ssh
mkdir -p "$SSHDIR"
if [ -f /shared-ssh/id_ed25519 ]; then
  install -m 0600 /shared-ssh/id_ed25519     "$SSHDIR/id_ed25519"
  install -m 0644 /shared-ssh/id_ed25519.pub "$SSHDIR/id_ed25519.pub"
  install -m 0600 /shared-ssh/id_ed25519.pub "$SSHDIR/authorized_keys"
  cat > "$SSHDIR/config" <<'EOF'
Host principal secondaire depot
    User postgres
    StrictHostKeyChecking no
    UserKnownHostsFile /dev/null
EOF
  chmod 0600 "$SSHDIR/config"
fi
chown -R postgres:postgres "$SSHDIR"
usermod -s /bin/bash postgres 2>/dev/null || true

# host keys + sshd
ssh-keygen -A >/dev/null 2>&1 || true
sed -i 's/#\?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config || true
/usr/sbin/sshd

install -d -o postgres -g postgres -m 0750 /srv/depot 2>/dev/null || true

echo "[entrypoint] node up: role=$ROLE host=$(hostname)"
# Keep the container alive for `docker compose exec` driven scenarios.
exec sleep infinity
