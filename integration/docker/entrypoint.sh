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

# Recent postgres base images set $HOME (/var/lib/postgresql) world-writable
# (drwxrwxrwt) so the server can run under an arbitrary uid. sshd StrictModes
# (on by default) then refuses ~/.ssh/authorized_keys because the home is
# group/other-writable, and pubkey auth fails silently with
# "Permission denied (publickey)" — breaking the remote-pull (02) and standby
# (05) scenarios. Tighten the home dir so StrictModes accepts the shared key.
chmod 0755 /var/lib/postgresql || true

# host keys + sshd
ssh-keygen -A >/dev/null 2>&1 || true
sed -i 's/#\?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config || true
/usr/sbin/sshd

install -d -o postgres -g postgres -m 0750 /srv/depot 2>/dev/null || true

# A freshly created named volume mounts its data-dir mountpoint as root:root
# (the custom path /var/lib/postgresql/16/<node> does not exist in the
# postgres:16 image, so Docker creates it as root rather than copying postgres
# ownership). The scenarios run `initdb` as the postgres user, which then fails
# to chmod the data dir with "could not change permissions ... Operation not
# permitted". Hand the PG data-dir mountpoints to postgres on every boot so
# initdb can take ownership. Harmless on the repo-only `depot` node (no match).
for d in /var/lib/postgresql/[0-9]*/principal /var/lib/postgresql/[0-9]*/secondaire; do
  [ -d "$d" ] && chown postgres:postgres "$d" || true
done

echo "[entrypoint] node up: role=$ROLE host=$(hostname)"
# Keep the container alive for `docker compose exec` driven scenarios.
exec sleep infinity
