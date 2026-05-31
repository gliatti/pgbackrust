#!/usr/bin/env bash
# Repository-server (depot) provisioning: the backup storage directory plus a
# baseline /etc/pgbackrest.conf for the "pull from depot" scenarios. The depot
# also runs the pgBackRest TLS server for the SSH-alternative scenario.
set -euo pipefail

REPO=/srv/nfs/depot/pgbackrest
install -d -o postgres -g postgres -m 0750 "$REPO"

# Baseline pull config (KB "Exemple 2"): depot reaches principal over SSH.
cat > /etc/pgbackrest.conf <<EOF
[global]
repo1-path=$REPO
repo1-retention-full=2
repo1-retention-diff=2
log-level-console=info
log-path=/var/log/pgbackrest
start-fast=y
process-max=2

[demo]
pg1-host=principal
pg1-host-user=postgres
pg1-host-port=22
pg1-path=/var/lib/postgresql/16/principal
pg1-port=5433
pg1-user=postgres
EOF
chown postgres:postgres /etc/pgbackrest.conf

echo "[repo] depot ready: repo=$REPO"
