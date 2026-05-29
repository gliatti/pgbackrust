#!/usr/bin/env bash
# Reset the principal PostgreSQL cluster to a clean, running baseline.
#
# The backup→restore validation stops the cluster, restores into its data dir,
# and restarts it. A run that fails mid-restore (or any earlier bug) can leave
# the data dir in a half-restored, non-bootable state — which then breaks every
# subsequent run because the harness assumes a live server. This script makes
# the validation idempotent: it tears the cluster down, re-initdbs it, rewrites
# the KB postgresql.conf knobs (port 5433, archiving wired to pgbackrest), and
# starts it. Run as root (it uses `sudo -u postgres` internally).
set -euo pipefail

PGV="${PGBR_PG_VERSION:-16}"
BIN="/usr/lib/postgresql/$PGV/bin"
PRI="/var/lib/postgresql/$PGV/principal"
PORT=5433

# Stop whatever might be running (ignore "not running"); -m immediate so a stuck
# recovery process does not block the stop.
sudo -u postgres "$BIN/pg_ctl" -D "$PRI" -m immediate -w stop >/dev/null 2>&1 || true

rm -rf "$PRI"
install -d -o postgres -g postgres -m 0700 "$PRI"
sudo -u postgres "$BIN/initdb" -D "$PRI" --data-checksums -E UTF8 >/dev/null

cat >> "$PRI/postgresql.conf" <<CONF
listen_addresses = '*'
port = $PORT
wal_level = replica
archive_mode = on
archive_command = '/usr/bin/pgbackrest --stanza=demo archive-push %p'
max_wal_senders = 10
hot_standby = on
CONF

cat >> "$PRI/pg_hba.conf" <<CONF
host    replication     replicator      192.168.56.0/24         scram-sha-256
host    all             all             192.168.56.0/24         scram-sha-256
CONF

sudo -u postgres "$BIN/pg_ctl" -D "$PRI" -l "$PRI/server.log" -w start
echo "principal cluster reset + started on $PORT"
