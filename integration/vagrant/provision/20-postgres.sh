#!/usr/bin/env bash
# PostgreSQL provisioning for the PG-bearing nodes (principal / secondaire).
#
# Mirrors the KB example layout:
#   principal : cluster at /var/lib/postgresql/$PGV/principal  on port 5433
#   secondaire: empty data dir at /var/lib/postgresql/$PGV/secondaire on 5434
#               (populated by the standby-restore scenario, not here)
#
# Archiving is wired to the Rust pgbackrest binary exactly as the KB shows.
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

PGV="${PGBR_PG_VERSION:-16}"
ROLE="${PGBR_ROLE:-primary}"
BIN=/usr/lib/postgresql/$PGV/bin

echo "[pg] install postgresql-$PGV"
apt-get install -y -qq "postgresql-$PGV" "postgresql-client-$PGV" >/dev/null

# Debian auto-creates a 'main' cluster on 5432; we use named clusters instead.
pg_dropcluster --stop "$PGV" main >/dev/null 2>&1 || true

if [ "$ROLE" = "primary" ]; then
  DATADIR=/var/lib/postgresql/$PGV/principal
  PORT=5433
  if [ ! -s "$DATADIR/PG_VERSION" ]; then
    echo "[pg] initdb principal ($DATADIR)"
    install -d -o postgres -g postgres "$DATADIR"
    sudo -u postgres "$BIN/initdb" -D "$DATADIR" --data-checksums -E UTF8 >/dev/null

    cat >> "$DATADIR/postgresql.conf" <<EOF
listen_addresses = '*'
port = $PORT
wal_level = replica
archive_mode = on
archive_command = '/usr/bin/pgbackrest --stanza=demo archive-push %p'
max_wal_senders = 10
hot_standby = on
EOF
    cat >> "$DATADIR/pg_hba.conf" <<EOF
host    replication     replicator      192.168.56.0/24         scram-sha-256
host    all             all             192.168.56.0/24         scram-sha-256
EOF
  fi
  sudo -u postgres "$BIN/pg_ctl" -D "$DATADIR" -l "$DATADIR/server.log" -w start || true
  sudo -u postgres "$BIN/psql" -p $PORT -tAc \
    "SELECT 1 FROM pg_roles WHERE rolname='replicator'" | grep -q 1 || \
    sudo -u postgres "$BIN/psql" -p $PORT -c \
    "CREATE ROLE replicator WITH REPLICATION LOGIN PASSWORD 'replicator'"
  sudo -u postgres "$BIN/psql" -p $PORT -tAc \
    "SELECT pg_create_physical_replication_slot('secondaire')" 2>/dev/null || true
  echo "[pg] principal up on $PORT"
else
  # secondaire: prepare an empty target; the standby-restore scenario fills it.
  DATADIR=/var/lib/postgresql/$PGV/secondaire
  install -d -o postgres -g postgres -m 0700 "$DATADIR"
  echo "[pg] secondaire data dir prepared at $DATADIR (port 5434, restore-driven)"
fi
echo "[pg] done role=$ROLE"
