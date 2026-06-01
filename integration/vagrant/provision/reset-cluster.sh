#!/usr/bin/env bash
# Reset the principal PostgreSQL cluster to a clean, running baseline.
#
# The backup→restore validation stops the cluster, restores into its data dir,
# and restarts it. A run that fails mid-restore (or any earlier bug) can leave
# the data dir in a half-restored, non-bootable state — which then breaks every
# subsequent run because the harness assumes a live server. This script makes
# the validation idempotent: it tears the cluster down, re-initdbs it, rewrites
# the KB postgresql.conf knobs (port 5433, archiving wired to pgbackrust), and
# starts it. Run as root (it uses `sudo -u postgres` internally).
set -euo pipefail

PGV="${PGBR_PG_VERSION:-18}"
BIN="/usr/lib/postgresql/$PGV/bin"
PRI="/var/lib/postgresql/$PGV/principal"
PORT=5433

# Stop systemd-logind from reaping the postgres user's POSIX IPC. The cluster is
# started via `sudo -u postgres pg_ctl`, so its DSM control segment under
# /dev/shm/PostgreSQL.* is owned by the postgres uid. With the systemd default
# RemoveIPC=yes (and no lingering user manager), logind removes all postgres-owned
# shared-memory segments the moment the last postgres login session closes — which
# happens constantly as the harness opens/closes `sudo -u postgres` sessions. The
# running postmaster then survives but every NEW backend dies with
#   FATAL: could not open shared memory segment "/PostgreSQL.<id>": No such file
# (seen as a pgbackrust "db-open" failure / hang on the pull-backup path). Enabling
# linger + RemoveIPC=no makes the segments persistent for the cluster's lifetime.
sudo loginctl enable-linger postgres >/dev/null 2>&1 || true
if grep -q '^RemoveIPC' /etc/systemd/logind.conf 2>/dev/null; then
  sed -i 's/^RemoveIPC.*/RemoveIPC=no/' /etc/systemd/logind.conf
else
  printf 'RemoveIPC=no\n' >> /etc/systemd/logind.conf
fi
systemctl restart systemd-logind >/dev/null 2>&1 || true

# Free port 5433 from ANY running postmaster, not just $PRI: after a PG-major
# switch a leftover cluster from the previous version (e.g. /var/lib/postgresql/
# 16/principal) is still bound to 5433, so the freshly-initdb'd cluster cannot
# start ("Address already in use") and every later step would silently hit the
# stale cluster instead. Walk every data dir's postmaster.pid and stop it with
# its own version's pg_ctl, -m immediate so a stuck recovery cannot block us.
for pidfile in /var/lib/postgresql/*/*/postmaster.pid; do
  [ -f "$pidfile" ] || continue
  dir="$(dirname "$pidfile")"
  ver="$(printf '%s\n' "$dir" | sed -E 's#.*/postgresql/([0-9]+)/.*#\1#')"
  pgctl="/usr/lib/postgresql/$ver/bin/pg_ctl"
  [ -x "$pgctl" ] && sudo -u postgres "$pgctl" -D "$dir" -m immediate -w stop >/dev/null 2>&1 || true
done
sudo -u postgres "$BIN/pg_ctl" -D "$PRI" -m immediate -w stop >/dev/null 2>&1 || true

rm -rf "$PRI"
install -d -o postgres -g postgres -m 0700 "$PRI"
sudo -u postgres "$BIN/initdb" -D "$PRI" --data-checksums -E UTF8 >/dev/null

cat >> "$PRI/postgresql.conf" <<CONF
listen_addresses = '*'
port = $PORT
wal_level = replica
archive_mode = on
archive_command = '/usr/bin/pgbackrust --stanza=demo archive-push %p'
max_wal_senders = 10
hot_standby = on
CONF

cat >> "$PRI/pg_hba.conf" <<CONF
host    replication     replicator      192.168.56.0/24         scram-sha-256
host    all             all             192.168.56.0/24         scram-sha-256
CONF

sudo -u postgres "$BIN/pg_ctl" -D "$PRI" -l "$PRI/server.log" -w start
echo "principal cluster reset + started on $PORT"
