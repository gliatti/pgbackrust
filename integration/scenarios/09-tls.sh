#!/usr/bin/env bash
# KB "Une alternative au SSH : TLS".
#
# depot and principal each run a pgBackRest TLS server. Mutual-TLS auth is
# enforced via tls-server-auth (client CN = allowed stanza). Validates
# server-ping in both directions, then a backup over the TLS transport
# (repo1-host-type=tls / pg1-host-type=tls).
set -euo pipefail
. "$(dirname "$0")/_lib.sh"

STANZA=main
DATADIR=/var/lib/postgresql/$PGV/principal
REPO=/srv/depot/pgbackrest-tls
BIN=/usr/lib/postgresql/$PGV/bin
CERTS=/etc/certs

info "09 tls: generate a CA + per-host certs (CN=hostname)"
gen_certs() {
  node "$1" bash -c "
    set -e
    install -d $CERTS
    cd $CERTS
    [ -f CA-key.pem ] || openssl req -x509 -newkey rsa:2048 -nodes -keyout CA-key.pem -out CA-cert.pem -days 5 -subj '/CN=pgbr-CA'
  "
}
# CA is generated on depot then shared via the repo, but for the harness we
# generate an independent CA per node and cross-trust by copying. Simplest:
# generate everything on depot and distribute.
node depot bash -c "
  set -e; install -d $CERTS; cd $CERTS
  openssl req -x509 -newkey rsa:2048 -nodes -keyout CA-key.pem -out CA-cert.pem -days 5 -subj '/CN=pgbr-CA'
  for h in depot principal; do
    openssl req -newkey rsa:2048 -nodes -keyout \$h-key.pem -out \$h.csr -subj \"/CN=\$h\"
    openssl x509 -req -in \$h.csr -CA CA-cert.pem -CAkey CA-key.pem -CAcreateserial -out \$h-cert.pem -days 5
  done
"
# distribute certs to principal via the shared ssh artifacts dir is not wired;
# copy through docker cp equivalent: tar over exec.
node depot bash -c "cd $CERTS && tar c CA-cert.pem principal-cert.pem principal-key.pem" \
  | node principal bash -c "install -d $CERTS && tar x -C $CERTS"

info "principal: TLS server + repo over TLS to depot"
node principal bash -c "cat > /etc/pgbackrest.conf <<EOF
[global]
repo1-host=depot
repo1-host-user=postgres
repo1-host-type=tls
repo1-host-cert-file=$CERTS/principal-cert.pem
repo1-host-key-file=$CERTS/principal-key.pem
repo1-host-ca-file=$CERTS/CA-cert.pem
repo1-path=$REPO
tls-server-address=*
tls-server-cert-file=$CERTS/principal-cert.pem
tls-server-key-file=$CERTS/principal-key.pem
tls-server-ca-file=$CERTS/CA-cert.pem
tls-server-auth=depot=$STANZA
[$STANZA]
pg1-path=$DATADIR
pg1-port=5433
EOF
chown postgres:postgres /etc/pgbackrest.conf"

info "depot: TLS server + reach principal's PG over TLS"
node depot bash -c "install -d -o postgres -g postgres -m 0750 $REPO; cat > /etc/pgbackrest.conf <<EOF
[global]
repo1-path=$REPO
repo1-retention-full=2
tls-server-address=*
tls-server-cert-file=$CERTS/depot-cert.pem
tls-server-key-file=$CERTS/depot-key.pem
tls-server-ca-file=$CERTS/CA-cert.pem
tls-server-auth=principal=$STANZA
[$STANZA]
pg1-host=principal
pg1-port=5433
pg1-path=$DATADIR
pg1-host-type=tls
pg1-host-cert-file=$CERTS/depot-cert.pem
pg1-host-key-file=$CERTS/depot-key.pem
pg1-host-ca-file=$CERTS/CA-cert.pem
EOF
chown postgres:postgres /etc/pgbackrest.conf"

info "launch the pgbackrest TLS servers"
pg_as principal bash -c "pgbackrest server >/var/log/pgbackrest/server.log 2>&1 &"
pg_as depot bash -c "pgbackrest server >/var/log/pgbackrest/server.log 2>&1 &"
sleep 2

info "server-ping both directions"
p1=$(pg_as principal pgbackrest server-ping depot 2>&1) || true
p2=$(pg_as depot pgbackrest server-ping principal 2>&1) || true
assert_contains "$p1" "completed successfully" "principal->depot ping"
assert_contains "$p2" "completed successfully" "depot->principal ping"

info "backup over TLS from depot"
pg_as depot pgbackrest --stanza=$STANZA stanza-create
out=$(pg_as depot pgbackrest --stanza=$STANZA --type=full backup 2>&1)
assert_contains "$out" "backup command end" "TLS backup completed"

pass "09 tls complete"
