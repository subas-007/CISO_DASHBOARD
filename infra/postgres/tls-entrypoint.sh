#!/bin/sh
# Installs TLS material with the ownership/permissions PostgreSQL requires, then
# hands over to the official entrypoint with TLS 1.3, SCRAM and connection logging.
set -eu

TLS_DIR=/var/lib/postgresql/tls
mkdir -p "$TLS_DIR"
install -o postgres -g postgres -m 0600 /certs-src/tls.key "$TLS_DIR/server.key"
install -o postgres -g postgres -m 0644 /certs-src/tls.crt "$TLS_DIR/server.crt"
install -o postgres -g postgres -m 0644 /certs-src/ca.crt  "$TLS_DIR/ca.crt"

exec docker-entrypoint.sh postgres \
  -c ssl=on \
  -c ssl_cert_file="$TLS_DIR/server.crt" \
  -c ssl_key_file="$TLS_DIR/server.key" \
  -c ssl_ca_file="$TLS_DIR/ca.crt" \
  -c ssl_min_protocol_version=TLSv1.3 \
  -c password_encryption=scram-sha-256 \
  -c hba_file=/etc/postgresql/pg_hba.conf \
  -c log_connections=on \
  -c log_disconnections=on \
  -c log_statement=ddl \
  -c log_line_prefix='%m [%p] %q%u@%d ' \
  "$@"
