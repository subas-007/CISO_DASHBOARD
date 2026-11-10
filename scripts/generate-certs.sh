#!/usr/bin/env bash
# Generates a private CA and a service certificate for the gateway, API, Keycloak and
# PostgreSQL (TLS 1.3 everywhere, mTLS gateway→API). For production, replace ./certs
# with certificates from your enterprise PKI (same file names).
#
#   usage: scripts/generate-certs.sh [public-hostname] [extra-ip]
set -euo pipefail
cd "$(dirname "$0")/.."
export MSYS_NO_PATHCONV=1 # Git Bash on Windows: keep "/O=..." subjects intact

HOST="${1:-localhost}"
EXTRA_IP="${2:-}"
OUT=certs
umask 077
mkdir -p "$OUT"

if [[ -f "$OUT/tls.crt" && "${FORCE:-}" != "1" ]]; then
  echo "certs/ already populated — set FORCE=1 to regenerate." >&2
  exit 1
fi

SAN="DNS:localhost,DNS:gateway,DNS:api,DNS:keycloak,DNS:postgres,IP:127.0.0.1"
[[ "$HOST" != "localhost" ]] && SAN="DNS:${HOST},${SAN}"
[[ -n "$EXTRA_IP" ]] && SAN="${SAN},IP:${EXTRA_IP}"

# Private CA (P-384)
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -out "$OUT/ca.key"
openssl req -x509 -new -key "$OUT/ca.key" -sha384 -days 1825 \
  -subj "/O=CISO Dashboard/CN=CISO Dashboard Internal CA" \
  -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -out "$OUT/ca.crt"

# Service certificate (P-256) — serverAuth for TLS endpoints, clientAuth for gateway→API mTLS
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$OUT/tls.key"
openssl req -new -key "$OUT/tls.key" -subj "/O=CISO Dashboard/CN=${HOST}" -out "$OUT/tls.csr"
cat > "$OUT/ext.cnf" <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth,clientAuth
subjectAltName=${SAN}
EOF
openssl x509 -req -in "$OUT/tls.csr" -CA "$OUT/ca.crt" -CAkey "$OUT/ca.key" -CAcreateserial \
  -days 397 -sha256 -extfile "$OUT/ext.cnf" -out "$OUT/tls.crt"

rm -f "$OUT/tls.csr" "$OUT/ext.cnf" "$OUT/ca.srl"
chmod 600 "$OUT/ca.key" "$OUT/tls.key"
chmod 644 "$OUT/ca.crt" "$OUT/tls.crt"

echo "Certificates written to ./certs (SAN: ${SAN})"
echo "Move certs/ca.key OFFLINE after generation — it is not needed at runtime."
echo "Import certs/ca.crt into your browser/OS trust store to avoid warnings."
