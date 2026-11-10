#!/usr/bin/env bash
# Generates a private CA and a service certificate for the gateway, API, Keycloak and
# PostgreSQL (TLS 1.3 everywhere, mTLS gateway→API). For production, replace ./certs
# with certificates from your enterprise PKI (same file names).
#
#   usage: scripts/generate-certs.sh [public-hostname] [extra-ip]
#          CERT_SANS=10.20.5.15,ciso.corp.example FORCE=1 scripts/generate-certs.sh ciso.corp.example
#
# With FORCE=1 and an existing certs/ca.key, only the service certificate is re-issued
# (browsers that already trust the CA keep working). Set NEW_CA=1 to replace the CA too.
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

declare -A SEEN=()
SAN=""
add_san() {
  local v="$1"
  [[ -z "$v" || -n "${SEEN[$v]:-}" ]] && return 0
  SEEN[$v]=1
  if [[ "$v" =~ ^[0-9]+(\.[0-9]+){3}$ || ( "$v" == *:* && "$v" =~ ^[0-9A-Fa-f:]+$ ) ]]; then SAN="${SAN:+$SAN,}IP:$v"
  elif [[ "$v" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$ ]]; then SAN="${SAN:+$SAN,}DNS:$v"
  else echo "Ignoring invalid certificate name: $v" >&2
  fi
}
add_san "$HOST"
for n in localhost gateway api keycloak postgres 127.0.0.1 "$EXTRA_IP"; do add_san "$n"; done
IFS=',' read -r -a EXTRA <<< "${CERT_SANS:-}"
for n in "${EXTRA[@]}"; do add_san "$(echo "$n" | tr -d '[:space:]')"; done

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
