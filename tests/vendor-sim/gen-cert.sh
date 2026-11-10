#!/usr/bin/env bash
# Issues a wildcard certificate for *.sim.test from the internal test CA (certs/ca.key).
set -euo pipefail
cd "$(dirname "$0")/../.."
export MSYS_NO_PATHCONV=1
[[ -f certs/sim.crt && "${FORCE:-}" != "1" ]] && { echo "certs/sim.crt exists"; exit 0; }
umask 077
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out certs/sim.key
openssl req -new -key certs/sim.key -subj "/O=Vendor Simulator/CN=*.sim.test" -out certs/sim.csr
printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:*.sim.test\n' > certs/sim.ext
openssl x509 -req -in certs/sim.csr -CA certs/ca.crt -CAkey certs/ca.key -CAcreateserial -days 30 -sha256 -extfile certs/sim.ext -out certs/sim.crt
rm -f certs/sim.csr certs/sim.ext certs/ca.srl
echo "issued certs/sim.crt (*.sim.test)"
