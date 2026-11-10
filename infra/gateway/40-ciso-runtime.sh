#!/bin/sh
# Renders runtime NGINX includes from the deployment profile (environment values set by
# scripts/apply-deployment.sh). Runs from the image entrypoint before NGINX starts and
# writes only to the tmpfs (/tmp) because the container filesystem is read-only.
# Every value is validated; anything malformed falls back to a safe default.
set -eu
OUT=/tmp/nginx-runtime
mkdir -p "$OUT"

int_or() { case "${1:-}" in '' | *[!0-9]*) echo "$2" ;; *) echo "$1" ;; esac; }
RPS=$(int_or "${EDGE_RATE_LIMIT_RPS:-}" 50)
AUTH_RPS=$(int_or "${EDGE_AUTH_RATE_LIMIT_RPS:-}" 20)

# Edge flood protection per source IP (per-user quotas are enforced by the API).
cat >"$OUT/http-ratelimit.conf" <<EOF
limit_req_zone \$binary_remote_addr zone=api:10m  rate=${RPS}r/s;
limit_req_zone \$binary_remote_addr zone=auth:10m rate=${AUTH_RPS}r/s;
EOF

# Trusted upstream load balancers: only they may supply the client IP (X-Forwarded-For).
: >"$OUT/server-realip.conf"
if [ -n "${TRUSTED_UPSTREAM_PROXIES:-}" ]; then
  for cidr in $(echo "$TRUSTED_UPSTREAM_PROXIES" | tr ',' ' '); do
    if echo "$cidr" | grep -Eq '^[0-9A-Fa-f:.]+(/[0-9]{1,3})?$'; then
      echo "set_real_ip_from $cidr;" >>"$OUT/server-realip.conf"
    else
      echo "40-ciso-runtime: ignoring invalid proxy CIDR '$cidr'" >&2
    fi
  done
  printf 'real_ip_header X-Forwarded-For;\nreal_ip_recursive on;\n' >>"$OUT/server-realip.conf"
fi

# Canonical public address: requests arriving via an alternative name / IP are redirected,
# so OIDC cookies and redirect URIs always match the configured public URL.
: >"$OUT/server-canonical.conf"
echo 'map $host $ciso_noncanonical { default 0; }' >"$OUT/http-canonical.conf"
URL="${PUBLIC_BASE_URL:-}"
if echo "$URL" | grep -Eq '^https://[A-Za-z0-9.-]+(:[0-9]{1,5})?$'; then
  HOST=$(echo "$URL" | sed -E 's#^https://([^:/]+).*#\1#' | tr 'A-Z' 'a-z')
  cat >"$OUT/http-canonical.conf" <<EOF
map \$host \$ciso_noncanonical {
  default 1;
  "${HOST}" 0;
}
EOF
  echo "if (\$ciso_noncanonical) { return 308 ${URL}\$request_uri; }" >"$OUT/server-canonical.conf"
fi

echo "40-ciso-runtime: edge ${RPS}r/s, auth ${AUTH_RPS}r/s, canonical '${URL:-<none>}', trusted proxies '${TRUSTED_UPSTREAM_PROXIES:-<none>}'"
