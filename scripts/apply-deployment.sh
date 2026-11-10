#!/usr/bin/env bash
# Applies a deployment profile downloaded from Configuration → Deployment (deployment.env):
# public URL / IP, ports, certificate names, trusted load balancers, gateway rate limits
# and container memory limits.
#
#   usage: scripts/apply-deployment.sh deployment.env [--dry-run] [--yes] [--allow-edited]
#
# Safety: the file is parsed (never sourced); only whitelisted keys with strictly
# validated values are accepted; the checksum written by the dashboard is verified;
# .env is backed up before changes; certificates are re-issued under the existing CA
# only when new names are required. The OIDC redirect URIs in Keycloak follow the new
# public URL automatically (idp-init runs on every deploy).
set -euo pipefail
cd "$(dirname "$0")/.."

PROFILE="${1:-}"
[[ -n "$PROFILE" && -f "$PROFILE" ]] || { echo "usage: scripts/apply-deployment.sh deployment.env [--dry-run] [--yes] [--allow-edited]" >&2; exit 2; }
shift
DRY=0; YES=0; ALLOW_EDITED=0
for a in "$@"; do
  case "$a" in
    --dry-run) DRY=1 ;;
    --yes) YES=1 ;;
    --allow-edited) ALLOW_EDITED=1 ;;
    *) echo "unknown option: $a" >&2; exit 2 ;;
  esac
done
[[ -f .env ]] || { echo "No .env found — run scripts/generate-secrets.sh first." >&2; exit 1; }

declare -A RULE=(
  [PUBLIC_BASE_URL]='^https://[A-Za-z0-9.-]+(:[0-9]{1,5})?$'
  [HTTPS_PORT]='^[0-9]{1,5}$'
  [HTTP_PORT]='^[0-9]{1,5}$'
  [CERT_SANS]='^[A-Za-z0-9.:,-]*$'
  [TRUSTED_UPSTREAM_PROXIES]='^[0-9A-Fa-f:./,]*$'
  [EDGE_RATE_LIMIT_RPS]='^[0-9]{1,5}$'
  [EDGE_AUTH_RATE_LIMIT_RPS]='^[0-9]{1,4}$'
  [API_MEMORY]='^[0-9]{3,6}m$'
  [KEYCLOAK_MEMORY]='^[0-9]{3,6}m$'
  [POSTGRES_MEMORY]='^[0-9]{3,6}m$'
)
ORDER=(PUBLIC_BASE_URL HTTPS_PORT HTTP_PORT CERT_SANS TRUSTED_UPSTREAM_PROXIES EDGE_RATE_LIMIT_RPS EDGE_AUTH_RATE_LIMIT_RPS API_MEMORY KEYCLOAK_MEMORY POSTGRES_MEMORY)

declare -A NEW=()
BODY=""
while IFS= read -r line || [[ -n "$line" ]]; do
  line="${line%$'\r'}"
  [[ -z "$line" || "$line" == \#* ]] && continue
  key="${line%%=*}"
  val="${line#*=}"
  [[ -n "${RULE[$key]:-}" ]] || { echo "Rejected: unknown key '$key'" >&2; exit 1; }
  [[ "$val" =~ ${RULE[$key]} ]] || { echo "Rejected: invalid value for $key" >&2; exit 1; }
  NEW[$key]="$val"
  BODY="${BODY:+$BODY$'\n'}$line"
done < "$PROFILE"

EXPECTED="$(grep -Eo 'sha256\(body\) = [0-9a-f]{64}' "$PROFILE" | awk '{print $NF}' || true)"
ACTUAL="$(printf '%s' "$BODY" | openssl dgst -sha256 | awk '{print $NF}')"
if [[ "$EXPECTED" != "$ACTUAL" && "$ALLOW_EDITED" != 1 ]]; then
  echo "Checksum mismatch: the profile was edited after download (or is not from the dashboard)." >&2
  echo "Re-download it, or pass --allow-edited if the edit is intentional." >&2
  exit 1
fi

env_get() { grep -E "^$1=" .env | tail -1 | cut -d= -f2- || true; }
CHANGED=()
echo "Deployment profile: $PROFILE"
for k in "${ORDER[@]}"; do
  [[ -v "NEW[$k]" ]] || continue
  old="$(env_get "$k")"
  if [[ "$old" != "${NEW[$k]}" ]]; then
    printf '  %-26s %s  →  %s\n' "$k" "${old:-<unset>}" "${NEW[$k]}"
    CHANGED+=("$k")
  fi
done
if [[ ${#CHANGED[@]} -eq 0 ]]; then echo "  (no changes — already applied)"; fi

# Certificate names required by the profile
HOST="$(echo "${NEW[PUBLIC_BASE_URL]:-$(env_get PUBLIC_BASE_URL)}" | sed -E 's#^https://([^:/]+).*#\1#')"
NEED_CERT=0
if [[ -f certs/tls.crt ]]; then
  CURRENT_SANS="$(openssl x509 -in certs/tls.crt -noout -ext subjectAltName 2>/dev/null | tail -n +2 | tr -d ' ')"
  IFS=',' read -r -a WANT <<< "${HOST},${NEW[CERT_SANS]:-}"
  for n in "${WANT[@]}"; do
    [[ -z "$n" ]] && continue
    if ! grep -Eq "(^|,)(DNS:|IPAddress:)${n//./\\.}(,|$)" <<< "$CURRENT_SANS"; then NEED_CERT=1; echo "  certificate is missing name: $n"; fi
  done
fi

if (( DRY )); then echo "Dry run — nothing changed."; exit 0; fi
if [[ ${#CHANGED[@]} -eq 0 && $NEED_CERT -eq 0 ]]; then exit 0; fi
if (( ! YES )); then
  read -r -p "Apply these changes and redeploy? [y/N] " answer
  [[ "$answer" =~ ^[Yy]$ ]] || { echo "Aborted."; exit 1; }
fi

BACKUP=".env.bak.$(date -u +%Y%m%dT%H%M%SZ)"
cp -p .env "$BACKUP"
for k in "${CHANGED[@]}"; do
  if grep -qE "^$k=" .env; then
    awk -v k="$k" -v v="${NEW[$k]}" 'BEGIN{FS=OFS="="} $1==k {print k "=" v; next} {print}' .env > .env.tmp && mv .env.tmp .env
  else
    printf '%s=%s\n' "$k" "${NEW[$k]}" >> .env
  fi
done
chmod 600 .env
echo ".env updated (backup: $BACKUP)"

RECREATE=()
if (( NEED_CERT )); then
  if [[ ! -f certs/ca.key ]]; then
    echo "certs/ca.key is not present (kept offline?). Issue a certificate for: ${HOST},${NEW[CERT_SANS]:-} and place it in certs/, then run: docker compose up -d --force-recreate" >&2
    exit 1
  fi
  FORCE=1 CERT_SANS="${NEW[CERT_SANS]:-}" scripts/generate-certs.sh "$HOST"
  RECREATE=(--force-recreate)
fi

docker compose up -d --wait "${RECREATE[@]}"
echo "Deployment applied. Public URL: $(env_get PUBLIC_BASE_URL)"
