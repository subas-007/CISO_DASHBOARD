#!/usr/bin/env bash
# Generates all runtime secrets with a CSPRNG. Nothing is hardcoded in the repository
# except the published *demo* administrator password (demo profile only, see below).
#   - .env         : compose interpolation values (git-ignored, mode 600)
#   - secrets/*    : Docker secrets mounted into containers as files (git-ignored, mode 600)
#
#   usage: PUBLIC_BASE_URL=https://ciso.corp.example scripts/generate-secrets.sh            # first install
#          scripts/generate-secrets.sh --upgrade   # add secrets/keys introduced by newer releases
#          scripts/generate-secrets.sh --force     # fresh deployment only (overwrites everything)
#
# Demo profile (SEED_DEMO_DATA=true, the default): creates the demo administrator
# "${DEMO_ADMIN_USERNAME:-admin}" with password "${DEMO_ADMIN_PASSWORD:-Admin@123!}" (override
# both via environment variables). MFA enrolment is still enforced at first sign-in.
# Production: SEED_DEMO_DATA=false — no demo accounts or demo data are created.
#
# WARNING: regenerating DATA_ENCRYPTION_KEYS / AUDIT_HMAC_KEY makes existing encrypted
# fields unreadable and breaks audit-chain verification. Rotate keys, don't replace them.
set -euo pipefail
cd "$(dirname "$0")/.."
umask 077

MODE=create
case "${1:-}" in
  --force) MODE=force ;;
  --upgrade) MODE=upgrade ;;
  "") ;;
  *) echo "unknown option: $1" >&2; exit 2 ;;
esac

hex() { openssl rand -hex "$1"; }
b64() { openssl rand -base64 "$1" | tr -d '\n'; }
env_get() { grep -E "^$1=" .env 2>/dev/null | tail -1 | cut -d= -f2- || true; }
# ensure_env KEY VALUE — appends KEY=VALUE to .env unless the key already exists
ensure_env() { grep -qE "^$1=" .env || printf '%s=%s\n' "$1" "$2" >> .env; }
# ensure_secret NAME VALUE — writes secrets/NAME unless it already exists
ensure_secret() { [[ -f "secrets/$1" ]] || { printf '%s' "$2" > "secrets/$1"; ADDED+=("secrets/$1"); }; }
ADDED=()

if [[ -f .env && "$MODE" == "create" ]]; then
  echo ".env already exists — use --upgrade to add newly required secrets (keeps existing ones)," >&2
  echo "or --force on a fresh deployment only." >&2
  exit 1
fi
if [[ "$MODE" == "create" && -f secrets/data_encryption_keys ]]; then
  echo "secrets/data_encryption_keys exists without .env — refusing to replace encryption keys (data loss)." >&2
  echo "Restore .env from backup, or use --force only if the database is new." >&2
  exit 1
fi
if [[ "$MODE" == "upgrade" && ! -f .env ]]; then
  echo "No .env found — run without --upgrade for a first installation." >&2
  exit 1
fi

if [[ "$MODE" != "upgrade" ]]; then
  PUBLIC_BASE_URL="${PUBLIC_BASE_URL:-https://localhost}"
  POSTGRES_DB=ciso
  POSTGRES_USER=ciso_owner
  POSTGRES_PASSWORD="$(hex 24)"
  APP_DB_PASSWORD="$(hex 24)"
  KC_DB_PASSWORD="$(hex 24)"
  OIDC_CLIENT_SECRET="$(hex 32)"

  cat > .env <<EOF
# Generated $(date -u +%Y-%m-%dT%H:%M:%SZ) — DO NOT COMMIT (git-ignored)
PUBLIC_BASE_URL=${PUBLIC_BASE_URL}
APP_UID=$(id -u)
APP_GID=$(id -g)
HTTPS_PORT=443
HTTP_PORT=80
LOG_LEVEL=info
SEED_DEMO_DATA=${SEED_DEMO_DATA:-true}

POSTGRES_DB=${POSTGRES_DB}
POSTGRES_USER=${POSTGRES_USER}
POSTGRES_PASSWORD=${POSTGRES_PASSWORD}
APP_DB_PASSWORD=${APP_DB_PASSWORD}
KC_DB_PASSWORD=${KC_DB_PASSWORD}

KC_BOOTSTRAP_ADMIN_USERNAME=kcadmin
KC_BOOTSTRAP_ADMIN_PASSWORD=Kc-$(hex 12)!Z9
OIDC_CLIENT_SECRET=${OIDC_CLIENT_SECRET}
DEMO_USER_PASSWORD=Ciso-$(hex 6)!A9

DATA_ENCRYPTION_ACTIVE_KEY=v1
SECRETS_PROVIDER=env
CONNECTOR_ALLOWED_HOSTS=
CONNECTOR_BLOCK_PRIVATE_NETWORKS=false
EOF

  mkdir -p secrets
  DB_OPTS="sslmode=require&sslcert=/run/certs/ca.crt&sslaccept=strict"
  printf '%s' "postgresql://ciso_app:${APP_DB_PASSWORD}@postgres:5432/${POSTGRES_DB}?${DB_OPTS}&connection_limit=20" > secrets/database_url
  printf '%s' "postgresql://${POSTGRES_USER}:${POSTGRES_PASSWORD}@postgres:5432/${POSTGRES_DB}?${DB_OPTS}" > secrets/migrate_database_url
  printf '%s' "${OIDC_CLIENT_SECRET}" > secrets/oidc_client_secret
  printf '%s' "$(hex 64)"            > secrets/jwt_secret
  printf '%s' "$(b64 32)"            > secrets/state_encryption_key
  printf '%s' "v1:$(b64 32)"         > secrets/data_encryption_keys
  printf '%s' "$(hex 32)"            > secrets/blind_index_key
  printf '%s' "$(hex 32)"            > secrets/audit_hmac_key
fi

mkdir -p secrets
DEMO="$(env_get SEED_DEMO_DATA)"

# --- Keys introduced by the dynamic configuration release (idempotent) ---------------
ensure_env CERT_SANS "$(env_get PUBLIC_BASE_URL | sed -E 's#^https://([^:/]+).*#\1#')"
ensure_env TRUSTED_UPSTREAM_PROXIES ""
ensure_env EDGE_RATE_LIMIT_RPS 50
ensure_env EDGE_AUTH_RATE_LIMIT_RPS 20
ensure_env API_MEMORY 1024m
ensure_env KEYCLOAK_MEMORY 1536m
ensure_env POSTGRES_MEMORY 2048m
if [[ "$DEMO" == "true" ]]; then
  ensure_env DEMO_ADMIN_USERNAME "${DEMO_ADMIN_USERNAME:-admin}"
  ensure_secret demo_admin_password "${DEMO_ADMIN_PASSWORD:-Admin@123!}"
else
  ensure_env DEMO_ADMIN_USERNAME ""
  ensure_secret demo_admin_password ""
fi
ensure_secret idp_provisioner_secret "$(hex 32)"
ensure_secret kc_bootstrap_admin_password "$(env_get KC_BOOTSTRAP_ADMIN_PASSWORD)"
chmod 600 .env secrets/*

if [[ "$MODE" == "upgrade" ]]; then
  if [[ ${#ADDED[@]} -eq 0 ]]; then echo "Nothing to add — secrets are up to date."; else printf 'Added: %s\n' "${ADDED[@]}"; fi
  exit 0
fi

cat <<EOF
Secrets generated.
  Public URL            : $(env_get PUBLIC_BASE_URL)
EOF
if [[ "$DEMO" == "true" ]]; then
cat <<EOF
  Demo administrator    : $(env_get DEMO_ADMIN_USERNAME) / (see secrets/demo_admin_password)   — authenticator-app enrolment at first sign-in
  Other demo users      : ciso.demo, admin.demo, secops.demo, patch.demo, auditor.demo
  Their initial password: $(env_get DEMO_USER_PASSWORD)   (temporary — change + TOTP enrolment forced at first login)
EOF
fi
cat <<EOF
  Keycloak admin        : kcadmin / see KC_BOOTSTRAP_ADMIN_PASSWORD in .env (console reachable from the host only)

Back up ./secrets/data_encryption_keys and ./secrets/audit_hmac_key to your vault NOW.
EOF
