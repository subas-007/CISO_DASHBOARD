#!/usr/bin/env bash
# Generates all runtime secrets with a CSPRNG. Nothing is hardcoded in the repository.
#   - .env         : compose interpolation values (git-ignored, mode 600)
#   - secrets/*    : Docker secrets mounted into the API as files (git-ignored, mode 600)
#
#   usage: PUBLIC_BASE_URL=https://ciso.corp.example scripts/generate-secrets.sh [--force]
#
# WARNING: regenerating DATA_ENCRYPTION_KEYS / AUDIT_HMAC_KEY makes existing encrypted
# fields unreadable and breaks audit-chain verification. Rotate keys, don't replace them.
set -euo pipefail
cd "$(dirname "$0")/.."
umask 077

if [[ -f .env && "${1:-}" != "--force" ]]; then
  echo ".env already exists — refusing to overwrite (use --force on a fresh deployment only)." >&2
  exit 1
fi

hex() { openssl rand -hex "$1"; }
b64() { openssl rand -base64 "$1" | tr -d '\n'; }

PUBLIC_BASE_URL="${PUBLIC_BASE_URL:-https://localhost}"
POSTGRES_DB=ciso
POSTGRES_USER=ciso_owner
POSTGRES_PASSWORD="$(hex 24)"
APP_DB_PASSWORD="$(hex 24)"
KC_DB_PASSWORD="$(hex 24)"
KC_BOOTSTRAP_ADMIN_PASSWORD="Kc-$(hex 12)!Z9"
OIDC_CLIENT_SECRET="$(hex 32)"
DEMO_USER_PASSWORD="Ciso-$(hex 6)!A9"

cat > .env <<EOF
# Generated $(date -u +%Y-%m-%dT%H:%M:%SZ) — DO NOT COMMIT (git-ignored)
PUBLIC_BASE_URL=${PUBLIC_BASE_URL}
APP_UID=$(id -u)
APP_GID=$(id -g)
HTTPS_PORT=443
HTTP_PORT=80
LOG_LEVEL=info
SEED_DEMO_DATA=true

POSTGRES_DB=${POSTGRES_DB}
POSTGRES_USER=${POSTGRES_USER}
POSTGRES_PASSWORD=${POSTGRES_PASSWORD}
APP_DB_PASSWORD=${APP_DB_PASSWORD}
KC_DB_PASSWORD=${KC_DB_PASSWORD}

KC_BOOTSTRAP_ADMIN_USERNAME=kcadmin
KC_BOOTSTRAP_ADMIN_PASSWORD=${KC_BOOTSTRAP_ADMIN_PASSWORD}
OIDC_CLIENT_SECRET=${OIDC_CLIENT_SECRET}
DEMO_USER_PASSWORD=${DEMO_USER_PASSWORD}

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
chmod 600 .env secrets/*

cat <<EOF
Secrets generated.
  Public URL            : ${PUBLIC_BASE_URL}
  Demo users            : ciso.demo, admin.demo, secops.demo, patch.demo, auditor.demo
  Initial demo password : ${DEMO_USER_PASSWORD}   (temporary — change + TOTP enrolment forced at first login)
  Keycloak admin        : kcadmin / see KC_BOOTSTRAP_ADMIN_PASSWORD in .env (console reachable from the host only)

Back up ./secrets/data_encryption_keys and ./secrets/audit_hmac_key to your vault NOW.
EOF
