#!/bin/sh
# First-boot bootstrap: least-privilege runtime role for the API and an isolated
# database + role for Keycloak. Runs once, only when the data volume is empty.
set -eu

: "${APP_DB_PASSWORD:?APP_DB_PASSWORD is required}"
: "${KC_DB_PASSWORD:?KC_DB_PASSWORD is required}"

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
  -v app_pw="$APP_DB_PASSWORD" -v kc_pw="$KC_DB_PASSWORD" -v db="$POSTGRES_DB" <<'EOSQL'
-- Runtime role used by the API: DML only, no DDL, no superuser.
CREATE ROLE ciso_app LOGIN PASSWORD :'app_pw' NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION;
ALTER ROLE ciso_app SET statement_timeout = '30s';
ALTER ROLE ciso_app SET idle_in_transaction_session_timeout = '60s';

-- Keycloak gets its own database and role (blast-radius isolation).
CREATE ROLE keycloak LOGIN PASSWORD :'kc_pw' NOSUPERUSER NOCREATEDB NOCREATEROLE;
CREATE DATABASE keycloak OWNER keycloak;

REVOKE ALL ON DATABASE keycloak FROM PUBLIC;
REVOKE ALL ON DATABASE :"db" FROM PUBLIC;
GRANT CONNECT ON DATABASE :"db" TO ciso_app;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
EOSQL
