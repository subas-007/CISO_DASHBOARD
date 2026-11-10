#!/usr/bin/env bash
# Full verification pipeline:
#   1. backend unit tests + typecheck, frontend typecheck + build
#   2. fresh stack (empty volumes → demo dummy data) + vendor API simulator
#   3. Playwright: auth/MFA, RBAC matrix, every page × role, workflows, 15 connectors,
#      resilience/hardening  (tests/e2e)
#   4. bash smoke test (scripts/smoke-test.sh)
#
#   usage: scripts/run-all-tests.sh [--keep-data]     (--keep-data: don't wipe volumes)
set -euo pipefail
cd "$(dirname "$0")/.."
export MSYS_NO_PATHCONV=1
COMPOSE=(docker compose -f docker-compose.yml -f docker-compose.test.yml)
step() { printf '\n\033[1;36m== %s\033[0m\n' "$*"; }

[[ -f .env && -f certs/tls.crt ]] || { echo "Run scripts/generate-certs.sh and scripts/generate-secrets.sh first"; exit 1; }
bash tests/vendor-sim/gen-cert.sh

step "Backend: typecheck + unit tests"
(cd backend && npm ci --ignore-scripts --no-audit --no-fund >/dev/null && npx prisma generate >/dev/null && npx tsc --noEmit && npx vitest run)

step "Frontend: typecheck + production build"
(cd frontend && npm ci --no-audit --no-fund >/dev/null && npm run build >/dev/null && echo "frontend build OK")

step "Build images"
"${COMPOSE[@]}" build

if [[ "${1:-}" != "--keep-data" ]]; then
  step "Reset stack (fresh volumes → seeded dummy data)"
  "${COMPOSE[@]}" down -v --remove-orphans
fi

step "Start stack + vendor simulator"
"${COMPOSE[@]}" up -d --wait
"${COMPOSE[@]}" ps --format 'table {{.Service}}\t{{.Status}}'

step "Playwright end-to-end suite"
(cd tests && npm ci --no-audit --no-fund >/dev/null && npx playwright install chromium >/dev/null && npx playwright test)

step "Bash smoke test"
bash scripts/smoke-test.sh

step "ALL TESTS PASSED"
