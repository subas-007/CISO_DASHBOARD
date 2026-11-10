#!/usr/bin/env bash
# End-to-end smoke test against a running stack (docker compose up).
# Creates temporary Keycloak users (one per role) via the admin API, signs in through the
# real OIDC flow, exercises RBAC / CSRF / SoD / SSRF / token rotation / audit integrity,
# then deletes the temporary users. Run from the Docker host (admin API is host-only).
#
#   usage: scripts/smoke-test.sh
set -uo pipefail
cd "$(dirname "$0")/.."
export MSYS_NO_PATHCONV=1

# shellcheck disable=SC1091
set -a; source .env; set +a
BASE="${PUBLIC_BASE_URL:-https://localhost}"
CURL=(curl -s --cacert certs/ca.crt)
[[ "$(uname -s)" == MINGW* || "$(uname -s)" == MSYS* ]] && CURL+=(--ssl-no-revoke)
WORK="$(mktemp -d)"
command -v cygpath >/dev/null && WORK="$(cygpath -m "$WORK")" # Git Bash: native curl needs C:/ paths
trap 'cleanup' EXIT
PASS=0; FAIL=0
ok()   { echo "  [PASS] $*"; PASS=$((PASS+1)); }
bad()  { echo "  [FAIL] $*"; FAIL=$((FAIL+1)); }
check(){ local name="$1" expected="$2" actual="$3"; [[ "$actual" == "$expected" ]] && ok "$name ($actual)" || bad "$name (expected $expected, got $actual)"; }

TEST_PW="E2e-$(openssl rand -hex 8)!Q7"
declare -A USER_IDS

admin_token() {
  "${CURL[@]}" -X POST "$BASE/auth/realms/master/protocol/openid-connect/token" \
    --data-urlencode grant_type=password --data-urlencode client_id=admin-cli \
    --data-urlencode "username=$KC_BOOTSTRAP_ADMIN_USERNAME" --data-urlencode "password=$KC_BOOTSTRAP_ADMIN_PASSWORD" \
    | sed -E 's/.*"access_token":"([^"]+)".*/\1/'
}

create_user() { # $1 username  $2 realm role
  local tok; tok="$(admin_token)"
  "${CURL[@]}" -o /dev/null -X POST "$BASE/auth/admin/realms/ciso/users" -H "Authorization: Bearer $tok" -H 'Content-Type: application/json' \
    -d "{\"username\":\"$1\",\"enabled\":true,\"emailVerified\":true,\"email\":\"$1@example.test\",\"firstName\":\"E2E\",\"lastName\":\"$2\",\"requiredActions\":[],\"credentials\":[{\"type\":\"password\",\"value\":\"$TEST_PW\",\"temporary\":false}]}"
  local id; id="$("${CURL[@]}" "$BASE/auth/admin/realms/ciso/users?username=$1&exact=true" -H "Authorization: Bearer $tok" | sed -E 's/^\[\{"id":"([^"]+)".*/\1/')"
  local role; role="$("${CURL[@]}" "$BASE/auth/admin/realms/ciso/roles/$2" -H "Authorization: Bearer $tok")"
  "${CURL[@]}" -o /dev/null -X POST "$BASE/auth/admin/realms/ciso/users/$id/role-mappings/realm" -H "Authorization: Bearer $tok" -H 'Content-Type: application/json' -d "[$role]"
  # The realm enforces authenticator enrolment for new identities; exempt these temporary
  # automation users explicitly (curl cannot complete TOTP enrolment).
  "${CURL[@]}" -o /dev/null -X PUT "$BASE/auth/admin/realms/ciso/users/$id" -H "Authorization: Bearer $tok" -H 'Content-Type: application/json' -d '{"requiredActions":[]}'
  USER_IDS[$1]="$id"
}

cleanup() {
  local tok; tok="$(admin_token 2>/dev/null)"
  for u in "${!USER_IDS[@]}"; do
    "${CURL[@]}" -o /dev/null -X DELETE "$BASE/auth/admin/realms/ciso/users/${USER_IDS[$u]}" -H "Authorization: Bearer $tok"
  done
  rm -rf "$WORK"
}

login() { # $1 username → cookie jar path
  local jar="$WORK/$1.jar"
  local page; page="$("${CURL[@]}" -L -c "$jar" -b "$jar" "$BASE/api/auth/login")"
  local action; action="$(printf '%s' "$page" | grep -oE 'action="[^"]+"' | head -1 | sed -E 's/action="([^"]+)"/\1/; s/&amp;/\&/g')"
  # No -X: curl POSTs the form, then follows the 302 with GET like a browser.
  "${CURL[@]}" -L -o /dev/null -c "$jar" -b "$jar" "$action" \
    --data-urlencode "username=$1" --data-urlencode "password=$TEST_PW" --data-urlencode credentialId=
  echo "$jar"
}

csrf() { grep -E '__Host-ciso_csrf' "$1" | awk '{print $7}'; }
code() { # $1 jar  $2 method  $3 path  [$4 json]
  local args=(-o "$WORK/body" -w '%{http_code}' -b "$1" -c "$1" -X "$2" -H "X-CSRF-Token: $(csrf "$1")" -H 'Content-Type: application/json')
  [[ -n "${4:-}" ]] && args+=(-d "$4")
  "${CURL[@]}" "${args[@]}" "$BASE/api$3"
}
body() { cat "$WORK/body"; }

echo "== Provisioning temporary users"
for pair in e2e.ciso:ciso e2e.admin:administrator e2e.secops:secops_analyst e2e.patch:patch_admin e2e.auditor:auditor; do
  create_user "${pair%%:*}" "${pair##*:}"
done
[[ ${#USER_IDS[@]} -eq 5 ]] && ok "5 users created" || bad "user creation"

echo "== OIDC login (Authorization Code + PKCE) per role"
for u in e2e.ciso e2e.admin e2e.secops e2e.patch e2e.auditor; do
  jar="$(login "$u")"
  check "login $u → /auth/me" 200 "$(code "$jar" GET /auth/me)"
done
J_CISO="$WORK/e2e.ciso.jar"; J_ADMIN="$WORK/e2e.admin.jar"; J_SEC="$WORK/e2e.secops.jar"; J_PATCH="$WORK/e2e.patch.jar"; J_AUD="$WORK/e2e.auditor.jar"
grep -q 'HttpOnly_' "$J_CISO" && ok "auth cookies are HttpOnly" || bad "auth cookies not HttpOnly"

echo "== Executive read paths"
check "CISO KPI summary" 200 "$(code "$J_CISO" GET /kpi/summary)"
body | grep -q '"mttdHours"' && ok "KPI payload has MTTD" || bad "KPI payload"
check "CISO KPI trends" 200 "$(code "$J_CISO" GET '/kpi/trends?days=30')"
check "CISO risk matrix" 200 "$(code "$J_CISO" GET /risks/matrix)"
RISK_ID="$(body | grep -oE '"risks":\[\{"id":"[0-9a-f-]{36}"' | head -1 | grep -oE '[0-9a-f-]{36}')"
check "CISO risk drill-down" 200 "$(code "$J_CISO" GET "/risks/$RISK_ID")"
check "Threat stream (filtered)" 200 "$(code "$J_AUD" GET '/threats?type=RANSOMWARE,SUPPLY_CHAIN&severity=CRITICAL,HIGH')"

echo "== RBAC enforcement"
check "Auditor cannot create risk" 403 "$(code "$J_AUD" POST /risks '{"title":"x","description":"y","category":"zz","likelihood":1,"impact":1,"ownerName":"me"}')"
check "Auditor reads audit log" 200 "$(code "$J_AUD" GET /audit?limit=5)"
check "Auditor compliance report" 200 "$(code "$J_AUD" GET /compliance/report)"
check "Patch admin cannot read audit" 403 "$(code "$J_PATCH" GET /audit)"
check "CISO cannot manage integrations" 403 "$(code "$J_CISO" POST /integrations '{}')"
check "Admin cannot approve acceptance" 403 "$(code "$J_ADMIN" POST /risk-acceptances/00000000-0000-4000-8000-000000000000/decision '{"decision":"APPROVE","note":"nope!"}')"
check "SecOps cannot update remediation" 403 "$(code "$J_SEC" PATCH /vulnerabilities/00000000-0000-4000-8000-000000000000 '{"status":"REMEDIATED"}')"
check "Admin system health" 200 "$(code "$J_ADMIN" GET /admin/system)"

echo "== Dynamic configuration"
check "Configuration status (auditor read)" 200 "$(code "$J_AUD" GET /admin/config/status)"
check "Identity policy synchronised" 200 "$(code "$J_ADMIN" POST /admin/identity/sync)"
body | grep -q '"ok":true' && ok "IdP sync: $(body | grep -oE 'TOTP [A-Za-z0-9/]+')" || bad "IdP sync failed: $(body)"
check "Auditor cannot change rate limits" 403 "$(code "$J_AUD" PUT /admin/settings/rateLimits '{"value":{}}')"
check "Unsafe public URL rejected" 400 "$(code "$J_ADMIN" PUT /admin/settings/deployment '{"value":{"publicBaseUrl":"https://x.example/$(reboot)","alternativeNames":[],"httpsPort":443,"httpPort":80,"trustedUpstreamProxies":[],"edgeRatePerSec":50,"edgeAuthRatePerSec":20,"apiMemoryMb":1024,"keycloakMemoryMb":1536,"postgresMemoryMb":2048}}')"
check "Self-lockout prevented" 400 "$(code "$J_ADMIN" PUT /admin/settings/networkAccess '{"value":{"allowedClientCidrs":["203.0.113.0/24"],"adminConsoleCidrs":[]}}')"
check "Host baseline script download" 200 "$(code "$J_ADMIN" GET '/admin/config/bundle/host?os=ubuntu')"
body | bash -n && ok "host script is valid bash" || bad "host script syntax error"
check "Gateway hides internal endpoints" 404 "$("${CURL[@]}" -o /dev/null -w '%{http_code}' "$BASE/api/internal/ip-gate/app")"
check "Enrolment lists IdP identities" 200 "$(code "$J_ADMIN" GET '/admin/identity/users?search=admin')"
body | grep -q '"username":"admin"' && ok "demo administrator 'admin' provisioned" || ok "no demo administrator (production profile)"

echo "== Input validation (mass assignment / bad types)"
check "Unknown field rejected" 400 "$(code "$J_CISO" POST /risks '{"title":"Valid title","description":"d","category":"Cyber","likelihood":3,"impact":3,"ownerName":"Owner","isAdmin":true}')"
check "Out-of-range likelihood" 400 "$(code "$J_CISO" POST /risks '{"title":"Valid title","description":"d","category":"Cyber","likelihood":9,"impact":3,"ownerName":"Owner"}')"
check "Missing CSRF header" 403 "$("${CURL[@]}" -o /dev/null -w '%{http_code}' -b "$J_CISO" -X POST -H 'Content-Type: application/json' -d '{}' "$BASE/api/risks")"

echo "== Risk acceptance workflow + segregation of duties"
check "SecOps creates risk" 201 "$(code "$J_SEC" POST /risks '{"title":"E2E legacy VPN risk","description":"Smoke test risk","category":"Cyber","likelihood":4,"impact":4,"ownerName":"SecOps"}')"
NEW_RISK="$(body | grep -oE '"id":"[0-9a-f-]{36}"' | head -1 | grep -oE '[0-9a-f-]{36}')"
check "CISO requests acceptance" 201 "$(code "$J_CISO" POST "/risks/$NEW_RISK/acceptances" '{"justification":"Compensating controls: segmentation and MFA in place.","expiresInDays":30}')"
ACC_ID="$(body | grep -oE '"id":"[0-9a-f-]{36}"' | head -1 | grep -oE '[0-9a-f-]{36}')"
check "CISO cannot approve own request (SoD)" 403 "$(code "$J_CISO" POST "/risk-acceptances/$ACC_ID/decision" '{"decision":"APPROVE","note":"self approval"}')"
check "SecOps requests acceptance on seeded risk path" 200 "$(code "$J_SEC" GET /risk-acceptances?status=PENDING)"
PENDING="$(body | grep -oE '"id":"[0-9a-f-]{36}","riskId"' | grep -v "$ACC_ID" | head -1 | grep -oE '[0-9a-f-]{36}' | head -1)"
check "CISO approves another requester's acceptance" 200 "$(code "$J_CISO" POST "/risk-acceptances/$PENDING/decision" '{"decision":"APPROVE","note":"Approved in smoke test"}')"

echo "== KRI parameter control"
check "Invalid KRI threshold ordering" 400 "$(code "$J_CISO" PUT /kri/open_critical '{"amberThreshold":30,"redThreshold":10,"enabled":true}')"
check "CISO updates KRI threshold" 200 "$(code "$J_CISO" PUT /kri/open_critical '{"amberThreshold":12,"redThreshold":30,"enabled":true}')"
check "Auditor cannot change KRI" 403 "$(code "$J_AUD" PUT /kri/open_critical '{"amberThreshold":1,"redThreshold":2,"enabled":true}')"

echo "== Connector framework + SSRF egress policy"
check "Catalog lists adapters" 200 "$(code "$J_SEC" GET /integrations/catalog)"
check "Blocks cloud metadata IP" 400 "$(code "$J_SEC" POST /integrations '{"name":"Evil meta","vendor":"generic_rest","baseUrl":"https://169.254.169.254","authMode":"API_KEY","pollIntervalSec":300,"settings":{"path":"/latest"},"credentials":{"apiKey":"x"}}')"
check "Blocks internal service host" 400 "$(code "$J_SEC" POST /integrations '{"name":"Evil internal","vendor":"generic_rest","baseUrl":"https://postgres:5432","authMode":"API_KEY","pollIntervalSec":300,"settings":{"path":"/x"},"credentials":{"apiKey":"x"}}')"
check "Blocks plain http" 400 "$(code "$J_SEC" POST /integrations '{"name":"Plain http","vendor":"generic_rest","baseUrl":"http://intel.example.com","authMode":"API_KEY","pollIntervalSec":300,"settings":{"path":"/x"},"credentials":{"apiKey":"x"}}')"
check "Creates mTLS-less API-key connector" 201 "$(code "$J_SEC" POST /integrations '{"name":"E2E Splunk","vendor":"splunk","baseUrl":"https://splunk.example.invalid:8089","authMode":"API_KEY","pollIntervalSec":300,"settings":{"search":"search index=notable | head 10"},"credentials":{"apiKey":"super-secret-token","apiKeyPrefix":"Bearer "}}')"
CONN_ID="$(body | grep -oE '"id":"[0-9a-f-]{36}"' | head -1 | grep -oE '[0-9a-f-]{36}')"
body | grep -q 'super-secret-token' && bad "credential echoed back" || ok "credentials never returned"
check "Test connection fails safely (unresolvable host)" 200 "$(code "$J_SEC" POST "/integrations/$CONN_ID/test")"
body | grep -q '"ok":false' && ok "test reports failure: $(body | grep -oE '"message":"[^"]+"')" || bad "unexpected test result"
check "Delete connector" 204 "$(code "$J_SEC" DELETE "/integrations/$CONN_ID")"
"${CURL[@]}" -b "$J_AUD" "$BASE/api/audit?action=integration.create&limit=5" | grep -q 'super-secret-token' && bad "secret leaked into audit log" || ok "secret absent from audit log"

echo "== Session security"
OLD_RT="$(grep -E '__Host-ciso_rt' "$J_PATCH" | awk '{print $7}')"
check "Refresh rotates token" 200 "$(code "$J_PATCH" POST /auth/refresh)"
NEW_RT="$(grep -E '__Host-ciso_rt' "$J_PATCH" | awk '{print $7}')"
[[ -n "$NEW_RT" && "$NEW_RT" != "$OLD_RT" ]] && ok "refresh token rotated" || bad "refresh token not rotated"
REPLAY="$("${CURL[@]}" -o /dev/null -w '%{http_code}' -X POST -H "X-CSRF-Token: $(csrf "$J_PATCH")" -b "__Host-ciso_rt=$OLD_RT; __Host-ciso_csrf=$(csrf "$J_PATCH")" "$BASE/api/auth/refresh")"
check "Replayed refresh token rejected" 401 "$REPLAY"
check "Token family revoked after reuse" 401 "$(code "$J_PATCH" POST /auth/refresh)"
check "Logout" 200 "$(code "$J_AUD" POST /auth/logout)"
check "Session dead after logout" 401 "$(code "$J_AUD" GET /auth/me)"

echo "== Audit chain integrity"
check "Verify chain" 200 "$(code "$J_ADMIN" GET /audit/verify)"
body | grep -q '"valid":true' && ok "hash chain valid: $(body | grep -oE '"checked":[0-9]+')" || bad "chain invalid: $(body)"
check "Export CSV" 200 "$(code "$J_ADMIN" GET /audit/export)"

echo "== Database-level immutability"
PGOUT="$(docker compose exec -T postgres sh -c 'PGPASSWORD="$POSTGRES_PASSWORD" psql -h 127.0.0.1 -U "$POSTGRES_USER" -d "$POSTGRES_DB" -c "UPDATE audit_log SET outcome = '"'"'SUCCESS'"'"' WHERE id = 1"' 2>&1)"
grep -q 'append-only' <<<"$PGOUT" && ok "UPDATE on audit_log blocked even for owner" || bad "audit_log UPDATE not blocked: $PGOUT"

echo
echo "Result: $PASS passed, $FAIL failed"
[[ $FAIL -eq 0 ]]
