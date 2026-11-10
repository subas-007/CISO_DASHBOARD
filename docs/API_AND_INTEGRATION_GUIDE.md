# CISO Executive Dashboard: API & Integration Guide

**Audience:** integration engineers, security-tool owners, identity engineers and developers.

- **Part A** documents the dashboard's own REST API.
- **Part B** sets out the requirements and guidelines for connecting security tools and identity providers.

**Related documents:**
- [User Manual](USER_MANUAL.md)
- [Maintenance Manual](MAINTENANCE_MANUAL.md)
- [Configuration reference](CONFIGURATION.md)
- [Security architecture](SECURITY.md)

---

## Contents

**Part A: Dashboard REST API**
- [A.1 Design principles](#a1-design-principles)
- [A.2 Authentication and session model](#a2-authentication-and-session-model)
- [A.3 Request requirements](#a3-request-requirements)
- [A.4 Responses and errors](#a4-responses-and-errors)
- [A.5 Rate limits](#a5-rate-limits)
- [A.6 Pagination](#a6-pagination)
- [A.7 Real-time event stream (SSE)](#a7-real-time-event-stream-sse)
- [A.8 Endpoint reference](#a8-endpoint-reference)
- [A.9 Request body reference](#a9-request-body-reference)
- [A.10 Enumerations](#a10-enumerations)
- [A.11 Examples](#a11-examples)
- [A.12 Compatibility policy](#a12-compatibility-policy)

**Part B: Integration requirements and guidelines**
- [B.1 Integration model](#b1-integration-model)
- [B.2 Requirements for every integration](#b2-requirements-for-every-integration)
- [B.3 Authentication modes and credential fields](#b3-authentication-modes-and-credential-fields)
- [B.4 Per-vendor requirements](#b4-per-vendor-requirements)
- [B.5 Advanced API parameters](#b5-advanced-api-parameters)
- [B.6 Generic REST/JSON adapters](#b6-generic-restjson-adapters)
- [B.7 Normalised data model and de-duplication](#b7-normalised-data-model-and-de-duplication)
- [B.8 Synchronisation behaviour](#b8-synchronisation-behaviour)
- [B.9 Identity provider (OIDC) integration](#b9-identity-provider-oidc-integration)
- [B.10 Outbound integration: logs and evidence](#b10-outbound-integration-logs-and-evidence)
- [B.11 Security guidelines](#b11-security-guidelines)
- [B.12 Onboarding checklist and acceptance test](#b12-onboarding-checklist-and-acceptance-test)
- [B.13 Developing a new adapter](#b13-developing-a-new-adapter)

---

# Part A: Dashboard REST API

## A.1 Design principles

| Principle | Implementation |
|-----------|----------------|
| One origin | The API is served under `https://<public-host>/api/` by the same gateway that serves the web application |
| Zero trust | Every request is authenticated, and authorisation is checked per route against a single permission table ([`rbac.ts`](../backend/src/auth/rbac.ts)). The server-side session is checked on every call, so revocation is immediate |
| Strict input | Every body and query is validated with a strict schema. **Unknown fields are rejected** (mass-assignment protection) |
| Safe output | Secrets (connector credentials, one-time passwords after display) are never returned. Errors never include stack traces, SQL or upstream payloads |
| Everything audited | State changes and denials write a hash-chained audit record in the same transaction (fail-closed) |

## A.2 Authentication and session model

The API is designed for the browser application. It uses **OpenID Connect authorisation code flow with PKCE (S256)**, and tokens are held in cookies, never in JavaScript.

1. `GET /api/auth/login?returnTo=/path` redirects (303) to the identity provider. It sets a sealed, short-lived `__Host-ciso_oidc` cookie that holds the state, nonce and PKCE verifier (valid for 10 minutes).
2. The user authenticates at the IdP, with password and TOTP.
3. The IdP redirects to `GET /api/auth/callback`. The API validates the state, nonce and PKCE, maps the role claim to dashboard roles, creates a server-side session, and sets:

| Cookie | Content | Lifetime |
|--------|---------|----------|
| `__Host-ciso_at` | Signed access token (JWT: `sub`, `sid`, `name`, `roles`) | Access-token TTL (default 600 s) |
| `__Host-ciso_rt` | Opaque refresh token, rotated on every use, with reuse detection | Idle timeout (default 900 s), capped by the absolute lifetime (default 8 h) |
| `__Host-ciso_csrf` | CSRF token; also sent as `X-CSRF-Token` | Absolute session lifetime |

All cookies are `__Host-` prefixed, `Secure`, `httpOnly` (except the CSRF cookie, which the application must read), `SameSite=Strict` and `Path=/`.

4. `POST /api/auth/refresh` rotates the refresh token and issues a new access token. If a refresh token is presented a second time, the API treats it as theft: the whole session family is revoked and `auth.refresh_token_reuse` is audited.
5. `POST /api/auth/logout` revokes the session and returns `{"logoutUrl": "…"}` for the IdP end-session redirect.

> **Machine-to-machine access.** The dashboard does not issue API keys or bearer tokens for inbound use, and every identity must complete interactive MFA. This is deliberate: the dashboard *pulls* data from your tools (Part B), and nothing pushes into it. To get data out:
> - export the audit log as CSV
> - forward container and host logs to your SIEM (B.10)
> - read the database through a read-only replica under your data-governance controls
>
> Scripted access through the browser flow is used only by the automated test suite, with dedicated test identities.

## A.3 Request requirements

| Requirement | Detail |
|-------------|--------|
| Transport | HTTPS (TLS 1.3 at the gateway). HTTP requests are redirected |
| Body | `Content-Type: application/json`, UTF-8, at most **100 KB** |
| CSRF (POST, PUT, PATCH, DELETE) | Header `X-CSRF-Token` equal to the `__Host-ciso_csrf` cookie. `Origin`, if sent, must equal the public base URL. `Sec-Fetch-Site`, if sent, must be `same-origin` |
| Identifiers | UUIDs (except audit IDs: decimal strings; KRI keys: `[a-z0-9_.]`) |
| Dates | ISO 8601 (`2026-11-10T09:30:00Z`); responses use UTC with milliseconds |
| Text | Trimmed; control characters rejected; single-line fields reject CR/LF |
| Lists in queries | Comma-separated, for example `severity=CRITICAL,HIGH` |
| Network | The caller's address must be inside *Configuration → Network access* (if set), otherwise `403 NETWORK_NOT_ALLOWED` |

## A.4 Responses and errors

Successful responses are JSON objects. Lists are wrapped as `{"items": [...]}`, together with pagination fields where relevant. `204 No Content` is used for deletes and revocations.

**Errors** always use this envelope:

```json
{ "error": { "code": "VALIDATION_FAILED", "message": "Request validation failed",
             "issues": [ { "path": "likelihood", "message": "Number must be less than or equal to 5" } ] } }
```

| HTTP | `code` | When |
|------|--------|------|
| 400 | `VALIDATION_FAILED` | Schema validation failed (`issues` lists up to 20 field errors) |
| 400 | `BAD_REQUEST` | Malformed JSON or a business rule failed (message explains) |
| 400 | `LOCKOUT_PREVENTED` | Saving a network allow list that excludes your own address |
| 400 | `SELF_MODIFICATION` / `LAST_ADMIN` | Identity safeguards |
| 400 | `CONFIRMATION_REQUIRED` | Demo regenerate without `"confirm":"REGENERATE"` |
| 400 | `EGRESS_POLICY` | A connector URL violates the egress policy |
| 400 | `IDP_REJECTED` | The IdP rejected the change (for example a password-policy violation) |
| 401 | `UNAUTHENTICATED` | Missing, invalid or expired access token, or the session was revoked |
| 403 | `FORBIDDEN` | Permission missing (audited as `access.denied`) |
| 403 | `CSRF` | CSRF token, Origin or Sec-Fetch-Site check failed |
| 403 | `NETWORK_NOT_ALLOWED` | Caller outside the allowed client networks |
| 404 | `NOT_FOUND` | Unknown resource or route |
| 409 | `CONFLICT` | State conflict (for example a pending acceptance already exists) or a duplicate unique value |
| 409 | `NOT_DEMO_MODE` | Demo controls on a non-demo installation |
| 413 | `BAD_REQUEST` | Payload too large |
| 429 | `RATE_LIMITED` | Quota exceeded; see A.5 |
| 429 | `TOO_MANY_STREAMS` | More than 5 concurrent SSE streams for one user |
| 500 | `INTERNAL` | Unexpected error; `requestId` correlates with the API log |
| 502 | `IDP_UNAVAILABLE` | The identity provider failed the request |
| 503 | `IDP_NOT_CONFIGURED` | Identity administration with an external IdP |

## A.5 Rate limits

Limits are administrator-defined in *Configuration → Rate limiting* and take effect immediately.

| Tier | Key | Default | Applies to |
|------|-----|---------|------------|
| Flood ceiling | source IP | 3000 / min | All `/api` requests |
| Sign-in | source IP | 120 / min | `/api/auth/login`, `/callback`, `/refresh` |
| Per user | user ID | 600 / min | All authenticated requests |
| Heavy | user ID | 30 / min | Connector test and sync, audit verify and export, identity sync, enforce MFA, enrol, password reset, demo tick and regenerate |

Throttled responses are `429` with the `RATE_LIMITED` envelope, plus these headers (IETF draft-7):
- `RateLimit`, for example `limit=600, remaining=0, reset=42`
- `RateLimit-Policy`
- `Retry-After`

Clients must wait for `Retry-After` seconds before retrying. Because limits are per user, colleagues behind the same NAT address are not throttled together.

The gateway also enforces per-IP limits (default 50 requests/s, and 20 requests/s for sign-in). These are set in *Configuration → Deployment*.

## A.6 Pagination

| Style | Endpoints | Parameters | Response |
|-------|-----------|------------|----------|
| Offset | `/incidents`, `/vulnerabilities`, `/assets` | `limit` (1–500, default 50), `offset` (0–1,000,000) | `{ total, items }` |
| Cursor | `/threats` | `limit` (1–200, default 50), `cursor` (the last item's ID) | `{ items, nextCursor, facets }` (`nextCursor` is `null` at the end) |
| Keyset | `/audit` | `limit` (1–500, default 100), `beforeId` | `{ items, nextBeforeId }` |
| Window | `/admin/identity/users` | `first` (offset), page size fixed at 50 | `{ items, first, hasMore }` |
| Capped | `/kri/breaches` (200), `/risk-acceptances` (500), `/change-tickets` (100), `/admin/sessions` (200) | — | `{ items }` |

## A.7 Real-time event stream (SSE)

`GET /api/stream` (permission `dashboard:read`) returns `text/event-stream`.

| Event | Sent when | `data` |
|-------|-----------|--------|
| `ready` | Stream opened | `{}` |
| `kpi` | KPI inputs or parameters changed | `{}` |
| `kri` | KRI thresholds or breaches changed | `{}` |
| `threats` | Threat items ingested or triaged | `{ "count"?: n }` |
| `incidents` | Incidents ingested, created or updated | `{ "count"?: n }` |
| `vulnerabilities` | Findings or assets changed | `{}` |
| `risks` | Risks or acceptances changed | `{}` |
| `connectors` | Connector status changed | `{}` |
| `reauth` | The access token expired; the stream closes | `{}` |

Events are **notifications only**: refetch the affected resource. The server sends a comment ping every 25 seconds and `retry: 5000`, and allows at most 5 concurrent streams per user. The stream closes when the access token expires (`reauth`), so a long-lived connection cannot outlive the user's authorisation.

## A.8 Endpoint reference

Permissions refer to [`rbac.ts`](../backend/src/auth/rbac.ts); the role mapping is in A.10. **H** marks the *heavy* rate-limit tier.

### Health and authentication

| Method | Path | Permission | Description |
|--------|------|------------|-------------|
| GET | `/api/health` | none | Liveness: `{"status":"ok"}` |
| GET | `/api/ready` | none | Readiness after a database check: `{"status":"ready"}` |
| GET | `/api/auth/login` | none | Starts OIDC sign-in. Query: `returnTo` (a relative path only) |
| GET | `/api/auth/callback` | none | OIDC redirect target. On failure redirects to `/login?error=<reason>` |
| POST | `/api/auth/refresh` | refresh cookie | Rotates the session: `{"ok":true}` |
| POST | `/api/auth/logout` | signed in | Revokes the session: `{"logoutUrl"}` |
| GET | `/api/auth/me` | signed in | `{ user: { id, name, roles, permissions, lastLoginAt }, session: { expiresAt } }` |

Sign-in failure reasons are `missing_state`, `invalid_state`, `idp_error`, `missing_subject`, `no_authorized_role`, `account_disabled` and `callback_failed`.

### KPIs and KRIs

| Method | Path | Permission | Description |
|--------|------|------------|-------------|
| GET | `/api/kpi/summary` | `kpi:read` | Current KPI values (A.10 lists the metrics) |
| GET | `/api/kpi/trends` | `kpi:read` | Query: `metrics` (comma list, at most 10; default `mttdHours,mttrHours,patchCompliancePct,openCriticalFindings`), `days` (7–365, default 90). Returns daily points |
| GET | `/api/kri` | `kri:read` | KRIs with current value and RAG status |
| PUT | `/api/kri/:key` | `parameters:manage` | Update thresholds (body A.9.1) |
| GET | `/api/kri/breaches` | `kri:read` | Query: `open=true` for unacknowledged only |
| POST | `/api/kri/breaches/:id/acknowledge` | `kri:acknowledge` | Acknowledge a breach (idempotent) |

### Risks and acceptances

| Method | Path | Permission | Description |
|--------|------|------------|-------------|
| GET | `/api/risks` | `risk:read` | Register with `score`, `level`, `aboveAppetite` and `assetCount`; includes `appetite` |
| GET | `/api/risks/matrix` | `risk:read` | 25 cells: `{ likelihood, impact, score, level, aboveAppetite, count, risks[] }` |
| GET | `/api/risks/:id` | `risk:read` | Drill-down: linked assets with open vulnerabilities, and the acceptance history |
| POST | `/api/risks` | `risk:write` | Register a risk (A.9.2) → 201 |
| PATCH | `/api/risks/:id` | `risk:write` | Partial update, including `status` and `assetIds` (replaces links) |
| POST | `/api/risks/:id/acceptances` | `risk:acceptance:request` | Request an acceptance (A.9.3) → 201 |
| GET | `/api/risk-acceptances` | `risk:read` | Query: `status`. Justifications are decrypted for authorised readers |
| POST | `/api/risk-acceptances/:id/decision` | `risk:acceptance:approve` | `{ decision: APPROVE\|REJECT, note }`. Deciding your own request returns 403 |
| POST | `/api/risk-acceptances/:id/revoke` | `risk:acceptance:approve` | `{ note }` → 204; the risk re-opens |

### Threat intelligence

| Method | Path | Permission | Description |
|--------|------|------------|-------------|
| GET | `/api/threats` | `threat:read` | Query: `type`, `severity`, `status` (comma lists), `source`, `q`, `since` (ISO), `impactedOnly=true`, `limit`, `cursor`. Returns `facets` by severity and type |
| GET | `/api/threats/sources` | `threat:read` | `[{ source, count }]` |
| PATCH | `/api/threats/:id` | `threat:triage` | `{ status, note? }` |

### Incidents, vulnerabilities, assets and change tickets

| Method | Path | Permission | Description |
|--------|------|------------|-------------|
| GET | `/api/incidents` | `incident:read` | Query: `status`, `severity`, `q`, `limit`, `offset` |
| POST | `/api/incidents` | `incident:write` | Log an incident (A.9.4) → 201 |
| PATCH | `/api/incidents/:id` | `incident:write` | `{ status?, severity?, assetsAffected? }`. Lifecycle timestamps are maintained by the server |
| GET | `/api/vulnerabilities` | `vuln:read` | Query: `status`, `severity`, `q`, `assetId`, `overdue=true`, `limit`, `offset`. Includes the asset and the change ticket |
| PATCH | `/api/vulnerabilities/:id` | `remediation:write` | `{ status: OPEN\|IN_PROGRESS\|REMEDIATED\|FALSE_POSITIVE, note? }`. `RISK_ACCEPTED` findings return 409 |
| POST | `/api/vulnerabilities/:id/change-ticket` | `change:link` | Link a ticket (A.9.5). Sets the finding to IN_PROGRESS |
| GET | `/api/change-tickets` | `vuln:read` | Query: `q`. Up to 100 tickets, with linked-finding counts |
| GET | `/api/assets` | `vuln:read` | Query: `q`, `nonCompliant=true`, `limit`, `offset`. Includes open-finding counts |

### Integrations

| Method | Path | Permission | Description |
|--------|------|------------|-------------|
| GET | `/api/integrations/catalog` | `integration:read` | Adapters (vendor, category, supported auth, settings fields), the effective egress policy and defaults |
| GET | `/api/integrations` | `integration:read` | Connectors, with `hasCredentials` and `credentialFields` (names only) |
| POST | `/api/integrations` | `integration:manage` | Create (A.9.6) → 201 |
| PATCH | `/api/integrations/:id` | `integration:manage` | `{ baseUrl?, authMode?, pollIntervalSec?, enabled?, settings?, requestOptions? }`. Changing the endpoint, auth or API parameters resets the status to UNTESTED (or DISABLED) |
| PUT | `/api/integrations/:id/credentials` | `integration:manage` | `{ credentials }` replaces the encrypted credentials → 204 |
| DELETE | `/api/integrations/:id` | `integration:manage` | Deletes the connector and its credentials → 204. Imported data is kept |
| POST | `/api/integrations/:id/test` **H** | `integration:manage` | `{ ok, message }` |
| POST | `/api/integrations/:id/sync` **H** | `integration:manage` | `{ ok, message, counts? }` |

### Administration: users, settings and system

| Method | Path | Permission | Description |
|--------|------|------------|-------------|
| GET | `/api/admin/users` | `users:read` | Dashboard accounts with active session counts |
| PATCH | `/api/admin/users/:id` | `users:manage` | `{ active }`. Deactivating ends sessions; you cannot deactivate yourself |
| POST | `/api/admin/users/:id/revoke-sessions` | `users:manage` | `{ revoked: n }` |
| GET | `/api/admin/settings` | `dashboard:read` (each item filtered by its read permission) | Catalogue: `{ key, label, description, category, categoryLabel, apply, value, fields[], warnings[], permission, readPermission, editable }` |
| PUT | `/api/admin/settings/:key` | per setting (`system:manage` or `parameters:manage`) | `{ value }` → `{ key, value, warnings[], applied: { ok, message } }` |
| GET | `/api/admin/system` | `system:manage` | Version, uptime, memory, database latency, replicas, scheduler, connectors by status, sessions, audit, security posture, demo |
| GET | `/api/admin/sessions` | `system:manage` | Up to 200 active sessions (IP, user agent, user) |

Setting keys:
- `riskAppetiteScore`, `vulnSlaDays`, `riskAcceptanceMaxDays`, `kpiWindowDays`
- `threatRetentionDays`, `snapshotRetentionDays`
- `networkAccess`, `rateLimits`, `sessionPolicy`, `identity`
- `connectorDefaults`, `logging`, `demoData`, `deployment`, `hostOs`

Schemas and ranges are in [CONFIGURATION.md](CONFIGURATION.md), and machine-readable in the `fields` of `GET /api/admin/settings`.

### Administration: configuration operations

| Method | Path | Permission | Description |
|--------|------|------------|-------------|
| GET | `/api/admin/config/status` | `config:read` | Deployment drift (running vs desired), IdP sync state, effective egress policy, simulator state |
| GET | `/api/admin/config/bundle/deployment` | `system:manage` | Downloads `deployment.env` (with checksum) |
| GET | `/api/admin/config/bundle/host` | `system:manage` | Query: `os=ubuntu\|rhel`. Downloads the host baseline script |
| POST | `/api/admin/config/demo/tick` **H** | `system:manage` | Runs one simulation tick (demo mode only) |
| POST | `/api/admin/config/demo/regenerate` **H** | `system:manage` | `{ "confirm": "REGENERATE" }` rebuilds the demo dataset |

### Administration: identity and enrolment

| Method | Path | Permission | Description |
|--------|------|------------|-------------|
| GET | `/api/admin/identity/status` | `config:read` | `{ configured, sync, policy }` |
| POST | `/api/admin/identity/sync` **H** | `system:manage` | Pushes the identity and session policy now (502 on failure) |
| POST | `/api/admin/identity/enforce-mfa` **H** | `system:manage` | Requires TOTP enrolment for identities without an authenticator |
| GET | `/api/admin/identity/users` | `users:read` | Query: `search`, `first`. IdP identities with roles, MFA state, required actions and last dashboard login |
| POST | `/api/admin/identity/users` **H** | `users:manage` | Enrol (A.9.7) → 201 `{ id, username, temporaryPassword, requiredActions }` |
| PATCH | `/api/admin/identity/users/:id` | `users:manage` | `{ enabled?, roles? }`. Reduced access ends sessions |
| POST | `/api/admin/identity/users/:id/reset-password` **H** | `users:manage` | `{ temporaryPassword }` |
| POST | `/api/admin/identity/users/:id/reset-mfa` | `users:manage` | `{ removedAuthenticators }` |
| DELETE | `/api/admin/identity/users/:id` | `users:manage` | → 204 |

### Audit, compliance and stream

| Method | Path | Permission | Description |
|--------|------|------------|-------------|
| GET | `/api/audit` | `audit:read` | Query: `action` (prefix), `actor`, `outcome`, `from`, `to`, `beforeId`, `limit` |
| GET | `/api/audit/actions` | `audit:read` | Distinct actions with counts |
| GET | `/api/audit/verify` **H** | `audit:read` | `{ valid, checked, firstInvalidId, verifiedAt }` |
| GET | `/api/audit/export` **H** | `audit:read` | CSV (at most 50,000 rows), same filters. Formula-injection-safe |
| GET | `/api/compliance/report` | `compliance:read` | Controls with status and evidence, audit chain result, posture, acceptance summary |
| GET | `/api/stream` | `dashboard:read` | SSE (A.7) |

Internal only (blocked at the gateway, returns 404 from outside): `/api/internal/ip-gate/app` and `/api/internal/ip-gate/admin-console`. They are used by the NGINX `auth_request` that gates `/auth/`.

## A.9 Request body reference

All objects are **strict**: unknown keys return `VALIDATION_FAILED`.

**A.9.1 KRI update** (`PUT /api/kri/:key`)
```json
{ "name": "Open critical findings", "description": "…", "amberThreshold": 10, "redThreshold": 25, "enabled": true }
```
`name` and `description` are optional. For *higher is worse* KRIs, red must be greater than amber; for *lower is worse*, red must be less than amber.

**A.9.2 Risk** (`POST /api/risks`; for `PATCH` every field is optional and `status` is allowed)
```json
{ "title": "Ransomware on file servers", "description": "…", "category": "Ransomware",
  "likelihood": 4, "impact": 5, "ownerName": "Head of IT Ops", "treatment": "EDR + immutable backups",
  "assetIds": ["0b6c…"] }
```
- `title`: 3–200 characters
- `description`: 1–4000
- `category`: 2–80
- `likelihood`, `impact`: integers 1–5
- `ownerName`: 2–120
- `treatment`: up to 2000
- `assetIds`: at most 500
- `status` (PATCH only): `OPEN`, `MITIGATING` or `CLOSED`

**A.9.3 Acceptance request** (`POST /api/risks/:id/acceptances`)
```json
{ "justification": "Compensating controls: network isolation and EDR; vendor patch due Q1.", "expiresInDays": 90 }
```
`justification` must be 20–4000 characters. `expiresInDays` must be between 1 and `riskAcceptanceMaxDays`.

**A.9.4 Incident** (`POST /api/incidents`)
```json
{ "title": "Phishing campaign targeting finance", "description": "…", "severity": "HIGH", "category": "Phishing",
  "occurredAt": "2026-11-10T07:40:00Z", "detectedAt": "2026-11-10T08:05:00Z", "assetsAffected": 3 }
```
`detectedAt` must be at or after `occurredAt`, and no later than now.

**A.9.5 Change-ticket link** (`POST /api/vulnerabilities/:id/change-ticket`)
```json
{ "system": "ServiceNow", "externalKey": "CHG0041234", "title": "Patch OpenSSL", "url": "https://corp.service-now.com/…" }
```
`externalKey` must match `[A-Za-z0-9_.-]{2,64}`. `url` must be https.

**A.9.6 Connector** (`POST /api/integrations`)
```json
{
  "name": "Splunk ES Production",
  "vendor": "splunk",
  "baseUrl": "https://splunk.corp.example:8089",
  "authMode": "API_KEY",
  "pollIntervalSec": 300,
  "enabled": true,
  "settings": { "search": "search `notable` | head 500" },
  "requestOptions": { "pathPrefix": "", "headers": {}, "query": {}, "timeoutMs": 30000, "maxRetries": 3 },
  "credentials": { "apiKey": "<token>", "apiKeyPrefix": "Bearer " }
}
```
- `name`: 3–80 characters, letters, digits, spaces and `_ ( ) . -`. It cannot be changed later, because it identifies the data source (B.7).
- `baseUrl`: https, with no query string, fragment or embedded credentials.
- `pollIntervalSec`: 60–86,400.
- `settings`: validated by the vendor's schema (B.4).
- `requestOptions`: B.5.
- `credentials`: B.3.

**A.9.7 Enrolment** (`POST /api/admin/identity/users`)
```json
{ "username": "j.smith", "email": "j.smith@corp.example", "firstName": "Jane", "lastName": "Smith", "roles": ["SECOPS"] }
```
`username` must match `^[a-z0-9][a-z0-9._-]{2,63}$`. Names accept letters, spaces and `. ' ( ) -`. `roles` must have between 1 and 5 entries.

## A.10 Enumerations

| Type | Values |
|------|--------|
| Role → permissions | **ADMIN**: platform, integrations, users, configuration, parameters, audit. **CISO**: posture, parameters, risk write, acceptance approve, triage, audit, view users/config. **SECOPS**: risk write, triage, incidents, integrations, KRI acknowledge. **PATCH_ADMIN**: remediation, change link, acceptance request. **AUDITOR**: read-only, audit, compliance, config view |
| Severity | `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO` |
| Incident status | `NEW`, `TRIAGE`, `CONTAINED`, `RESOLVED`, `CLOSED` |
| Vulnerability status | `OPEN`, `IN_PROGRESS`, `REMEDIATED`, `RISK_ACCEPTED`, `FALSE_POSITIVE` |
| Risk status | `OPEN`, `MITIGATING`, `ACCEPTED`, `CLOSED` |
| Acceptance status | `PENDING`, `APPROVED`, `REJECTED`, `EXPIRED`, `REVOKED` |
| Threat type / status | `CVE`, `RANSOMWARE`, `SUPPLY_CHAIN`, `ADVISORY`, `IOC` / `NEW`, `TRIAGED`, `ACTIONED`, `DISMISSED` |
| Connector category | `SIEM`, `VULNERABILITY`, `PATCH`, `CHANGE`, `THREAT_INTEL` |
| Connector status | `UNTESTED`, `HEALTHY`, `FAILED`, `DISABLED` |
| Auth mode | `NONE`, `API_KEY`, `BASIC`, `OAUTH2`, `MTLS` |
| KPI metrics (`/kpi/summary`, trends) | `mttdHours`, `mttrHours`, `patchCompliancePct`, `remediationVelocityPerWeek`, `meanDaysToRemediate`, `openCriticalFindings`, `openHighFindings`, `overdueCriticalFindings`, `overdueFindings`, `activeIncidents`, `totalAssets`, `risksAboveAppetite`, `failedConnectors`, `pendingAcceptances` (all except `overdueFindings`, `totalAssets`, `failedConnectors` and `pendingAcceptances` are available as trends) |
| Risk level (score = L × I) | `CRITICAL` ≥ 15, `HIGH` 10–14, `MEDIUM` 5–9, `LOW` 1–4 |

## A.11 Examples

From the browser console on the dashboard origin, signed in:

```js
const csrf = document.cookie.match(/__Host-ciso_csrf=([^;]+)/)?.[1];
// Read: open critical and high findings past SLA
await (await fetch('/api/vulnerabilities?severity=CRITICAL,HIGH&overdue=true&limit=100')).json();
// Write: triage a threat item
await fetch('/api/threats/<id>', {
  method: 'PATCH',
  headers: { 'content-type': 'application/json', 'x-csrf-token': csrf },
  body: JSON.stringify({ status: 'TRIAGED', note: 'Affects 3 internet-facing hosts' }),
});
```

Handling throttling in any client:

```js
async function call(url, init) {
  for (;;) {
    const r = await fetch(url, init);
    if (r.status !== 429) return r;
    await new Promise((ok) => setTimeout(ok, (Number(r.headers.get('retry-after')) || 1) * 1000));
  }
}
```

## A.12 Compatibility policy

- The API is released together with the web application, with no version prefix. Breaking changes are released as a pair.
- Consumers must **ignore unknown response fields**. New fields may be added at any time.
- Request bodies are strict, so a client must not send fields that are not documented here.

---

# Part B: Integration requirements and guidelines

## B.1 Integration model

```
scheduler (30 s) ── due? ── DB lease ──► HTTP client ──► vendor API
                                         │ egress guard (URL policy + connect-time IP check)
                                         │ auth (API key / Basic / OAuth2 / mTLS), retries, size cap
                                         ▼
                                     adapter.sync() ──► normalised records ──► ingest (idempotent upsert)
                                                                             └► live events → dashboards
```

- **Pull only.** The dashboard calls your tools. Nothing needs inbound access to the dashboard.
- **Read only.** No adapter writes to a vendor system. Grant read-only permissions.
- **Normalised, zero retention.** Raw responses exist only in memory and are zero-filled after parsing. Only normalised fields (B.7) are stored. Upstream bodies are never logged or echoed in errors.
- **Credentials** are encrypted with AES-256-GCM, bound to the connector, and decrypted only in memory for the duration of a call. They are never returned by the API.

## B.2 Requirements for every integration

| # | Requirement | Why |
|---|-------------|-----|
| 1 | **HTTPS** endpoint, TLS 1.2 or higher, with a certificate valid for the hostname used | TLS verification cannot be disabled |
| 2 | If the certificate is from a private CA, its PEM is supplied in the connector's *CA certificate* field | Trust is per connector |
| 3 | Reachable from the Docker host's egress (routing, firewalls, vendor IP allow lists include the host's egress IP) | Connector traffic leaves through the host |
| 4 | **Hostname is allowed** by *Configuration → Integration defaults* (if an allow list is set) | Egress policy |
| 5 | The address is not loopback, link-local, a cloud metadata address, a Docker internal zone (172.30.0.0/16), or (if blocked) RFC 1918 | SSRF protection, checked when the socket connects |
| 6 | A **dedicated, read-only service account** or API client per connector, named for the dashboard (for example `svc-ciso-dashboard`) | Least privilege, attribution, revocation |
| 7 | Credentials have an owner and an **expiry or rotation date**, recorded in your credential register | Rotation (Maintenance Manual §11.2) |
| 8 | The vendor's rate limit allows the polling interval. 429 and 5xx responses are retried with back-off, and `Retry-After` is honoured | Avoid throttling |
| 9 | One poll's response fits within the maximum response size (default 50 MB), so use the page-size settings | Memory protection |
| 10 | The vendor's clock is accurate, and timestamps include a time zone (ISO 8601 or epoch) | Incremental sync and MTTD/MTTR |
| 11 | Responses are JSON (XML for Qualys; NDJSON for Splunk export) | Parsers |
| 12 | No credentials in URLs; no `http://` (insecure HTTP is refused in production) | Policy |

## B.3 Authentication modes and credential fields

| Mode | Required fields | Optional fields | What is sent |
|------|-----------------|-----------------|--------------|
| `NONE` | — | `caCert` | No credentials (public feeds such as CISA KEV) |
| `API_KEY` | `apiKey` | `apiKeyHeader` (default `Authorization`), `apiKeyPrefix` (for example `Bearer `, `ApiKey `, `SSWS `; **include the trailing space**), `apiSecret` (key pairs), `caCert` | `<apiKeyHeader>: <apiKeyPrefix><apiKey>`. Tenable/Nessus send `X-ApiKeys: accessKey=<apiKey>;secretKey=<apiSecret>`; QRadar sends `SEC: <apiKey>` |
| `BASIC` | `username`, `password` | `caCert` | `Authorization: Basic …` |
| `OAUTH2` | `tokenUrl`, `clientId`, `clientSecret` | `scope`, `caCert` | Client-credentials grant to `tokenUrl` (client authenticates with HTTP Basic). The bearer token is cached until 30 s before `expires_in` |
| `MTLS` | `clientCert`, `clientKey` (PEM) | `passphrase`, `apiKey` / `apiKeyHeader` / `apiKeyPrefix` (layered on top), `caCert` | Client certificate in the TLS handshake |

Credential field limits:
- single-line values (no CR/LF)
- `apiKey` and `apiSecret` up to 4096 characters
- PEM blocks up to 20,000 characters
- `tokenUrl` must be https and passes the same egress policy

Credentials are **write-only**. To change one, select *Replace credentials* (`PUT /api/integrations/:id/credentials`) and supply the complete set.

## B.4 Per-vendor requirements

For each adapter: supported auth modes, default polling interval, vendor endpoints called, settings, the minimum permissions to grant, and how data is mapped.

### SIEM → incidents

| | **Splunk Enterprise Security** (`splunk`) | **Elastic Security** (`elastic`) | **IBM QRadar** (`qradar`) |
|---|---|---|---|
| Auth | API_KEY (Splunk token, prefix `Bearer `), BASIC, MTLS | API_KEY (header `Authorization`, prefix `ApiKey `), BASIC, MTLS | API_KEY (sent as `SEC` header), MTLS |
| Default poll | 300 s | 300 s | 300 s |
| Base URL | `https://splunk.corp.example:8089` (management port) | `https://es.corp.example:9200` | `https://qradar.corp.example` |
| Test call | `GET /services/server/info?output_mode=json` | `GET /` | `GET /api/system/about` |
| Sync call | `POST /services/search/jobs/export` (form: `search`, `output_mode=json`, `earliest_time=<since>`) | `POST /<index>/_search` (range on `@timestamp` ≥ since) | `GET /api/siem/offenses?filter=last_updated_time > <since ms>` with `Range: items=0-N` and `Version` headers |
| Settings | `search` (SPL; default ``search `notable` \| head 500``) | `index` (default `.alerts-security.alerts-default`), `size` (1–5000, default 500) | `apiVersion` (default `20.0`), `maxOffenses` (1–5000, default 500) |
| Minimum permission | Role with the `search` capability and read access to the notable index (`notable`); token auth enabled | Cluster `monitor`; index `read` on the alerts index pattern | Authorised service token whose security profile covers the offences in scope; *Offenses* permission |
| Mapping | `event_id` → ID; `rule_name` → title; `urgency` → severity; `orig_time`/`_time` → occurred/detected; `status_label` closed/resolved → RESOLVED; `security_domain` → category | `_id`; `kibana.alert.rule.name`; `kibana.alert.severity`; `kibana.alert.original_time`/`@timestamp`; workflow `closed` → RESOLVED, `acknowledged` → TRIAGE | `id`; `description`; magnitude ≥ 8 CRITICAL, ≥ 6 HIGH, ≥ 4 MEDIUM, otherwise LOW; `start_time`/`first_persisted_time`; `CLOSED` → RESOLVED with `close_time` |

### Vulnerability management → findings and assets

| | **Tenable Vulnerability Management** (`tenable`) | **Tenable Nessus** (`nessus`) | **Qualys VMDR** (`qualys`) |
|---|---|---|---|
| Auth | API_KEY: `apiKey` = access key, `apiSecret` = secret key | API_KEY (key pair, as Tenable), MTLS | BASIC |
| Default poll / base URL | 3600 s / `https://cloud.tenable.com` | 3600 s / `https://nessus.corp.example:8834` | 3600 s / `https://qualysapi.qualys.com` (use your platform's API URL) |
| Test call | `GET /session` | `GET /server/status` | `POST /api/2.0/fo/asset/host/` (`action=list`) |
| Sync calls | `POST /vulns/export` → poll `/vulns/export/<uuid>/status` (every 5 s, up to 5 min) → `GET /chunks/<n>` | `GET /scans/<scanId>` → `GET /scans/<scanId>/hosts/<hostId>` per host | `POST /api/2.0/fo/asset/host/vm/detection/` (XML) with `detection_updated_since` |
| Settings | `severities` (default `critical,high,medium`), `maxChunks` (1–200, default 20) | `scanId` (required), `maxHosts` (default 500) | `severities` (`3-5` default), `truncationLimit` (1–10,000, default 1000) |
| Minimum permission | A user whose role and access groups allow viewing vulnerabilities for the in-scope assets; API keys generated for that user | API keys of a user who can view the designated scan | API-enabled user with a read-only role (for example *Reader*) scoped to the asset groups in scope |
| Mapping | States OPEN, REOPENED, FIXED; FIXED → REMEDIATED with `last_fixed`; CVSS v3 (else v2) → severity | Plugin severity 4/3/2/1 → CRITICAL/HIGH/MEDIUM/LOW (informational skipped); CVE from the plugin name | Severity 5/4/3/2/1 → CRITICAL…INFO; `Fixed` → REMEDIATED; title `Qualys QID <n>` |
| Notes | Exports are asynchronous; large estates need `maxChunks` sized to the asset count | One scan per connector; create several connectors for several scans | Requires the `X-Requested-With` header (sent automatically) |

### Patch management → asset compliance

| | **Microsoft WSUS** (`wsus`) | **Ansible AAP / AWX** (`ansible`) | **Red Hat Satellite** (`satellite`) |
|---|---|---|---|
| Auth | API_KEY or MTLS (**mTLS recommended**) | API_KEY (OAuth2 personal token, prefix `Bearer `), OAUTH2, BASIC | BASIC, MTLS |
| Default poll | 3600 s | 1800 s | 3600 s |
| Calls | `GET <reportPath>` (default `/wsus/compliance.json`) | `GET /api/v2/ping/`; `GET /api/v2/inventories/<id>/hosts/?page_size=200`, following `next` | `GET /api/status`; `GET /api/v2/hosts?per_page=200&page=n` |
| Settings | `reportPath` | `inventoryId` (required), `maxPages` (1–100, default 20) | `organizationId` (optional), `maxPages` (default 20) |
| Minimum permission | Read access to the published report folder only | *Read* on the inventory | A user with the *Viewer* role in the organisation |
| Mapping | `neededCount + failedCount = 0` → compliant | Host has active failures, or the last job was not `successful` → non-compliant | Security errata count = 0 → compliant; count → missing patches |
| Prerequisite | WSUS has no REST API. Run [`tools/wsus-bridge.ps1`](../tools/wsus-bridge.ps1) on the WSUS server as a scheduled task (for example every 30 minutes) and publish its output folder through IIS over HTTPS. Output: `[{ computerName, ipAddress, os, neededCount, failedCount, lastSyncTime }]` | Run a patch job template against the inventory so `last_job` reflects patch status | Hosts registered as content hosts with errata applicability calculated |

### Change management → change tickets

| | **ServiceNow** (`servicenow`) | **Atlassian Jira** (`jira`) |
|---|---|---|
| Auth | BASIC, OAUTH2 (ServiceNow OAuth application registry, client credentials), MTLS | Cloud: BASIC (account email + API token). Data Center: API_KEY (personal access token, prefix `Bearer `). OAUTH2 |
| Default poll | 900 s | 900 s |
| Calls | `GET /api/now/table/<table>?sysparm_query=<query>^sys_updated_on>=<since>` | Cloud: `POST /rest/api/3/search/jql`. DC: `POST /rest/api/2/search` |
| Settings | `table` (default `change_request`), `query` (default `active=true`), `limit` (default 500) | `jql` (required), `apiVersion` (`3` Cloud, `2` Data Center), `maxResults` (default 200) |
| Minimum permission | Read ACL on the table and fields `sys_id, number, short_description, state, sys_updated_on` (for example a custom read-only role) | *Browse projects* on the projects in the JQL |
| Mapping | `number` → key; `short_description` → title; `state` (display value) → status; deep link `nav_to.do?uri=<table>.do?sys_id=…` | `key`; `summary`; `status.name`; link `/browse/<key>` |

### Threat intelligence → threat stream

| | **CISA KEV** (`cisa_kev`) | **MISP** (`misp`) | **STIX/TAXII 2.1** (`taxii`) | **Commercial JSON** (`generic_rest`) |
|---|---|---|---|---|
| Auth | NONE | API_KEY (MISP auth key in `Authorization`, no prefix), MTLS | API_KEY, BASIC, MTLS, OAUTH2 | API_KEY, OAUTH2, BASIC, MTLS |
| Default poll | 21600 s (enabled by default) | 900 s | 1800 s | 1800 s |
| Calls | `GET <path>` (the public KEV JSON on `https://www.cisa.gov`) | `GET /servers/getVersion`; `POST /events/restSearch` (published events since the last poll) | `GET <apiRoot>collections/<id>/objects/?added_after=<since>` with the `application/taxii+json;version=2.1` accept header | `GET <path>` |
| Settings | `path`, `maxItems` (default 300) | `limit` (default 500) | `apiRoot` (for example `/taxii2/api1/`), `collectionId`, `limit` | `path`, `itemsPath`, `idField`, `titleField`, `summaryField`, `severityField`, `publishedField`, `tagsField` |
| Minimum permission | — (outbound access to www.cisa.gov) | A user with a read-only role in the sharing groups in scope | Read on the collection | Read-only API client |
| Mapping | Known ransomware use → RANSOMWARE / CRITICAL, otherwise CVE / HIGH | Threat level 1–4 → HIGH…INFO; vulnerability attribute → CVE; ransomware tags → CRITICAL | `vulnerability` → CVE; `malware` (ransomware) → RANSOMWARE; `report` → classified; `indicator` → IOC | Tags and title classify the type: ransom → RANSOMWARE; supply chain, npm or pypi → SUPPLY_CHAIN; CVE → CVE; otherwise ADVISORY |

Threat items that carry a CVE are matched against open findings on your assets, which sets the *impacted assets* count.

## B.5 Advanced API parameters

Every connector has **Advanced API parameters** (`requestOptions`). They adapt any adapter to a vendor deployment without code changes:

| Field | Rules | Example |
|-------|-------|---------|
| `pathPrefix` | `/segment/segment`, no trailing slash, no query string; segments may not start with `.` (no `.`/`..` traversal) | `/gateway/splunk` when the API sits behind an API gateway |
| `headers` | At most 20. Names `[A-Za-z0-9-]`, values single-line, at most 500 characters | `Version: 20.0` (QRadar), `elastic-api-version: 2023-10-31`, `X-Api-Version: 2` |
| `query` | At most 20. Added to every adapter request; the adapter's own parameters take precedence | `tenant=emea`, `region=eu-west-1` |
| `timeoutMs` | 1,000–300,000 | `120000` for slow exports |
| `maxRetries` | 0–5 | `4` for a flaky gateway |

Rejected for safety:
- **Credential-like names**, matching `auth`, `token`, `secret`, `passw`, `api-key`, `session`, `cookie` or `signature`. Put secrets in the encrypted credential fields.
- **Hop-by-hop, routing and cookie headers:** `Host`, `Content-Length`, `Content-Type`, `Transfer-Encoding`, `Connection`, `TE`, `Upgrade`, `Proxy-*`, `X-Forwarded-*`, `Forwarded`, `Cookie`, `Set-Cookie`.

Header precedence, lowest to highest: defaults (`accept`, `user-agent: ciso-dashboard-connector/1.0`), administrator headers, authentication headers, then adapter headers.

## B.6 Generic REST/JSON adapters

Use a generic adapter when a tool is not in the catalogue but has a JSON REST API. There is one per category:

| Vendor key | Category | Produces | Typical tools |
|------------|----------|----------|---------------|
| `generic_siem` | SIEM | incidents | Microsoft Sentinel, Google SecOps (Chronicle), CrowdStrike, Sumo Logic, Wazuh, SOAR platforms |
| `generic_vulnerability` | Vulnerability | findings and assets | Rapid7, Wiz, Snyk, Defender Vulnerability Management, OpenVAS bridges |
| `generic_patch` | Patch | asset compliance | Intune, MECM bridges, Tanium, ManageEngine, Automox |
| `generic_change` | Change | change tickets | BMC Helix, Freshservice, Cherwell, TOPdesk, GLPI |
| `generic_rest` | Threat intel | threat items | Recorded Future, Mandiant, other commercial feeds (single request, no pagination) |

All four paginated generic adapters support every auth mode, poll every 900 seconds by default, and share these settings:

| Setting | Default | Meaning |
|---------|---------|---------|
| `path` | — (required) | Endpoint path, for example `/api/v2/alerts`. No query string; use *Advanced API parameters → query* for fixed parameters |
| `testPath` | empty | Optional health-check path. When empty, the test requests `path` with a page size of 1 and checks the items array |
| `itemsPath` | empty (= root) | Dot path to the array of records, for example `data.items` |
| `pagination` | `none` | `none` · `offset` · `page` · `cursor` · `link` |
| `pageSize` / `pageSizeParam` | 100 / `limit` | Records per page and the parameter name |
| `offsetParam` | `offset` | For `offset` |
| `pageParam` / `firstPage` | `page` / `1` | For `page` (first page 0 or 1) |
| `cursorParam` / `nextCursorPath` | `cursor` / `next_cursor` | For `cursor`: parameter name and the dot path to the next token in the body |
| `maxPages` | 20 (1–100) | Upper bound per poll. There is also a hard cap of **5,000 records per poll** |
| `sinceParam` / `sinceFormat` | empty / `iso` | Incremental parameter name and its format: `iso` (ISO 8601), `epoch` (Unix seconds) or `epoch_ms` |

**Pagination behaviour** (request sequence):

| Style | Requests | Stops when |
|-------|----------|------------|
| `none` | `GET path` | after one request |
| `offset` | `?offset=0&limit=100`, `?offset=100&limit=100`, … | a page returns fewer than `pageSize` items |
| `page` | `?page=1&per_page=…` (with `pageSizeParam=per_page`), `?page=2…` | a short page |
| `cursor` | `?limit=100`, then `?limit=100&cursor=<body.next_cursor>` | the next cursor is empty, repeated, or the page is empty |
| `link` | `?limit=100`, then follows `Link: <…>; rel="next"` exactly | no `next` link. **A `next` URL on a different origin is blocked** |

**Field mappings** (dot paths into each record; `a.b.c` walks nested objects):

| Adapter | Mapping fields (defaults) | Normalisation rules |
|---------|---------------------------|---------------------|
| `generic_siem` | `idField` (`id`), `titleField` (`title`), `severityField` (`severity`), `occurredField` (`created_at`), `detectedField` (empty = occurred), `statusField` (`status`), `resolvedField` (`resolved_at`), `categoryField` (`category`), `assetsField` (empty) | Severity: a number is treated as a 0–10 score (≥ 9 CRITICAL, ≥ 7 HIGH, ≥ 4 MEDIUM, > 0 LOW); text is matched by keyword (crit/urgent → CRITICAL, high/severe, med/moderate, low/minor, info). Status keywords: closed, resolved, done, complete or fixed → RESOLVED; contain → CONTAINED; triage, investigating, in progress, assigned or ack → TRIAGE; otherwise NEW. A resolved timestamp on a NEW record → RESOLVED |
| `generic_vulnerability` | `idField` (`id`), `hostField` (`asset.hostname`), `ipField` (`asset.ip`), `cveField` (`cve`), `titleField` (`title`), `severityField` (`severity`), `cvssField` (`cvss`), `discoveredField` (`first_seen`), `stateField` (`state`), `remediatedField` (`fixed_at`) | CVE extracted from the CVE field or the title. Severity text, else the CVSS score. A state containing fix, remediat, closed or resolved → REMEDIATED |
| `generic_patch` | `hostField` (`hostname`), `ipField` (`ip`), `osField` (`os`), `compliantField` (`compliant`), `missingField` (`missing_patches`), `lastPatchedField` (`last_patched`) | Compliant if the field is `true`, `yes`, `1`, `compliant`, `ok`, `patched` or `up to date`. If the field is absent, compliant when missing = 0. Records without a hostname are skipped |
| `generic_change` | `keyField` (`number`), `titleField` (`summary`), `statusField` (`state`), `urlField` (`url`), `updatedField` (`updated_at`) | URLs are kept only if they are `https://` |

**Worked example: a SIEM API with cursor paging**

Vendor response for `GET https://xdr.corp.example/gw/api/v2/alerts?tenant=emea&limit=100&updated_since=2026-11-10T08:00:00.000Z`:

```json
{ "data": { "items": [
    { "alert_id": "A-1042", "name": "Credential dumping", "risk": { "score": 8.7 },
      "timestamps": { "first_seen": "2026-11-10T08:11:02Z", "closed": null }, "state": "investigating" } ] },
  "meta": { "next_cursor": "c2Vxlg==" } }
```

Connector configuration:

| Setting | Value |
|---------|-------|
| Base URL | `https://xdr.corp.example` |
| Advanced: path prefix / query / headers | `/gw` / `tenant=emea` / `X-Api-Version: 2` |
| `path` | `/api/v2/alerts` |
| `itemsPath` | `data.items` |
| `pagination` / `pageSizeParam` / `cursorParam` / `nextCursorPath` | `cursor` / `limit` / `cursor` / `meta.next_cursor` |
| `sinceParam` / `sinceFormat` | `updated_since` / `iso` |
| `idField` / `titleField` / `severityField` | `alert_id` / `name` / `risk.score` |
| `occurredField` / `statusField` / `resolvedField` | `timestamps.first_seen` / `state` / `timestamps.closed` |

Result: incident `A-1042`, "Credential dumping", HIGH (score 8.7), status TRIAGE.

## B.7 Normalised data model and de-duplication

Records are upserted. Re-reading the same record updates it rather than duplicating it.

| Record | Unique key | Created with | Updated on re-sync |
|--------|-----------|--------------|--------------------|
| Incident | (connector name, `externalId`) | title, severity, status (default NEW), category, occurred, detected, responded, resolved, assets affected | title, severity, and status / responded / resolved when supplied |
| Vulnerability | (connector name, `externalId`) | asset (by hostname), CVE, title, severity, CVSS, discovered, **due date = discovered + SLA(severity)**, status OPEN or REMEDIATED | title, severity, CVSS; becomes REMEDIATED when the source reports it fixed |
| Asset | `hostname` (lower-case) | IP, OS, patch fields | IP and OS when supplied; patch compliance, missing count and last patched from patch connectors |
| Change ticket | (connector name, `externalKey`) | title, status, URL, source updated time | title, status, URL, updated time |
| Threat item | (connector name, `sourceRef`) | type, title, summary, severity, CVE, published, tags | title, summary, severity, tags |

Implications:
- **The connector name is the source identity.** It cannot be renamed. If you delete a connector and re-create it under a new name, the same records are imported a second time under the new source.
- **Hostnames join data across tools.** Configure scanners and patch tools to report the same FQDN or short-name convention, or the same server appears as two assets.
- **The source is authoritative for imported incidents.** A status set by the SIEM overwrites a manual change at the next sync. Analysts should update incidents in the SIEM, or log manual incidents in the dashboard.
- **Analyst decisions on findings are preserved.** A sync never re-opens a finding that a patch administrator marked Remediated or False positive. Risk-accepted findings change only through the acceptance workflow.
- Deleting a connector keeps the data it imported. Retention jobs purge threat items and snapshots.

## B.8 Synchronisation behaviour

| Aspect | Behaviour |
|--------|-----------|
| Schedule | Every 30 s the scheduler checks each **enabled** connector; it syncs when `lastSyncAt + pollInterval` has passed |
| Concurrency | A database lease (15 min) ensures only one replica syncs a connector at a time |
| First sync window | The previous **30 days** |
| Incremental window | From the last *successful* sync minus a **5-minute overlap**, so no records are lost at the boundaries (duplicates are de-duplicated) |
| Retries | Network errors and HTTP 429/502/503/504: exponential back-off from `retryBackoffMs` (default 1 s) with jitter; `Retry-After` honoured up to 60 s; `maxRetries` (default 2) |
| Timeouts / size | `timeoutMs` (default 60 s) for headers and body; responses above the maximum size (default 50 MB) are aborted |
| Redirects | **Never followed.** Point the base URL at the final API address |
| Status | Test or sync success → HEALTHY (DISABLED if the connector is disabled); failure → FAILED with a safe `lastError`; configuration change → UNTESTED |
| Manual actions | **Test** (no data imported) and **Sync now** (imports immediately, also on disabled connectors, without enabling them) |
| Events | Successful syncs publish `threats`, `incidents`, `vulnerabilities` and `connectors` events, so dashboards refresh live |

## B.9 Identity provider (OIDC) integration

The bundled Keycloak can be replaced by any OpenID Connect provider (Entra ID, Okta, Ping, ADFS 2019+).

**Requirements for the IdP:**

| # | Requirement |
|---|-------------|
| 1 | A **confidential** web client using the authorisation code flow with **PKCE S256** |
| 2 | Redirect URI `https://<public-host>/api/auth/callback`; post-logout redirect `https://<public-host>/` |
| 3 | Scopes `openid profile email` (configurable via `OIDC_SCOPES`) |
| 4 | A **roles or groups claim** in the ID token or user-info response. Set `OIDC_ROLE_CLAIM` to its name |
| 5 | **MFA enforced in the IdP** (conditional access, or an authentication policy) for every user of the application |
| 6 | Session and token lifetimes in the IdP no longer than the dashboard's policy |
| 7 | An end-session endpoint advertised in discovery (for single sign-out) |
| 8 | A TLS certificate trusted by the API container (public CA, or mount your CA) |

**Configuration:**

```bash
OIDC_ISSUER_URL=https://login.microsoftonline.com/<tenant-id>/v2.0
OIDC_CLIENT_ID=<application-id>
# client secret → secrets/oidc_client_secret
OIDC_ROLE_CLAIM=roles
OIDC_ROLE_MAPPING=CISO-Dashboard-Admins:ADMIN,CISO-Dashboard-Execs:CISO,SOC-Analysts:SECOPS,Patch-Team:PATCH_ADMIN,IT-Audit:AUDITOR
# leave IDP_ADMIN_URL unset → identity administration is done in the IdP
```

Then:
- remove the `keycloak` and `idp-init` services
- remove the `/auth/` locations in `infra/nginx/nginx.conf`
- redeploy

Role matching is case-insensitive. Users with no mapped role are refused (`no_authorized_role`).

| IdP | Roles claim |
|-----|-------------|
| Entra ID | Define **app roles** on the registration and assign groups to them. They appear in the `roles` claim |
| Okta | Add a **groups claim** (filter by prefix) to the ID token. Set `OIDC_ROLE_CLAIM=groups` |
| Ping / ADFS | Issue the group or role attribute as a multi-valued claim and point `OIDC_ROLE_CLAIM` at it |

## B.10 Outbound integration: logs and evidence

| Need | Mechanism |
|------|-----------|
| Security monitoring of the dashboard itself | Ship container JSON logs (Docker logging driver or an agent) and host syslog (*Configuration → Host OS → Syslog*, TLS RFC 5425) to the SIEM |
| Audit evidence | Audit Log → Export CSV (`/api/audit/export`, up to 50,000 rows per request, date-filtered), plus `/api/audit/verify` |
| Compliance evidence | `/api/compliance/report` (JSON) or print from the UI |
| Uptime monitoring | `GET /api/ready` (no authentication) |

## B.11 Security guidelines

**Do**
- Create a dedicated read-only account per connector. Scope it to the minimum projects, indexes, asset groups or tables.
- Prefer **mTLS** or **OAuth2 client credentials**. Use API keys only where nothing else is offered, and give them an expiry date.
- Set an **egress allow list** (*Configuration → Integration defaults*) once all your connectors are known. Turn on **Block RFC 1918** when every tool is SaaS-hosted.
- Supply private CA certificates per connector instead of weakening TLS.
- Rotate credentials on staff changes and at least annually. Use *Replace credentials*; every rotation is audited.
- Review `integration.*` audit events regularly.

**Don't**
- Put credentials in URLs, API-parameter headers or query strings. The dashboard rejects them.
- Grant write or admin permissions "to make it work". No adapter ever writes.
- Point connectors at internal Docker service names, localhost, or cloud metadata addresses. They are always blocked.
- Use `http://` endpoints or self-signed certificates without supplying their CA.

## B.12 Onboarding checklist and acceptance test

| # | Step | Evidence |
|---|------|----------|
| 1 | Tool owner creates the read-only service account / API client and records the owner and expiry | Ticket reference |
| 2 | Network: route, firewall and vendor allow list opened from the Docker host's egress IP to the API host and port | `curl -v https://<tool>/` from the host |
| 3 | Hostname added to the egress allow list (if one is used) | Configuration audit record |
| 4 | Connector created **disabled**, with settings, API parameters and credentials | `integration.create` |
| 5 | **Test** returns `ok` with a version or identity message | `integration.test` SUCCESS |
| 6 | **Sync now** imports the expected record counts; spot-check 3 records against the source (title, severity, timestamps, hostname) | `integration.sync.manual` with counts |
| 7 | Enable the connector with an agreed polling interval | `integration.update` |
| 8 | After 24 hours: status HEALTHY, the *Failed security feeds* KRI is green, and the vendor reports no rate-limit complaints | Screenshot or report |

**Development and testing:** `tests/vendor-sim/server.mjs` simulates every vendor API, including the generic API with all pagination styles, API-parameter requirements and a flaky endpoint for retry testing. The Playwright suite `tests/e2e/05-connectors.spec.ts` exercises all 19 adapters against it.

## B.13 Developing a new adapter

Add a dedicated adapter when a vendor needs logic the generic adapters can't express, such as asynchronous exports, XML or multi-step calls.

1. Create or extend a file in [`backend/src/connectors/adapters/`](../backend/src/connectors/adapters/) and use `defineAdapter({...})` ([`types.ts`](../backend/src/connectors/types.ts)):
   - `vendor` (unique key), `displayName`, `category`, `description`, `supportedAuth`, `defaultPollSec`, optional `defaultBaseUrl`
   - `settingsFields` (rendered automatically in the UI) and a **strict** zod `settingsSchema` with regex-validated paths and bounded numbers
   - optional `apiKeyHeaders(creds)` for vendor-specific key schemes
   - `test(ctx, settings)`, which returns a short human-readable message, and `sync(ctx, settings)`, which returns a `NormalizedBatch`
2. Make every call through `ctx.http.call()` or `callWithMeta()`, with paths relative to the base URL. Never use `fetch` or another client: the HTTP client provides the egress guard, authentication, retries, size caps and zero retention.
3. Use the helpers in `adapters/util.ts`:
   - `str()` caps strings and strips control characters
   - `toDate`, `optDate`
   - `severityFromText`, `severityFromScore`
   - `extractCve`, `normHost`, `getPath`
4. Bound the work: cap pages, records and polling loops.
5. Register the adapter in [`registry.ts`](../backend/src/connectors/registry.ts).
6. Add a simulator route in `tests/vendor-sim/server.mjs` and a case in `tests/e2e/05-connectors.spec.ts`, then run `scripts/run-all-tests.sh`.
7. Document the vendor's requirements in B.4.
