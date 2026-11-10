# CISO Executive Dashboard

A full-stack, zero-trust security posture dashboard for CISOs. It brings in data from SIEM, vulnerability, patch, change-management and threat-intel tools, and turns it into:

- **KPIs:** MTTD, MTTR, patch compliance, remediation velocity, open critical findings.
- **KRIs:** Red/Amber/Green status against your risk-appetite thresholds.
- **A 5×5 ISO 31000 risk matrix:** drill down from a cell to the risks, assets and vulnerabilities behind it.
- **A live threat-intelligence stream.**

| Layer | Stack |
|-------|-------|
| Frontend | React 18 · TypeScript · Vite · Tailwind CSS · lucide-react · Recharts |
| API | Node.js 22 · Express 5 · TypeScript · Zod · Prisma 6 |
| Data | PostgreSQL 17 (TLS 1.3, SCRAM, append-only audit; optional read replicas) |
| Identity | OpenID Connect (bundled Keycloak 26 with forced TOTP MFA; any OIDC IdP) |
| Edge | NGINX (unprivileged) — TLS 1.3 only, HSTS, strict CSP, mTLS to the API |
| Packaging | Multi-stage Dockerfiles · Docker Compose with segmented networks |

📐 **Architecture diagrams:** [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)
🔀 **Flowcharts and sequence diagrams:** [docs/FLOWCHARTS.md](docs/FLOWCHARTS.md)
🖼 **Offline viewer:** open [docs/diagrams.html](docs/diagrams.html) in a browser. Raw sources are in [docs/diagrams/](docs/diagrams/).
🔐 **Security controls and the OWASP / NIST / PCI mapping:** [docs/SECURITY.md](docs/SECURITY.md)
🧪 **Test strategy and coverage:** [docs/TESTING.md](docs/TESTING.md)
🖥 **Screenshots:** [docs/screenshots/](docs/screenshots/)

![Executive overview](docs/screenshots/01-overview.png)

---

## Quick start (Ubuntu 22.04+/24.04, RHEL 9, or Docker Desktop)

Prerequisites: Docker Engine 24+ with the Compose plugin (or Podman 4.9+ with `podman compose`), `openssl` and `bash`.

```bash
# 1. TLS material: internal CA + service certificate (use your PKI in production)
./scripts/generate-certs.sh ciso.corp.example        # or: localhost

# 2. Secrets: .env + ./secrets (random values, mode 600, git-ignored)
PUBLIC_BASE_URL=https://ciso.corp.example ./scripts/generate-secrets.sh

# 3. Build and start
docker compose up -d --build --wait

# 4. Verify (52 end-to-end checks: OIDC, RBAC, CSRF, SoD, SSRF, token rotation, audit chain)
./scripts/smoke-test.sh
```

Then open `https://<host>/`. Import `certs/ca.crt` into your browser or OS trust store, or accept the warning in development.

**Demo accounts:** `ciso.demo`, `admin.demo`, `secops.demo`, `patch.demo`, `auditor.demo`. They share one initial password, `DEMO_USER_PASSWORD` in `.env`. On first login each account must change its password and enrol an authenticator app (TOTP).

**Stop:** `docker compose down`. **Wipe all data:** `docker compose down -v`.

On Windows (Git Bash), run the scripts with `bash scripts/<name>.sh` and set `APP_UID=1000` and `APP_GID=1000` in `.env`.

---

## Roles and access control

Roles come from the IdP's `roles` claim and are mapped by `OIDC_ROLE_MAPPING`. The API enforces every permission; the UI only hides what a role cannot use.

| Capability | CISO | Admin | SecOps | Patch Admin | Auditor |
|------------|:---:|:---:|:---:|:---:|:---:|
| Executive overview, KPIs, KRIs, risk matrix, threat stream | ✅ | ✅ | ✅ | ✅ | ✅ (read) |
| Edit KRI thresholds and risk parameters | ✅ | ✅ | | | |
| Register and edit risks | ✅ | | ✅ | | |
| Request a risk acceptance | ✅ | | ✅ | ✅ | |
| **Approve risk acceptance** (never your own request) | ✅ | | | | |
| Manage integrations (endpoints, credentials, test, sync) | view | ✅ | ✅ | | |
| Triage threats | ✅ | | ✅ | | |
| Log and update incidents | | | ✅ | | |
| Update remediation status, link change tickets | | | | ✅ | |
| Users, sessions, system health | view users | ✅ | | | |
| Audit log (view, verify, export) and compliance report | ✅ | ✅ | | | ✅ |

---

## Functional modules

- **Integration layer:** 15 parameterised connectors. Each one is configured in the UI with its endpoint, polling interval, auth mode (API key, Basic, OAuth2 client credentials, or mTLS), vendor-specific settings and a custom CA. Each has *Test connection* and *Sync now* actions.

  | Category | Connectors |
  |----------|------------|
  | SIEM | Splunk ES · Elastic Security · IBM QRadar |
  | Vulnerability | Tenable VM · Nessus · Qualys VMDR |
  | Patch | WSUS (via [tools/wsus-bridge.ps1](tools/wsus-bridge.ps1)) · Ansible AWX/AAP · Red Hat Satellite |
  | Change | ServiceNow · Jira |
  | Threat intel | MISP · STIX/TAXII 2.1 · CISA KEV (enabled by default) · generic commercial JSON |

  Credentials are encrypted with AES-256-GCM and are write-only: the API never returns them. Outbound calls pass through an SSRF egress guard.

- **KPI & KRI engine:** live KPI calculation, a snapshot every 15 minutes for trend charts, and a KRI check every 5 minutes. Breaches go to a breach register that CISO, SecOps and Admin can acknowledge.

- **Risk:** the 5×5 likelihood × impact heat map is marked against your risk appetite. You can drill down from a cell to its risks, their linked assets, and those assets' open vulnerabilities with SLA due dates. Risk acceptance has an approval workflow with expiry.

- **Threat intelligence stream:** CVEs, ransomware advisories, supply-chain risks and IOCs. Filter by type, severity, source, status, text, or *impacting my assets*. Each item shows its source and how many of your assets it affects. Updates arrive live over SSE.

- **Incidents and remediation:** MTTD and MTTR are calculated from incident lifecycle timestamps. Vulnerabilities carry SLA due dates and can be linked to a change ticket.

- **Governance:** the audit log is immutable and hash-chained, with integrity verification and CSV export. A live compliance report maps controls to NIST 800-53 AU and PCI DSS v4.0.1 Requirement 10.

---

## Repository layout

```
backend/                 Express API (TypeScript, ESM)
  prisma/                schema + migrations (incl. audit triggers, least-privilege grants)
  src/auth/              OIDC RP, sessions, JWT, RBAC, middleware
  src/audit/             hash-chained audit service + routes
  src/connectors/        framework: egress guard, HTTP client, 15 adapters, ingest, runner
  src/modules/           kpi · risk · threats · incidents · remediation · integrations · admin · compliance · stream · settings
  src/scheduler/         polling leases, snapshots, KRI evaluation, retention
  test/                  unit tests (crypto, RBAC, SSRF, audit chain, KPI maths)
frontend/                React SPA (pages, components, hooks)
infra/                   gateway Dockerfile, nginx, postgres (TLS entrypoint, hba, init), keycloak realm
scripts/                 generate-certs.sh · generate-secrets.sh · smoke-test.sh · run-all-tests.sh
tests/                   Playwright e2e suite (tests/e2e) + vendor API simulator (tests/vendor-sim)
tools/                   wsus-bridge.ps1
docs/                    architecture, flowcharts, security, testing, diagrams, screenshots
```

## Testing

```bash
scripts/run-all-tests.sh      # unit tests → builds → fresh stack with dummy data + vendor simulator
                              # → Playwright end-to-end suite → bash smoke test
```

The full pipeline covers:
- unit tests
- every page for every role, in a real browser
- a 47-endpoint × 5-role RBAC matrix
- MFA enrolment
- all 15 connectors against a vendor API simulator with dummy data
- audit tamper detection, database privileges and TLS, container and network isolation
- key rotation and rate limiting

Details are in [docs/TESTING.md](docs/TESTING.md).

## Development

```bash
cd backend && npm ci && npx prisma generate
npm run typecheck && npm test            # unit tests
cd ../frontend && npm ci && npm run build
```

To develop the API outside Docker, run `docker compose up -d postgres keycloak`. Then export the variables listed in [backend/src/config/env.ts](backend/src/config/env.ts) (the `*_FILE` variables can point at `./secrets/*`) and run `npm run dev`. `vite dev` proxies `/api` to `https://localhost`.

### Database migrations

```bash
cd backend
npx prisma migrate dev --name <change>       # against a dev database
docker compose up -d --force-recreate migrate api   # applies pending migrations, then restarts the API
```

The `migrate` service connects as the schema owner. The API runs as `ciso_app`, which has DML rights only and cannot UPDATE or DELETE `audit_log`.

## Configuration reference (API)

| Variable | Default | Purpose |
|----------|---------|---------|
| `PUBLIC_BASE_URL` | — | External https URL (cookies, OIDC redirect, CSRF origin) |
| `DATABASE_URL[_FILE]` / `DATABASE_REPLICA_URLS` | — | Primary database and optional comma-separated read replicas |
| `OIDC_ISSUER_URL`, `OIDC_DISCOVERY_URL`, `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET[_FILE]` | — | IdP settings |
| `OIDC_ROLE_CLAIM`, `OIDC_ROLE_MAPPING` | `roles`, `administrator:ADMIN,…` | Map IdP roles or groups to app roles |
| `ACCESS_TOKEN_TTL_SEC` / `REFRESH_IDLE_TTL_SEC` / `SESSION_ABSOLUTE_TTL_SEC` | 600 / 900 / 28800 | Session lifetimes |
| `DATA_ENCRYPTION_KEYS[_FILE]`, `DATA_ENCRYPTION_ACTIVE_KEY` | — / `v1` | AES-256 key ring (`id:base64,…`) |
| `JWT_SECRET`, `STATE_ENCRYPTION_KEY`, `BLIND_INDEX_KEY`, `AUDIT_HMAC_KEY` (`_FILE`) | — | Signing, state, blind-index and audit-chain keys |
| `SECRETS_PROVIDER` | `env` | `vault` loads secrets from HashiCorp Vault KV v2 |
| `CONNECTOR_ALLOWED_HOSTS` / `CONNECTOR_DENIED_HOSTS` / `CONNECTOR_BLOCKED_CIDRS` | — | Egress policy |
| `CONNECTOR_BLOCK_PRIVATE_NETWORKS` / `CONNECTOR_ALLOW_INSECURE_HTTP` | false / false | Egress policy toggles (insecure HTTP is refused in production) |
| `TLS_CERT_FILE`, `TLS_KEY_FILE`, `TLS_CA_FILE`, `TLS_REQUIRE_CLIENT_CERT` | — | API HTTPS listener and mTLS |

These parameters are set at runtime in the UI (KRI & Parameters page) and every change is audited: risk appetite, vulnerability SLA days, maximum risk-acceptance validity, KPI window, and retention periods.

## Using a corporate IdP instead of Keycloak

1. Register a confidential web app with redirect URI `https://<host>/api/auth/callback` and post-logout URI `https://<host>/`.
2. Emit a roles or groups claim. For example, in Entra ID use app roles in the `roles` claim. Set `OIDC_ROLE_CLAIM` and `OIDC_ROLE_MAPPING`, e.g. `CISO-Dashboard-Execs:CISO,SOC-Analysts:SECOPS`.
3. Set `OIDC_ISSUER_URL` (and leave `OIDC_DISCOVERY_URL` unset) and put the client secret in `secrets/oidc_client_secret`.
4. Remove the `keycloak` service and the `/auth/` locations from `infra/nginx/nginx.conf`.

## Operations

- **Backups:** `docker compose exec postgres pg_dump -U ciso_owner -Fc ciso > backup.dump`, then encrypt the dump. Back up `secrets/` to your vault separately.
- **Key rotation:** see [docs/SECURITY.md §4](docs/SECURITY.md#key-rotation-no-downtime).
- **Logs:** all containers write JSON logs to stdout. Ship them to your SIEM with the Docker logging driver or a log agent.
- **Keycloak admin console:** reachable only from the Docker host. Use `ssh -L 8443:localhost:443 vm`, then open `https://localhost:8443/auth/admin/`.
- **RHEL / SELinux:** bind mounts use `:z` relabelling. With Podman, run `podman compose up -d --build`. Open the firewall with `firewall-cmd --add-service=https --permanent && firewall-cmd --reload`.
