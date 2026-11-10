# Administrator-defined configuration

Every platform parameter that an administrator should own lives on the **Configuration** page (`/configuration`). The page is generated from the server's parameter catalogue ([`settings.service.ts`](../backend/src/modules/settings/settings.service.ts)), so a new parameter appears in the UI without frontend changes.

Every change goes through four steps:

1. **Validated** by a strict schema. Each network value is an IP or CIDR, a hostname or an https URL; free-form strings are never accepted. Cross-field rules also apply, for example idle timeout ≤ absolute lifetime.
2. **Audited** as `setting.update`, with before and after values.
3. **Applied** according to its *apply mode*.
4. **Checked** for compliance. Warnings (PCI DSS, authenticator compatibility) are shown next to the form and in the save response.

| Apply mode | Badge | How it takes effect |
|------------|-------|---------------------|
| `live` | Live | The running API picks it up within seconds. Other replicas converge within 30 s. |
| `identity` | IdP sync | Pushed to Keycloak through its admin API when saved. The scheduler re-applies it hourly and retries every 5 minutes after a failure. |
| `redeploy` | Redeploy | Rendered into `deployment.env` and applied on the Docker host with `scripts/apply-deployment.sh`. |
| `host` | Host script | Rendered into an idempotent Ubuntu or RHEL script that an operator reviews and runs with `sudo`. |

Read access: CISO, Admin and Auditor (`config:read`). Changes: Admin (`system:manage`). The risk and retention parameters stay on *KRI & Parameters*, and CISO can edit the risk ones.

---

## Parameter reference

### Network access (live)

| Field | Effect |
|-------|--------|
| Allowed client networks | IPs or CIDRs allowed to sign in and call the API. They are enforced in the API for every `/api` call, including sign-in, and at the gateway for the identity-provider pages (NGINX `auth_request`). Empty means any network. Saving a list that excludes your own address is refused (`LOCKOUT_PREVENTED`). |
| Keycloak admin console networks | Networks allowed to reach `/auth/admin/`, in addition to the Docker host, which is always allowed. |

### Rate limiting (live)

| Field | Default | Scope |
|-------|---------|-------|
| Per user — API requests | 600/min | Signed-in traffic, keyed by **user** so that offices behind one NAT address do not share a quota |
| Per user — heavy operations | 30/min | Connector test/sync, audit verification and export, demo tools, identity sync |
| Per source IP — flood ceiling | 3000/min | All `/api` traffic |
| Per source IP — login/callback/refresh | 120/min | Unauthenticated sign-in endpoints. Keycloak also locks accounts. |

Throttled calls get **HTTP 429** with `Retry-After`, `RateLimit` and `RateLimit-Policy` headers and the body `{"error":{"code":"RATE_LIMITED"}}`. The gateway's own per-IP flood limits are deployment parameters.

### Sessions (IdP sync)

Access-token lifetime (60–900 s), idle timeout (300–7200 s) and absolute lifetime (900–43200 s). They apply to new sign-ins and refreshes, and are pushed to Keycloak's SSO session timeouts. A warning is shown when the idle timeout exceeds 15 minutes (PCI DSS 8.2.8).

### Identity, MFA & enrolment (IdP sync)

| Field | Default | Notes |
|-------|---------|-------|
| Require authenticator-app MFA | on | Makes `CONFIGURE_TOTP` a default required action for every new identity. *Enforce MFA for existing users* flags identities that have no authenticator. |
| TOTP algorithm | **HmacSHA1** | **Google Authenticator and Microsoft Authenticator only support HmacSHA1.** Choosing SHA-256/512 shows a blocking-severity warning. |
| TOTP digits / period | 6 / 30 s | Keep the defaults for app compatibility. |
| Password policy | ≥ 12 characters, upper, lower, digit, special, history 12, no expiry | The demo profile seeds a minimum of 10 so that the requested demo password `Admin@123!` is valid. A warning cites PCI DSS 8.3.6. |
| Lockout | 5 failures, 60 s → 900 s, not permanent | A warning is shown above 10 attempts (PCI DSS 8.3.4). |

**Enrolment** (*System & Users → Identity & enrolment*). An administrator enters the username, email, name and dashboard roles. The server generates a CSPRNG one-time password that is shown once and never stored or logged. At first sign-in the user sets a new password and registers an authenticator app.

Further actions:
- Change roles. Removing a role ends the user's sessions.
- Reset the password, which issues a new one-time password.
- Reset MFA, which removes the authenticator and forces re-enrolment.
- Disable, enable or delete the user.

Safeguards:
- You cannot change your own identity.
- At least one enabled administrator must remain.
- Every action is audited, without secrets.

With an external IdP such as Entra ID or Okta, leave `IDP_ADMIN_URL` unset and manage these settings in the IdP. The page then says so.

### Integration defaults (live)

| Field | Notes |
|-------|-------|
| Allowed destination hosts | `*.domain` wildcards are supported. Empty means any public host. |
| Additional denied hosts | Extends the built-in denylist of internal service names. |
| Block RFC 1918 / ULA destinations | Use this when every tool is SaaS-hosted. |
| Request timeout, maximum response size | Apply to every connector unless the connector overrides them. |
| Retries / initial back-off | On 429, 502, 503, 504 and transient network errors. Exponential back-off with jitter; `Retry-After` is honoured up to 60 s. |
| Default polling interval | Used for new connectors. |

Internal zones (`172.30.0.0/16`), loopback, link-local and cloud-metadata addresses are always blocked, whatever these values are.

#### Per-connector API parameters

In the connector dialog, under *Advanced API parameters*:

- **Path prefix**, for vendors behind an API gateway, e.g. `/gateway/splunk`. `.` and `..` segments are rejected.
- **Extra headers**, e.g. `Version: 20.0` (QRadar), `elastic-api-version: 2023-10-31`, `X-Api-Version: 2`.
- **Extra query parameters**, e.g. tenant or region selectors.
- **Timeout and retries**, which override the integration defaults.

Header and parameter names that look like credentials (`auth`, `token`, `secret`, `key`, `password`, `cookie`, `session`, `signature`) are rejected. Credentials must go in the encrypted credential fields. Hop-by-hop, routing and cookie headers are also rejected.

#### Generic REST/JSON adapters

There is one generic adapter per category:
- `generic_siem` produces incidents
- `generic_vulnerability` produces findings
- `generic_patch` produces device compliance
- `generic_change` produces change tickets
- `generic_rest` produces threat intel

You configure each one with:
- the endpoint path, and optionally a health-check path
- the items path, and field mappings as dot paths
- incremental polling: a "since" parameter in ISO 8601, epoch or epoch-ms format
- pagination, in one of these styles:

| Style | Requests |
|-------|----------|
| none | single request |
| offset | `?offset=N&limit=M`; stops at a short page |
| page | `?page=N&per_page=M`; first page 0 or 1 |
| cursor | `?cursor=<token>`, where the token is read from a body path such as `meta.next_cursor` |
| link | follows the RFC 8288 `Link: <…>; rel="next"` header; the URL must stay on the same origin |

Limits: at most 100 pages and 5000 records per poll. Status and severity text are classified by keyword; numeric severities are treated as CVSS. Ticket URLs are kept only if they use `https://`.

### Logging (live)

The API log level (`fatal` … `debug`). Secrets and third-party payloads are always redacted.

### Demo data (live, demo profile only)

| Field | Purpose |
|-------|---------|
| Live simulation, tick interval | The scheduler runs a simulation tick every *interval* seconds. |
| New incidents / threat items / findings / remediations per hour | Per-tick volume = rate × interval / 3600, with the fractional part drawn at random. |
| Dataset sizes and KPI history days | Used by *Regenerate demo dataset*, which requires typing `REGENERATE`. Audit records, users, connectors and parameters are kept. |

Each tick creates incidents and moves open ones through NEW → TRIAGE → CONTAINED → RESOLVED. It also creates findings with SLA due dates, remediates the oldest critical and high findings first, publishes threat items, introduces patch drift, and pushes SSE updates to every open dashboard. A database advisory lock prevents concurrent ticks across replicas.

### Deployment (redeploy)

| Field | Rendered as |
|-------|-------------|
| Public URL (hostname **or IP**) | `PUBLIC_BASE_URL`. Keycloak hostname, OIDC redirect URIs, cookies and CSRF origin all follow it. |
| Alternative names / IPs | `CERT_SANS`. They are added to the TLS certificate, and requests that use them are redirected (308) to the public URL. |
| Published HTTPS / HTTP ports | `HTTPS_PORT`, `HTTP_PORT` |
| Trusted load balancers | `TRUSTED_UPSTREAM_PROXIES`. NGINX `set_real_ip_from` is set only for these addresses, so client IPs (for rate limits and allowlists) cannot be spoofed. |
| Gateway flood / sign-in limit per IP | `EDGE_RATE_LIMIT_RPS`, `EDGE_AUTH_RATE_LIMIT_RPS` |
| Memory limits | `API_MEMORY`, `KEYCLOAK_MEMORY`, `POSTGRES_MEMORY` |

The status strip compares the saved profile with what the containers were started with, and lists any drift.

```bash
# On the Docker host, in the installation directory
scripts/apply-deployment.sh deployment.env --dry-run   # show the diff and any missing certificate names
scripts/apply-deployment.sh deployment.env             # back up .env, re-issue the certificate, redeploy
```

The script never `source`s the file. It accepts only the ten whitelisted keys, validates every value against a strict pattern, and verifies the checksum written by the dashboard. Pass `--allow-edited` for deliberate edits. When certificate names change it re-issues the service certificate under the existing CA, so browsers that already trust `certs/ca.crt` keep working. On redeploy, `idp-init` points the Keycloak client at the new public URL.

### Host operating system (host script)

| Area | Ubuntu | RHEL / Rocky / Alma |
|------|--------|---------------------|
| Time zone, NTP | `timedatectl`, chrony managed block | same (`chronyd`) |
| DNS resolvers | systemd-resolved drop-in | NetworkManager global DNS |
| Syslog to SIEM | rsyslog `omfwd`, TLS (RFC 5425) with peer-name check | same, `rsyslog-gnutls` |
| Edge firewall | `DOCKER-USER` chain filtered by original destination port. Docker-published ports bypass ufw and firewalld, so this is the effective control. It is persisted by `ciso-edge-firewall.service`. | same |
| SSH restriction | ufw rules, applied only if networks are listed | firewalld rich rules, applied only if networks are listed |
| Security updates | unattended-upgrades | dnf-automatic (security) |
| Kernel hardening | sysctl drop-in (keeps `ip_forward` for Docker) | same |
| auditd | watches on Docker binaries and config, `secrets/`, `certs/`, `.env` | same |
| Docker log rotation | merged into `daemon.json` (needs `jq` when the file exists) | same |

```bash
sudo bash ciso-host-baseline-ubuntu.sh --dry-run --app-dir /opt/ciso-dashboard
sudo bash ciso-host-baseline-ubuntu.sh --app-dir /opt/ciso-dashboard
```

The script is idempotent and refuses to run on the wrong OS family. If no SSH networks are defined it leaves SSH untouched, so you cannot lock yourself out. The web application has no path to execute anything on the host; this is deliberate, because a web-to-root path would break the zero-trust model.

---

## Bootstrap and upgrade

- `scripts/generate-secrets.sh --upgrade` adds the secrets introduced by this feature set: the provisioner client secret, the bootstrap admin password file and the demo admin password file. It never modifies existing secrets.
- The one-shot `idp-init` container runs on every `docker compose up`. It is the only container that ever receives the Keycloak bootstrap administrator password. It:
  - creates or rotates the least-privilege `ciso-provisioner` service account (realm-management: view/manage users, query users, view/manage realm)
  - points the dashboard OIDC client at the current public URL
  - applies the stored identity policy
  - in the demo profile, creates the demo administrator `admin` if that user does not exist
