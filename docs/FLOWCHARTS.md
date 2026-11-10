# Process Flows & Flowcharts — CISO Executive Dashboard

Mermaid sources; render on GitHub/GitLab, in VS Code, or via [`diagrams.html`](diagrams.html).

1. [OIDC sign-in (Authorization Code + PKCE)](#1-oidc-sign-in-authorization-code--pkce)
2. [Zero-trust request pipeline](#2-zero-trust-request-pipeline)
3. [Session refresh, rotation & theft detection](#3-session-refresh-rotation--theft-detection)
4. [Connector sync with zero data retention](#4-connector-sync-with-zero-data-retention)
5. [KPI snapshot & KRI breach evaluation](#5-kpi-snapshot--kri-breach-evaluation)
6. [Risk acceptance lifecycle](#6-risk-acceptance-lifecycle)
7. [Tamper-evident audit write & verification](#7-tamper-evident-audit-write--verification)
8. [Risk matrix drill-down (user journey)](#8-risk-matrix-drill-down-user-journey)
9. [Deployment & bootstrap](#9-deployment--bootstrap)

---

## 1. OIDC sign-in (Authorization Code + PKCE)

```mermaid
sequenceDiagram
    autonumber
    actor U as User (browser)
    participant GW as Gateway (NGINX, TLS 1.3)
    participant API as API (mTLS)
    participant IdP as Keycloak / corporate IdP
    participant DB as PostgreSQL

    U->>GW: GET /api/auth/login
    GW->>API: forward (mTLS)
    API->>API: generate state, nonce, PKCE verifier (S256)
    API-->>U: 303 → IdP authorize URL + Set-Cookie __Host-ciso_oidc (JWE-encrypted state, 10 min)
    U->>IdP: authenticate (password + TOTP MFA, brute-force lockout)
    IdP-->>U: 302 → /api/auth/callback?code&state
    U->>API: GET /api/auth/callback (via gateway)
    API->>API: decrypt state cookie, verify state
    API->>IdP: token exchange (code + code_verifier, client_secret_basic) over TLS backchannel
    IdP-->>API: id_token, access_token, refresh_token
    API->>API: validate id_token (sig, iss, aud, exp, nonce) → map role claim → app roles
    alt no mapped role / user disabled
        API->>DB: audit auth.login FAILURE
        API-->>U: 303 /login?error=…
    else authorised
        API->>DB: upsert user (email AES-256-GCM + blind index), create session (refresh hash only)
        API->>DB: audit auth.login SUCCESS
        API-->>U: 303 returnTo + Set-Cookie __Host-ciso_at (JWT 10 min), __Host-ciso_rt, __Host-ciso_csrf
    end
```

## 2. Zero-trust request pipeline

Every API call is re-verified; nothing is trusted because of network location.

```mermaid
flowchart TD
    A([HTTPS request]) --> B{TLS 1.3 at gateway?}
    B -- no --> X1[[handshake refused]]
    B -- yes --> C[Gateway: rate limit · body size · overwrite X-Forwarded-For]
    C --> D[mTLS hop to API<br/>client cert verified against internal CA]
    D --> E[Security headers · Cache-Control: no-store]
    E --> F{Unsafe method?}
    F -- yes --> G{Sec-Fetch-Site / Origin OK<br/>and X-CSRF-Token == cookie?}
    G -- no --> X2[[403 CSRF]]
    G -- yes --> H
    F -- no --> H{Access JWT valid?<br/>HS512 · iss · aud · exp}
    H -- no --> X3[[401 → client tries silent refresh]]
    H -- yes --> I{Server-side session live?<br/>not revoked · user active · absolute TTL}
    I -- no --> X3
    I -- yes --> J{RBAC: role grants permission?}
    J -- no --> K[audit access.denied] --> X4[[403]]
    J -- yes --> L{Zod .strict validation<br/>types · ranges · unknown keys}
    L -- no --> X5[[400 with field paths, no values]]
    L -- yes --> M[Business logic<br/>Prisma parameterised queries]
    M --> N[(Transaction:<br/>change + audit record)]
    N --> O[Publish SSE change notification]
    O --> P([JSON response])
```

## 3. Session refresh, rotation & theft detection

```mermaid
flowchart TD
    A([POST /api/auth/refresh<br/>__Host-ciso_rt cookie]) --> B[lookup by SHA-256 of token]
    B --> C{found?}
    C -- no --> R1[[401]]
    C -- yes --> D{already revoked?}
    D -- "yes, reason = ROTATED" --> E[REUSE DETECTED<br/>revoke entire token family] --> F[audit auth.refresh_token_reuse DENIED] --> R1
    D -- "yes, other reason" --> R1
    D -- no --> G{idle TTL, absolute TTL ok<br/>and user active?}
    G -- no --> H[revoke EXPIRED] --> R1
    G -- yes --> I[Continuous verification:<br/>exchange IdP refresh token]
    I --> J{IdP accepts and user<br/>still has a mapped role?}
    J -- no --> K[revoke IDP_REVERIFY_FAILED] --> R1
    J -- yes --> L[update roles from IdP claims]
    L --> M[mark old session ROTATED<br/>create new session in same family]
    M --> N([200 + new access, refresh and CSRF cookies])
```

## 4. Connector sync with zero data retention

```mermaid
flowchart TD
    S([Scheduler tick every 30 s]) --> A{connector enabled<br/>and poll interval elapsed?}
    A -- no --> S
    A -- yes --> B{acquire DB lease<br/>UPDATE … WHERE leaseUntil expired}
    B -- lost --> S
    B -- won --> C[decrypt credentials in memory<br/>AES-256-GCM, AAD = connector id]
    C --> D[Egress policy: https only · allowlist · denied hosts]
    D --> E[Connect: DNS lookup checked at socket level<br/>blocks loopback · link-local/metadata · internal CIDRs]
    E --> F[Auth: API key · Basic · OAuth2 client-credentials · mTLS]
    F --> G[Fetch with timeout + response-size cap<br/>no redirects followed]
    G --> H{HTTP ok?}
    H -- no --> Z[status FAILED · generic error stored<br/>upstream body never echoed] --> R
    H -- yes --> I[Parse JSON / XML<br/>XML entity expansion disabled]
    I --> J[[ZERO DATA RETENTION<br/>raw buffer zero-filled immediately]]
    J --> K[Normalise to canonical records<br/>incidents · vulns · patch status · changes · threats]
    K --> L[(Upsert normalised fields only)]
    L --> M[Recompute impacted-asset counts for CVEs]
    M --> N[status HEALTHY · counts · publish SSE]
    N --> R[release lease · close HTTP agent · drop references]
    R --> S
```

## 5. KPI snapshot & KRI breach evaluation

```mermaid
flowchart LR
    subgraph Every_15_min[Every 15 min]
        A[compute KPIs] --> B[(metric_snapshots)]
    end
    subgraph Every_5_min[Every 5 min]
        C[compute KPIs] --> D[load KRI definitions<br/>thresholds = risk appetite]
        D --> E{for each enabled KRI:<br/>value vs amber / red}
        E -- GREEN --> F[no action]
        E -- AMBER/RED --> G{open unacknowledged breach<br/>at same or higher level?}
        G -- yes --> F
        G -- "no, or AMBER→RED escalation" --> H[(kri_breaches)] --> I[SSE: kri] --> J[Dashboard RAG updates live]
    end
    K[CISO / Admin edits threshold] --> L{red/amber ordering valid<br/>for direction?}
    L -- no --> M[[400]]
    L -- yes --> N[(update + audit before/after)] --> I
```

KPI definitions (rolling window, default 30 days, configurable):

| KPI | Formula |
|-----|---------|
| MTTD | mean(`detectedAt − occurredAt`) for incidents detected in window |
| MTTR | mean(`resolvedAt − detectedAt`) for incidents resolved in window |
| Patch compliance % | assets with `patchCompliant` ÷ all assets × 100 |
| Remediation velocity | findings remediated in window ÷ (window ÷ 7) per week |
| Open critical findings | CRITICAL vulns in OPEN / IN_PROGRESS |

## 6. Risk acceptance lifecycle

```mermaid
stateDiagram-v2
    [*] --> PENDING: request (CISO / SecOps / Patch Admin)<br/>justification encrypted · validity ≤ max days
    PENDING --> APPROVED: CISO approves<br/>approver ≠ requester (SoD)
    PENDING --> REJECTED: CISO rejects with rationale
    APPROVED --> EXPIRED: validity date passes<br/>(hourly job) → risk re-opens
    APPROVED --> REVOKED: CISO revokes → risk re-opens
    REJECTED --> [*]
    EXPIRED --> [*]
    REVOKED --> [*]
    note right of APPROVED
        Risk status = ACCEPTED.
        Every transition is written to the
        immutable audit log in the same
        transaction as the change.
    end note
```

## 7. Tamper-evident audit write & verification

```mermaid
flowchart TD
    subgraph Write[Append within the business transaction]
        A[event: actor · action · target · outcome · IP · UA · details] --> B[strip credential-like keys]
        B --> C[pg_advisory_xact_lock — serialise chain]
        C --> D[read last hash, or genesis 000…0]
        D --> E["hash = HMAC-SHA256(AUDIT_HMAC_KEY, prevHash | canonicalJSON(record))"]
        E --> F[(INSERT audit_log)]
    end
    subgraph Protect[Protection]
        G[trigger blocks UPDATE / DELETE / TRUNCATE for every role]
        H[ciso_app role: INSERT + SELECT only]
    end
    subgraph Verify[Verification — on demand and in compliance report]
        I[iterate by id ascending] --> J{prevHash == previous hash?}
        J -- no --> K[[deleted / reordered record → FAIL]]
        J -- yes --> L{recomputed HMAC == stored hash?}
        L -- no --> M[[modified record → FAIL]]
        L -- yes --> I
        I -- all records checked --> N[[chain valid]]
    end
    F --> Protect
    F --> Verify
```

## 8. Risk matrix drill-down (user journey)

```mermaid
flowchart LR
    A[Executive overview<br/>KPI tiles · KRI RAG · mini heat map] --> B[Risk Matrix page<br/>5×5 likelihood × impact]
    B -->|click cell| C[Risks in cell<br/>title · owner · status]
    C -->|click risk| D[Risk detail<br/>score · treatment]
    D --> E[Linked assets<br/>criticality · patch state]
    E --> F[Open vulnerabilities<br/>CVE · CVSS · SLA due date]
    D --> G{role can request acceptance?}
    G -- yes --> H[Request acceptance] --> I[CISO approval queue]
    F --> J[Remediation page<br/>Patch Admin links change ticket]
```

## 9. Deployment & bootstrap

```mermaid
flowchart TD
    A[Ubuntu / RHEL VM<br/>Docker Engine or Podman + compose] --> B[scripts/generate-certs.sh host<br/>internal CA + service cert]
    B --> C[scripts/generate-secrets.sh<br/>.env + secrets/ — mode 600, git-ignored<br/>--upgrade adds new secrets only]
    C --> D[docker compose up -d --build]
    D --> E[postgres: TLS entrypoint · SCRAM · init roles]
    E --> F[migrate: prisma migrate deploy<br/>+ triggers, grants · seed settings and demo data]
    E --> G[keycloak: realm import<br/>roles · client · demo users with forced TOTP]
    F --> K[idp-init: provisioner service account<br/>redirect URIs follow PUBLIC_BASE_URL<br/>identity policy · demo admin]
    G --> K
    K --> H[api: healthy over mTLS<br/>applies live settings · syncs IdP policy]
    H --> I[gateway: renders runtime config<br/>rate zones · trusted proxies · canonical host<br/>TLS 1.3 on :443]
    I --> J[scripts/smoke-test.sh]
    I --> L[Administrator: Configuration page]
    L -->|redeploy parameters| M[download deployment.env]
    M --> N[scripts/apply-deployment.sh<br/>validate · checksum · back up .env<br/>re-issue cert names · compose up]
    N --> K
    L -->|host parameters| O[download host baseline script]
    O --> P[sudo bash script --dry-run, then apply<br/>NTP · DNS · syslog · firewall · updates · sysctl · auditd]
```

## 10. Administrator-defined configuration (save → validate → audit → apply)

```mermaid
flowchart TD
    A[Administrator edits a parameter<br/>Configuration page — form generated<br/>from server field descriptors] --> B["PUT /api/admin/settings/:key"]
    B --> C{RBAC: system:manage<br/>or parameters:manage?}
    C -- no --> C1[403 + access.denied audit]
    C -- yes --> D{Zod schema valid?<br/>IP / CIDR / hostname / https URL<br/>cross-field rules}
    D -- no --> D1[400 with field-level issues]
    D -- yes --> E{network allowlist would<br/>exclude caller IP?}
    E -- yes --> E1[400 LOCKOUT_PREVENTED]
    E -- no --> F[(system_settings upsert<br/>+ setting.update audit<br/>before / after, same transaction)]
    F --> G[cache invalidated · compliance warnings computed]
    G --> H{apply mode}
    H -- live --> L1[rate limits · network allowlists<br/>egress policy · log level · demo generator<br/>effective within seconds]
    H -- identity --> L2[Keycloak admin API<br/>TOTP algorithm / digits / period<br/>password policy · lockout · SSO timeouts<br/>CONFIGURE_TOTP default action]
    H -- redeploy --> L3[deployment.env<br/>public URL or IP · ports · cert names<br/>trusted proxies · edge limits · memory]
    H -- host --> L4[host baseline script<br/>Ubuntu or RHEL]
    L1 --> R[Response: value · warnings · applied status]
    L2 --> R
    L3 --> R
    L4 --> R
    S[Scheduler: every 30 s and 5 min] -.->|re-applies live settings| L1
    S -.->|retries IdP sync| L2
```

## 11. Identity enrolment with enforced authenticator-app MFA

```mermaid
sequenceDiagram
    autonumber
    actor Admin as Administrator
    participant UI as Dashboard (System and Users)
    participant API as API (identity routes)
    participant KC as Keycloak (admin REST)
    actor User as New user
    Admin->>UI: Enrol user (username, email, name, roles)
    UI->>API: POST /api/admin/identity/users
    API->>API: RBAC users:manage · Zod validation
    API->>API: CSPRNG one-time password meeting policy
    API->>KC: create user (UPDATE_PASSWORD + CONFIGURE_TOTP, temporary password)
    API->>KC: map realm roles (rollback on failure)
    API->>API: audit identity.user.enrol (no secrets)
    API-->>UI: one-time password (shown once, never stored)
    Admin-->>User: share password over a separate channel
    User->>KC: sign in with one-time password
    KC-->>User: set new password (policy enforced)
    KC-->>User: Mobile Authenticator setup (QR, HmacSHA1, 6 digits, 30 s)
    User->>KC: TOTP code from Google or Microsoft Authenticator
    KC-->>API: authorization code (PKCE) and roles claim
    API-->>User: dashboard session (role-scoped)
    Note over Admin,API: Later: change roles, reset MFA or password, disable, delete — each audited, revoking live sessions when access is reduced
```
