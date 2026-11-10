# Architecture — CISO Executive Dashboard

All diagrams are [Mermaid](https://mermaid.js.org) and render natively on GitHub/GitLab,
in VS Code (Markdown Preview Mermaid Support), or by opening [`diagrams.html`](diagrams.html)
in a browser. Source files for each diagram also live in [`diagrams/`](diagrams/) for reuse
in other tools (e.g. `mmdc -i diagrams/01-system-context.mmd -o out.svg`).

---

## 1. System context

```mermaid
flowchart LR
    subgraph People
        CISO([CISO / Executive])
        ADM([Administrator])
        SEC([SecOps Analyst])
        PAT([IT / Patch Admin])
        AUD([Auditor])
    end

    DASH[[CISO Executive Dashboard]]
    IDP[(Corporate IdP<br/>OIDC + MFA)]

    subgraph Security_Tools["Security and IT tool estate"]
        SIEM[SIEM<br/>Splunk · Elastic · QRadar]
        VM[Vulnerability Mgmt<br/>Tenable · Nessus · Qualys]
        PM[Patch Mgmt<br/>WSUS · Ansible · Satellite]
        CM[Change Mgmt<br/>ServiceNow · Jira]
        TI[Threat Intel<br/>MISP · TAXII · CISA KEV · commercial]
    end

    CISO & ADM & SEC & PAT & AUD -- HTTPS TLS 1.3 --> DASH
    DASH -- OIDC Auth Code + PKCE --> IDP
    DASH -- outbound HTTPS<br/>API key · OAuth2 · mTLS --> SIEM & VM & PM & CM & TI
```

## 2. Container / deployment view (zero-trust network zones)

```mermaid
flowchart TB
    Browser([Browser<br/>React SPA])

    subgraph EDGE["edge network — only published ports 80/443"]
        GW["Gateway — NGINX (unprivileged, read-only FS)<br/>TLS 1.3 only · HSTS · strict CSP<br/>rate limiting · serves SPA"]
    end

    subgraph APPNET["app network (internal: true)"]
        API["API — Node.js 22 / Express 5 / TypeScript<br/>OIDC RP · RBAC · Zod validation<br/>KPI/KRI engine · connector framework<br/>scheduler · SSE stream"]
        KC["Keycloak 26 (OIDC IdP)<br/>MFA (TOTP) · brute-force protection<br/>password policy"]
    end

    subgraph DATANET["data network (internal: true)"]
        PG[("PostgreSQL 17 primary<br/>TLS 1.3 · SCRAM-SHA-256<br/>append-only audit_log")]
        PGR[("Read replicas<br/>(optional, multi-cluster)")]
        MIG["migrate (one-shot)<br/>prisma migrate deploy + seed"]
    end

    subgraph EGRESS["egress network"]
        EXT[[External security tool APIs]]
    end

    VAULT[("HashiCorp Vault KV v2<br/>(optional secrets provider)")]

    Browser -- "HTTPS (TLS 1.3)" --> GW
    GW -- "mTLS 1.3 (client cert)" --> API
    GW -- "TLS 1.3 /auth/*" --> KC
    API -- "TLS backchannel (token, JWKS, userinfo)" --> KC
    API -- "TLS + SCRAM (ciso_app: DML only)" --> PG
    API -.->|reads| PGR
    KC -- "TLS verify-full" --> PG
    MIG -- "TLS (owner role)" --> PG
    API -- "HTTPS · SSRF-guarded · size-capped" --> EXT
    API -.->|AppRole or token| VAULT
```

| Zone | Members | Exposure |
|------|---------|----------|
| `edge` | gateway | Ports 80 (redirect + health) and 443 published on the host |
| `app` | gateway, api, keycloak | Internal only — no route to the internet |
| `data` | api, migrate, keycloak, postgres | Internal only |
| `egress` | api | Outbound to security tool APIs; `172.30.0.0/16` blocked by the connector SSRF guard |

## 3. API component view

```mermaid
flowchart TB
    subgraph Pipeline["Request pipeline (app.ts)"]
        direction LR
        H[helmet headers<br/>no-store] --> RL[rate limit] --> CSRF[CSRF guard<br/>Origin + double-submit] --> AUTHN[authenticate<br/>JWT + live session] --> RBAC[requirePermission] --> ZOD[Zod .strict schemas]
    end

    subgraph Modules
        AUTH[auth<br/>OIDC · sessions · tokens]
        KPI[kpi / kri<br/>engine · trends · breaches]
        RISK[risk<br/>5×5 matrix · drill-down · acceptance]
        THR[threats<br/>stream · facets · triage]
        INC[incidents]
        REM[remediation<br/>vulns · assets · change tickets]
        INT[integrations<br/>connector config · test · sync]
        ADMIN[admin<br/>users · settings · system]
        AUDIT[audit<br/>query · verify · CSV export]
        COMP[compliance report]
        SSE["stream — SSE"]
    end

    subgraph Core
        CRYPTO[crypto<br/>AES-256-GCM key ring<br/>HMAC blind index]
        AUDSVC[audit service<br/>HMAC hash chain]
        PRISMA[Prisma client<br/>+ read replicas]
        EVENTS[event hub]
        SCHED[scheduler<br/>connector leases · snapshots<br/>KRI eval · retention]
    end

    subgraph Connectors["Connector framework"]
        REG[registry<br/>15 adapters]
        HTTP[ConnectorHttpClient<br/>API key · Basic · OAuth2 · mTLS]
        EGR[egress policy<br/>connect-time IP checks]
        ING[ingest<br/>normalised upserts only]
    end

    Pipeline --> Modules
    Modules --> AUDSVC & PRISMA & EVENTS
    INT --> REG
    SCHED --> REG
    REG --> HTTP --> EGR
    REG --> ING --> PRISMA
    AUTH & INT & INC & RISK --> CRYPTO
    SSE --> EVENTS
```

## 4. Data model

```mermaid
erDiagram
    USER ||--o{ SESSION : has
    ASSET ||--o{ VULNERABILITY : exposes
    CHANGE_TICKET ||--o{ VULNERABILITY : remediates
    RISK ||--o{ RISK_ASSET : links
    ASSET ||--o{ RISK_ASSET : links
    RISK ||--o{ RISK_ACCEPTANCE : "accepted via"
    KRI_DEFINITION ||--o{ KRI_BREACH : "breached by (kriKey)"

    USER {
        uuid id PK
        string subject UK "OIDC sub"
        string emailEnc "AES-256-GCM"
        string emailIndex UK "HMAC blind index"
        enum_list roles "OIDC-mapped"
        bool active
    }
    SESSION {
        uuid id PK
        uuid familyId "rotation family"
        string refreshHash UK "SHA-256 only"
        string idpRefreshEnc "AES-256-GCM"
        datetime expiresAt "idle"
        datetime absoluteExpiresAt
        datetime revokedAt
    }
    CONNECTOR {
        uuid id PK
        string vendor
        enum category
        string baseUrl
        enum authMode
        int pollIntervalSec
        json settings
        string secretEnc "AES-256-GCM, AAD=connector id"
        enum status
    }
    ASSET {
        uuid id PK
        string hostname UK
        int criticality "1-5"
        bool patchCompliant
    }
    VULNERABILITY {
        uuid id PK
        string source
        string externalId
        string cveId
        enum severity
        enum status
        datetime dueAt "SLA"
        datetime remediatedAt
    }
    INCIDENT {
        uuid id PK
        enum severity
        enum status
        datetime occurredAt
        datetime detectedAt "MTTD"
        datetime resolvedAt "MTTR"
        string descriptionEnc
    }
    THREAT_ITEM {
        uuid id PK
        enum type "CVE|RANSOMWARE|SUPPLY_CHAIN|ADVISORY|IOC"
        enum severity
        string source "attribution"
        int impactedAssetCount
    }
    RISK {
        uuid id PK
        int likelihood "1-5"
        int impact "1-5"
        enum status
    }
    RISK_ACCEPTANCE {
        uuid id PK
        string justificationEnc
        uuid requestedById
        uuid decidedById "≠ requester (SoD)"
        enum status
        datetime expiresAt
    }
    KRI_DEFINITION {
        string key UK
        string metric
        enum direction
        float amberThreshold
        float redThreshold
    }
    AUDIT_LOG {
        bigint id PK
        timestamptz ts
        string action
        string outcome
        json details
        string prevHash
        string hash UK "HMAC-SHA256 chain"
    }
```

## 5. Technology choices

| Concern | Choice | Why |
|---------|--------|-----|
| Frontend | React 18, TypeScript, Vite, Tailwind CSS, lucide-react, Recharts | Typed, fast builds, no inline scripts/styles → strict CSP |
| Backend | Node.js 22, Express 5, TypeScript (ESM) | Single language across the stack; Express 5 propagates async errors |
| Validation | Zod `.strict()` schemas on every body/query/param | Rejects unknown keys (mass assignment), enforces types/lengths |
| ORM | Prisma 6 (parameterised queries), `@prisma/extension-read-replicas` | SQL-injection-safe by construction; read scaling across clusters |
| Database | PostgreSQL 17 | Triggers for append-only audit, CHECK constraints, SCRAM, TLS 1.3 |
| Identity | OpenID Connect (Keycloak bundled; any compliant IdP) | MFA, brute-force protection and lifecycle mastered in the IdP |
| Sessions | 10-min HS512 JWT + rotating opaque refresh token in `__Host-` cookies | Short-lived, httpOnly, SameSite=Strict, server-side revocation |
| Crypto | AES-256-GCM (AAD-bound), HMAC-SHA256 | Authenticated encryption; tamper-evident audit chain |
| Edge | NGINX unprivileged, TLS 1.3 only | HSTS, CSP, rate limiting, mTLS to the API |
| Packaging | Multi-stage Dockerfiles, Compose with segmented networks | Non-root, read-only root FS, `cap_drop: ALL`, `no-new-privileges` |

## 6. Scaling and multi-cluster notes

* **Database:** set `DATABASE_REPLICA_URLS` to route reads to replicas (streaming replication / Patroni / cloud read replicas). Writes, transactions and the audit chain always use the primary.
* **API replicas:** connector polling uses a DB lease (`connectors.leaseUntil`) so several API instances never run the same connector concurrently. The SSE hub is in-process; for >1 replica, replace `lib/events.ts` with PostgreSQL `LISTEN/NOTIFY` or Redis pub/sub.
* **Gateway:** stateless; place several behind an L4 load balancer.
