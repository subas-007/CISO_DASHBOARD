/**
 * Strictly validated runtime configuration. The process refuses to start if any
 * value is missing, malformed, or insecure for production.
 */
import { z } from 'zod';
import { loadSecrets, scrubSecretsFromEnv } from './secrets.js';

const bool = z
  .enum(['true', 'false', '1', '0'])
  .transform((v) => v === 'true' || v === '1');

/** Optional value where an empty string (unset compose interpolation) means "absent". */
const opt = <T extends z.ZodTypeAny>(schema: T) => z.preprocess((v) => (v === '' ? undefined : v), schema.optional());

const base64Key32 = z
  .string()
  .refine((v) => Buffer.from(v, 'base64').length === 32, 'must be 32 bytes, base64 encoded');

const EnvSchema = z.object({
  NODE_ENV: z.enum(['development', 'test', 'production']).default('production'),
  PORT: z.coerce.number().int().min(1).max(65535).default(8443),
  LOG_LEVEL: z.enum(['fatal', 'error', 'warn', 'info', 'debug', 'trace']).default('info'),
  APP_VERSION: z.string().default('1.0.0'),
  PUBLIC_BASE_URL: z.string().url().transform((v) => v.replace(/\/+$/, '')),
  TRUST_PROXY_HOPS: z.coerce.number().int().min(0).max(5).default(1),

  // Transport security for the API listener (mTLS from the gateway)
  TLS_CERT_FILE: z.string().optional(),
  TLS_KEY_FILE: z.string().optional(),
  TLS_CA_FILE: z.string().optional(),
  TLS_REQUIRE_CLIENT_CERT: bool.default('false'),

  // Database (primary + optional read replicas for multi-cluster deployments)
  DATABASE_URL: z.string().min(1),
  DATABASE_REPLICA_URLS: z.string().optional().default(''),

  // OpenID Connect
  OIDC_ISSUER_URL: z.string().url(),
  OIDC_DISCOVERY_URL: z.string().url().optional(),
  OIDC_CLIENT_ID: z.string().min(1),
  OIDC_CLIENT_SECRET: z.string().min(16),
  OIDC_SCOPES: z.string().default('openid profile email'),
  OIDC_ROLE_CLAIM: z.string().default('roles'),
  OIDC_ROLE_MAPPING: z
    .string()
    .default('administrator:ADMIN,ciso:CISO,secops_analyst:SECOPS,patch_admin:PATCH_ADMIN,auditor:AUDITOR'),

  // Session & token lifetimes
  JWT_SECRET: z.string().min(64, 'JWT_SECRET must be at least 64 characters'),
  STATE_ENCRYPTION_KEY: base64Key32,
  ACCESS_TOKEN_TTL_SEC: z.coerce.number().int().min(60).max(900).default(600),
  // PCI DSS 4.0.1 8.2.8: re-authentication after ≤15 minutes of inactivity
  REFRESH_IDLE_TTL_SEC: z.coerce.number().int().min(300).max(7200).default(900),
  SESSION_ABSOLUTE_TTL_SEC: z.coerce.number().int().min(900).max(43200).default(28800),
  COOKIE_SECURE: bool.default('true'),

  // Cryptography at rest
  DATA_ENCRYPTION_KEYS: z.string().min(1),
  DATA_ENCRYPTION_ACTIVE_KEY: z.string().regex(/^[a-z0-9]{1,16}$/),
  BLIND_INDEX_KEY: z.string().min(32),
  AUDIT_HMAC_KEY: z.string().min(32),

  // Connector egress controls (SSRF defence)
  CONNECTOR_ALLOWED_HOSTS: z.string().default(''),
  CONNECTOR_DENIED_HOSTS: z.string().default('localhost,postgres,keycloak,api,gateway,metadata.google.internal'),
  CONNECTOR_BLOCKED_CIDRS: z.string().default(''),
  CONNECTOR_BLOCK_PRIVATE_NETWORKS: bool.default('false'),
  CONNECTOR_ALLOW_INSECURE_HTTP: bool.default('false'),
  CONNECTOR_MAX_RESPONSE_BYTES: z.coerce.number().int().min(1024).default(50 * 1024 * 1024),
  CONNECTOR_TIMEOUT_MS: z.coerce.number().int().min(1000).max(300_000).default(60_000),

  SCHEDULER_ENABLED: bool.default('true'),
  // Running deployment profile (non-secret; passed by compose) — used to detect drift
  // between the administrator's desired deployment parameters and what is running.
  DEPLOY_HTTPS_PORT: opt(z.coerce.number().int()),
  DEPLOY_HTTP_PORT: opt(z.coerce.number().int()),
  DEPLOY_CERT_SANS: opt(z.string()),
  DEPLOY_TRUSTED_PROXIES: opt(z.string()),
  DEPLOY_EDGE_RPS: opt(z.coerce.number().int()),
  DEPLOY_EDGE_AUTH_RPS: opt(z.coerce.number().int()),

  // Demo profile: enables the live demo-data simulator and dataset regeneration.
  DEMO_MODE: bool.default('false'),

  // Identity provider administration (Keycloak admin REST API) for enrolment and
  // MFA / password policy management. Optional: leave unset for external IdPs
  // (Entra ID, Okta, Ping) where enrolment is managed in the IdP itself.
  IDP_ADMIN_URL: opt(z.string().url()),
  IDP_REALM: z.string().regex(/^[A-Za-z0-9_-]{1,64}$/).default('ciso'),
  IDP_PROVISIONER_CLIENT_ID: z.string().regex(/^[A-Za-z0-9_.-]{1,64}$/).default('ciso-provisioner'),
  IDP_PROVISIONER_CLIENT_SECRET: opt(z.string().min(16)),
  // One-shot bootstrap (idp-init) only
  IDP_BOOTSTRAP_ADMIN_USERNAME: opt(z.string()),
  IDP_BOOTSTRAP_ADMIN_PASSWORD: opt(z.string()),
  DEMO_ADMIN_USERNAME: opt(z.string().regex(/^[a-z0-9._-]{3,64}$/)),
  DEMO_ADMIN_PASSWORD: opt(z.string().min(8).max(128)),

  RATE_LIMIT_PER_MIN: z.coerce.number().int().min(10).default(3000),
  RATE_LIMIT_PER_USER_MIN: z.coerce.number().int().min(10).default(600),
});

export type Env = z.infer<typeof EnvSchema>;

await loadSecrets();

const parsed = EnvSchema.safeParse(process.env);
if (!parsed.success) {
  // Print only the variable names, never the values.
  const problems = parsed.error.issues.map((i) => `${i.path.join('.')}: ${i.message}`).join('\n  ');
  console.error(`Invalid configuration:\n  ${problems}`);
  process.exit(1);
}

export const env: Env = Object.freeze(parsed.data);

if (env.NODE_ENV === 'production') {
  const insecure: string[] = [];
  if (!env.COOKIE_SECURE) insecure.push('COOKIE_SECURE=false');
  if (env.CONNECTOR_ALLOW_INSECURE_HTTP) insecure.push('CONNECTOR_ALLOW_INSECURE_HTTP=true');
  if (!env.PUBLIC_BASE_URL.startsWith('https://')) insecure.push('PUBLIC_BASE_URL must be https');
  if (insecure.length) {
    console.error(`Refusing to start in production with insecure settings: ${insecure.join(', ')}`);
    process.exit(1);
  }
}

if (env.NODE_ENV !== 'test') scrubSecretsFromEnv();
