/**
 * Configuration catalogue — every administrator-definable parameter of the platform.
 *
 * Each entry declares:
 *  - a strict zod schema (the only gate between the UI and the runtime),
 *  - its default (and an optional demo-profile default),
 *  - who may read / change it,
 *  - how a change takes effect (`apply`):
 *      live      → picked up by the running API within seconds
 *      identity  → pushed to the identity provider (Keycloak admin API)
 *      redeploy  → rendered into a deployment profile applied with scripts/apply-deployment.sh
 *      host      → rendered into a host OS script (Ubuntu / RHEL) run by an operator
 *  - field descriptors so the UI renders the form dynamically,
 *  - compliance warnings computed from the value.
 */
import { z } from 'zod';
import type { Prisma } from '@prisma/client';
import { env } from '../../config/env.js';
import { prisma } from '../../lib/prisma.js';
import { cidr, hostOrIp, hostPattern, ipAddress, publicBaseUrl, uniqueList } from '../../lib/net.js';
import type { Permission } from '../../auth/rbac.js';

export type ApplyMode = 'live' | 'identity' | 'redeploy' | 'host';

export const CATEGORIES = {
  risk: 'Risk & KPI',
  retention: 'Data retention',
  access: 'Network access',
  ratelimit: 'Rate limiting',
  session: 'Sessions',
  identity: 'Identity & enrolment',
  integrations: 'Integration defaults',
  logging: 'Logging',
  demo: 'Demo data',
  deployment: 'Deployment',
  host: 'Host operating system',
} as const;
export type Category = keyof typeof CATEGORIES;

export interface FieldDescriptor {
  /** Dotted path inside the value; '' for scalar settings. */
  path: string;
  label: string;
  type: 'number' | 'boolean' | 'string' | 'select' | 'list';
  min?: number;
  max?: number;
  unit?: string;
  options?: { value: string | number; label: string }[];
  help?: string;
  placeholder?: string;
}

interface SettingDef<S extends z.ZodTypeAny = z.ZodTypeAny> {
  label: string;
  description: string;
  category: Category;
  apply: ApplyMode;
  schema: S;
  default: z.input<S>;
  demoDefault?: z.input<S>;
  permission: Permission;
  readPermission: Permission;
  fields: FieldDescriptor[];
  warnings?: (value: z.infer<S>) => string[];
}

const def = <S extends z.ZodTypeAny>(d: SettingDef<S>) => d;

/* --------------------------------- Schemas --------------------------------- */

const sla = z
  .object({
    CRITICAL: z.number().int().min(1).max(365),
    HIGH: z.number().int().min(1).max(365),
    MEDIUM: z.number().int().min(1).max(730),
    LOW: z.number().int().min(1).max(1095),
  })
  .strict();

const rateLimits = z
  .object({
    perIpPerMin: z.number().int().min(100).max(100_000),
    authPerIpPerMin: z.number().int().min(10).max(5_000),
    perUserPerMin: z.number().int().min(30).max(20_000),
    heavyPerUserPerMin: z.number().int().min(5).max(1_000),
  })
  .strict()
  .refine((v) => v.authPerIpPerMin <= v.perIpPerMin, { message: 'Auth limit cannot exceed the per-IP limit', path: ['authPerIpPerMin'] })
  .refine((v) => v.heavyPerUserPerMin <= v.perUserPerMin, { message: 'Heavy-operation limit cannot exceed the per-user limit', path: ['heavyPerUserPerMin'] });

const access = z
  .object({
    allowedClientCidrs: uniqueList(cidr, 64),
    adminConsoleCidrs: uniqueList(cidr, 32),
  })
  .strict();

const sessionPolicy = z
  .object({
    accessTokenTtlSec: z.number().int().min(60).max(900),
    idleTimeoutSec: z.number().int().min(300).max(7200),
    absoluteTimeoutSec: z.number().int().min(900).max(43_200),
  })
  .strict()
  .refine((v) => v.accessTokenTtlSec <= v.idleTimeoutSec, { message: 'Access token lifetime must not exceed the idle timeout', path: ['accessTokenTtlSec'] })
  .refine((v) => v.idleTimeoutSec <= v.absoluteTimeoutSec, { message: 'Idle timeout must not exceed the absolute lifetime', path: ['idleTimeoutSec'] });

export const OTP_ALGORITHMS = ['HmacSHA1', 'HmacSHA256', 'HmacSHA512'] as const;
const identity = z
  .object({
    mfaRequired: z.boolean(),
    otpAlgorithm: z.enum(OTP_ALGORITHMS),
    otpDigits: z.union([z.literal(6), z.literal(8)]),
    otpPeriodSec: z.union([z.literal(30), z.literal(60)]),
    passwordMinLength: z.number().int().min(8).max(128),
    requireUppercase: z.boolean(),
    requireLowercase: z.boolean(),
    requireDigit: z.boolean(),
    requireSpecial: z.boolean(),
    passwordHistory: z.number().int().min(0).max(24),
    passwordExpiryDays: z.number().int().min(0).max(365),
    lockoutMaxFailures: z.number().int().min(3).max(30),
    lockoutWaitSec: z.number().int().min(30).max(3600),
    lockoutMaxWaitSec: z.number().int().min(60).max(86_400),
    permanentLockout: z.boolean(),
  })
  .strict()
  .refine((v) => v.lockoutMaxWaitSec >= v.lockoutWaitSec, { message: 'Maximum lockout must be ≥ the initial lockout', path: ['lockoutMaxWaitSec'] });

const connectorDefaults = z
  .object({
    allowedHosts: uniqueList(hostPattern, 100),
    deniedHosts: uniqueList(hostPattern, 100),
    blockPrivateNetworks: z.boolean(),
    requestTimeoutMs: z.number().int().min(1000).max(300_000),
    maxResponseMb: z.number().int().min(1).max(512),
    maxRetries: z.number().int().min(0).max(5),
    retryBackoffMs: z.number().int().min(100).max(30_000),
    defaultPollSec: z.number().int().min(60).max(86_400),
  })
  .strict();

const logging = z.object({ level: z.enum(['fatal', 'error', 'warn', 'info', 'debug']) }).strict();

const demoData = z
  .object({
    liveSimulation: z.boolean(),
    intervalSec: z.number().int().min(15).max(3600),
    incidentsPerHour: z.number().int().min(0).max(120),
    threatsPerHour: z.number().int().min(0).max(120),
    vulnerabilitiesPerHour: z.number().int().min(0).max(600),
    remediationsPerHour: z.number().int().min(0).max(600),
    datasetAssets: z.number().int().min(10).max(1000),
    datasetVulnerabilities: z.number().int().min(50).max(10_000),
    datasetIncidents: z.number().int().min(10).max(2000),
    historyDays: z.number().int().min(30).max(365),
  })
  .strict();

const deployment = z
  .object({
    publicBaseUrl,
    alternativeNames: uniqueList(hostOrIp, 20),
    httpsPort: z.number().int().min(1).max(65_535),
    httpPort: z.number().int().min(1).max(65_535),
    trustedUpstreamProxies: uniqueList(cidr, 16),
    edgeRatePerSec: z.number().int().min(1).max(10_000),
    edgeAuthRatePerSec: z.number().int().min(1).max(1_000),
    apiMemoryMb: z.number().int().min(256).max(65_536),
    keycloakMemoryMb: z.number().int().min(768).max(65_536),
    postgresMemoryMb: z.number().int().min(256).max(262_144),
  })
  .strict()
  .refine((v) => v.httpsPort !== v.httpPort, { message: 'HTTPS and HTTP ports must differ', path: ['httpPort'] });

const TZ_RE = /^(?:UTC|[A-Za-z]+(?:\/[A-Za-z0-9_+-]+){1,2})$/;
const hostOs = z
  .object({
    targetOs: z.enum(['ubuntu', 'rhel']),
    timezone: z.string().trim().max(64).regex(TZ_RE, 'must be an IANA time zone such as Europe/London'),
    ntpServers: uniqueList(hostOrIp, 8),
    dnsServers: uniqueList(ipAddress, 4),
    syslog: z
      .object({
        enabled: z.boolean(),
        host: z.union([z.literal(''), hostOrIp]),
        port: z.number().int().min(1).max(65_535),
        protocol: z.enum(['tcp', 'udp', 'tls']),
      })
      .strict(),
    firewall: z
      .object({
        enabled: z.boolean(),
        httpsAllowedCidrs: uniqueList(cidr, 64),
        sshAllowedCidrs: uniqueList(cidr, 32),
        sshPort: z.number().int().min(1).max(65_535),
      })
      .strict(),
    autoSecurityUpdates: z.boolean(),
    kernelHardening: z.boolean(),
    auditd: z.boolean(),
    dockerLogMaxSizeMb: z.number().int().min(1).max(1024),
    dockerLogMaxFiles: z.number().int().min(1).max(50),
  })
  .strict()
  .refine((v) => !v.syslog.enabled || v.syslog.host !== '', { message: 'Syslog host is required when forwarding is enabled', path: ['syslog', 'host'] });

/* --------------------------------- Catalogue --------------------------------- */

const num = (path: string, label: string, min: number, max: number, extra: Partial<FieldDescriptor> = {}): FieldDescriptor => ({ path, label, type: 'number', min, max, ...extra });
const bool = (path: string, label: string, help?: string): FieldDescriptor => ({ path, label, type: 'boolean', help });
const list = (path: string, label: string, placeholder: string, help?: string): FieldDescriptor => ({ path, label, type: 'list', placeholder, help });

export const SETTINGS = {
  riskAppetiteScore: def({
    label: 'Risk appetite (max tolerated inherent score, 1-25)',
    description: 'Risks scoring above this value are flagged as outside appetite on the 5×5 matrix and in the KRI.',
    category: 'risk',
    apply: 'live',
    schema: z.number().int().min(1).max(25),
    default: 12,
    permission: 'parameters:manage',
    readPermission: 'dashboard:read',
    fields: [num('', 'Risk appetite (max tolerated inherent score, 1-25)', 1, 25)],
  }),
  vulnSlaDays: def({
    label: 'Vulnerability remediation SLA (days by severity)',
    description: 'Due dates for new findings and the "past SLA" KPI are calculated from these values.',
    category: 'risk',
    apply: 'live',
    schema: sla,
    default: { CRITICAL: 15, HIGH: 30, MEDIUM: 90, LOW: 180 },
    permission: 'parameters:manage',
    readPermission: 'dashboard:read',
    fields: [
      num('CRITICAL', 'Critical', 1, 365, { unit: 'days' }),
      num('HIGH', 'High', 1, 365, { unit: 'days' }),
      num('MEDIUM', 'Medium', 1, 730, { unit: 'days' }),
      num('LOW', 'Low', 1, 1095, { unit: 'days' }),
    ],
    warnings: (v) => (v.CRITICAL > 30 ? ['PCI DSS v4.0.1 6.3.3 expects critical patches within one month of release.'] : []),
  }),
  riskAcceptanceMaxDays: def({
    label: 'Maximum risk acceptance validity (days)',
    description: 'Approved acceptances expire after this period and the risk re-opens automatically.',
    category: 'risk',
    apply: 'live',
    schema: z.number().int().min(1).max(365),
    default: 180,
    permission: 'parameters:manage',
    readPermission: 'dashboard:read',
    fields: [num('', 'Maximum risk acceptance validity (days)', 1, 365, { unit: 'days' })],
  }),
  kpiWindowDays: def({
    label: 'KPI rolling window (days) for MTTD / MTTR / velocity',
    description: 'Look-back period used when computing time-based KPIs.',
    category: 'risk',
    apply: 'live',
    schema: z.number().int().min(7).max(365),
    default: 30,
    permission: 'parameters:manage',
    readPermission: 'dashboard:read',
    fields: [num('', 'KPI rolling window (days) for MTTD / MTTR / velocity', 7, 365, { unit: 'days' })],
  }),
  threatRetentionDays: def({
    label: 'Threat intel retention (days) — data minimisation',
    description: 'Threat items older than this are purged by the hourly housekeeping job.',
    category: 'retention',
    apply: 'live',
    schema: z.number().int().min(30).max(3650),
    default: 365,
    permission: 'system:manage',
    readPermission: 'dashboard:read',
    fields: [num('', 'Threat intel retention (days) — data minimisation', 30, 3650, { unit: 'days' })],
  }),
  snapshotRetentionDays: def({
    label: 'KPI snapshot retention (days)',
    description: 'KPI history older than this is purged.',
    category: 'retention',
    apply: 'live',
    schema: z.number().int().min(30).max(3650),
    default: 400,
    permission: 'system:manage',
    readPermission: 'dashboard:read',
    fields: [num('', 'KPI snapshot retention (days)', 30, 3650, { unit: 'days' })],
  }),

  networkAccess: def({
    label: 'Client network access',
    description:
      'Restrict which source networks may use the dashboard and reach the Keycloak admin console. Use this when the platform is hosted on a server rather than the local machine. Empty client list = any network.',
    category: 'access',
    apply: 'live',
    schema: access,
    default: { allowedClientCidrs: [], adminConsoleCidrs: [] },
    permission: 'system:manage',
    readPermission: 'config:read',
    fields: [
      list('allowedClientCidrs', 'Allowed client networks', '10.20.0.0/16', 'IP addresses or CIDRs allowed to sign in and call the API. Your own address must be included.'),
      list('adminConsoleCidrs', 'Keycloak admin console networks', '10.20.5.10/32', 'In addition to the Docker host itself (always allowed).'),
    ],
    warnings: (v) => (v.allowedClientCidrs.some((c) => c.endsWith('/0')) ? ['A /0 network allows every address — equivalent to no restriction.'] : []),
  }),
  rateLimits: def({
    label: 'API rate limits',
    description:
      'Per-user quotas apply to signed-in traffic, so colleagues behind one office NAT address are not throttled together. Per-IP ceilings only protect against floods and sign-in abuse. Throttled calls receive HTTP 429 with a Retry-After header.',
    category: 'ratelimit',
    apply: 'live',
    schema: rateLimits,
    default: { perIpPerMin: 3000, authPerIpPerMin: 120, perUserPerMin: 600, heavyPerUserPerMin: 30 },
    permission: 'system:manage',
    readPermission: 'config:read',
    fields: [
      num('perUserPerMin', 'Per user — API requests', 30, 20_000, { unit: 'per min' }),
      num('heavyPerUserPerMin', 'Per user — heavy operations (sync, verify, export)', 5, 1000, { unit: 'per min' }),
      num('perIpPerMin', 'Per source IP — flood ceiling', 100, 100_000, { unit: 'per min' }),
      num('authPerIpPerMin', 'Per source IP — login / callback / refresh', 10, 5000, { unit: 'per min' }),
    ],
  }),
  sessionPolicy: def({
    label: 'Session & token lifetimes',
    description: 'Applied to new sign-ins and token refreshes; also pushed to the identity provider SSO session.',
    category: 'session',
    apply: 'identity',
    schema: sessionPolicy,
    default: { accessTokenTtlSec: env.ACCESS_TOKEN_TTL_SEC, idleTimeoutSec: env.REFRESH_IDLE_TTL_SEC, absoluteTimeoutSec: env.SESSION_ABSOLUTE_TTL_SEC },
    permission: 'system:manage',
    readPermission: 'config:read',
    fields: [
      num('accessTokenTtlSec', 'Access token lifetime', 60, 900, { unit: 'sec' }),
      num('idleTimeoutSec', 'Idle timeout', 300, 7200, { unit: 'sec' }),
      num('absoluteTimeoutSec', 'Absolute session lifetime', 900, 43_200, { unit: 'sec' }),
    ],
    warnings: (v) => (v.idleTimeoutSec > 900 ? ['PCI DSS v4.0.1 8.2.8 requires re-authentication after at most 15 minutes of inactivity.'] : []),
  }),
  identity: def({
    label: 'Identity, MFA & enrolment policy',
    description:
      'Pushed to Keycloak immediately. Controls authenticator-app enrolment (TOTP), password rules and brute-force lockout for every user, including those enrolled from the Users page.',
    category: 'identity',
    apply: 'identity',
    schema: identity,
    default: {
      mfaRequired: true,
      otpAlgorithm: 'HmacSHA1',
      otpDigits: 6,
      otpPeriodSec: 30,
      passwordMinLength: 12,
      requireUppercase: true,
      requireLowercase: true,
      requireDigit: true,
      requireSpecial: true,
      passwordHistory: 12,
      passwordExpiryDays: 0,
      lockoutMaxFailures: 5,
      lockoutWaitSec: 60,
      lockoutMaxWaitSec: 900,
      permanentLockout: false,
    },
    // Demo profile: allows the requested demo administrator password (10 characters).
    demoDefault: {
      mfaRequired: true,
      otpAlgorithm: 'HmacSHA1',
      otpDigits: 6,
      otpPeriodSec: 30,
      passwordMinLength: 10,
      requireUppercase: true,
      requireLowercase: true,
      requireDigit: true,
      requireSpecial: true,
      passwordHistory: 12,
      passwordExpiryDays: 0,
      lockoutMaxFailures: 5,
      lockoutWaitSec: 60,
      lockoutMaxWaitSec: 900,
      permanentLockout: false,
    },
    permission: 'system:manage',
    readPermission: 'config:read',
    fields: [
      bool('mfaRequired', 'Require authenticator-app MFA for every user', 'Users without an authenticator are asked to enrol at their next sign-in.'),
      {
        path: 'otpAlgorithm',
        label: 'TOTP algorithm',
        type: 'select',
        options: [
          { value: 'HmacSHA1', label: 'HmacSHA1 — Google / Microsoft Authenticator, Authy, FreeOTP (recommended)' },
          { value: 'HmacSHA256', label: 'HmacSHA256 — hardware tokens / FreeOTP only' },
          { value: 'HmacSHA512', label: 'HmacSHA512 — hardware tokens / FreeOTP only' },
        ],
      },
      { path: 'otpDigits', label: 'TOTP digits', type: 'select', options: [{ value: 6, label: '6 digits' }, { value: 8, label: '8 digits' }] },
      { path: 'otpPeriodSec', label: 'TOTP period', type: 'select', options: [{ value: 30, label: '30 seconds' }, { value: 60, label: '60 seconds' }] },
      num('passwordMinLength', 'Minimum password length', 8, 128, { unit: 'chars' }),
      bool('requireUppercase', 'Require an uppercase letter'),
      bool('requireLowercase', 'Require a lowercase letter'),
      bool('requireDigit', 'Require a digit'),
      bool('requireSpecial', 'Require a special character'),
      num('passwordHistory', 'Password history (cannot reuse last N)', 0, 24),
      num('passwordExpiryDays', 'Password expiry (0 = never, NIST SP 800-63B)', 0, 365, { unit: 'days' }),
      num('lockoutMaxFailures', 'Lock account after failed attempts', 3, 30),
      num('lockoutWaitSec', 'Initial lockout', 30, 3600, { unit: 'sec' }),
      num('lockoutMaxWaitSec', 'Maximum lockout', 60, 86_400, { unit: 'sec' }),
      bool('permanentLockout', 'Permanent lockout (requires administrator unlock)'),
    ],
    warnings: (v) => {
      const w: string[] = [];
      if (v.otpAlgorithm !== 'HmacSHA1') w.push('Google Authenticator and Microsoft Authenticator only support HmacSHA1 — users of those apps will be unable to enrol or sign in.');
      if (v.otpDigits !== 6 || v.otpPeriodSec !== 30) w.push('Many authenticator apps ignore non-default digits/period; keep 6 digits / 30 seconds unless all users have compatible apps.');
      if (!v.mfaRequired) w.push('PCI DSS v4.0.1 8.4.2 requires MFA for all access into the cardholder data environment.');
      if (v.passwordMinLength < 12) w.push('Below the PCI DSS v4.0.1 8.3.6 minimum of 12 characters (acceptable only for the demo profile).');
      if (v.lockoutMaxFailures > 10) w.push('PCI DSS v4.0.1 8.3.4 limits invalid attempts to 10 before lockout.');
      return w;
    },
  }),
  connectorDefaults: def({
    label: 'Integration egress & HTTP defaults',
    description:
      'Applies to every connector. Internal infrastructure zones and cloud-metadata addresses stay blocked regardless of these values.',
    category: 'integrations',
    apply: 'live',
    schema: connectorDefaults,
    default: {
      allowedHosts: [],
      deniedHosts: [],
      blockPrivateNetworks: env.CONNECTOR_BLOCK_PRIVATE_NETWORKS,
      requestTimeoutMs: env.CONNECTOR_TIMEOUT_MS,
      maxResponseMb: Math.round(env.CONNECTOR_MAX_RESPONSE_BYTES / 1_048_576),
      maxRetries: 2,
      retryBackoffMs: 1000,
      defaultPollSec: 900,
    },
    permission: 'system:manage',
    readPermission: 'config:read',
    fields: [
      list('allowedHosts', 'Allowed destination hosts', '*.splunkcloud.com', 'Empty = any public host. Supports *.domain wildcards.'),
      list('deniedHosts', 'Additional denied hosts', 'legacy.corp.example'),
      bool('blockPrivateNetworks', 'Block RFC 1918 / ULA destinations', 'Enable when every security tool is SaaS-hosted.'),
      num('requestTimeoutMs', 'Request timeout', 1000, 300_000, { unit: 'ms' }),
      num('maxResponseMb', 'Maximum response size', 1, 512, { unit: 'MB' }),
      num('maxRetries', 'Retries on 429 / 5xx / network errors', 0, 5),
      num('retryBackoffMs', 'Initial retry back-off (exponential, honours Retry-After)', 100, 30_000, { unit: 'ms' }),
      num('defaultPollSec', 'Default polling interval for new connectors', 60, 86_400, { unit: 'sec' }),
    ],
  }),
  logging: def({
    label: 'API log level',
    description: 'Changes verbosity immediately. Secrets and third-party payloads are always redacted.',
    category: 'logging',
    apply: 'live',
    schema: logging,
    default: { level: env.LOG_LEVEL === 'trace' ? 'debug' : env.LOG_LEVEL },
    permission: 'system:manage',
    readPermission: 'config:read',
    fields: [
      {
        path: 'level',
        label: 'Level',
        type: 'select',
        options: ['fatal', 'error', 'warn', 'info', 'debug'].map((l) => ({ value: l, label: l })),
      },
    ],
    warnings: (v) => (v.level === 'debug' ? ['Debug logging increases volume; disable after troubleshooting.'] : []),
  }),
  demoData: def({
    label: 'Demo data generator',
    description:
      'Demo mode only. The live simulator continuously creates and progresses incidents, findings and threat intel so every dashboard can be verified with moving data. Dataset sizes are used by "Regenerate demo dataset".',
    category: 'demo',
    apply: 'live',
    schema: demoData,
    default: {
      liveSimulation: env.DEMO_MODE,
      intervalSec: 60,
      incidentsPerHour: 6,
      threatsPerHour: 3,
      vulnerabilitiesPerHour: 12,
      remediationsPerHour: 10,
      datasetAssets: 90,
      datasetVulnerabilities: 480,
      datasetIncidents: 160,
      historyDays: 90,
    },
    permission: 'system:manage',
    readPermission: 'config:read',
    fields: [
      bool('liveSimulation', 'Live simulation'),
      num('intervalSec', 'Simulation tick', 15, 3600, { unit: 'sec' }),
      num('incidentsPerHour', 'New incidents', 0, 120, { unit: 'per hour' }),
      num('threatsPerHour', 'New threat-intel items', 0, 120, { unit: 'per hour' }),
      num('vulnerabilitiesPerHour', 'New vulnerability findings', 0, 600, { unit: 'per hour' }),
      num('remediationsPerHour', 'Remediated findings', 0, 600, { unit: 'per hour' }),
      num('datasetAssets', 'Dataset — assets', 10, 1000),
      num('datasetVulnerabilities', 'Dataset — vulnerability findings', 50, 10_000),
      num('datasetIncidents', 'Dataset — incidents', 10, 2000),
      num('historyDays', 'Dataset — KPI history', 30, 365, { unit: 'days' }),
    ],
  }),
  deployment: def({
    label: 'Deployment profile',
    description:
      'Public address and gateway parameters for hosting on a server instead of the local machine. Saved here, then applied on the Docker host with scripts/apply-deployment.sh (regenerates certificates when names change and redeploys).',
    category: 'deployment',
    apply: 'redeploy',
    schema: deployment,
    default: {
      publicBaseUrl: env.PUBLIC_BASE_URL,
      alternativeNames: [],
      httpsPort: 443,
      httpPort: 80,
      trustedUpstreamProxies: [],
      edgeRatePerSec: 50,
      edgeAuthRatePerSec: 20,
      apiMemoryMb: 1024,
      keycloakMemoryMb: 1536,
      postgresMemoryMb: 2048,
    },
    permission: 'system:manage',
    readPermission: 'config:read',
    fields: [
      { path: 'publicBaseUrl', label: 'Public URL (hostname or IP)', type: 'string', placeholder: 'https://10.20.5.15 or https://ciso.corp.example' },
      list('alternativeNames', 'Alternative names / IPs', '10.20.5.15', 'Added to the TLS certificate; requests using them are redirected to the public URL.'),
      num('httpsPort', 'Published HTTPS port', 1, 65_535),
      num('httpPort', 'Published HTTP port (redirect only)', 1, 65_535),
      list('trustedUpstreamProxies', 'Trusted load balancers / reverse proxies', '10.20.0.10/32', 'Only these may supply X-Forwarded-For; needed for correct client IPs behind a load balancer.'),
      num('edgeRatePerSec', 'Gateway flood limit per IP', 1, 10_000, { unit: 'req/s' }),
      num('edgeAuthRatePerSec', 'Gateway sign-in limit per IP', 1, 1000, { unit: 'req/s' }),
      num('apiMemoryMb', 'API memory limit', 256, 65_536, { unit: 'MB' }),
      num('keycloakMemoryMb', 'Keycloak memory limit', 768, 65_536, { unit: 'MB' }),
      num('postgresMemoryMb', 'PostgreSQL memory limit', 256, 262_144, { unit: 'MB' }),
    ],
    warnings: (v) => {
      const w: string[] = [];
      const port = new URL(v.publicBaseUrl).port;
      if (v.trustedUpstreamProxies.length === 0 && port && Number(port) !== v.httpsPort) w.push('Public URL port differs from the published HTTPS port — expected only behind a load balancer.');
      if (v.trustedUpstreamProxies.some((c) => c.endsWith('/0'))) w.push('Trusting every address as a proxy lets clients spoof their IP (rate limits and allowlists become ineffective).');
      return w;
    },
  }),
  hostOs: def({
    label: 'Host OS baseline',
    description:
      'Operating-system settings for the Docker host (Ubuntu or RHEL). The dashboard never changes the host itself: download the generated script, review it and run it with sudo (supports --dry-run).',
    category: 'host',
    apply: 'host',
    schema: hostOs,
    default: {
      targetOs: 'ubuntu',
      timezone: 'UTC',
      ntpServers: ['time.cloudflare.com', 'pool.ntp.org'],
      dnsServers: [],
      syslog: { enabled: false, host: '', port: 6514, protocol: 'tls' },
      firewall: { enabled: true, httpsAllowedCidrs: ['0.0.0.0/0'], sshAllowedCidrs: [], sshPort: 22 },
      autoSecurityUpdates: true,
      kernelHardening: true,
      auditd: true,
      dockerLogMaxSizeMb: 20,
      dockerLogMaxFiles: 5,
    },
    permission: 'system:manage',
    readPermission: 'config:read',
    fields: [
      { path: 'targetOs', label: 'Target OS', type: 'select', options: [{ value: 'ubuntu', label: 'Ubuntu 22.04 / 24.04 LTS' }, { value: 'rhel', label: 'RHEL / Rocky / Alma 8–9' }] },
      { path: 'timezone', label: 'Time zone', type: 'string', placeholder: 'UTC' },
      list('ntpServers', 'NTP servers', 'ntp.corp.example', 'Accurate time is required for TOTP and audit evidence (PCI DSS 10.6).'),
      list('dnsServers', 'DNS resolvers', '10.20.0.53'),
      bool('syslog.enabled', 'Forward system logs to SIEM'),
      { path: 'syslog.host', label: 'Syslog collector', type: 'string', placeholder: 'siem-collector.corp.example' },
      num('syslog.port', 'Syslog port', 1, 65_535),
      { path: 'syslog.protocol', label: 'Syslog transport', type: 'select', options: [{ value: 'tls', label: 'TCP + TLS (RFC 5425)' }, { value: 'tcp', label: 'TCP' }, { value: 'udp', label: 'UDP' }] },
      bool('firewall.enabled', 'Manage host firewall (ufw / firewalld)'),
      list('firewall.httpsAllowedCidrs', 'Networks allowed to reach HTTPS/HTTP', '10.0.0.0/8'),
      list('firewall.sshAllowedCidrs', 'Networks allowed to reach SSH', '10.20.5.0/24', 'Empty = SSH rules are left unchanged.'),
      num('firewall.sshPort', 'SSH port', 1, 65_535),
      bool('autoSecurityUpdates', 'Automatic security updates'),
      bool('kernelHardening', 'Kernel network hardening (sysctl)'),
      bool('auditd', 'auditd rules for Docker and secrets'),
      num('dockerLogMaxSizeMb', 'Docker log file size', 1, 1024, { unit: 'MB' }),
      num('dockerLogMaxFiles', 'Docker log files kept', 1, 50),
    ],
    warnings: (v) => {
      const w: string[] = [];
      if (v.syslog.enabled && v.syslog.protocol !== 'tls') w.push('Logs leave the host unencrypted; PCI DSS 4.0.1 4.2.1 expects strong cryptography in transit.');
      if (v.firewall.enabled && v.firewall.httpsAllowedCidrs.length === 0) w.push('No network may reach HTTPS — the dashboard will be unreachable.');
      if (v.ntpServers.length === 0) w.push('Without NTP, clock drift breaks TOTP codes and audit timestamps.');
      return w;
    },
  }),
} as const;

export type SettingKey = keyof typeof SETTINGS;
export type SettingValue<K extends SettingKey> = z.infer<(typeof SETTINGS)[K]['schema']>;
export const SETTING_KEYS = Object.keys(SETTINGS) as [SettingKey, ...SettingKey[]];

const anyDef = (key: SettingKey) => SETTINGS[key] as unknown as SettingDef;

export function defaultFor(key: SettingKey): unknown {
  const d = anyDef(key);
  return env.DEMO_MODE && d.demoDefault !== undefined ? d.demoDefault : d.default;
}

const cache = new Map<SettingKey, { value: unknown; until: number }>();
const CACHE_MS = 15_000;

export async function getSetting<K extends SettingKey>(key: K): Promise<SettingValue<K>> {
  const hit = cache.get(key);
  if (hit && hit.until > Date.now()) return hit.value as SettingValue<K>;
  const row = await prisma.systemSetting.findUnique({ where: { key } });
  const d = anyDef(key);
  const parsed = d.schema.safeParse(row?.value);
  const value = (parsed.success ? parsed.data : d.schema.parse(defaultFor(key))) as SettingValue<K>;
  cache.set(key, { value, until: Date.now() + CACHE_MS });
  return value;
}

/** Synchronous read of the last cached value (used on hot paths such as rate limiting). */
export function peekSetting<K extends SettingKey>(key: K): SettingValue<K> {
  const hit = cache.get(key);
  if (hit && hit.until > Date.now()) return hit.value as SettingValue<K>;
  void getSetting(key).catch(() => undefined); // refresh in the background
  return (hit?.value ?? anyDef(key).schema.parse(defaultFor(key))) as SettingValue<K>;
}

export function settingWarnings(key: SettingKey, value: unknown): string[] {
  const d = anyDef(key);
  return d.warnings ? d.warnings(value) : [];
}

export function describeSetting(key: SettingKey) {
  const d = anyDef(key);
  return {
    key,
    label: d.label,
    description: d.description,
    category: d.category,
    categoryLabel: CATEGORIES[d.category],
    apply: d.apply,
    permission: d.permission,
    readPermission: d.readPermission,
    fields: d.fields,
  };
}

export async function getAllSettings() {
  const out: Record<string, ReturnType<typeof describeSetting> & { value: unknown; warnings: string[] }> = {};
  for (const key of SETTING_KEYS) {
    const value = await getSetting(key);
    out[key] = { ...describeSetting(key), value, warnings: settingWarnings(key, value) };
  }
  return out;
}

export function invalidateSettingsCache(): void {
  cache.clear();
}

export async function ensureDefaultSettings(): Promise<void> {
  for (const key of SETTING_KEYS) {
    const value = anyDef(key).schema.parse(defaultFor(key));
    await prisma.systemSetting.upsert({
      where: { key },
      create: { key, value: value as Prisma.InputJsonValue },
      update: {},
    });
  }
}
