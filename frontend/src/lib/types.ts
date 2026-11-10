export type Role = 'ADMIN' | 'CISO' | 'SECOPS' | 'PATCH_ADMIN' | 'AUDITOR';
export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
export type Rag = 'GREEN' | 'AMBER' | 'RED';
export type RiskLevel = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
export type AuthMode = 'NONE' | 'API_KEY' | 'BASIC' | 'OAUTH2' | 'MTLS';
export type ConnectorCategory = 'SIEM' | 'VULNERABILITY' | 'PATCH' | 'CHANGE' | 'THREAT_INTEL';

export interface Me {
  user: { id: string; name: string; roles: Role[]; permissions: string[]; lastLoginAt: string | null };
  session: { expiresAt: string };
}

export interface KpiValues {
  mttdHours: number | null;
  mttrHours: number | null;
  patchCompliancePct: number | null;
  remediationVelocityPerWeek: number;
  meanDaysToRemediate: number | null;
  openCriticalFindings: number;
  openHighFindings: number;
  overdueCriticalFindings: number;
  overdueFindings: number;
  activeIncidents: number;
  totalAssets: number;
  risksAboveAppetite: number;
  failedConnectors: number;
  pendingAcceptances: number;
}

export interface KriStatus {
  key: string;
  name: string;
  description: string;
  metric: string;
  unit: string;
  direction: 'HIGHER_IS_WORSE' | 'LOWER_IS_WORSE';
  amberThreshold: number;
  redThreshold: number;
  enabled: boolean;
  value: number | null;
  status: Rag | null;
  updatedAt: string;
}

export interface KpiSummary {
  generatedAt: string;
  windowDays: number;
  riskAppetiteScore: number;
  kpis: KpiValues;
  deltas: Record<string, number | null>;
  kris: KriStatus[];
  connectorHealth: Record<string, number>;
}

export interface TrendResponse {
  metrics: string[];
  days: number;
  points: ({ date: string } & Record<string, number | string>)[];
}

export interface RiskSummary {
  id: string;
  title: string;
  category: string;
  likelihood: number;
  impact: number;
  status: string;
  ownerName: string;
}

export interface MatrixCell {
  likelihood: number;
  impact: number;
  score: number;
  level: RiskLevel;
  aboveAppetite: boolean;
  count: number;
  risks: RiskSummary[];
}

export interface Vulnerability {
  id: string;
  cveId: string | null;
  title: string;
  severity: Severity;
  cvss: number | null;
  status: string;
  source: string;
  discoveredAt: string;
  dueAt: string | null;
  remediatedAt: string | null;
  remediationNote?: string | null;
  asset?: { id: string; hostname: string; businessUnit: string; criticality: number };
  changeTicket?: { id: string; system: string; externalKey: string; status: string; url: string | null } | null;
}

export interface Asset {
  id: string;
  hostname: string;
  ipAddress: string | null;
  os: string | null;
  businessUnit: string;
  criticality: number;
  patchCompliant: boolean;
  missingPatches: number;
  vulnerabilities?: Vulnerability[];
}

export interface Acceptance {
  id: string;
  riskId: string;
  justification: string | null;
  requestedById: string;
  requestedByName: string;
  requestedAt: string;
  status: 'PENDING' | 'APPROVED' | 'REJECTED' | 'EXPIRED' | 'REVOKED';
  decidedByName: string | null;
  decidedAt: string | null;
  decisionNote: string | null;
  expiresAt: string;
  risk?: { id: string; title: string; likelihood: number; impact: number; category: string };
}

export interface RiskDetail extends RiskSummary {
  description: string;
  treatment: string | null;
  score: number;
  level: RiskLevel;
  assets: Asset[];
  acceptances: Acceptance[];
}

export interface ThreatItem {
  id: string;
  source: string;
  sourceRef: string;
  type: 'CVE' | 'RANSOMWARE' | 'SUPPLY_CHAIN' | 'ADVISORY' | 'IOC';
  title: string;
  summary: string;
  severity: Severity;
  cveId: string | null;
  publishedAt: string;
  impactedAssetCount: number;
  tags: string[];
  status: 'NEW' | 'TRIAGED' | 'ACTIONED' | 'DISMISSED';
  triageNote: string | null;
}

export interface Incident {
  id: string;
  source: string;
  title: string;
  description: string | null;
  severity: Severity;
  status: 'NEW' | 'TRIAGE' | 'CONTAINED' | 'RESOLVED' | 'CLOSED';
  category: string;
  occurredAt: string;
  detectedAt: string;
  respondedAt: string | null;
  resolvedAt: string | null;
  assetsAffected: number;
}

export interface FieldSpec {
  key: string;
  label: string;
  type: 'string' | 'number' | 'boolean' | 'textarea' | 'select';
  required?: boolean;
  placeholder?: string;
  help?: string;
  options?: { value: string | number; label: string }[];
}

export interface RequestOptions {
  pathPrefix?: string;
  headers?: Record<string, string>;
  query?: Record<string, string>;
  timeoutMs?: number;
  maxRetries?: number;
}

export interface CatalogItem {
  vendor: string;
  displayName: string;
  category: ConnectorCategory;
  description: string;
  supportedAuth: AuthMode[];
  defaultPollSec: number;
  defaultBaseUrl: string | null;
  settingsFields: FieldSpec[];
}

export interface Connector {
  id: string;
  name: string;
  vendor: string;
  category: ConnectorCategory;
  baseUrl: string;
  authMode: AuthMode;
  pollIntervalSec: number;
  enabled: boolean;
  settings: Record<string, string | number | boolean>;
  requestOptions?: RequestOptions;
  status: 'UNTESTED' | 'HEALTHY' | 'FAILED' | 'DISABLED';
  lastTestAt: string | null;
  lastSyncAt: string | null;
  lastSuccessAt: string | null;
  lastError: string | null;
  lastRecordCount: number | null;
  hasCredentials: boolean;
  credentialFields: string[];
  updatedAt: string;
}

export interface AuditEntry {
  id: string;
  ts: string;
  actorId: string | null;
  actorName: string | null;
  actorRoles: string[];
  action: string;
  targetType: string | null;
  targetId: string | null;
  outcome: 'SUCCESS' | 'FAILURE' | 'DENIED';
  ip: string | null;
  userAgent: string | null;
  details: unknown;
  prevHash: string;
  hash: string;
}

export interface ChainVerification {
  valid: boolean;
  checked: number;
  firstInvalidId: string | null;
  reason: string | null;
  verifiedAt: string;
}

export type ApplyMode = 'live' | 'identity' | 'redeploy' | 'host';

export interface SettingField {
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

export interface SettingItem {
  key: string;
  label: string;
  description: string;
  category: string;
  categoryLabel: string;
  apply: ApplyMode;
  value: unknown;
  warnings: string[];
  fields: SettingField[];
  permission: string;
  readPermission: string;
  editable: boolean;
}

export interface SettingSaveResult {
  key: string;
  value: unknown;
  warnings: string[];
  applied: { mode: ApplyMode; ok: boolean; message: string };
}

export interface IdentityUser {
  id: string;
  username: string;
  email: string | null;
  firstName: string | null;
  lastName: string | null;
  enabled: boolean;
  createdAt: string | null;
  roles: Role[];
  mfaConfigured: boolean;
  requiredActions: string[];
  lastLoginAt: string | null;
}
