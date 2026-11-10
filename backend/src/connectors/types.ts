import type { AuthMode, ConnectorCategory, IncidentStatus, Severity, ThreatType } from '@prisma/client';
import type { z } from 'zod';
import type { ConnectorHttpClient } from './httpClient.js';

/** Credential material. Stored only as AES-256-GCM ciphertext; never returned by the API. */
export interface Credentials {
  apiKey?: string;
  apiSecret?: string;
  apiKeyHeader?: string;
  apiKeyPrefix?: string;
  username?: string;
  password?: string;
  tokenUrl?: string;
  clientId?: string;
  clientSecret?: string;
  scope?: string;
  clientCert?: string;
  clientKey?: string;
  caCert?: string;
  passphrase?: string;
}

/* ---------- Normalised records: the ONLY shape third-party data is persisted in ---------- */

export interface NormIncident {
  externalId: string;
  title: string;
  severity: Severity;
  occurredAt: Date;
  detectedAt: Date;
  respondedAt?: Date | null;
  resolvedAt?: Date | null;
  status?: IncidentStatus;
  category?: string;
  assetsAffected?: number;
}

export interface NormVuln {
  externalId: string;
  hostname: string;
  ipAddress?: string | null;
  cveId?: string | null;
  title: string;
  severity: Severity;
  cvss?: number | null;
  discoveredAt: Date;
  fixed?: boolean;
  remediatedAt?: Date | null;
}

export interface NormPatchStatus {
  hostname: string;
  ipAddress?: string | null;
  os?: string | null;
  compliant: boolean;
  missingPatches: number;
  lastPatchedAt?: Date | null;
}

export interface NormChange {
  externalKey: string;
  title: string;
  status: string;
  url?: string | null;
  updatedAt?: Date | null;
}

export interface NormThreat {
  sourceRef: string;
  type: ThreatType;
  title: string;
  summary: string;
  severity: Severity;
  cveId?: string | null;
  publishedAt: Date;
  tags: string[];
  impactedAssetCount?: number;
}

export interface NormalizedBatch {
  incidents?: NormIncident[];
  vulnerabilities?: NormVuln[];
  patches?: NormPatchStatus[];
  changes?: NormChange[];
  threats?: NormThreat[];
}

export interface FieldSpec {
  key: string;
  label: string;
  type: 'string' | 'number' | 'boolean' | 'textarea';
  required?: boolean;
  placeholder?: string;
  help?: string;
}

export interface AdapterContext {
  connectorId: string;
  baseUrl: URL;
  http: ConnectorHttpClient;
  /** Lower bound for incremental fetches. */
  since: Date;
}

export interface ConnectorAdapter {
  vendor: string;
  displayName: string;
  category: ConnectorCategory;
  description: string;
  supportedAuth: AuthMode[];
  defaultPollSec: number;
  defaultBaseUrl?: string;
  settingsFields: FieldSpec[];
  settingsSchema: z.ZodTypeAny;
  /** Optional vendor-specific header scheme for API_KEY auth (e.g. Tenable X-ApiKeys). */
  apiKeyHeaders?: (c: Credentials) => Record<string, string>;
  test(ctx: AdapterContext, settings: unknown): Promise<string>;
  sync(ctx: AdapterContext, settings: unknown): Promise<NormalizedBatch>;
}

/** Helper preserving per-adapter settings typing while exposing a uniform interface. */
export function defineAdapter<S extends z.ZodTypeAny>(
  def: Omit<ConnectorAdapter, 'settingsSchema' | 'test' | 'sync'> & {
    settingsSchema: S;
    test(ctx: AdapterContext, settings: z.infer<S>): Promise<string>;
    sync(ctx: AdapterContext, settings: z.infer<S>): Promise<NormalizedBatch>;
  },
): ConnectorAdapter {
  return {
    ...def,
    test: (ctx, s) => def.test(ctx, def.settingsSchema.parse(s)),
    sync: (ctx, s) => def.sync(ctx, def.settingsSchema.parse(s)),
  };
}
