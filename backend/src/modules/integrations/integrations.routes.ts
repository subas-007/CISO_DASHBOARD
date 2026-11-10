/**
 * Parameterised connector configuration. Credentials are write-only: they are encrypted
 * (AES-256-GCM, AAD-bound to the connector id) on receipt and never returned.
 */
import { randomUUID } from 'node:crypto';
import { Router } from 'express';
import { z } from 'zod';
import type { AuthMode, Connector, Prisma } from '@prisma/client';
import { env } from '../../config/env.js';
import { requirePermission } from '../../auth/middleware.js';
import { audit, auditContext, writeAudit } from '../../audit/audit.service.js';
import { decryptJson, encryptJson } from '../../lib/crypto.js';
import { badRequest, notFound } from '../../lib/errors.js';
import { publish } from '../../lib/events.js';
import { prisma } from '../../lib/prisma.js';
import { IdParam, singleLine } from '../../lib/validation.js';
import { heavyRateLimit } from '../../security/rateLimit.js';
import { assertUrlAllowed, EgressPolicyError } from '../../connectors/egress.js';
import { getAdapter, listAdapters, VENDORS } from '../../connectors/registry.js';
import { credentialAad, syncConnector, testConnector } from '../../connectors/runner.js';
import type { Credentials } from '../../connectors/types.js';

export const integrationsRouter = Router();

const AUTH_MODES = ['NONE', 'API_KEY', 'BASIC', 'OAUTH2', 'MTLS'] as const;
const noCrLf = (max: number) => z.string().max(max).regex(/^[^\r\n]*$/, 'must be a single line');
const pem = z.string().max(20_000).regex(/-----BEGIN [A-Z0-9 ]+-----[\s\S]+-----END [A-Z0-9 ]+-----/, 'must be PEM encoded');

const CredentialsSchema = z
  .object({
    apiKey: noCrLf(4096).min(1).optional(),
    apiSecret: noCrLf(4096).min(1).optional(),
    apiKeyHeader: z.string().regex(/^[A-Za-z0-9-]{1,64}$/).optional(),
    apiKeyPrefix: noCrLf(32).optional(),
    username: noCrLf(256).min(1).optional(),
    password: noCrLf(1024).min(1).optional(),
    tokenUrl: z.string().url().max(500).optional(),
    clientId: noCrLf(256).min(1).optional(),
    clientSecret: noCrLf(2048).min(1).optional(),
    scope: noCrLf(500).optional(),
    clientCert: pem.optional(),
    clientKey: pem.optional(),
    caCert: pem.optional(),
    passphrase: noCrLf(1024).optional(),
  })
  .strict();

const REQUIRED_BY_MODE: Record<AuthMode, (keyof Credentials)[]> = {
  NONE: [],
  API_KEY: ['apiKey'],
  BASIC: ['username', 'password'],
  OAUTH2: ['tokenUrl', 'clientId', 'clientSecret'],
  MTLS: ['clientCert', 'clientKey'],
};

function assertCredentialsFor(mode: AuthMode, creds: Credentials): void {
  const missing = REQUIRED_BY_MODE[mode].filter((k) => !creds[k]);
  if (missing.length) throw badRequest(`Missing credential fields for ${mode}: ${missing.join(', ')}`);
  if (creds.tokenUrl) assertUrlSafe(creds.tokenUrl);
}

function assertUrlSafe(raw: string): URL {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw badRequest('Invalid URL');
  }
  if (url.hash || url.search) throw badRequest('Base URL must not include a query string or fragment');
  try {
    assertUrlAllowed(url);
  } catch (err) {
    if (err instanceof EgressPolicyError) throw badRequest(err.message, 'EGRESS_POLICY');
    throw err;
  }
  return url;
}

/** Public projection — never includes secret material. */
function present(c: Connector) {
  let credentialFields: string[] = [];
  if (c.secretEnc) {
    try {
      credentialFields = Object.keys(decryptJson<Credentials>(c.secretEnc, credentialAad(c.id)));
    } catch {
      credentialFields = ['<unreadable — re-enter credentials>'];
    }
  }
  const { secretEnc: _s, leaseUntil: _l, ...rest } = c;
  return { ...rest, hasCredentials: !!c.secretEnc, credentialFields };
}

integrationsRouter.get('/catalog', requirePermission('integration:read'), (_req, res) => {
  res.json({
    items: listAdapters().map((a) => ({
      vendor: a.vendor,
      displayName: a.displayName,
      category: a.category,
      description: a.description,
      supportedAuth: a.supportedAuth,
      defaultPollSec: a.defaultPollSec,
      defaultBaseUrl: a.defaultBaseUrl ?? null,
      settingsFields: a.settingsFields,
    })),
    egressPolicy: {
      httpsOnly: !env.CONNECTOR_ALLOW_INSECURE_HTTP,
      allowlist: env.CONNECTOR_ALLOWED_HOSTS ? env.CONNECTOR_ALLOWED_HOSTS.split(',').map((s) => s.trim()) : [],
      privateNetworksBlocked: env.CONNECTOR_BLOCK_PRIVATE_NETWORKS,
    },
  });
});

integrationsRouter.get('/', requirePermission('integration:read'), async (_req, res) => {
  const items = await prisma.connector.findMany({ orderBy: [{ category: 'asc' }, { name: 'asc' }] });
  res.json({ items: items.map(present) });
});

const settingsJson = z.record(z.union([z.string().max(2000), z.number(), z.boolean()])).default({});

const ConnectorCreate = z
  .object({
    name: singleLine(80, 3).refine((v) => /^[A-Za-z0-9 _().-]+$/.test(v), 'only letters, digits, spaces and _ ( ) . -'),
    vendor: z.enum(VENDORS),
    baseUrl: z.string().url().max(500),
    authMode: z.enum(AUTH_MODES),
    pollIntervalSec: z.number().int().min(60).max(86_400),
    enabled: z.boolean().default(false),
    settings: settingsJson,
    credentials: CredentialsSchema.default({}),
  })
  .strict();

integrationsRouter.post('/', requirePermission('integration:manage'), async (req, res) => {
  const body = ConnectorCreate.parse(req.body);
  const adapter = getAdapter(body.vendor)!;
  if (!adapter.supportedAuth.includes(body.authMode)) throw badRequest(`${adapter.displayName} does not support ${body.authMode}`);
  const url = assertUrlSafe(body.baseUrl);
  const settings = adapter.settingsSchema.parse(body.settings) as Prisma.InputJsonValue;
  assertCredentialsFor(body.authMode, body.credentials);

  const id = randomUUID();
  const created = await prisma.$transaction(async (tx) => {
    const c = await tx.connector.create({
      data: {
        id,
        name: body.name,
        vendor: body.vendor,
        category: adapter.category,
        baseUrl: url.toString().replace(/\/+$/, ''),
        authMode: body.authMode,
        pollIntervalSec: body.pollIntervalSec,
        enabled: body.enabled,
        status: body.enabled ? 'UNTESTED' : 'DISABLED',
        settings,
        secretEnc: Object.keys(body.credentials).length ? encryptJson(body.credentials, credentialAad(id)) : null,
        createdById: req.auth!.userId,
        updatedById: req.auth!.userId,
      },
    });
    await writeAudit(tx, {
      ...auditContext(req),
      action: 'integration.create',
      outcome: 'SUCCESS',
      targetType: 'connector',
      targetId: id,
      details: { name: c.name, vendor: c.vendor, baseUrl: c.baseUrl, authMode: c.authMode, credentialFields: Object.keys(body.credentials) },
    });
    return c;
  });
  publish({ type: 'connectors' });
  res.status(201).json(present(created));
});

const ConnectorUpdate = z
  .object({
    baseUrl: z.string().url().max(500).optional(),
    authMode: z.enum(AUTH_MODES).optional(),
    pollIntervalSec: z.number().int().min(60).max(86_400).optional(),
    enabled: z.boolean().optional(),
    settings: settingsJson.optional(),
  })
  .strict();

integrationsRouter.patch('/:id', requirePermission('integration:manage'), async (req, res) => {
  const { id } = IdParam.parse(req.params);
  const body = ConnectorUpdate.parse(req.body);
  const before = await prisma.connector.findUnique({ where: { id } });
  if (!before) throw notFound('Connector not found');
  const adapter = getAdapter(before.vendor)!;
  const data: Prisma.ConnectorUpdateInput = { updatedById: req.auth!.userId };
  if (body.baseUrl) data.baseUrl = assertUrlSafe(body.baseUrl).toString().replace(/\/+$/, '');
  if (body.authMode) {
    if (!adapter.supportedAuth.includes(body.authMode)) throw badRequest(`${adapter.displayName} does not support ${body.authMode}`);
    data.authMode = body.authMode;
  }
  if (body.pollIntervalSec) data.pollIntervalSec = body.pollIntervalSec;
  if (body.settings) data.settings = adapter.settingsSchema.parse(body.settings) as Prisma.InputJsonValue;
  if (body.enabled !== undefined) {
    data.enabled = body.enabled;
    data.status = body.enabled ? 'UNTESTED' : 'DISABLED';
  }
  // Changing the endpoint or auth mode invalidates the health state.
  if (body.baseUrl || body.authMode) data.status = 'UNTESTED';

  const updated = await prisma.$transaction(async (tx) => {
    const c = await tx.connector.update({ where: { id }, data });
    await writeAudit(tx, {
      ...auditContext(req),
      action: 'integration.update',
      outcome: 'SUCCESS',
      targetType: 'connector',
      targetId: id,
      details: {
        changed: Object.keys(body),
        before: { baseUrl: before.baseUrl, authMode: before.authMode, pollIntervalSec: before.pollIntervalSec, enabled: before.enabled, settings: before.settings },
        after: { baseUrl: c.baseUrl, authMode: c.authMode, pollIntervalSec: c.pollIntervalSec, enabled: c.enabled, settings: c.settings },
      },
    });
    return c;
  });
  publish({ type: 'connectors' });
  res.json(present(updated));
});

integrationsRouter.put('/:id/credentials', requirePermission('integration:manage'), async (req, res) => {
  const { id } = IdParam.parse(req.params);
  const body = z.object({ credentials: CredentialsSchema }).strict().parse(req.body);
  const c = await prisma.connector.findUnique({ where: { id } });
  if (!c) throw notFound('Connector not found');
  assertCredentialsFor(c.authMode, body.credentials);
  await prisma.$transaction(async (tx) => {
    await tx.connector.update({
      where: { id },
      data: { secretEnc: encryptJson(body.credentials, credentialAad(id)), status: c.enabled ? 'UNTESTED' : 'DISABLED', updatedById: req.auth!.userId },
    });
    await writeAudit(tx, {
      ...auditContext(req),
      action: 'integration.credentials.rotate',
      outcome: 'SUCCESS',
      targetType: 'connector',
      targetId: id,
      details: { name: c.name, credentialFields: Object.keys(body.credentials) },
    });
  });
  publish({ type: 'connectors' });
  res.status(204).end();
});

integrationsRouter.delete('/:id', requirePermission('integration:manage'), async (req, res) => {
  const { id } = IdParam.parse(req.params);
  await prisma.$transaction(async (tx) => {
    const c = await tx.connector.findUnique({ where: { id } });
    if (!c) throw notFound('Connector not found');
    await tx.connector.delete({ where: { id } }); // credentials are destroyed with the row
    await writeAudit(tx, {
      ...auditContext(req),
      action: 'integration.delete',
      outcome: 'SUCCESS',
      targetType: 'connector',
      targetId: id,
      details: { name: c.name, vendor: c.vendor },
    });
  });
  publish({ type: 'connectors' });
  res.status(204).end();
});

integrationsRouter.post('/:id/test', heavyRateLimit, requirePermission('integration:manage'), async (req, res) => {
  const { id } = IdParam.parse(req.params);
  const c = await prisma.connector.findUnique({ where: { id } });
  if (!c) throw notFound('Connector not found');
  const result = await testConnector(c);
  await audit({
    ...auditContext(req),
    action: 'integration.test',
    outcome: result.ok ? 'SUCCESS' : 'FAILURE',
    targetType: 'connector',
    targetId: id,
    details: { name: c.name, message: result.message },
  });
  res.json(result);
});

integrationsRouter.post('/:id/sync', heavyRateLimit, requirePermission('integration:manage'), async (req, res) => {
  const { id } = IdParam.parse(req.params);
  const c = await prisma.connector.findUnique({ where: { id } });
  if (!c) throw notFound('Connector not found');
  const result = await syncConnector(c);
  await audit({
    ...auditContext(req),
    action: 'integration.sync.manual',
    outcome: result.ok ? 'SUCCESS' : 'FAILURE',
    targetType: 'connector',
    targetId: id,
    details: { name: c.name, message: result.message, counts: result.counts ?? null },
  });
  res.json(result);
});
