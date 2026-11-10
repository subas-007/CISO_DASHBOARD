/** System administration: users, sessions, parameter definitions, system health. */
import { Router } from 'express';
import { z } from 'zod';
import type { Prisma } from '@prisma/client';
import { env } from '../../config/env.js';
import { requirePermission } from '../../auth/middleware.js';
import { can } from '../../auth/rbac.js';
import { revokeUserSessions } from '../../auth/session.service.js';
import { auditContext, audit, writeAudit } from '../../audit/audit.service.js';
import { activeEncryptionKeyId } from '../../lib/crypto.js';
import { badRequest, forbidden, notFound } from '../../lib/errors.js';
import { publish } from '../../lib/events.js';
import { prisma, replicaCount } from '../../lib/prisma.js';
import { IdParam } from '../../lib/validation.js';
import { schedulerState } from '../../scheduler/scheduler.js';
import { SETTINGS, SETTING_KEYS, getAllSettings, getSetting, invalidateSettingsCache, settingWarnings } from '../settings/settings.service.js';
import { applySettingChange } from '../config/apply.js';
import { ipInCidrs } from '../../lib/net.js';
import { idpConfigured, idpSyncState } from '../../idp/identity.service.js';
import { simulatorState } from '../../demo/simulator.js';

export const adminRouter = Router();

adminRouter.get('/users', requirePermission('users:read'), async (_req, res) => {
  const now = new Date();
  const users = await prisma.user.findMany({
    orderBy: { displayName: 'asc' },
    select: {
      id: true,
      displayName: true,
      roles: true,
      active: true,
      lastLoginAt: true,
      createdAt: true,
      _count: { select: { sessions: { where: { revokedAt: null, absoluteExpiresAt: { gt: now } } } } },
    },
  });
  res.json({ items: users.map(({ _count, ...u }) => ({ ...u, activeSessions: _count.sessions })) });
});

adminRouter.patch('/users/:id', requirePermission('users:manage'), async (req, res) => {
  const { id } = IdParam.parse(req.params);
  const body = z.object({ active: z.boolean() }).strict().parse(req.body);
  if (id === req.auth!.userId && !body.active) throw badRequest('You cannot deactivate your own account');
  const user = await prisma.$transaction(async (tx) => {
    const before = await tx.user.findUnique({ where: { id } });
    if (!before) throw notFound('User not found');
    const u = await tx.user.update({ where: { id }, data: { active: body.active } });
    await writeAudit(tx, {
      ...auditContext(req),
      action: body.active ? 'user.activate' : 'user.deactivate',
      outcome: 'SUCCESS',
      targetType: 'user',
      targetId: id,
      details: { displayName: before.displayName },
    });
    return u;
  });
  if (!body.active) await revokeUserSessions(id, 'USER_DEACTIVATED');
  res.json({ id: user.id, active: user.active });
});

adminRouter.post('/users/:id/revoke-sessions', requirePermission('users:manage'), async (req, res) => {
  const { id } = IdParam.parse(req.params);
  const count = await revokeUserSessions(id, 'ADMIN_REVOKED');
  await audit({ ...auditContext(req), action: 'user.sessions.revoke', outcome: 'SUCCESS', targetType: 'user', targetId: id, details: { count } });
  res.json({ revoked: count });
});

/* ------------------------------ Parameters ------------------------------ */

adminRouter.get('/settings', requirePermission('dashboard:read'), async (req, res) => {
  const all = await getAllSettings();
  res.json({
    items: Object.values(all)
      .filter((s) => can(req.auth!.roles, s.readPermission))
      .map((s) => ({ ...s, editable: can(req.auth!.roles, s.permission) })),
  });
});

adminRouter.put('/settings/:key', async (req, res) => {
  const { key } = z.object({ key: z.enum(SETTING_KEYS) }).strict().parse(req.params);
  const def = SETTINGS[key];
  if (!can(req.auth!.roles, def.permission)) {
    await audit({ ...auditContext(req), action: 'setting.update', outcome: 'DENIED', targetType: 'setting', targetId: key }, { bestEffort: true });
    throw forbidden();
  }
  const { value } = z.object({ value: def.schema }).strict().parse(req.body);
  // Never let an administrator lock themselves (and everyone on their network) out.
  if (key === 'networkAccess') {
    const v = value as { allowedClientCidrs: string[] };
    if (v.allowedClientCidrs.length > 0 && !ipInCidrs(req.ip, v.allowedClientCidrs)) {
      throw badRequest(`Your current address (${req.ip}) is not in the allowed networks — saving would lock you out`, 'LOCKOUT_PREVENTED');
    }
  }
  await prisma.$transaction(async (tx) => {
    const before = await tx.systemSetting.findUnique({ where: { key } });
    await tx.systemSetting.upsert({
      where: { key },
      create: { key, value: value as Prisma.InputJsonValue, updatedById: req.auth!.userId },
      update: { value: value as Prisma.InputJsonValue, updatedById: req.auth!.userId },
    });
    await writeAudit(tx, {
      ...auditContext(req),
      action: 'setting.update',
      outcome: 'SUCCESS',
      targetType: 'setting',
      targetId: key,
      details: { before: before?.value ?? null, after: value },
    });
  });
  invalidateSettingsCache();
  const applied = await applySettingChange(key);
  publish({ type: 'kpi' });
  res.json({ key, value, warnings: settingWarnings(key, value), applied });
});

/* ------------------------------ System health ------------------------------ */

adminRouter.get('/system', requirePermission('system:manage'), async (_req, res) => {
  const [sp, identity] = await Promise.all([getSetting('sessionPolicy'), getSetting('identity')]);
  const t0 = Date.now();
  await prisma.$queryRaw`SELECT 1`;
  const dbLatencyMs = Date.now() - t0;
  const now = new Date();
  const [connectors, activeSessions, auditCount, lastAudit] = await Promise.all([
    prisma.connector.groupBy({ by: ['status'], _count: { _all: true } }),
    prisma.session.count({ where: { revokedAt: null, absoluteExpiresAt: { gt: now } } }),
    prisma.auditLog.count(),
    prisma.auditLog.findFirst({ orderBy: { id: 'desc' }, select: { ts: true } }),
  ]);
  res.json({
    version: env.APP_VERSION,
    nodeVersion: process.version,
    uptimeSec: Math.round(process.uptime()),
    memoryMb: Math.round(process.memoryUsage().rss / 1_048_576),
    database: { ok: true, latencyMs: dbLatencyMs, readReplicas: replicaCount },
    scheduler: { enabled: env.SCHEDULER_ENABLED, ...schedulerState },
    connectors: Object.fromEntries(connectors.map((c) => [c.status, c._count._all])),
    sessions: { active: activeSessions },
    audit: { records: auditCount, lastEventAt: lastAudit?.ts ?? null },
    security: {
      encryptionKeyId: activeEncryptionKeyId(),
      accessTokenTtlSec: sp.accessTokenTtlSec,
      refreshIdleTtlSec: sp.idleTimeoutSec,
      sessionAbsoluteTtlSec: sp.absoluteTimeoutSec,
      mtlsFromGateway: env.TLS_REQUIRE_CLIENT_CERT,
      connectorHttpsOnly: !env.CONNECTOR_ALLOW_INSECURE_HTTP,
      mfaRequired: identity.mfaRequired,
      otpAlgorithm: identity.otpAlgorithm,
      idpPolicySync: idpConfigured() ? (idpSyncState.ok ? 'in sync' : idpSyncState.message) : 'external IdP',
    },
    demo: { demoMode: env.DEMO_MODE, simulatorTicks: simulatorState.ticks, lastTickAt: simulatorState.lastTickAt },
  });
});

adminRouter.get('/sessions', requirePermission('system:manage'), async (_req, res) => {
  const sessions = await prisma.session.findMany({
    where: { revokedAt: null, absoluteExpiresAt: { gt: new Date() } },
    orderBy: { createdAt: 'desc' },
    take: 200,
    select: { id: true, createdAt: true, expiresAt: true, absoluteExpiresAt: true, ip: true, userAgent: true, user: { select: { id: true, displayName: true, roles: true } } },
  });
  res.json({ items: sessions });
});
