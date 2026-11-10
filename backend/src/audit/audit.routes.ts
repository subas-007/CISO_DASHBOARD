import { Router } from 'express';
import { z } from 'zod';
import type { Prisma } from '@prisma/client';
import { requirePermission } from '../auth/middleware.js';
import { heavyRateLimit } from '../security/rateLimit.js';
import { prisma } from '../lib/prisma.js';
import { isoDate, singleLine } from '../lib/validation.js';
import { audit, auditContext, verifyAuditChain } from './audit.service.js';

export const auditRouter = Router();

const AuditQuery = z
  .object({
    action: z.string().regex(/^[a-z0-9_.]{1,80}$/).optional(),
    actor: singleLine(120).optional(),
    outcome: z.enum(['SUCCESS', 'FAILURE', 'DENIED']).optional(),
    from: isoDate.optional(),
    to: isoDate.optional(),
    beforeId: z.string().regex(/^\d{1,19}$/).optional(),
    limit: z.coerce.number().int().min(1).max(500).default(100),
  })
  .strict();

function buildWhere(q: z.infer<typeof AuditQuery>): Prisma.AuditLogWhereInput {
  return {
    ...(q.action ? { action: { startsWith: q.action } } : {}),
    ...(q.actor ? { actorName: { contains: q.actor, mode: 'insensitive' } } : {}),
    ...(q.outcome ? { outcome: q.outcome } : {}),
    ...(q.from || q.to ? { ts: { ...(q.from ? { gte: q.from } : {}), ...(q.to ? { lte: q.to } : {}) } } : {}),
  };
}

const serialize = (r: { id: bigint } & Record<string, unknown>) => ({ ...r, id: r.id.toString() });

auditRouter.get('/', requirePermission('audit:read'), async (req, res) => {
  const q = AuditQuery.parse(req.query);
  const where = { ...buildWhere(q), ...(q.beforeId ? { id: { lt: BigInt(q.beforeId) } } : {}) };
  const rows = await prisma.auditLog.findMany({ where, orderBy: { id: 'desc' }, take: q.limit });
  res.json({
    items: rows.map(serialize),
    nextBeforeId: rows.length === q.limit ? rows[rows.length - 1]!.id.toString() : null,
  });
});

auditRouter.get('/actions', requirePermission('audit:read'), async (_req, res) => {
  const rows = await prisma.auditLog.groupBy({ by: ['action'], _count: { _all: true }, orderBy: { action: 'asc' } });
  res.json({ items: rows.map((r) => ({ action: r.action, count: r._count._all })) });
});

auditRouter.get('/verify', heavyRateLimit, requirePermission('audit:read'), async (req, res) => {
  const result = await verifyAuditChain();
  await audit({
    ...auditContext(req),
    action: 'audit.verify',
    outcome: result.valid ? 'SUCCESS' : 'FAILURE',
    targetType: 'audit_log',
    details: { checked: result.checked, firstInvalidId: result.firstInvalidId },
  });
  res.json({ ...result, verifiedAt: new Date().toISOString() });
});

/** Neutralise spreadsheet formula injection (CSV injection) and quote safely. */
export function csvCell(value: unknown): string {
  let s = value == null ? '' : typeof value === 'object' ? JSON.stringify(value) : String(value);
  if (/^[=+\-@\t\r]/.test(s)) s = `'${s}`;
  return `"${s.replace(/"/g, '""')}"`;
}

auditRouter.get('/export', heavyRateLimit, requirePermission('audit:read'), async (req, res) => {
  const q = AuditQuery.omit({ beforeId: true, limit: true }).parse(req.query);
  const rows = await prisma.auditLog.findMany({ where: buildWhere({ ...q, limit: 0 }), orderBy: { id: 'asc' }, take: 50_000 });
  await audit({
    ...auditContext(req),
    action: 'audit.export',
    outcome: 'SUCCESS',
    targetType: 'audit_log',
    details: { rows: rows.length, filters: q },
  });
  const header = ['id', 'ts', 'actorId', 'actorName', 'actorRoles', 'action', 'targetType', 'targetId', 'outcome', 'ip', 'userAgent', 'details', 'prevHash', 'hash'];
  const lines = [header.join(',')];
  for (const r of rows) {
    lines.push(
      [r.id.toString(), r.ts.toISOString(), r.actorId, r.actorName, r.actorRoles.join('|'), r.action, r.targetType, r.targetId, r.outcome, r.ip, r.userAgent, r.details, r.prevHash, r.hash]
        .map(csvCell)
        .join(','),
    );
  }
  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.setHeader('Content-Disposition', `attachment; filename="audit-log-${new Date().toISOString().slice(0, 10)}.csv"`);
  res.send(lines.join('\r\n'));
});
