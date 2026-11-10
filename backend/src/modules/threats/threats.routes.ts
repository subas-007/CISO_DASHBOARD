import { Router } from 'express';
import { z } from 'zod';
import type { Prisma } from '@prisma/client';
import { requirePermission } from '../../auth/middleware.js';
import { auditContext, writeAudit } from '../../audit/audit.service.js';
import { notFound } from '../../lib/errors.js';
import { publish } from '../../lib/events.js';
import { prisma } from '../../lib/prisma.js';
import { IdParam, csvEnum, isoDate, safeText, singleLine } from '../../lib/validation.js';

export const threatsRouter = Router();

const ThreatQuery = z
  .object({
    type: csvEnum(['CVE', 'RANSOMWARE', 'SUPPLY_CHAIN', 'ADVISORY', 'IOC']),
    severity: csvEnum(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']),
    status: csvEnum(['NEW', 'TRIAGED', 'ACTIONED', 'DISMISSED']),
    source: singleLine(120).optional(),
    q: singleLine(120).optional(),
    since: isoDate.optional(),
    impactedOnly: z.enum(['true', 'false']).optional(),
    limit: z.coerce.number().int().min(1).max(200).default(50),
    cursor: z.string().uuid().optional(),
  })
  .strict();

threatsRouter.get('/', requirePermission('threat:read'), async (req, res) => {
  const q = ThreatQuery.parse(req.query);
  const where: Prisma.ThreatItemWhereInput = {
    ...(q.type.length ? { type: { in: q.type } } : {}),
    ...(q.severity.length ? { severity: { in: q.severity } } : {}),
    ...(q.status.length ? { status: { in: q.status } } : {}),
    ...(q.source ? { source: q.source } : {}),
    ...(q.since ? { publishedAt: { gte: q.since } } : {}),
    ...(q.impactedOnly === 'true' ? { impactedAssetCount: { gt: 0 } } : {}),
    ...(q.q
      ? {
          OR: [
            { title: { contains: q.q, mode: 'insensitive' } },
            { cveId: { contains: q.q, mode: 'insensitive' } },
            { tags: { has: q.q.toLowerCase() } },
          ],
        }
      : {}),
  };
  const items = await prisma.threatItem.findMany({
    where,
    orderBy: [{ publishedAt: 'desc' }, { id: 'asc' }],
    take: q.limit + 1,
    ...(q.cursor ? { cursor: { id: q.cursor }, skip: 1 } : {}),
  });
  const hasMore = items.length > q.limit;
  const page = items.slice(0, q.limit);
  const [bySeverity, byType] = await Promise.all([
    prisma.threatItem.groupBy({ by: ['severity'], where, _count: { _all: true } }),
    prisma.threatItem.groupBy({ by: ['type'], where, _count: { _all: true } }),
  ]);
  res.json({
    items: page,
    nextCursor: hasMore ? page[page.length - 1]!.id : null,
    facets: {
      severity: Object.fromEntries(bySeverity.map((b) => [b.severity, b._count._all])),
      type: Object.fromEntries(byType.map((b) => [b.type, b._count._all])),
    },
  });
});

threatsRouter.get('/sources', requirePermission('threat:read'), async (_req, res) => {
  const rows = await prisma.threatItem.groupBy({ by: ['source'], _count: { _all: true }, orderBy: { source: 'asc' } });
  res.json({ items: rows.map((r) => ({ source: r.source, count: r._count._all })) });
});

const Triage = z
  .object({
    status: z.enum(['NEW', 'TRIAGED', 'ACTIONED', 'DISMISSED']),
    note: safeText(2000).optional(),
  })
  .strict();

threatsRouter.patch('/:id', requirePermission('threat:triage'), async (req, res) => {
  const { id } = IdParam.parse(req.params);
  const body = Triage.parse(req.body);
  const updated = await prisma.$transaction(async (tx) => {
    const before = await tx.threatItem.findUnique({ where: { id }, select: { status: true, title: true } });
    if (!before) throw notFound();
    const t = await tx.threatItem.update({
      where: { id },
      data: { status: body.status, triageNote: body.note ?? null, triagedById: req.auth!.userId, triagedAt: new Date() },
    });
    await writeAudit(tx, {
      ...auditContext(req),
      action: 'threat.triage',
      outcome: 'SUCCESS',
      targetType: 'threat',
      targetId: id,
      details: { from: before.status, to: body.status, title: before.title },
    });
    return t;
  });
  publish({ type: 'threats' });
  res.json(updated);
});
