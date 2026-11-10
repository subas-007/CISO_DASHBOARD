/** Vulnerability remediation tracking, change ticket linkage and asset inventory. */
import { Router } from 'express';
import { z } from 'zod';
import type { Prisma } from '@prisma/client';
import { requirePermission } from '../../auth/middleware.js';
import { auditContext, writeAudit } from '../../audit/audit.service.js';
import { conflict, notFound } from '../../lib/errors.js';
import { publish } from '../../lib/events.js';
import { prisma } from '../../lib/prisma.js';
import { IdParam, Pagination, csvEnum, safeText, singleLine } from '../../lib/validation.js';
import { refreshImpactedAssetCounts } from '../../connectors/ingest.js';

export const vulnerabilitiesRouter = Router();
export const assetsRouter = Router();
export const changeTicketsRouter = Router();

const VULN_STATUSES = ['OPEN', 'IN_PROGRESS', 'REMEDIATED', 'RISK_ACCEPTED', 'FALSE_POSITIVE'] as const;

const VulnQuery = Pagination.extend({
  status: csvEnum([...VULN_STATUSES]),
  severity: csvEnum(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']),
  q: singleLine(120).optional(),
  assetId: z.string().uuid().optional(),
  overdue: z.enum(['true', 'false']).optional(),
}).strict();

vulnerabilitiesRouter.get('/', requirePermission('vuln:read'), async (req, res) => {
  const q = VulnQuery.parse(req.query);
  const where: Prisma.VulnerabilityWhereInput = {
    ...(q.status.length ? { status: { in: q.status } } : {}),
    ...(q.severity.length ? { severity: { in: q.severity } } : {}),
    ...(q.assetId ? { assetId: q.assetId } : {}),
    ...(q.overdue === 'true' ? { dueAt: { lt: new Date() }, status: { in: ['OPEN', 'IN_PROGRESS'] } } : {}),
    ...(q.q
      ? {
          OR: [
            { title: { contains: q.q, mode: 'insensitive' } },
            { cveId: { contains: q.q, mode: 'insensitive' } },
            { asset: { hostname: { contains: q.q, mode: 'insensitive' } } },
          ],
        }
      : {}),
  };
  const [items, total] = await Promise.all([
    prisma.vulnerability.findMany({
      where,
      orderBy: [{ severity: 'asc' }, { dueAt: 'asc' }],
      take: q.limit,
      skip: q.offset,
      include: {
        asset: { select: { id: true, hostname: true, businessUnit: true, criticality: true } },
        changeTicket: { select: { id: true, system: true, externalKey: true, status: true, url: true } },
      },
    }),
    prisma.vulnerability.count({ where }),
  ]);
  res.json({ total, items });
});

const VulnUpdate = z
  .object({
    status: z.enum(['OPEN', 'IN_PROGRESS', 'REMEDIATED', 'FALSE_POSITIVE']),
    note: safeText(2000).optional(),
  })
  .strict();

vulnerabilitiesRouter.patch('/:id', requirePermission('remediation:write'), async (req, res) => {
  const { id } = IdParam.parse(req.params);
  const body = VulnUpdate.parse(req.body);
  const updated = await prisma.$transaction(async (tx) => {
    const before = await tx.vulnerability.findUnique({ where: { id } });
    if (!before) throw notFound();
    if (before.status === 'RISK_ACCEPTED') throw conflict('Risk-accepted findings are governed by the risk acceptance workflow');
    const v = await tx.vulnerability.update({
      where: { id },
      data: {
        status: body.status,
        remediationNote: body.note ?? before.remediationNote,
        remediatedAt: body.status === 'REMEDIATED' ? before.remediatedAt ?? new Date() : null,
        updatedById: req.auth!.userId,
      },
    });
    await writeAudit(tx, {
      ...auditContext(req),
      action: 'vulnerability.status_change',
      outcome: 'SUCCESS',
      targetType: 'vulnerability',
      targetId: id,
      details: { from: before.status, to: body.status, cve: before.cveId },
    });
    return v;
  });
  publish({ type: 'vulnerabilities' });
  publish({ type: 'kpi' });
  void refreshImpactedAssetCounts();
  res.json(updated);
});

const LinkTicket = z
  .object({
    system: singleLine(80, 2),
    externalKey: z.string().trim().regex(/^[A-Za-z0-9_.-]{2,64}$/),
    title: singleLine(300).optional(),
    url: z
      .string()
      .url()
      .refine((u) => u.startsWith('https://'), 'URL must be https')
      .optional(),
  })
  .strict();

vulnerabilitiesRouter.post('/:id/change-ticket', requirePermission('change:link'), async (req, res) => {
  const { id } = IdParam.parse(req.params);
  const body = LinkTicket.parse(req.body);
  const result = await prisma.$transaction(async (tx) => {
    const v = await tx.vulnerability.findUnique({ where: { id }, select: { id: true } });
    if (!v) throw notFound();
    const ticket = await tx.changeTicket.upsert({
      where: { system_externalKey: { system: body.system, externalKey: body.externalKey } },
      create: { system: body.system, externalKey: body.externalKey, title: body.title ?? body.externalKey, status: 'Linked', url: body.url ?? null },
      update: {},
    });
    const updated = await tx.vulnerability.update({
      where: { id },
      data: { changeTicketId: ticket.id, status: 'IN_PROGRESS', updatedById: req.auth!.userId },
      include: { changeTicket: true },
    });
    await writeAudit(tx, {
      ...auditContext(req),
      action: 'vulnerability.change_ticket_link',
      outcome: 'SUCCESS',
      targetType: 'vulnerability',
      targetId: id,
      details: { system: body.system, ticket: body.externalKey },
    });
    return updated;
  });
  publish({ type: 'vulnerabilities' });
  res.json(result);
});

changeTicketsRouter.get('/', requirePermission('vuln:read'), async (req, res) => {
  const q = z.object({ q: singleLine(80).optional() }).strict().parse(req.query);
  const items = await prisma.changeTicket.findMany({
    where: q.q ? { OR: [{ externalKey: { contains: q.q, mode: 'insensitive' } }, { title: { contains: q.q, mode: 'insensitive' } }] } : undefined,
    orderBy: { updatedAt: 'desc' },
    take: 100,
    include: { _count: { select: { vulnerabilities: true } } },
  });
  res.json({ items });
});

assetsRouter.get('/', requirePermission('vuln:read'), async (req, res) => {
  const q = Pagination.extend({ q: singleLine(120).optional(), nonCompliant: z.enum(['true', 'false']).optional() })
    .strict()
    .parse(req.query);
  const where: Prisma.AssetWhereInput = {
    ...(q.q ? { OR: [{ hostname: { contains: q.q, mode: 'insensitive' } }, { businessUnit: { contains: q.q, mode: 'insensitive' } }] } : {}),
    ...(q.nonCompliant === 'true' ? { patchCompliant: false } : {}),
  };
  const [items, total] = await Promise.all([
    prisma.asset.findMany({
      where,
      orderBy: [{ criticality: 'desc' }, { hostname: 'asc' }],
      take: q.limit,
      skip: q.offset,
      include: { _count: { select: { vulnerabilities: { where: { status: { in: ['OPEN', 'IN_PROGRESS'] } } } } } },
    }),
    prisma.asset.count({ where }),
  ]);
  res.json({ total, items });
});
