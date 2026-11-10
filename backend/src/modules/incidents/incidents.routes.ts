import { randomUUID } from 'node:crypto';
import { Router } from 'express';
import { z } from 'zod';
import type { Prisma } from '@prisma/client';
import { requirePermission } from '../../auth/middleware.js';
import { auditContext, writeAudit } from '../../audit/audit.service.js';
import { decryptOptional, encryptOptional } from '../../lib/crypto.js';
import { badRequest, notFound } from '../../lib/errors.js';
import { publish } from '../../lib/events.js';
import { prisma } from '../../lib/prisma.js';
import { IdParam, Pagination, SeverityEnum, csvEnum, isoDate, safeText, singleLine } from '../../lib/validation.js';

export const incidentsRouter = Router();

const descAad = (id: string) => `incident:${id}:description`;
const STATUSES = ['NEW', 'TRIAGE', 'CONTAINED', 'RESOLVED', 'CLOSED'] as const;

const IncidentQuery = Pagination.extend({
  status: csvEnum([...STATUSES]),
  severity: csvEnum(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']),
  q: singleLine(120).optional(),
}).strict();

incidentsRouter.get('/', requirePermission('incident:read'), async (req, res) => {
  const q = IncidentQuery.parse(req.query);
  const where: Prisma.IncidentWhereInput = {
    ...(q.status.length ? { status: { in: q.status } } : {}),
    ...(q.severity.length ? { severity: { in: q.severity } } : {}),
    ...(q.q ? { title: { contains: q.q, mode: 'insensitive' } } : {}),
  };
  const [items, total] = await Promise.all([
    prisma.incident.findMany({ where, orderBy: { detectedAt: 'desc' }, take: q.limit, skip: q.offset }),
    prisma.incident.count({ where }),
  ]);
  res.json({
    total,
    items: items.map(({ descriptionEnc, ...i }) => ({ ...i, description: decryptOptional(descriptionEnc, descAad(i.id)) })),
  });
});

const IncidentCreate = z
  .object({
    title: singleLine(200, 3),
    description: safeText(8000).optional(),
    severity: SeverityEnum,
    category: singleLine(60, 2).default('General'),
    occurredAt: isoDate,
    detectedAt: isoDate,
    assetsAffected: z.number().int().min(0).max(1_000_000).default(0),
  })
  .strict()
  .refine((v) => v.detectedAt >= v.occurredAt, { message: 'detectedAt must not precede occurredAt', path: ['detectedAt'] })
  .refine((v) => v.detectedAt.getTime() <= Date.now() + 60_000, { message: 'detectedAt cannot be in the future', path: ['detectedAt'] });

incidentsRouter.post('/', requirePermission('incident:write'), async (req, res) => {
  const body = IncidentCreate.parse(req.body);
  const id = randomUUID();
  const incident = await prisma.$transaction(async (tx) => {
    const i = await tx.incident.create({
      data: {
        id,
        source: 'manual',
        externalId: id,
        title: body.title,
        descriptionEnc: encryptOptional(body.description, descAad(id)),
        severity: body.severity,
        category: body.category,
        occurredAt: body.occurredAt,
        detectedAt: body.detectedAt,
        assetsAffected: body.assetsAffected,
        createdById: req.auth!.userId,
      },
    });
    await writeAudit(tx, {
      ...auditContext(req),
      action: 'incident.create',
      outcome: 'SUCCESS',
      targetType: 'incident',
      targetId: id,
      details: { title: body.title, severity: body.severity },
    });
    return i;
  });
  publish({ type: 'incidents' });
  publish({ type: 'kpi' });
  const { descriptionEnc: _omit, ...safe } = incident;
  res.status(201).json(safe);
});

const IncidentUpdate = z
  .object({
    status: z.enum(STATUSES).optional(),
    severity: SeverityEnum.optional(),
    assetsAffected: z.number().int().min(0).max(1_000_000).optional(),
  })
  .strict();

incidentsRouter.patch('/:id', requirePermission('incident:write'), async (req, res) => {
  const { id } = IdParam.parse(req.params);
  const body = IncidentUpdate.parse(req.body);
  if (Object.keys(body).length === 0) throw badRequest('No changes supplied');
  const updated = await prisma.$transaction(async (tx) => {
    const before = await tx.incident.findUnique({ where: { id } });
    if (!before) throw notFound();
    const now = new Date();
    const data: Prisma.IncidentUpdateInput = { ...body };
    // Lifecycle timestamps drive MTTR.
    if (body.status && body.status !== 'NEW' && !before.respondedAt) data.respondedAt = now;
    if (body.status && ['RESOLVED', 'CLOSED'].includes(body.status) && !before.resolvedAt) data.resolvedAt = now;
    if (body.status && ['NEW', 'TRIAGE', 'CONTAINED'].includes(body.status)) data.resolvedAt = null;
    const i = await tx.incident.update({ where: { id }, data });
    await writeAudit(tx, {
      ...auditContext(req),
      action: 'incident.update',
      outcome: 'SUCCESS',
      targetType: 'incident',
      targetId: id,
      details: { before: { status: before.status, severity: before.severity }, after: { status: i.status, severity: i.severity } },
    });
    return i;
  });
  publish({ type: 'incidents' });
  publish({ type: 'kpi' });
  const { descriptionEnc: _omit, ...safe } = updated;
  res.json(safe);
});
