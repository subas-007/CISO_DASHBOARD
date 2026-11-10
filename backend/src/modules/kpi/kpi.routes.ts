import { Router } from 'express';
import { z } from 'zod';
import { requirePermission } from '../../auth/middleware.js';
import { auditContext, writeAudit } from '../../audit/audit.service.js';
import { badRequest, notFound } from '../../lib/errors.js';
import { publish } from '../../lib/events.js';
import { prisma } from '../../lib/prisma.js';
import { IdParam, safeText, singleLine } from '../../lib/validation.js';
import { thresholdsValid } from './metrics.js';
import { computeKriStatuses, getKpiSummary, getTrends, SNAPSHOT_METRICS } from './kpi.service.js';

export const kpiRouter = Router();

kpiRouter.get('/summary', requirePermission('kpi:read'), async (_req, res) => {
  res.json(await getKpiSummary());
});

const TrendQuery = z
  .object({
    metrics: z
      .string()
      .default('mttdHours,mttrHours,patchCompliancePct,openCriticalFindings')
      .transform((v) => v.split(','))
      .pipe(z.array(z.enum(SNAPSHOT_METRICS as [string, ...string[]])).min(1).max(10)),
    days: z.coerce.number().int().min(7).max(365).default(90),
  })
  .strict();

kpiRouter.get('/trends', requirePermission('kpi:read'), async (req, res) => {
  const q = TrendQuery.parse(req.query);
  res.json({ metrics: q.metrics, days: q.days, points: await getTrends(q.metrics, q.days) });
});

/* --------------------------------- KRIs ---------------------------------- */

export const kriRouter = Router();

kriRouter.get('/', requirePermission('kri:read'), async (_req, res) => {
  res.json({ items: await computeKriStatuses() });
});

const KriKeyParam = z.object({ key: z.string().regex(/^[a-z0-9_.]{1,64}$/) }).strict();
const KriUpdate = z
  .object({
    name: singleLine(120, 3).optional(),
    description: safeText(500).optional(),
    amberThreshold: z.number().finite(),
    redThreshold: z.number().finite(),
    enabled: z.boolean(),
  })
  .strict();

kriRouter.put('/:key', requirePermission('parameters:manage'), async (req, res) => {
  const { key } = KriKeyParam.parse(req.params);
  const body = KriUpdate.parse(req.body);
  const before = await prisma.kriDefinition.findUnique({ where: { key } });
  if (!before) throw notFound('KRI not found');
  if (!thresholdsValid(before.direction, body.amberThreshold, body.redThreshold)) {
    throw badRequest(
      before.direction === 'HIGHER_IS_WORSE'
        ? 'Red threshold must be greater than amber for "higher is worse" KRIs'
        : 'Red threshold must be lower than amber for "lower is worse" KRIs',
    );
  }
  const updated = await prisma.$transaction(async (tx) => {
    const u = await tx.kriDefinition.update({ where: { key }, data: { ...body, updatedById: req.auth!.userId } });
    await writeAudit(tx, {
      ...auditContext(req),
      action: 'kri.update',
      outcome: 'SUCCESS',
      targetType: 'kri',
      targetId: key,
      details: {
        before: { amber: before.amberThreshold, red: before.redThreshold, enabled: before.enabled },
        after: { amber: u.amberThreshold, red: u.redThreshold, enabled: u.enabled },
      },
    });
    return u;
  });
  publish({ type: 'kri' });
  res.json(updated);
});

const BreachQuery = z.object({ open: z.enum(['true', 'false']).optional() }).strict();

kriRouter.get('/breaches', requirePermission('kri:read'), async (req, res) => {
  const q = BreachQuery.parse(req.query);
  const items = await prisma.kriBreach.findMany({
    where: q.open === 'true' ? { acknowledgedAt: null } : undefined,
    orderBy: { detectedAt: 'desc' },
    take: 200,
  });
  res.json({ items });
});

kriRouter.post('/breaches/:id/acknowledge', requirePermission('kri:acknowledge'), async (req, res) => {
  const { id } = IdParam.parse(req.params);
  const result = await prisma.$transaction(async (tx) => {
    const b = await tx.kriBreach.findUnique({ where: { id } });
    if (!b) throw notFound();
    if (b.acknowledgedAt) return b;
    const u = await tx.kriBreach.update({ where: { id }, data: { acknowledgedAt: new Date(), acknowledgedById: req.auth!.userId } });
    await writeAudit(tx, {
      ...auditContext(req),
      action: 'kri.breach.acknowledge',
      outcome: 'SUCCESS',
      targetType: 'kri_breach',
      targetId: id,
      details: { kri: b.kriKey, level: b.level, value: b.value },
    });
    return u;
  });
  publish({ type: 'kri' });
  res.json(result);
});
