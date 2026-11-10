/**
 * ISO 31000 risk register, 5x5 matrix with drill-down, and the risk acceptance
 * workflow (request → CISO approval with segregation of duties → expiry).
 */
import { randomUUID } from 'node:crypto';
import { Router } from 'express';
import { z } from 'zod';
import { requirePermission } from '../../auth/middleware.js';
import { audit, auditContext, writeAudit } from '../../audit/audit.service.js';
import { decryptOptional, encrypt } from '../../lib/crypto.js';
import { badRequest, conflict, forbidden, notFound } from '../../lib/errors.js';
import { publish } from '../../lib/events.js';
import { prisma } from '../../lib/prisma.js';
import { IdParam, safeText, singleLine } from '../../lib/validation.js';
import { riskLevel } from '../kpi/metrics.js';
import { getSetting } from '../settings/settings.service.js';

export const riskRouter = Router();
export const acceptanceRouter = Router();

const scale = z.number().int().min(1).max(5);
const justificationAad = (id: string) => `risk_acceptance:${id}:justification`;

const RiskCreate = z
  .object({
    title: singleLine(200, 3),
    description: safeText(4000, 1),
    category: singleLine(80, 2),
    likelihood: scale,
    impact: scale,
    ownerName: singleLine(120, 2),
    treatment: safeText(2000).optional(),
    assetIds: z.array(z.string().uuid()).max(500).default([]),
  })
  .strict();

const RiskUpdate = RiskCreate.partial()
  .extend({ status: z.enum(['OPEN', 'MITIGATING', 'CLOSED']).optional() })
  .strict();

riskRouter.get('/', requirePermission('risk:read'), async (_req, res) => {
  const appetite = await getSetting('riskAppetiteScore');
  const risks = await prisma.risk.findMany({
    orderBy: [{ updatedAt: 'desc' }],
    include: { _count: { select: { assets: true } } },
  });
  res.json({
    appetite,
    items: risks.map((r) => ({
      ...r,
      score: r.likelihood * r.impact,
      level: riskLevel(r.likelihood, r.impact),
      aboveAppetite: r.likelihood * r.impact > appetite,
      assetCount: r._count.assets,
    })),
  });
});

riskRouter.get('/matrix', requirePermission('risk:read'), async (_req, res) => {
  const appetite = await getSetting('riskAppetiteScore');
  const risks = await prisma.risk.findMany({
    where: { status: { not: 'CLOSED' } },
    select: { id: true, title: true, likelihood: true, impact: true, status: true, category: true, ownerName: true },
  });
  const cells = [];
  for (let likelihood = 5; likelihood >= 1; likelihood--) {
    for (let impact = 1; impact <= 5; impact++) {
      const inCell = risks.filter((r) => r.likelihood === likelihood && r.impact === impact);
      cells.push({
        likelihood,
        impact,
        score: likelihood * impact,
        level: riskLevel(likelihood, impact),
        aboveAppetite: likelihood * impact > appetite,
        count: inCell.length,
        risks: inCell,
      });
    }
  }
  res.json({ appetite, cells, total: risks.length });
});

riskRouter.get('/:id', requirePermission('risk:read'), async (req, res) => {
  const { id } = IdParam.parse(req.params);
  const risk = await prisma.risk.findUnique({
    where: { id },
    include: {
      assets: {
        include: {
          asset: {
            include: {
              vulnerabilities: {
                where: { status: { in: ['OPEN', 'IN_PROGRESS', 'RISK_ACCEPTED'] } },
                orderBy: [{ severity: 'asc' }, { discoveredAt: 'asc' }],
                take: 50,
              },
            },
          },
        },
      },
      acceptances: { orderBy: { requestedAt: 'desc' } },
    },
  });
  if (!risk) throw notFound('Risk not found');
  res.json({
    ...risk,
    score: risk.likelihood * risk.impact,
    level: riskLevel(risk.likelihood, risk.impact),
    assets: risk.assets.map((ra) => ra.asset),
    acceptances: risk.acceptances.map(({ justificationEnc, ...a }) => ({
      ...a,
      justification: decryptOptional(justificationEnc, justificationAad(a.id)),
    })),
  });
});

riskRouter.post('/', requirePermission('risk:write'), async (req, res) => {
  const body = RiskCreate.parse(req.body);
  const risk = await prisma.$transaction(async (tx) => {
    const r = await tx.risk.create({
      data: {
        title: body.title,
        description: body.description,
        category: body.category,
        likelihood: body.likelihood,
        impact: body.impact,
        ownerName: body.ownerName,
        treatment: body.treatment ?? null,
        createdById: req.auth!.userId,
        assets: { create: body.assetIds.map((assetId) => ({ assetId })) },
      },
    });
    await writeAudit(tx, {
      ...auditContext(req),
      action: 'risk.create',
      outcome: 'SUCCESS',
      targetType: 'risk',
      targetId: r.id,
      details: { title: r.title, likelihood: r.likelihood, impact: r.impact, assets: body.assetIds.length },
    });
    return r;
  });
  publish({ type: 'risks' });
  res.status(201).json(risk);
});

riskRouter.patch('/:id', requirePermission('risk:write'), async (req, res) => {
  const { id } = IdParam.parse(req.params);
  const body = RiskUpdate.parse(req.body);
  const updated = await prisma.$transaction(async (tx) => {
    const before = await tx.risk.findUnique({ where: { id } });
    if (!before) throw notFound('Risk not found');
    if (before.status === 'ACCEPTED' && body.status) throw conflict('Accepted risks change status via the acceptance workflow');
    const { assetIds, ...fields } = body;
    const r = await tx.risk.update({
      where: { id },
      data: {
        ...fields,
        ...(assetIds ? { assets: { deleteMany: {}, create: assetIds.map((assetId) => ({ assetId })) } } : {}),
      },
    });
    await writeAudit(tx, {
      ...auditContext(req),
      action: 'risk.update',
      outcome: 'SUCCESS',
      targetType: 'risk',
      targetId: id,
      details: {
        changed: Object.keys(body),
        before: { likelihood: before.likelihood, impact: before.impact, status: before.status },
        after: { likelihood: r.likelihood, impact: r.impact, status: r.status },
      },
    });
    return r;
  });
  publish({ type: 'risks' });
  res.json(updated);
});

/* ------------------------------ Risk acceptance ------------------------------ */

const AcceptanceRequest = z
  .object({
    justification: safeText(4000, 20),
    expiresInDays: z.number().int().min(1).max(365),
  })
  .strict();

riskRouter.post('/:id/acceptances', requirePermission('risk:acceptance:request'), async (req, res) => {
  const { id } = IdParam.parse(req.params);
  const body = AcceptanceRequest.parse(req.body);
  const maxDays = await getSetting('riskAcceptanceMaxDays');
  if (body.expiresInDays > maxDays) throw badRequest(`Acceptance cannot exceed ${maxDays} days`);
  const created = await prisma.$transaction(async (tx) => {
    const risk = await tx.risk.findUnique({ where: { id } });
    if (!risk) throw notFound('Risk not found');
    if (risk.status === 'CLOSED') throw conflict('Closed risks cannot be accepted');
    const pending = await tx.riskAcceptance.count({ where: { riskId: id, status: { in: ['PENDING', 'APPROVED'] } } });
    if (pending > 0) throw conflict('An active or pending acceptance already exists for this risk');
    const acceptanceId = randomUUID();
    const a = await tx.riskAcceptance.create({
      data: {
        id: acceptanceId,
        riskId: id,
        justificationEnc: encrypt(body.justification, justificationAad(acceptanceId)),
        requestedById: req.auth!.userId,
        requestedByName: req.auth!.name,
        expiresAt: new Date(Date.now() + body.expiresInDays * 86_400_000),
      },
    });
    await writeAudit(tx, {
      ...auditContext(req),
      action: 'risk.acceptance.request',
      outcome: 'SUCCESS',
      targetType: 'risk_acceptance',
      targetId: a.id,
      details: { riskId: id, expiresAt: a.expiresAt.toISOString() },
    });
    return a;
  });
  publish({ type: 'risks' });
  const { justificationEnc: _omit, ...safe } = created;
  res.status(201).json(safe);
});

const AcceptanceQuery = z.object({ status: z.enum(['PENDING', 'APPROVED', 'REJECTED', 'EXPIRED', 'REVOKED']).optional() }).strict();

acceptanceRouter.get('/', requirePermission('risk:read'), async (req, res) => {
  const q = AcceptanceQuery.parse(req.query);
  const items = await prisma.riskAcceptance.findMany({
    where: q.status ? { status: q.status } : undefined,
    orderBy: { requestedAt: 'desc' },
    include: { risk: { select: { id: true, title: true, likelihood: true, impact: true, category: true } } },
    take: 500,
  });
  res.json({
    items: items.map(({ justificationEnc, ...a }) => ({ ...a, justification: decryptOptional(justificationEnc, justificationAad(a.id)) })),
  });
});

const Decision = z.object({ decision: z.enum(['APPROVE', 'REJECT']), note: safeText(2000, 5) }).strict();

acceptanceRouter.post('/:id/decision', requirePermission('risk:acceptance:approve'), async (req, res) => {
  const { id } = IdParam.parse(req.params);
  const body = Decision.parse(req.body);
  const existing = await prisma.riskAcceptance.findUnique({ where: { id }, select: { requestedById: true } });
  if (!existing) throw notFound();
  if (existing.requestedById === req.auth!.userId) {
    // Audited outside the transaction so the denial record is not rolled back.
    await audit({
      ...auditContext(req),
      action: 'risk.acceptance.decision',
      outcome: 'DENIED',
      targetType: 'risk_acceptance',
      targetId: id,
      details: { reason: 'segregation_of_duties' },
    });
    throw forbidden('Segregation of duties: you cannot approve your own request');
  }
  const result = await prisma.$transaction(async (tx) => {
    const a = await tx.riskAcceptance.findUnique({ where: { id } });
    if (!a) throw notFound();
    if (a.status !== 'PENDING') throw conflict('Only pending requests can be decided');
    const status = body.decision === 'APPROVE' ? 'APPROVED' : 'REJECTED';
    const u = await tx.riskAcceptance.update({
      where: { id },
      data: { status, decidedById: req.auth!.userId, decidedByName: req.auth!.name, decidedAt: new Date(), decisionNote: body.note },
    });
    if (status === 'APPROVED') await tx.risk.update({ where: { id: a.riskId }, data: { status: 'ACCEPTED' } });
    await writeAudit(tx, {
      ...auditContext(req),
      action: `risk.acceptance.${status.toLowerCase()}`,
      outcome: 'SUCCESS',
      targetType: 'risk_acceptance',
      targetId: id,
      details: { riskId: a.riskId, expiresAt: a.expiresAt.toISOString(), note: body.note },
    });
    return u;
  });
  publish({ type: 'risks' });
  const { justificationEnc: _omit, ...safe } = result;
  res.json(safe);
});

acceptanceRouter.post('/:id/revoke', requirePermission('risk:acceptance:approve'), async (req, res) => {
  const { id } = IdParam.parse(req.params);
  const body = z.object({ note: safeText(2000, 5) }).strict().parse(req.body);
  await prisma.$transaction(async (tx) => {
    const a = await tx.riskAcceptance.findUnique({ where: { id } });
    if (!a) throw notFound();
    if (a.status !== 'APPROVED') throw conflict('Only approved acceptances can be revoked');
    await tx.riskAcceptance.update({ where: { id }, data: { status: 'REVOKED', decisionNote: body.note } });
    await tx.risk.update({ where: { id: a.riskId }, data: { status: 'OPEN' } });
    await writeAudit(tx, {
      ...auditContext(req),
      action: 'risk.acceptance.revoke',
      outcome: 'SUCCESS',
      targetType: 'risk_acceptance',
      targetId: id,
      details: { riskId: a.riskId, note: body.note },
    });
  });
  publish({ type: 'risks' });
  res.status(204).end();
});
