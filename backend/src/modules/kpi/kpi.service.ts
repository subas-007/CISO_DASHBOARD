/**
 * CISO KPI & KRI engine.
 *   KPIs: MTTD, MTTR, patch compliance %, remediation velocity, open critical findings …
 *   KRIs: configurable thresholds (risk appetite) evaluated to Red/Amber/Green with
 *         breach tracking.
 */
import type { KriDefinition, RagStatus } from '@prisma/client';
import { prisma } from '../../lib/prisma.js';
import { publish } from '../../lib/events.js';
import { logger } from '../../lib/logger.js';
import { getSetting } from '../settings/settings.service.js';
import { meanDays, meanDurationHours, percentage, ragStatus, velocityPerWeek } from './metrics.js';

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

export const SNAPSHOT_METRICS: (keyof KpiValues)[] = [
  'mttdHours',
  'mttrHours',
  'patchCompliancePct',
  'remediationVelocityPerWeek',
  'meanDaysToRemediate',
  'openCriticalFindings',
  'openHighFindings',
  'overdueCriticalFindings',
  'activeIncidents',
  'risksAboveAppetite',
];

const OPEN = ['OPEN', 'IN_PROGRESS'] as const;

export async function computeKpis(): Promise<KpiValues> {
  const windowDays = await getSetting('kpiWindowDays');
  const appetite = await getSetting('riskAppetiteScore');
  const since = new Date(Date.now() - windowDays * 86_400_000);
  const now = new Date();

  const [
    detected,
    resolved,
    remediated,
    totalAssets,
    compliantAssets,
    openCritical,
    openHigh,
    overdueCritical,
    overdue,
    activeIncidents,
    risks,
    failedConnectors,
    pendingAcceptances,
  ] = await Promise.all([
    prisma.incident.findMany({ where: { detectedAt: { gte: since } }, select: { occurredAt: true, detectedAt: true } }),
    prisma.incident.findMany({ where: { resolvedAt: { gte: since } }, select: { detectedAt: true, resolvedAt: true } }),
    prisma.vulnerability.findMany({ where: { remediatedAt: { gte: since } }, select: { discoveredAt: true, remediatedAt: true } }),
    prisma.asset.count(),
    prisma.asset.count({ where: { patchCompliant: true } }),
    prisma.vulnerability.count({ where: { severity: 'CRITICAL', status: { in: [...OPEN] } } }),
    prisma.vulnerability.count({ where: { severity: 'HIGH', status: { in: [...OPEN] } } }),
    prisma.vulnerability.count({ where: { severity: 'CRITICAL', status: { in: [...OPEN] }, dueAt: { lt: now } } }),
    prisma.vulnerability.count({ where: { status: { in: [...OPEN] }, dueAt: { lt: now } } }),
    prisma.incident.count({ where: { status: { in: ['NEW', 'TRIAGE', 'CONTAINED'] } } }),
    prisma.risk.findMany({ where: { status: { in: ['OPEN', 'MITIGATING'] } }, select: { likelihood: true, impact: true } }),
    prisma.connector.count({ where: { enabled: true, status: 'FAILED' } }),
    prisma.riskAcceptance.count({ where: { status: 'PENDING' } }),
  ]);

  return {
    mttdHours: meanDurationHours(detected.map((i) => ({ start: i.occurredAt, end: i.detectedAt }))),
    mttrHours: meanDurationHours(resolved.map((i) => ({ start: i.detectedAt, end: i.resolvedAt }))),
    patchCompliancePct: percentage(compliantAssets, totalAssets),
    remediationVelocityPerWeek: velocityPerWeek(remediated.length, windowDays),
    meanDaysToRemediate: meanDays(remediated.map((v) => ({ start: v.discoveredAt, end: v.remediatedAt }))),
    openCriticalFindings: openCritical,
    openHighFindings: openHigh,
    overdueCriticalFindings: overdueCritical,
    overdueFindings: overdue,
    activeIncidents,
    totalAssets,
    risksAboveAppetite: risks.filter((r) => r.likelihood * r.impact > appetite).length,
    failedConnectors,
    pendingAcceptances,
  };
}

export interface KriStatus {
  key: string;
  name: string;
  description: string;
  metric: string;
  unit: string;
  direction: KriDefinition['direction'];
  amberThreshold: number;
  redThreshold: number;
  enabled: boolean;
  value: number | null;
  status: RagStatus | null;
  updatedAt: Date;
}

export async function computeKriStatuses(values?: KpiValues): Promise<KriStatus[]> {
  const v = values ?? (await computeKpis());
  const defs = await prisma.kriDefinition.findMany({ orderBy: { name: 'asc' } });
  return defs.map((d) => {
    const raw = (v as unknown as Record<string, number | null>)[d.metric];
    const value = typeof raw === 'number' ? raw : null;
    return {
      key: d.key,
      name: d.name,
      description: d.description,
      metric: d.metric,
      unit: d.unit,
      direction: d.direction,
      amberThreshold: d.amberThreshold,
      redThreshold: d.redThreshold,
      enabled: d.enabled,
      value,
      status: d.enabled ? ragStatus(value, d) : null,
      updatedAt: d.updatedAt,
    };
  });
}

/** Value of each snapshot metric ~N days ago (for trend deltas). */
async function valuesDaysAgo(days: number): Promise<Record<string, number>> {
  const cutoff = new Date(Date.now() - days * 86_400_000);
  const rows = await prisma.metricSnapshot.findMany({
    where: { capturedAt: { lte: cutoff, gte: new Date(cutoff.getTime() - 2 * 86_400_000) } },
    orderBy: { capturedAt: 'desc' },
  });
  const out: Record<string, number> = {};
  for (const r of rows) if (!(r.metric in out)) out[r.metric] = r.value;
  return out;
}

export async function getKpiSummary() {
  const kpis = await computeKpis();
  const [kris, previous, connectors] = await Promise.all([
    computeKriStatuses(kpis),
    valuesDaysAgo(7),
    prisma.connector.groupBy({ by: ['status'], where: { enabled: true }, _count: { _all: true } }),
  ]);
  const deltas: Record<string, number | null> = {};
  for (const m of SNAPSHOT_METRICS) {
    const cur = kpis[m];
    deltas[m] = typeof cur === 'number' && previous[m] !== undefined ? Math.round((cur - previous[m]!) * 10) / 10 : null;
  }
  return {
    generatedAt: new Date().toISOString(),
    windowDays: await getSetting('kpiWindowDays'),
    riskAppetiteScore: await getSetting('riskAppetiteScore'),
    kpis,
    deltas,
    kris: kris.filter((k) => k.enabled),
    connectorHealth: Object.fromEntries(connectors.map((c) => [c.status, c._count._all])),
  };
}

export async function captureSnapshot(): Promise<void> {
  const kpis = await computeKpis();
  const capturedAt = new Date();
  await prisma.metricSnapshot.createMany({
    data: SNAPSHOT_METRICS.filter((m) => typeof kpis[m] === 'number').map((m) => ({ metric: m, value: kpis[m] as number, capturedAt })),
  });
  publish({ type: 'kpi' });
}

/** Evaluates KRIs, records new/escalated breaches and notifies clients. */
export async function evaluateKris(): Promise<number> {
  const statuses = await computeKriStatuses();
  let created = 0;
  for (const k of statuses) {
    if (!k.enabled || k.value == null || (k.status !== 'AMBER' && k.status !== 'RED')) continue;
    const last = await prisma.kriBreach.findFirst({
      where: { kriKey: k.key, acknowledgedAt: null },
      orderBy: { detectedAt: 'desc' },
    });
    // Only record a new breach when none is open, or the level escalated AMBER → RED.
    if (last && !(last.level === 'AMBER' && k.status === 'RED')) continue;
    await prisma.kriBreach.create({
      data: {
        kriKey: k.key,
        level: k.status,
        value: k.value,
        threshold: k.status === 'RED' ? k.redThreshold : k.amberThreshold,
      },
    });
    created++;
  }
  if (created) {
    logger.warn({ created }, 'KRI threshold breaches recorded');
    publish({ type: 'kri', data: { breaches: created } });
  }
  return created;
}

export async function getTrends(metrics: string[], days: number) {
  const since = new Date(Date.now() - days * 86_400_000);
  const rows = await prisma.metricSnapshot.findMany({
    where: { metric: { in: metrics }, capturedAt: { gte: since } },
    orderBy: { capturedAt: 'asc' },
    select: { metric: true, value: true, capturedAt: true },
  });
  const byDay = new Map<string, Record<string, number | string>>();
  for (const r of rows) {
    const day = r.capturedAt.toISOString().slice(0, 10);
    const point = byDay.get(day) ?? { date: day };
    point[r.metric] = r.value; // last value of the day wins (rows are ascending)
    byDay.set(day, point);
  }
  return [...byDay.values()];
}
