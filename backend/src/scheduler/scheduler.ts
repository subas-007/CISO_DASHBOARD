/**
 * Background jobs. Connector polling uses a DB lease (leaseUntil) so multiple API
 * replicas never run the same connector concurrently.
 */
import { prisma } from '../lib/prisma.js';
import { logger } from '../lib/logger.js';
import { publish } from '../lib/events.js';
import { syncConnector } from '../connectors/runner.js';
import { captureSnapshot, evaluateKris } from '../modules/kpi/kpi.service.js';
import { getSetting } from '../modules/settings/settings.service.js';
import { applyLiveSettings } from '../modules/config/apply.js';
import { idpConfigured, idpSyncState, syncIdentityPolicy } from '../idp/identity.service.js';
import { maybeSimulate } from '../demo/simulator.js';

const LEASE_MS = 15 * 60_000;
const timers: NodeJS.Timeout[] = [];
const running = new Set<string>();

export const schedulerState = {
  startedAt: null as Date | null,
  lastConnectorTick: null as Date | null,
  lastSnapshot: null as Date | null,
  lastKriEvaluation: null as Date | null,
  lastHousekeeping: null as Date | null,
};

async function connectorTick(): Promise<void> {
  schedulerState.lastConnectorTick = new Date();
  const now = Date.now();
  const connectors = await prisma.connector.findMany({ where: { enabled: true } });
  for (const c of connectors) {
    if (running.has(c.id)) continue;
    const due = !c.lastSyncAt || c.lastSyncAt.getTime() + c.pollIntervalSec * 1000 <= now;
    if (!due) continue;
    // Atomic lease acquisition (safe across replicas).
    const lease = await prisma.connector.updateMany({
      where: { id: c.id, enabled: true, OR: [{ leaseUntil: null }, { leaseUntil: { lt: new Date() } }] },
      data: { leaseUntil: new Date(Date.now() + LEASE_MS) },
    });
    if (lease.count !== 1) continue;
    running.add(c.id);
    void syncConnector(c)
      .catch((err: unknown) => logger.error({ err, connector: c.name }, 'scheduled sync crashed'))
      .finally(async () => {
        running.delete(c.id);
        await prisma.connector.update({ where: { id: c.id }, data: { leaseUntil: null } }).catch(() => undefined);
      });
  }
}

async function housekeeping(): Promise<void> {
  schedulerState.lastHousekeeping = new Date();
  const now = new Date();
  // Expire risk acceptances past their validity date.
  const expired = await prisma.riskAcceptance.findMany({ where: { status: 'APPROVED', expiresAt: { lt: now } }, select: { id: true, riskId: true } });
  for (const a of expired) {
    await prisma.$transaction([
      prisma.riskAcceptance.update({ where: { id: a.id }, data: { status: 'EXPIRED' } }),
      prisma.risk.update({ where: { id: a.riskId }, data: { status: 'OPEN' } }),
    ]);
  }
  if (expired.length) publish({ type: 'risks' });

  // Data minimisation / retention.
  const threatDays = await getSetting('threatRetentionDays');
  const snapDays = await getSetting('snapshotRetentionDays');
  await prisma.threatItem.deleteMany({ where: { publishedAt: { lt: new Date(now.getTime() - threatDays * 86_400_000) } } });
  await prisma.metricSnapshot.deleteMany({ where: { capturedAt: { lt: new Date(now.getTime() - snapDays * 86_400_000) } } });
  // Purge long-dead sessions (keep 30 days for investigations).
  await prisma.session.deleteMany({ where: { absoluteExpiresAt: { lt: new Date(now.getTime() - 30 * 86_400_000) } } });
}

function every(ms: number, name: string, fn: () => Promise<unknown>, runNow = false): void {
  const wrapped = () => {
    fn().catch((err: unknown) => logger.error({ err, job: name }, 'scheduled job failed'));
  };
  if (runNow) setTimeout(wrapped, 5_000).unref();
  const t = setInterval(wrapped, ms);
  t.unref();
  timers.push(t);
}

export function startScheduler(): void {
  schedulerState.startedAt = new Date();
  every(30_000, 'connectors', connectorTick, true);
  every(15 * 60_000, 'kpi-snapshot', async () => {
    await captureSnapshot();
    schedulerState.lastSnapshot = new Date();
  }, true);
  every(5 * 60_000, 'kri-evaluation', async () => {
    await evaluateKris();
    schedulerState.lastKriEvaluation = new Date();
  }, true);
  every(60 * 60_000, 'housekeeping', housekeeping, true);
  // Converge live settings changed on another replica.
  every(30_000, 'live-settings', applyLiveSettings);
  // Re-apply the identity policy: retry quickly after a failure, otherwise hourly drift correction.
  every(5 * 60_000, 'idp-policy', async () => {
    if (!idpConfigured()) return;
    const stale = !idpSyncState.lastSuccessAt || Date.now() - idpSyncState.lastSuccessAt.getTime() > 60 * 60_000;
    if (idpSyncState.ok === false || stale) await syncIdentityPolicy();
  });
  every(15_000, 'demo-simulator', maybeSimulate);
  logger.info('scheduler started');
}

export function stopScheduler(): void {
  timers.splice(0).forEach(clearInterval);
}
