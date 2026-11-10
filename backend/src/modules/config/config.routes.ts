/**
 * Configuration operations: effective/drift status, deployment & host-OS bundles,
 * identity-policy sync status, and demo-data controls.
 */
import { Router } from 'express';
import { z } from 'zod';
import { env } from '../../config/env.js';
import { requirePermission } from '../../auth/middleware.js';
import { audit, auditContext } from '../../audit/audit.service.js';
import { badRequest, HttpError } from '../../lib/errors.js';
import { publish } from '../../lib/events.js';
import { egressPolicy } from '../../connectors/egress.js';
import { idpConfigured, idpSyncState } from '../../idp/identity.service.js';
import { heavyRateLimit } from '../../security/rateLimit.js';
import { clearDemoDataset, generateDemoDataset } from '../../demo/dataset.js';
import { simulationTick, simulatorState } from '../../demo/simulator.js';
import { refreshImpactedAssetCounts } from '../../connectors/ingest.js';
import { getSetting, invalidateSettingsCache } from '../settings/settings.service.js';
import { certificateSans, renderDeploymentEnv, renderHostScript } from './bundle.js';

export const configRouter = Router();

/** What the running containers were started with (passed by compose; non-secret). */
function runningDeployment() {
  const csv = (v?: string) => (v ?? '').split(',').map((s) => s.trim()).filter(Boolean).sort();
  return {
    publicBaseUrl: env.PUBLIC_BASE_URL,
    httpsPort: env.DEPLOY_HTTPS_PORT ?? null,
    httpPort: env.DEPLOY_HTTP_PORT ?? null,
    certificateSans: csv(env.DEPLOY_CERT_SANS),
    trustedUpstreamProxies: csv(env.DEPLOY_TRUSTED_PROXIES),
    edgeRatePerSec: env.DEPLOY_EDGE_RPS ?? null,
    edgeAuthRatePerSec: env.DEPLOY_EDGE_AUTH_RPS ?? null,
  };
}

configRouter.get('/status', requirePermission('config:read'), async (_req, res) => {
  const desired = await getSetting('deployment');
  const running = runningDeployment();
  const differences: { field: string; running: unknown; desired: unknown }[] = [];
  const cmp = (field: string, r: unknown, d: unknown) => {
    if (r !== null && JSON.stringify(r) !== JSON.stringify(d)) differences.push({ field, running: r, desired: d });
  };
  cmp('publicBaseUrl', running.publicBaseUrl, desired.publicBaseUrl);
  cmp('httpsPort', running.httpsPort, desired.httpsPort);
  cmp('httpPort', running.httpPort, desired.httpPort);
  cmp('trustedUpstreamProxies', running.trustedUpstreamProxies, [...desired.trustedUpstreamProxies].sort());
  cmp('edgeRatePerSec', running.edgeRatePerSec, desired.edgeRatePerSec);
  cmp('edgeAuthRatePerSec', running.edgeAuthRatePerSec, desired.edgeAuthRatePerSec);
  const missingSans = certificateSans(desired).filter((n) => running.certificateSans.length > 0 && !running.certificateSans.includes(n));
  if (missingSans.length) differences.push({ field: 'certificateSans', running: running.certificateSans, desired: certificateSans(desired) });

  const demo = await getSetting('demoData');
  res.json({
    deployment: { running, desired, redeployRequired: differences.length > 0, differences },
    identity: { configured: idpConfigured(), ...idpSyncState },
    egress: egressPolicy(),
    demo: { demoMode: env.DEMO_MODE, liveSimulation: env.DEMO_MODE && demo.liveSimulation, intervalSec: demo.intervalSec, ...simulatorState },
  });
});

function attachment(res: import('express').Response, filename: string, type: string, body: string) {
  res.setHeader('Content-Type', `${type}; charset=utf-8`);
  res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
  res.setHeader('Cache-Control', 'no-store');
  res.send(body);
}

configRouter.get('/bundle/deployment', requirePermission('system:manage'), async (req, res) => {
  const body = renderDeploymentEnv(await getSetting('deployment'), req.auth!.name);
  await audit({ ...auditContext(req), action: 'config.bundle.deployment', outcome: 'SUCCESS', targetType: 'config' });
  attachment(res, 'deployment.env', 'text/plain', body);
});

configRouter.get('/bundle/host', requirePermission('system:manage'), async (req, res) => {
  const { os } = z.object({ os: z.enum(['ubuntu', 'rhel']).optional() }).strict().parse(req.query);
  const host = await getSetting('hostOs');
  const target = { ...host, targetOs: os ?? host.targetOs };
  const body = renderHostScript(target, await getSetting('deployment'), req.auth!.name);
  await audit({ ...auditContext(req), action: 'config.bundle.host', outcome: 'SUCCESS', targetType: 'config', details: { os: target.targetOs } });
  attachment(res, `ciso-host-baseline-${target.targetOs}.sh`, 'text/x-shellscript', body);
});

/* ------------------------------- Demo data ------------------------------- */

function requireDemoMode() {
  if (!env.DEMO_MODE) throw new HttpError(409, 'NOT_DEMO_MODE', 'Demo data controls are only available in demo mode (SEED_DEMO_DATA=true)');
}

configRouter.post('/demo/tick', heavyRateLimit, requirePermission('system:manage'), async (req, res) => {
  requireDemoMode();
  const counts = await simulationTick();
  await audit({ ...auditContext(req), action: 'demo.simulation.tick', outcome: 'SUCCESS', targetType: 'demo', details: counts ? { ...counts } : { skipped: true } });
  res.json({ counts });
});

configRouter.post('/demo/regenerate', heavyRateLimit, requirePermission('system:manage'), async (req, res) => {
  requireDemoMode();
  const { confirm } = z.object({ confirm: z.string() }).strict().parse(req.body);
  if (confirm !== 'REGENERATE') throw badRequest('Type REGENERATE to confirm', 'CONFIRMATION_REQUIRED');
  const d = await getSetting('demoData');
  const opts = { assets: d.datasetAssets, vulnerabilities: d.datasetVulnerabilities, incidents: d.datasetIncidents, historyDays: d.historyDays, seed: Date.now() };
  const t0 = Date.now();
  await clearDemoDataset();
  await generateDemoDataset(opts);
  await refreshImpactedAssetCounts();
  invalidateSettingsCache();
  await audit({ ...auditContext(req), action: 'demo.dataset.regenerate', outcome: 'SUCCESS', targetType: 'demo', details: { ...opts, ms: Date.now() - t0 } });
  for (const type of ['kpi', 'kri', 'threats', 'incidents', 'risks', 'vulnerabilities'] as const) publish({ type });
  res.json({ ok: true, ...opts, ms: Date.now() - t0 });
});
