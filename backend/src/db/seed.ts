/**
 * Seeds reference data (KRI definitions, parameters, CISA KEV connector) and — when
 * SEED_DEMO_DATA=true and the database is empty — the demo dataset sized by the
 * "Demo data" parameters.
 */
import { randomUUID } from 'node:crypto';
import type { Prisma } from '@prisma/client';
import { prisma } from '../lib/prisma.js';
import { logger } from '../lib/logger.js';
import { audit } from '../audit/audit.service.js';
import { ensureDefaultSettings, getSetting } from '../modules/settings/settings.service.js';
import { cisaKev } from '../connectors/adapters/threatIntel.js';
import { generateDemoDataset } from '../demo/dataset.js';

const KRI_DEFAULTS: Prisma.KriDefinitionCreateInput[] = [
  { key: 'open_critical', name: 'Open critical findings', description: 'Critical vulnerabilities not yet remediated.', metric: 'openCriticalFindings', unit: 'findings', direction: 'HIGHER_IS_WORSE', amberThreshold: 10, redThreshold: 25 },
  { key: 'overdue_critical', name: 'Critical findings past SLA', description: 'Critical vulnerabilities beyond the remediation SLA.', metric: 'overdueCriticalFindings', unit: 'findings', direction: 'HIGHER_IS_WORSE', amberThreshold: 1, redThreshold: 5 },
  { key: 'patch_compliance', name: 'Patch compliance', description: 'Share of assets fully patched.', metric: 'patchCompliancePct', unit: '%', direction: 'LOWER_IS_WORSE', amberThreshold: 95, redThreshold: 85 },
  { key: 'mttd', name: 'Mean time to detect', description: 'Average hours from occurrence to detection.', metric: 'mttdHours', unit: 'hours', direction: 'HIGHER_IS_WORSE', amberThreshold: 8, redThreshold: 24 },
  { key: 'mttr', name: 'Mean time to respond', description: 'Average hours from detection to resolution.', metric: 'mttrHours', unit: 'hours', direction: 'HIGHER_IS_WORSE', amberThreshold: 24, redThreshold: 72 },
  { key: 'risks_above_appetite', name: 'Risks above appetite', description: 'Open risks with inherent score above the risk appetite.', metric: 'risksAboveAppetite', unit: 'risks', direction: 'HIGHER_IS_WORSE', amberThreshold: 3, redThreshold: 6 },
  { key: 'connector_failures', name: 'Failed security feeds', description: 'Enabled integrations currently failing.', metric: 'failedConnectors', unit: 'connectors', direction: 'HIGHER_IS_WORSE', amberThreshold: 1, redThreshold: 3 },
  { key: 'active_incidents', name: 'Active incidents', description: 'Incidents not yet resolved.', metric: 'activeIncidents', unit: 'incidents', direction: 'HIGHER_IS_WORSE', amberThreshold: 8, redThreshold: 15 },
];

async function seedReference(): Promise<void> {
  for (const k of KRI_DEFAULTS) {
    await prisma.kriDefinition.upsert({ where: { key: k.key }, create: k, update: {} });
  }
  await ensureDefaultSettings();
  const kev = await prisma.connector.findUnique({ where: { name: 'CISA KEV' } });
  if (!kev) {
    await prisma.connector.create({
      data: {
        id: randomUUID(),
        name: 'CISA KEV',
        vendor: cisaKev.vendor,
        category: cisaKev.category,
        baseUrl: cisaKev.defaultBaseUrl!,
        authMode: 'NONE',
        pollIntervalSec: cisaKev.defaultPollSec,
        enabled: process.env.SEED_ENABLE_KEV !== 'false',
        status: 'UNTESTED',
        settings: cisaKev.settingsSchema.parse({}) as Prisma.InputJsonValue,
      },
    });
  }
}

async function main(): Promise<void> {
  await seedReference();
  const demo = process.env.SEED_DEMO_DATA === 'true';
  if (demo && (await prisma.asset.count()) === 0) {
    const d = await getSetting('demoData');
    logger.info('seeding demo data');
    await generateDemoDataset({ assets: d.datasetAssets, vulnerabilities: d.datasetVulnerabilities, incidents: d.datasetIncidents, historyDays: d.historyDays });
    await audit({ action: 'system.seed.demo', outcome: 'SUCCESS', details: { note: 'Demo dataset loaded', assets: d.datasetAssets, vulnerabilities: d.datasetVulnerabilities, incidents: d.datasetIncidents } });
  } else {
    await audit({ action: 'system.seed.reference', outcome: 'SUCCESS' }, { bestEffort: true });
  }
  logger.info('seed complete');
}

main()
  .catch((err: unknown) => {
    logger.fatal({ err }, 'seed failed');
    process.exitCode = 1;
  })
  .finally(() => prisma.$disconnect());
