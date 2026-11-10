/**
 * Live demo-data simulator (DEMO_MODE only). Each tick creates and progresses records at
 * the administrator-defined hourly rates so KPIs, KRIs, trends, the threat stream and
 * SSE notifications can be verified against continuously changing data:
 *
 *   incidents        new detections; open incidents advance NEW → TRIAGE → CONTAINED → RESOLVED
 *   vulnerabilities  new findings (SLA due dates from parameters); oldest open ones get remediated
 *   threat intel     new advisories / KEV-style CVE items, impacted-asset counts refreshed
 *   patch posture    occasional compliance drift on assets
 *
 * A transaction-scoped advisory lock prevents concurrent ticks across API replicas.
 */
import { randomUUID } from 'node:crypto';
import type { IncidentStatus, Prisma, Severity, ThreatType } from '@prisma/client';
import { env } from '../config/env.js';
import { encrypt } from '../lib/crypto.js';
import { publish } from '../lib/events.js';
import { logger } from '../lib/logger.js';
import { prisma } from '../lib/prisma.js';
import { dueDateFor, refreshImpactedAssetCounts } from '../connectors/ingest.js';
import { getSetting } from '../modules/settings/settings.service.js';
import { CVES } from './dataset.js';

export interface TickCounts {
  incidentsCreated: number;
  incidentsProgressed: number;
  vulnerabilitiesCreated: number;
  vulnerabilitiesRemediated: number;
  threatsCreated: number;
  assetsDrifted: number;
}

export const simulatorState = {
  ticks: 0,
  lastTickAt: null as Date | null,
  lastCounts: null as TickCounts | null,
};

const SOURCE = 'Demo simulator';
const pick = <T>(arr: readonly T[]): T => arr[Math.floor(Math.random() * arr.length)]!;
/** Rate-per-hour → integer count for one tick, preserving the fractional expectation. */
const draws = (perHour: number, intervalSec: number) => {
  const expected = (perHour * intervalSec) / 3600;
  return Math.floor(expected) + (Math.random() < expected % 1 ? 1 : 0);
};

const INCIDENTS: [string, string][] = [
  ['Credential phishing campaign targeting finance', 'Phishing'],
  ['Cobalt Strike beacon detected on endpoint', 'Malware'],
  ['Impossible travel sign-in for privileged account', 'Unauthorised access'],
  ['Suspicious large outbound transfer to cloud storage', 'Data exfiltration'],
  ['Mass file rename activity on file server', 'Ransomware precursor'],
  ['Brute force against VPN gateway', 'Unauthorised access'],
  ['Malicious OAuth app consent', 'Unauthorised access'],
  ['EDR tamper attempt', 'Malware'],
  ['Web shell detected on DMZ host', 'Malware'],
  ['Anomalous service account Kerberoasting', 'Insider'],
  ['MFA push-bombing against executive account', 'Phishing'],
  ['DNS tunnelling from build server', 'Data exfiltration'],
];
const ADVISORIES: [ThreatType, string, string, string[]][] = [
  ['RANSOMWARE', 'Ransomware affiliate exploiting edge VPN appliances', 'Initial access via unpatched SSL VPN, followed by credential dumping and ESXi encryption.', ['ransomware', 'vpn']],
  ['SUPPLY_CHAIN', 'Malicious package published to public registry', 'Typosquatted dependency exfiltrates CI secrets during install; pin versions and verify provenance.', ['supply-chain', 'ci-cd']],
  ['ADVISORY', 'Phishing kit bypassing legacy MFA via adversary-in-the-middle', 'Session-cookie theft against SSO; enforce phishing-resistant MFA for privileged users.', ['phishing', 'identity']],
  ['IOC', 'New C2 infrastructure linked to loader campaign', 'Domains and IPs associated with a commodity loader delivering ransomware precursors.', ['c2', 'loader']],
  ['ADVISORY', 'Exploitation of file-transfer appliances reported by national CERT', 'Mass exploitation targeting managed file transfer; restrict internet exposure and patch.', ['mft', 'exploited']],
];

const SEVERITY_WEIGHTS: Severity[] = ['CRITICAL', 'HIGH', 'HIGH', 'MEDIUM', 'MEDIUM', 'MEDIUM', 'LOW'];
const NEXT: Partial<Record<IncidentStatus, IncidentStatus>> = { NEW: 'TRIAGE', TRIAGE: 'CONTAINED', CONTAINED: 'RESOLVED' };

export async function simulationTick(): Promise<TickCounts | null> {
  if (!env.DEMO_MODE) return null;
  const cfg = await getSetting('demoData');
  const sla = (await getSetting('vulnSlaDays')) as Record<string, number>;
  const interval = cfg.intervalSec;
  const counts: TickCounts = { incidentsCreated: 0, incidentsProgressed: 0, vulnerabilitiesCreated: 0, vulnerabilitiesRemediated: 0, threatsCreated: 0, assetsDrifted: 0 };

  const ran = await prisma.$transaction(
    async (tx) => {
      const [{ locked }] = await tx.$queryRaw<{ locked: boolean }[]>`SELECT pg_try_advisory_xact_lock(7340021) AS locked`;
      if (!locked) return false;
      const now = Date.now();

      // Incidents — new detections
      const newIncidents: Prisma.IncidentCreateManyInput[] = [];
      for (let i = 0; i < draws(cfg.incidentsPerHour, interval); i++) {
        const id = randomUUID();
        const [title, category] = pick(INCIDENTS);
        const occurredAt = new Date(now - (0.2 + Math.random() * 4) * 3_600_000);
        newIncidents.push({
          id,
          source: SOURCE,
          externalId: id,
          title,
          descriptionEnc: encrypt('Simulated detection generated by the demo data simulator.', `incident:${id}:description`),
          severity: pick(SEVERITY_WEIGHTS),
          status: 'NEW',
          category,
          occurredAt,
          detectedAt: new Date(Math.min(now, occurredAt.getTime() + Math.random() * 2 * 3_600_000)),
          assetsAffected: 1 + Math.floor(Math.random() * 8),
        });
      }
      if (newIncidents.length) await tx.incident.createMany({ data: newIncidents });
      counts.incidentsCreated = newIncidents.length;

      // Incidents — progress the oldest open ones through the response lifecycle
      const open = await tx.incident.findMany({
        where: { status: { in: ['NEW', 'TRIAGE', 'CONTAINED'] } },
        orderBy: { detectedAt: 'asc' },
        take: Math.max(1, draws(cfg.incidentsPerHour * 1.5, interval)),
        select: { id: true, status: true, detectedAt: true },
      });
      for (const inc of open) {
        const next = NEXT[inc.status];
        if (!next) continue;
        const at = new Date(Math.max(now, inc.detectedAt.getTime() + 60_000));
        await tx.incident.update({
          where: { id: inc.id },
          data: { status: next, ...(next === 'TRIAGE' ? { respondedAt: at } : {}), ...(next === 'RESOLVED' ? { resolvedAt: at } : {}) },
        });
        counts.incidentsProgressed++;
      }

      // Vulnerabilities — new findings on random assets
      const assets = await tx.asset.findMany({ select: { id: true, hostname: true } });
      if (assets.length) {
        const vulns: Prisma.VulnerabilityCreateManyInput[] = [];
        for (let i = 0; i < draws(cfg.vulnerabilitiesPerHour, interval); i++) {
          const [cve, title, cvss] = pick(CVES);
          const asset = pick(assets);
          const severity: Severity = cvss >= 9 ? 'CRITICAL' : cvss >= 7 ? 'HIGH' : 'MEDIUM';
          const discoveredAt = new Date(now);
          vulns.push({
            assetId: asset.id,
            source: SOURCE,
            externalId: `sim:${randomUUID()}`,
            cveId: cve,
            title,
            severity,
            cvss,
            status: 'OPEN',
            discoveredAt,
            dueAt: dueDateFor(severity, discoveredAt, sla),
          });
        }
        if (vulns.length) await tx.vulnerability.createMany({ data: vulns });
        counts.vulnerabilitiesCreated = vulns.length;
      }

      // Vulnerabilities — remediate the oldest open critical/high findings first
      const toFix = await tx.vulnerability.findMany({
        where: { status: { in: ['OPEN', 'IN_PROGRESS'] } },
        orderBy: [{ severity: 'asc' }, { discoveredAt: 'asc' }],
        take: draws(cfg.remediationsPerHour, interval),
        select: { id: true },
      });
      if (toFix.length) {
        await tx.vulnerability.updateMany({ where: { id: { in: toFix.map((v) => v.id) } }, data: { status: 'REMEDIATED', remediatedAt: new Date(now) } });
        counts.vulnerabilitiesRemediated = toFix.length;
      }

      // Threat intel
      const threats: Prisma.ThreatItemCreateManyInput[] = [];
      for (let i = 0; i < draws(cfg.threatsPerHour, interval); i++) {
        if (Math.random() < 0.5) {
          const [cve, title] = pick(CVES);
          threats.push({ source: `${SOURCE} – KEV`, sourceRef: `sim-${randomUUID()}`, type: 'CVE', title: `${cve} — ${title}`, summary: 'Newly reported exploitation in the wild. Prioritise internet-facing assets.', severity: 'HIGH', cveId: cve, publishedAt: new Date(now), tags: ['kev', 'exploited', 'simulated'] });
        } else {
          const [type, title, summary, tags] = pick(ADVISORIES);
          threats.push({ source: `${SOURCE} – Intel`, sourceRef: `sim-${randomUUID()}`, type, title, summary, severity: pick(['CRITICAL', 'HIGH', 'MEDIUM'] as const), publishedAt: new Date(now), tags: [...tags, 'simulated'], impactedAssetCount: Math.floor(Math.random() * 12) });
        }
      }
      if (threats.length) await tx.threatItem.createMany({ data: threats });
      counts.threatsCreated = threats.length;

      // Patch posture drift
      if (assets.length && Math.random() < Math.min(1, interval / 120)) {
        const a = await tx.asset.findUnique({ where: { id: pick(assets).id }, select: { id: true, patchCompliant: true } });
        if (a) {
          await tx.asset.update({
            where: { id: a.id },
            data: a.patchCompliant
              ? { patchCompliant: false, missingPatches: 1 + Math.floor(Math.random() * 6) }
              : { patchCompliant: true, missingPatches: 0, lastPatchedAt: new Date(now) },
          });
          counts.assetsDrifted = 1;
        }
      }
      return true;
    },
    { timeout: 30_000 },
  );
  if (!ran) return null;

  if (counts.threatsCreated) await refreshImpactedAssetCounts();
  simulatorState.ticks++;
  simulatorState.lastTickAt = new Date();
  simulatorState.lastCounts = counts;
  if (counts.incidentsCreated || counts.incidentsProgressed) publish({ type: 'incidents', data: { count: counts.incidentsCreated } });
  if (counts.vulnerabilitiesCreated || counts.vulnerabilitiesRemediated || counts.assetsDrifted) publish({ type: 'vulnerabilities' });
  if (counts.threatsCreated) publish({ type: 'threats', data: { count: counts.threatsCreated } });
  publish({ type: 'kpi' });
  logger.debug({ counts }, 'demo simulation tick');
  return counts;
}

/** Scheduler hook: runs a tick when enabled and the configured interval has elapsed. */
export async function maybeSimulate(): Promise<void> {
  if (!env.DEMO_MODE) return;
  const cfg = await getSetting('demoData');
  if (!cfg.liveSimulation) return;
  if (simulatorState.lastTickAt && Date.now() - simulatorState.lastTickAt.getTime() < cfg.intervalSec * 1000) return;
  await simulationTick();
}
