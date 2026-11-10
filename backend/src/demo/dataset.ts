/**
 * Demo dataset generator (demo profile only). Parameterised by the administrator
 * (Configuration → Demo data) and used by the initial seed and by
 * "Regenerate demo dataset". Deterministic PRNG for reproducible numbers unless a
 * new seed is supplied.
 */
import { randomUUID } from 'node:crypto';
import type { IncidentStatus, Prisma, Severity, ThreatType, VulnStatus } from '@prisma/client';
import { prisma } from '../lib/prisma.js';
import { encrypt } from '../lib/crypto.js';
import { getSetting } from '../modules/settings/settings.service.js';
import { dueDateFor } from '../connectors/ingest.js';

export interface DatasetOptions {
  assets: number;
  vulnerabilities: number;
  incidents: number;
  historyDays: number;
  seed?: number;
}
export const DEFAULT_DATASET: DatasetOptions = { assets: 90, vulnerabilities: 480, incidents: 160, historyDays: 90 };

export const DAY = 86_400_000;
let seed = 0x5eed1234;
export function reseed(value: number): void {
  seed = value | 0;
}
export const rand = () => {
  seed |= 0;
  seed = (seed + 0x6d2b79f5) | 0;
  let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
  t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
  return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
};
export const pick = <T>(arr: readonly T[]): T => arr[Math.floor(rand() * arr.length)]!;
export const between = (min: number, max: number) => min + rand() * (max - min);
export const daysAgo = (d: number) => new Date(Date.now() - d * DAY);

export const CVES: [string, string, number][] = [
  ['CVE-2024-3400', 'PAN-OS GlobalProtect command injection', 10.0],
  ['CVE-2023-4966', 'Citrix NetScaler ADC information disclosure (Citrix Bleed)', 9.4],
  ['CVE-2024-21762', 'Fortinet FortiOS SSL VPN out-of-bounds write', 9.8],
  ['CVE-2023-34362', 'Progress MOVEit Transfer SQL injection', 9.8],
  ['CVE-2021-44228', 'Apache Log4j2 JNDI remote code execution', 10.0],
  ['CVE-2024-6387', 'OpenSSH regreSSHion signal handler race', 8.1],
  ['CVE-2023-20198', 'Cisco IOS XE web UI privilege escalation', 10.0],
  ['CVE-2024-1709', 'ConnectWise ScreenConnect authentication bypass', 10.0],
  ['CVE-2023-22515', 'Atlassian Confluence broken access control', 10.0],
  ['CVE-2024-23897', 'Jenkins CLI arbitrary file read', 9.8],
  ['CVE-2023-46604', 'Apache ActiveMQ deserialisation RCE', 10.0],
  ['CVE-2024-3094', 'XZ Utils liblzma backdoor', 10.0],
  ['CVE-2023-44487', 'HTTP/2 Rapid Reset denial of service', 7.5],
  ['CVE-2024-21412', 'Windows Internet Shortcut SmartScreen bypass', 8.1],
  ['CVE-2024-30051', 'Windows DWM Core Library elevation of privilege', 7.8],
  ['CVE-2023-36884', 'Office and Windows HTML RCE', 8.8],
  ['CVE-2024-4577', 'PHP-CGI argument injection', 9.8],
  ['CVE-2023-27997', 'FortiOS heap-based buffer overflow', 9.8],
  ['CVE-2024-38063', 'Windows TCP/IP IPv6 remote code execution', 9.8],
  ['CVE-2023-4863', 'libwebp heap buffer overflow', 8.8],
  ['CVE-2024-47575', 'FortiManager missing authentication (FortiJump)', 9.8],
  ['CVE-2023-48795', 'SSH Terrapin prefix truncation', 5.9],
  ['CVE-2024-0012', 'PAN-OS management interface authentication bypass', 9.3],
  ['CVE-2023-38545', 'curl SOCKS5 heap buffer overflow', 9.8],
  ['CVE-2024-27198', 'JetBrains TeamCity authentication bypass', 9.8],
  ['CVE-2022-41040', 'Microsoft Exchange SSRF (ProxyNotShell)', 8.8],
  ['CVE-2023-35078', 'Ivanti EPMM authentication bypass', 9.8],
  ['CVE-2024-21887', 'Ivanti Connect Secure command injection', 9.1],
  ['CVE-2023-2868', 'Barracuda ESG remote command injection', 9.4],
  ['CVE-2024-5806', 'MOVEit Transfer SFTP authentication bypass', 9.1],
];

export const BUS = ['Finance', 'Retail Banking', 'Engineering', 'Operations', 'Human Resources', 'Corporate IT', 'Payments', 'Customer Service'];
export const OSES = ['Windows Server 2022', 'Windows Server 2019', 'RHEL 9.4', 'RHEL 8.10', 'Ubuntu 22.04 LTS', 'Ubuntu 24.04 LTS', 'Windows 11 Enterprise', 'PAN-OS 11.1', 'FortiOS 7.4'];
export const PREFIXES = ['web', 'app', 'db', 'dc', 'fw', 'vpn', 'k8s', 'jump', 'mail', 'file', 'erp', 'pay'];

export async function generateDemoDataset(o: DatasetOptions = DEFAULT_DATASET): Promise<void> {
  if (o.seed !== undefined) reseed(o.seed);
  const spanDays = o.historyDays + 5;
  const sla = (await getSetting('vulnSlaDays')) as Record<string, number>;

  // Assets
  const assets: (Prisma.AssetCreateManyInput & { id: string; hostname: string; missingPatches: number })[] = [];
  for (let i = 0; i < o.assets; i++) {
    const bu = pick(BUS);
    assets.push({
      id: randomUUID(),
      hostname: `${pick(PREFIXES)}-${bu.toLowerCase().replace(/[^a-z]/g, '').slice(0, 4)}-${String(i + 1).padStart(3, '0')}.corp.example`,
      ipAddress: `10.${Math.floor(between(10, 40))}.${Math.floor(between(0, 255))}.${Math.floor(between(2, 254))}`,
      os: pick(OSES),
      businessUnit: bu,
      owner: `${bu} IT Owner`,
      criticality: Math.ceil(between(0.01, 5)),
      patchCompliant: rand() > 0.12,
      missingPatches: 0,
      lastPatchedAt: daysAgo(between(1, 40)),
    });
  }
  for (const a of assets) if (!a.patchCompliant) a.missingPatches = Math.ceil(between(1, 12));
  await prisma.asset.createMany({ data: assets });

  // Vulnerabilities — remediation velocity improving over 90 days
  const vulns: Prisma.VulnerabilityCreateManyInput[] = [];
  for (let i = 0; i < o.vulnerabilities; i++) {
    const [cve, title, cvss] = pick(CVES);
    const asset = pick(assets);
    const severity: Severity = cvss >= 9 ? 'CRITICAL' : cvss >= 7 ? 'HIGH' : 'MEDIUM';
    let discoveredAt = daysAgo(between(0, spanDays * 1.3));
    const age = (Date.now() - discoveredAt.getTime()) / DAY;
    const fixProbability = severity === 'CRITICAL' ? 0.92 : severity === 'HIGH' ? 0.8 : 0.55;
    let status: VulnStatus = 'OPEN';
    let remediatedAt: Date | null = null;
    if (age > 3 && rand() < fixProbability) {
      status = 'REMEDIATED';
      const fixDays = severity === 'CRITICAL' ? between(2, 18) : between(5, 45);
      remediatedAt = new Date(Math.min(Date.now() - DAY * 0.2, discoveredAt.getTime() + fixDays * DAY));
    } else {
      // Still-open findings are mostly recent; a minority has breached its SLA.
      const slaDays = sla[severity] ?? 30;
      discoveredAt = daysAgo(rand() < 0.25 ? between(slaDays + 1, slaDays * 2) : between(0, slaDays * 0.9));
      if (rand() < 0.35) status = 'IN_PROGRESS';
    }
    vulns.push({
      assetId: asset.id,
      source: pick(['Tenable VM', 'Qualys VMDR', 'Nessus Internal']),
      externalId: `${asset.hostname}:${cve}:${i}`,
      cveId: cve,
      title,
      severity,
      cvss,
      status,
      discoveredAt,
      dueAt: dueDateFor(severity, discoveredAt, sla),
      remediatedAt,
    });
  }
  await prisma.vulnerability.createMany({ data: vulns, skipDuplicates: true });

  // Change tickets linked to a subset of in-progress findings
  const tickets = [];
  for (let i = 0; i < 14; i++) {
    tickets.push({
      id: randomUUID(),
      system: i % 2 ? 'ServiceNow' : 'Jira',
      externalKey: i % 2 ? `CHG00${41230 + i}` : `CHG-${880 + i}`,
      title: `Emergency patch window ${i + 1}: ${pick(CVES)[1]}`,
      status: pick(['Scheduled', 'Implement', 'Review', 'Closed']),
    });
  }
  await prisma.changeTicket.createMany({ data: tickets });
  const inProgress = await prisma.vulnerability.findMany({ where: { status: 'IN_PROGRESS' }, take: 40, select: { id: true } });
  for (const v of inProgress) await prisma.vulnerability.update({ where: { id: v.id }, data: { changeTicketId: pick(tickets).id } });

  // Incidents — MTTD/MTTR trending down
  const categories = ['Phishing', 'Malware', 'Unauthorised access', 'Data exfiltration', 'Ransomware precursor', 'Insider', 'DDoS'];
  const incidentTitles = [
    'Credential phishing campaign targeting finance',
    'Cobalt Strike beacon detected on endpoint',
    'Impossible travel sign-in for privileged account',
    'Suspicious large outbound transfer to cloud storage',
    'Mass file rename activity on file server',
    'Brute force against VPN gateway',
    'Malicious OAuth app consent',
    'EDR tamper attempt',
    'Web shell detected on DMZ host',
    'Anomalous service account Kerberoasting',
  ];
  const incidents: Prisma.IncidentCreateManyInput[] = [];
  for (let i = 0; i < o.incidents; i++) {
    const daysBack = between(0, spanDays);
    const improvement = 0.45 + (daysBack / spanDays) * 0.9; // older incidents slower
    const occurredAt = daysAgo(daysBack);
    const detectedAt = new Date(occurredAt.getTime() + between(0.3, 9) * improvement * 3_600_000);
    const severity: Severity = pick(['CRITICAL', 'HIGH', 'HIGH', 'MEDIUM', 'MEDIUM', 'LOW']);
    const resolved = detectedAt.getTime() < Date.now() - 2 * DAY ? rand() < 0.93 : rand() < 0.35;
    const resolvedAt = resolved ? new Date(Math.min(Date.now() - 3_600_000, detectedAt.getTime() + between(2, 40) * improvement * 3_600_000)) : null;
    let status: IncidentStatus = resolved ? pick(['RESOLVED', 'CLOSED'] as const) : pick(['NEW', 'TRIAGE', 'CONTAINED'] as const);
    if (resolvedAt && resolvedAt < detectedAt) status = 'NEW';
    const id = randomUUID();
    incidents.push({
      id,
      source: pick(['Splunk ES', 'Elastic Security', 'QRadar', 'manual']),
      externalId: id,
      title: pick(incidentTitles),
      descriptionEnc: encrypt('Seeded demo incident. Investigation notes are encrypted at rest.', `incident:${id}:description`),
      severity,
      status,
      category: pick(categories),
      occurredAt,
      detectedAt,
      respondedAt: new Date(detectedAt.getTime() + between(0.2, 3) * 3_600_000),
      resolvedAt: status === 'RESOLVED' || status === 'CLOSED' ? resolvedAt : null,
      assetsAffected: Math.ceil(between(0.01, 12)),
    });
  }
  await prisma.incident.createMany({ data: incidents });

  // Threat intel stream
  const threats: Prisma.ThreatItemCreateManyInput[] = [];
  CVES.slice(0, 22).forEach(([cve, title], i) => {
    threats.push({
      source: i % 3 === 0 ? 'MISP – FS-ISAC' : 'CISA KEV (demo)',
      sourceRef: `demo-${cve}`,
      type: 'CVE',
      title: `${cve} — ${title}`,
      summary: `Actively exploited vulnerability. Apply vendor mitigations and patches; prioritise internet-facing assets.`,
      severity: i % 4 === 0 ? 'CRITICAL' : 'HIGH',
      cveId: cve,
      publishedAt: daysAgo(between(0, 60)),
      tags: ['kev', 'exploited'],
    });
  });
  const advisories: [ThreatType, Severity, string, string, string[]][] = [
    ['RANSOMWARE', 'CRITICAL', 'LockBit 3.0 affiliates exploiting Citrix Bleed', 'Joint advisory: affiliates leverage CVE-2023-4966 for initial access, followed by RMM tool abuse and data exfiltration.', ['lockbit', 'ransomware', 'citrix']],
    ['RANSOMWARE', 'CRITICAL', 'Akira ransomware targeting Cisco ASA/FTD VPNs without MFA', 'Brute-force and credential stuffing against SSL VPN without MFA, then ESXi encryption.', ['akira', 'ransomware', 'vpn']],
    ['RANSOMWARE', 'HIGH', 'Black Basta campaign using Teams vishing + Quick Assist', 'Social engineering via Microsoft Teams leading to remote access and Qakbot/Cobalt Strike.', ['blackbasta', 'ransomware', 'social-engineering']],
    ['RANSOMWARE', 'HIGH', 'Play ransomware ESXi Linux variant', 'New Linux variant targets VMware ESXi environments, encrypting VM disks.', ['play', 'ransomware', 'esxi']],
    ['SUPPLY_CHAIN', 'CRITICAL', 'XZ Utils backdoor in liblzma 5.6.0/5.6.1', 'Malicious code in upstream tarballs enables SSH authentication bypass on affected distros.', ['supply-chain', 'xz', 'linux']],
    ['SUPPLY_CHAIN', 'HIGH', 'Compromised GitHub Action tj-actions/changed-files', 'Malicious commit exposed CI secrets in workflow logs; rotate secrets and pin actions to SHA.', ['supply-chain', 'ci-cd', 'github-actions']],
    ['SUPPLY_CHAIN', 'HIGH', 'polyfill.io CDN domain serving malicious JavaScript', 'Third-party script injection redirects mobile users; remove references and use self-hosted assets.', ['supply-chain', 'javascript', 'cdn']],
    ['SUPPLY_CHAIN', 'MEDIUM', 'Typosquatted npm packages exfiltrating environment variables', 'Dozens of packages mimic popular libraries and exfiltrate .env contents on install.', ['supply-chain', 'npm']],
    ['ADVISORY', 'HIGH', 'Nation-state targeting of edge devices for persistence', 'Advisory on living-off-the-land techniques against network appliances.', ['apt', 'edge']],
    ['ADVISORY', 'MEDIUM', 'Increase in MFA fatigue attacks against SaaS', 'Push-bombing observed against SSO tenants; enforce number matching.', ['mfa', 'identity']],
    ['IOC', 'MEDIUM', 'Cobalt Strike C2 infrastructure update', '45 new C2 IPs and domains associated with ransomware precursors.', ['c2', 'cobalt-strike']],
  ];
  advisories.forEach(([type, severity, title, summary, tags], i) =>
    threats.push({
      source: pick(['TAXII – Vendor Intel', 'MISP – FS-ISAC', 'Commercial TI']),
      sourceRef: `demo-adv-${i}`,
      type,
      title,
      summary,
      severity,
      publishedAt: daysAgo(between(0, 30)),
      impactedAssetCount: Math.floor(between(0, 25)),
      tags,
    }),
  );
  await prisma.threatItem.createMany({ data: threats });
  const { refreshImpactedAssetCounts } = await import('../connectors/ingest.js');
  await refreshImpactedAssetCounts();

  // Risk register
  const riskDefs: [string, string, number, number, string][] = [
    ['Ransomware compromise of core banking', 'Cyber', 4, 5, 'Head of Infrastructure'],
    ['Unpatched internet-facing VPN appliances', 'Vulnerability', 4, 4, 'Network Security Lead'],
    ['Third-party SaaS data breach', 'Third party', 3, 4, 'Vendor Risk Manager'],
    ['Privileged access misuse', 'Identity', 3, 5, 'IAM Lead'],
    ['Cloud storage misconfiguration', 'Cloud', 3, 3, 'Cloud Platform Owner'],
    ['Business email compromise', 'Fraud', 4, 3, 'Finance Controller'],
    ['Legacy OT systems without vendor support', 'Operational', 2, 4, 'OT Manager'],
    ['Insider data exfiltration', 'Insider', 2, 4, 'HR & Security'],
    ['DDoS on customer portal', 'Availability', 3, 2, 'Digital Channels Lead'],
    ['Software supply chain compromise (CI/CD)', 'Supply chain', 3, 4, 'Head of Engineering'],
    ['Inadequate logging on payment systems', 'Compliance', 2, 3, 'Payments Platform Owner'],
    ['Weak MFA coverage for contractors', 'Identity', 4, 3, 'IAM Lead'],
    ['Data residency non-compliance', 'Compliance', 2, 2, 'DPO'],
    ['Shadow IT SaaS adoption', 'Governance', 3, 2, 'CIO Office'],
    ['Backup restoration failure', 'Resilience', 2, 5, 'Infrastructure Manager'],
    ['Phishing-led credential theft', 'Cyber', 5, 3, 'Security Awareness Lead'],
    ['Lost/stolen unencrypted laptops', 'Endpoint', 1, 3, 'End-user Computing'],
    ['API abuse on mobile banking', 'Application', 3, 4, 'AppSec Lead'],
  ];
  const riskIds: string[] = [];
  for (const [title, category, likelihood, impact, ownerName] of riskDefs) {
    const linked = Array.from({ length: Math.ceil(between(1, 6)) }, () => pick(assets).id);
    const r = await prisma.risk.create({
      data: {
        title,
        category,
        likelihood,
        impact,
        ownerName,
        description: `${title}. Assessed under ISO 31000 using the enterprise 5x5 likelihood/impact scale.`,
        treatment: 'Mitigate — controls in progress; see linked remediation items.',
        status: likelihood * impact >= 16 ? 'MITIGATING' : 'OPEN',
        assets: { create: [...new Set(linked)].map((assetId) => ({ assetId })) },
      },
    });
    riskIds.push(r.id);
  }
  const seedActor = '00000000-0000-4000-8000-000000000000';
  for (const [idx, status] of [[6, 'PENDING'], [12, 'APPROVED'], [13, 'REJECTED']] as const) {
    const id = randomUUID();
    await prisma.riskAcceptance.create({
      data: {
        id,
        riskId: riskIds[idx]!,
        justificationEnc: encrypt('Compensating controls in place (network segmentation, enhanced monitoring). Replacement planned next fiscal year.', `risk_acceptance:${id}:justification`),
        requestedById: seedActor,
        requestedByName: 'Demo Seed',
        status,
        decidedByName: status === 'PENDING' ? null : 'Demo Seed',
        decidedAt: status === 'PENDING' ? null : daysAgo(3),
        decisionNote: status === 'PENDING' ? null : 'Seeded decision',
        expiresAt: new Date(Date.now() + 120 * DAY),
      },
    });
    if (status === 'APPROVED') await prisma.risk.update({ where: { id: riskIds[idx]! }, data: { status: 'ACCEPTED' } });
  }

  await seedKpiHistory(o.historyDays);
}

/**
 * N days of daily KPI history that converges on today's *computed* values, so trend
 * charts and 7-day deltas are consistent with the live dataset (improving posture).
 * `pastFactor` = how the metric looked N days ago relative to today.
 */
async function seedKpiHistory(days: number): Promise<void> {
  const { computeKpis } = await import('../modules/kpi/kpi.service.js');
  const now = await computeKpis();
  const plan: [keyof typeof now, number, boolean][] = [
    ['mttdHours', 2.2, false],
    ['mttrHours', 2.0, false],
    ['patchCompliancePct', 0.88, false],
    ['remediationVelocityPerWeek', 0.6, false],
    ['meanDaysToRemediate', 1.7, false],
    ['openCriticalFindings', 2.3, true],
    ['openHighFindings', 1.6, true],
    ['overdueCriticalFindings', 3.0, true],
    ['activeIncidents', 1.5, true],
    ['risksAboveAppetite', 1.6, true],
  ];
  const snapshots: Prisma.MetricSnapshotCreateManyInput[] = [];
  for (let d = days; d >= 1; d--) {
    const t = d / days; // 1 → 0 as we approach today
    const capturedAt = new Date(daysAgo(d).setUTCHours(23, 0, 0, 0));
    for (const [metric, pastFactor, integer] of plan) {
      const current = now[metric];
      if (typeof current !== 'number') continue;
      const base = current * (1 + (pastFactor - 1) * t);
      let value = base * (1 + between(-0.04, 0.04));
      if (metric === 'patchCompliancePct') value = Math.min(99.5, value);
      value = integer ? Math.round(value) : Math.round(value * 10) / 10;
      snapshots.push({ metric, value: Math.max(0, value), capturedAt });
    }
  }
  await prisma.metricSnapshot.createMany({ data: snapshots });
}

/** Removes operational demo data. Audit records, users, sessions, connectors, settings and KRI definitions are kept. */
export async function clearDemoDataset(): Promise<void> {
  await prisma.$transaction([
    prisma.riskAcceptance.deleteMany(),
    prisma.riskAsset.deleteMany(),
    prisma.risk.deleteMany(),
    prisma.vulnerability.deleteMany(),
    prisma.changeTicket.deleteMany(),
    prisma.asset.deleteMany(),
    prisma.incident.deleteMany(),
    prisma.threatItem.deleteMany(),
    prisma.metricSnapshot.deleteMany(),
    prisma.kriBreach.deleteMany(),
  ]);
}
