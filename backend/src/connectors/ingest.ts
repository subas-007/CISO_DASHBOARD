/**
 * Persists normalised connector output. Only normalised fields are stored — raw
 * third-party payloads never reach the database or logs (zero data retention).
 */
import type { Severity } from '@prisma/client';
import { prisma } from '../lib/prisma.js';
import { getSetting } from '../modules/settings/settings.service.js';
import type { NormalizedBatch } from './types.js';

export interface IngestCounts {
  incidents: number;
  vulnerabilities: number;
  assets: number;
  changes: number;
  threats: number;
}

async function upsertAsset(hostname: string, data: { ipAddress?: string | null; os?: string | null }) {
  return prisma.asset.upsert({
    where: { hostname },
    create: { hostname, ipAddress: data.ipAddress ?? null, os: data.os ?? null },
    update: {
      ...(data.ipAddress ? { ipAddress: data.ipAddress } : {}),
      ...(data.os ? { os: data.os } : {}),
    },
    select: { id: true },
  });
}

export function dueDateFor(severity: Severity, discoveredAt: Date, sla: Record<string, number>): Date | null {
  const days = sla[severity];
  return days ? new Date(discoveredAt.getTime() + days * 86_400_000) : null;
}

/** Recomputes impacted-asset counts for CVE-linked threat items. */
export async function refreshImpactedAssetCounts(): Promise<void> {
  const rows = await prisma.$queryRaw<{ cveId: string; n: bigint }[]>`
    SELECT v."cveId" AS "cveId", COUNT(DISTINCT v."assetId") AS n
    FROM vulnerabilities v
    WHERE v."cveId" IS NOT NULL AND v.status IN ('OPEN', 'IN_PROGRESS')
    GROUP BY v."cveId"`;
  const counts = new Map(rows.map((r) => [r.cveId, Number(r.n)]));
  const threats = await prisma.threatItem.findMany({ where: { cveId: { not: null } }, select: { id: true, cveId: true, impactedAssetCount: true } });
  for (const t of threats) {
    const n = counts.get(t.cveId!) ?? 0;
    if (n !== t.impactedAssetCount) await prisma.threatItem.update({ where: { id: t.id }, data: { impactedAssetCount: n } });
  }
}

export async function ingestBatch(source: string, batch: NormalizedBatch): Promise<IngestCounts> {
  const counts: IngestCounts = { incidents: 0, vulnerabilities: 0, assets: 0, changes: 0, threats: 0 };
  const sla = await getSetting('vulnSlaDays');

  for (const i of batch.incidents ?? []) {
    if (!i.externalId) continue;
    await prisma.incident.upsert({
      where: { source_externalId: { source, externalId: i.externalId } },
      create: {
        source,
        externalId: i.externalId,
        title: i.title,
        severity: i.severity,
        status: i.status ?? 'NEW',
        category: i.category ?? 'SIEM',
        occurredAt: i.occurredAt,
        detectedAt: i.detectedAt,
        respondedAt: i.respondedAt ?? null,
        resolvedAt: i.resolvedAt ?? null,
        assetsAffected: i.assetsAffected ?? 0,
      },
      update: {
        title: i.title,
        severity: i.severity,
        ...(i.status ? { status: i.status } : {}),
        ...(i.respondedAt ? { respondedAt: i.respondedAt } : {}),
        ...(i.resolvedAt ? { resolvedAt: i.resolvedAt } : {}),
      },
    });
    counts.incidents++;
  }

  const assetIds = new Map<string, string>();
  for (const v of batch.vulnerabilities ?? []) {
    if (!v.externalId) continue;
    let assetId = assetIds.get(v.hostname);
    if (!assetId) {
      assetId = (await upsertAsset(v.hostname, { ipAddress: v.ipAddress })).id;
      assetIds.set(v.hostname, assetId);
      counts.assets++;
    }
    const fixed = !!v.fixed;
    await prisma.vulnerability.upsert({
      where: { source_externalId: { source, externalId: v.externalId } },
      create: {
        assetId,
        source,
        externalId: v.externalId,
        cveId: v.cveId ?? null,
        title: v.title,
        severity: v.severity,
        cvss: v.cvss ?? null,
        status: fixed ? 'REMEDIATED' : 'OPEN',
        discoveredAt: v.discoveredAt,
        dueAt: dueDateFor(v.severity, v.discoveredAt, sla),
        remediatedAt: fixed ? v.remediatedAt ?? new Date() : null,
      },
      update: {
        title: v.title,
        severity: v.severity,
        cvss: v.cvss ?? null,
        ...(fixed ? { status: 'REMEDIATED', remediatedAt: v.remediatedAt ?? new Date() } : {}),
      },
    });
    counts.vulnerabilities++;
  }

  for (const p of batch.patches ?? []) {
    await prisma.asset.upsert({
      where: { hostname: p.hostname },
      create: {
        hostname: p.hostname,
        ipAddress: p.ipAddress ?? null,
        os: p.os ?? null,
        patchCompliant: p.compliant,
        missingPatches: p.missingPatches,
        lastPatchedAt: p.lastPatchedAt ?? null,
      },
      update: {
        patchCompliant: p.compliant,
        missingPatches: p.missingPatches,
        ...(p.lastPatchedAt ? { lastPatchedAt: p.lastPatchedAt } : {}),
        ...(p.os ? { os: p.os } : {}),
        ...(p.ipAddress ? { ipAddress: p.ipAddress } : {}),
      },
    });
    counts.assets++;
  }

  for (const c of batch.changes ?? []) {
    if (!c.externalKey) continue;
    await prisma.changeTicket.upsert({
      where: { system_externalKey: { system: source, externalKey: c.externalKey } },
      create: { system: source, externalKey: c.externalKey, title: c.title, status: c.status, url: c.url ?? null, sourceUpdatedAt: c.updatedAt ?? null },
      update: { title: c.title, status: c.status, url: c.url ?? null, sourceUpdatedAt: c.updatedAt ?? null },
    });
    counts.changes++;
  }

  for (const t of batch.threats ?? []) {
    if (!t.sourceRef) continue;
    await prisma.threatItem.upsert({
      where: { source_sourceRef: { source, sourceRef: t.sourceRef } },
      create: {
        source,
        sourceRef: t.sourceRef,
        type: t.type,
        title: t.title,
        summary: t.summary,
        severity: t.severity,
        cveId: t.cveId ?? null,
        publishedAt: t.publishedAt,
        tags: t.tags,
        impactedAssetCount: t.impactedAssetCount ?? 0,
      },
      update: { title: t.title, summary: t.summary, severity: t.severity, tags: t.tags },
    });
    counts.threats++;
  }

  if (counts.threats > 0 || counts.vulnerabilities > 0) await refreshImpactedAssetCounts();
  return counts;
}
