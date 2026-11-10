/** Patch management connectors: WSUS (via reporting bridge), Ansible AWX/AAP, Red Hat Satellite. */
import { z } from 'zod';
import { defineAdapter, type NormPatchStatus } from '../types.js';
import { normHost, optDate, str } from './util.js';

export const wsus = defineAdapter({
  vendor: 'wsus',
  displayName: 'Microsoft WSUS (reporting bridge)',
  category: 'PATCH',
  description:
    'WSUS has no REST API; deploy tools/wsus-bridge.ps1 on the WSUS server behind HTTPS (mTLS recommended) to expose a JSON compliance report.',
  supportedAuth: ['API_KEY', 'MTLS'],
  defaultPollSec: 3600,
  settingsFields: [{ key: 'reportPath', label: 'Report path', type: 'string', required: true, placeholder: '/wsus/compliance.json' }],
  settingsSchema: z.object({ reportPath: z.string().regex(/^\/[A-Za-z0-9/_.-]{1,200}$/).default('/wsus/compliance.json') }).strict(),
  async test({ http }, s) {
    const rows = await http.call<unknown[]>(s.reportPath);
    return `WSUS bridge reachable (${Array.isArray(rows) ? rows.length : 0} computers)`;
  },
  async sync({ http }, s) {
    const rows = await http.call<Record<string, unknown>[]>(s.reportPath);
    const patches: NormPatchStatus[] = (rows ?? []).map((r) => {
      const needed = Number(r.neededCount ?? 0) + Number(r.failedCount ?? 0);
      return {
        hostname: normHost(r.computerName),
        ipAddress: str(r.ipAddress, 64) || null,
        os: str(r.os, 120) || null,
        compliant: needed === 0,
        missingPatches: needed,
        lastPatchedAt: optDate(r.lastSyncTime),
      };
    });
    return { patches };
  },
});

export const ansible = defineAdapter({
  vendor: 'ansible',
  displayName: 'Ansible Automation Platform / AWX',
  category: 'PATCH',
  description: 'Derives patch compliance from inventory hosts and their last patch job outcome.',
  supportedAuth: ['API_KEY', 'OAUTH2', 'BASIC'],
  defaultPollSec: 1800,
  settingsFields: [{ key: 'inventoryId', label: 'Inventory ID', type: 'number', required: true }],
  settingsSchema: z.object({ inventoryId: z.coerce.number().int().positive(), maxPages: z.coerce.number().int().min(1).max(100).default(20) }).strict(),
  async test({ http }) {
    const ping = await http.call<{ version?: string }>('/api/v2/ping/');
    return `Connected to AWX/AAP ${ping.version ?? ''}`.trim();
  },
  async sync({ http }, s) {
    const patches: NormPatchStatus[] = [];
    let next: string | null = `/api/v2/inventories/${s.inventoryId}/hosts/?page_size=200`;
    for (let page = 0; next && page < s.maxPages; page++) {
      const res: { next?: string | null; results?: Record<string, any>[] } = await http.call(next);
      for (const h of res.results ?? []) {
        const last = h.summary_fields?.last_job;
        const failing = Boolean(h.has_active_failures) || (last && last.status !== 'successful');
        patches.push({
          hostname: normHost(h.name),
          compliant: !failing,
          missingPatches: failing ? 1 : 0,
          lastPatchedAt: optDate(last?.finished),
        });
      }
      next = res.next ?? null;
    }
    return { patches };
  },
});

export const satellite = defineAdapter({
  vendor: 'satellite',
  displayName: 'Red Hat Satellite',
  category: 'PATCH',
  description: 'Uses applicable security errata counts per content host.',
  supportedAuth: ['BASIC', 'MTLS'],
  defaultPollSec: 3600,
  settingsFields: [{ key: 'organizationId', label: 'Organization ID (optional)', type: 'number' }],
  settingsSchema: z
    .object({
      organizationId: z.coerce.number().int().positive().optional(),
      maxPages: z.coerce.number().int().min(1).max(100).default(20),
    })
    .strict(),
  async test({ http }) {
    const st = await http.call<{ version?: string; satellite_version?: string }>('/api/status');
    return `Connected to Satellite ${st.satellite_version ?? st.version ?? ''}`.trim();
  },
  async sync({ http }, s) {
    const patches: NormPatchStatus[] = [];
    for (let page = 1; page <= s.maxPages; page++) {
      const res = await http.call<{ results?: Record<string, any>[]; total?: number; per_page?: number }>('/api/v2/hosts', {
        query: { per_page: 200, page, organization_id: s.organizationId },
      });
      const results = res.results ?? [];
      for (const h of results) {
        const security = Number(h.content_facet_attributes?.errata_counts?.security ?? 0);
        patches.push({
          hostname: normHost(h.name),
          ipAddress: str(h.ip, 64) || null,
          os: str(h.operatingsystem_name, 120) || null,
          compliant: security === 0,
          missingPatches: security,
          lastPatchedAt: optDate(h.last_report),
        });
      }
      if (results.length < 200) break;
    }
    return { patches };
  },
});
