/**
 * Generic REST/JSON adapters — one per category — so any tool with a JSON API can be
 * integrated by configuration alone: endpoint path, field mapping (dot paths), and one
 * of the common pagination conventions:
 *
 *   none    single request
 *   offset  ?offset=N&limit=M            (ServiceNow, Qualys-style)
 *   page    ?page=N&per_page=M           (GitHub, many SaaS APIs)
 *   cursor  ?cursor=<token from body>    (Slack, Okta-style, CrowdStrike)
 *   link    RFC 8288 `Link: <…>; rel="next"` response header
 *
 * Incremental polling sends the last successful sync time in a configurable query
 * parameter (ISO 8601, Unix seconds or milliseconds).
 */
import { z } from 'zod';
import type { ConnectorCategory, IncidentStatus } from '@prisma/client';
import { defineAdapter, type AdapterContext, type FieldSpec, type NormalizedBatch } from '../types.js';
import { asArray, extractCve, getPath, normHost, optDate, severityFromScore, severityFromText, str, toDate } from './util.js';

const fieldPath = z.string().regex(/^[A-Za-z0-9_.@$-]{0,100}$/, 'dot path such as data.attributes.title');
const paramName = z.string().regex(/^[A-Za-z0-9_.[\]-]{1,64}$/);

const paging = {
  path: z.string().regex(/^\/[A-Za-z0-9/_.~%-]{0,300}$/, 'must start with / and contain no query string'),
  testPath: z.string().regex(/^(\/[A-Za-z0-9/_.~%-]{0,300})?$/).default(''),
  itemsPath: fieldPath.default(''),
  pagination: z.enum(['none', 'offset', 'page', 'cursor', 'link']).default('none'),
  pageSize: z.coerce.number().int().min(1).max(1000).default(100),
  pageSizeParam: paramName.default('limit'),
  offsetParam: paramName.default('offset'),
  pageParam: paramName.default('page'),
  firstPage: z.coerce.number().int().min(0).max(1).default(1),
  cursorParam: paramName.default('cursor'),
  nextCursorPath: fieldPath.default('next_cursor'),
  maxPages: z.coerce.number().int().min(1).max(100).default(20),
  sinceParam: z.union([z.literal(''), paramName]).default(''),
  sinceFormat: z.enum(['iso', 'epoch', 'epoch_ms']).default('iso'),
};

export const PAGING_FIELDS: FieldSpec[] = [
  { key: 'path', label: 'Endpoint path', type: 'string', required: true, placeholder: '/api/v2/alerts' },
  { key: 'testPath', label: 'Health-check path (optional)', type: 'string', placeholder: '/api/v2/status' },
  { key: 'itemsPath', label: 'Items array path', type: 'string', placeholder: 'data.items (empty = response root)' },
  {
    key: 'pagination',
    label: 'Pagination',
    type: 'select',
    options: [
      { value: 'none', label: 'None (single request)' },
      { value: 'offset', label: 'Offset / limit' },
      { value: 'page', label: 'Page number / page size' },
      { value: 'cursor', label: 'Cursor token in body' },
      { value: 'link', label: 'RFC 8288 Link header' },
    ],
  },
  { key: 'pageSize', label: 'Page size', type: 'number', placeholder: '100' },
  { key: 'pageSizeParam', label: 'Page size parameter', type: 'string', placeholder: 'limit' },
  { key: 'offsetParam', label: 'Offset parameter', type: 'string', placeholder: 'offset' },
  { key: 'pageParam', label: 'Page parameter', type: 'string', placeholder: 'page' },
  { key: 'firstPage', label: 'First page number', type: 'select', options: [{ value: 1, label: '1' }, { value: 0, label: '0' }] },
  { key: 'cursorParam', label: 'Cursor parameter', type: 'string', placeholder: 'cursor' },
  { key: 'nextCursorPath', label: 'Next-cursor path in body', type: 'string', placeholder: 'meta.next_cursor' },
  { key: 'maxPages', label: 'Maximum pages per poll', type: 'number', placeholder: '20' },
  { key: 'sinceParam', label: 'Incremental "since" parameter (optional)', type: 'string', placeholder: 'updated_since' },
  { key: 'sinceFormat', label: '"Since" format', type: 'select', options: [{ value: 'iso', label: 'ISO 8601' }, { value: 'epoch', label: 'Unix seconds' }, { value: 'epoch_ms', label: 'Unix milliseconds' }] },
];

const MAX_RECORDS = 5000;

type Paging = { [K in keyof typeof paging]: z.infer<(typeof paging)[K]> };

function sinceValue(since: Date, fmt: Paging['sinceFormat']): string {
  if (fmt === 'epoch') return String(Math.floor(since.getTime() / 1000));
  if (fmt === 'epoch_ms') return String(since.getTime());
  return since.toISOString();
}

function nextLink(header: string | string[] | undefined, base: URL): string | null {
  const raw = Array.isArray(header) ? header.join(',') : header;
  if (!raw) return null;
  for (const part of raw.split(',')) {
    const m = /<([^>]+)>\s*;\s*rel="?next"?/i.exec(part.trim());
    if (m) return new URL(m[1]!, base).toString();
  }
  return null;
}

/** Fetches every page according to the configured convention (bounded). */
export async function fetchAllItems({ http, since, baseUrl }: AdapterContext, s: Paging): Promise<unknown[]> {
  const items: unknown[] = [];
  const baseQuery: Record<string, string | number> = {};
  if (s.sinceParam) baseQuery[s.sinceParam] = sinceValue(since, s.sinceFormat);

  let path: string = s.path;
  let cursor: string | null = null;
  for (let page = 0; page < s.maxPages && items.length < MAX_RECORDS; page++) {
    const query: Record<string, string | number> = { ...baseQuery };
    if (s.pagination === 'offset') Object.assign(query, { [s.offsetParam]: page * s.pageSize, [s.pageSizeParam]: s.pageSize });
    if (s.pagination === 'page') Object.assign(query, { [s.pageParam]: s.firstPage + page, [s.pageSizeParam]: s.pageSize });
    if (s.pagination === 'cursor') {
      query[s.pageSizeParam] = s.pageSize;
      if (cursor) query[s.cursorParam] = cursor;
    }
    if (s.pagination === 'link' && page === 0) query[s.pageSizeParam] = s.pageSize;

    const res = await http.callWithMeta(path, { query: s.pagination === 'link' && page > 0 ? {} : query });
    const batch = asArray(getPath(res.body, s.itemsPath) as unknown[]);
    items.push(...batch);

    if (s.pagination === 'none') break;
    if (s.pagination === 'offset' || s.pagination === 'page') {
      if (batch.length < s.pageSize) break;
    } else if (s.pagination === 'cursor') {
      const next = str(getPath(res.body, s.nextCursorPath), 2000);
      if (!next || next === cursor || batch.length === 0) break;
      cursor = next;
    } else if (s.pagination === 'link') {
      const next = nextLink(res.headers['link'], baseUrl);
      if (!next) break;
      path = next; // same-origin check enforced by the HTTP client
    }
  }
  return items.slice(0, MAX_RECORDS);
}

async function testGeneric(ctx: AdapterContext, s: Paging): Promise<string> {
  if (s.testPath) {
    await ctx.http.call(s.testPath);
    return `Endpoint reachable (${s.testPath})`;
  }
  const res = await ctx.http.callWithMeta(s.path, { query: s.pagination === 'none' ? {} : { [s.pageSizeParam]: 1 } });
  const items = getPath(res.body, s.itemsPath);
  return `Endpoint reachable — ${Array.isArray(items) ? 'items array found' : 'WARNING: no array at items path'} ("${s.itemsPath || '<root>'}")`;
}

const map = (key: string, label: string, placeholder: string): FieldSpec => ({ key, label, type: 'string', placeholder });

function makeGeneric<M extends z.ZodRawShape>(opts: {
  vendor: string;
  displayName: string;
  category: ConnectorCategory;
  description: string;
  mapping: M;
  mappingFields: FieldSpec[];
  normalise: (items: unknown[], m: z.infer<z.ZodObject<M>>) => NormalizedBatch;
}) {
  const schema = z.object({ ...paging, ...opts.mapping }).strict();
  return defineAdapter({
    vendor: opts.vendor,
    displayName: opts.displayName,
    category: opts.category,
    description: opts.description,
    supportedAuth: ['NONE', 'API_KEY', 'BASIC', 'OAUTH2', 'MTLS'],
    defaultPollSec: 900,
    settingsFields: [...PAGING_FIELDS, ...opts.mappingFields],
    settingsSchema: schema,
    test: (ctx, s) => testGeneric(ctx, s as unknown as Paging),
    async sync(ctx, s) {
      const items = await fetchAllItems(ctx, s as unknown as Paging);
      return opts.normalise(items, s as z.infer<z.ZodObject<M>>);
    },
  });
}

function incidentStatus(v: unknown): IncidentStatus {
  const t = String(v ?? '').toLowerCase();
  if (/clos|resolv|done|complete|fixed/.test(t)) return 'RESOLVED';
  if (/contain/.test(t)) return 'CONTAINED';
  if (/triage|investigat|progress|assigned|ack/.test(t)) return 'TRIAGE';
  return 'NEW';
}

const truthy = (v: unknown) => v === true || /^(true|yes|1|compliant|ok|patched|up[- ]?to[- ]?date)$/i.test(String(v ?? '').trim());

export const genericSiem = makeGeneric({
  vendor: 'generic_siem',
  displayName: 'Generic SIEM / XDR (REST JSON)',
  category: 'SIEM',
  description: 'Any SIEM, XDR or SOAR exposing alerts/incidents over a JSON REST API (Sentinel, Chronicle, CrowdStrike, Sumo Logic, Wazuh…).',
  mapping: {
    idField: fieldPath.default('id'),
    titleField: fieldPath.default('title'),
    severityField: fieldPath.default('severity'),
    occurredField: fieldPath.default('created_at'),
    detectedField: fieldPath.default(''),
    statusField: fieldPath.default('status'),
    resolvedField: fieldPath.default('resolved_at'),
    categoryField: fieldPath.default('category'),
    assetsField: fieldPath.default(''),
  },
  mappingFields: [
    map('idField', 'ID field', 'id'),
    map('titleField', 'Title field', 'title'),
    map('severityField', 'Severity field (text or 0-10 score)', 'severity'),
    map('occurredField', 'Occurred-at field', 'created_at'),
    map('detectedField', 'Detected-at field (optional)', 'detected_at'),
    map('statusField', 'Status field', 'status'),
    map('resolvedField', 'Resolved-at field', 'resolved_at'),
    map('categoryField', 'Category field', 'category'),
    map('assetsField', 'Affected-asset count field (optional)', 'asset_count'),
  ],
  normalise: (items, m) => ({
    incidents: items
      .map((it) => {
        const occurred = toDate(getPath(it, m.occurredField));
        const sevRaw = getPath(it, m.severityField);
        const status = incidentStatus(getPath(it, m.statusField));
        const resolvedAt = optDate(getPath(it, m.resolvedField));
        return {
          externalId: str(getPath(it, m.idField), 200),
          title: str(getPath(it, m.titleField), 300) || 'SIEM alert',
          severity: typeof sevRaw === 'number' ? severityFromScore(sevRaw) : severityFromText(sevRaw),
          occurredAt: occurred,
          detectedAt: m.detectedField ? toDate(getPath(it, m.detectedField), occurred) : occurred,
          status: resolvedAt && status === 'NEW' ? 'RESOLVED' : status,
          resolvedAt,
          category: str(getPath(it, m.categoryField), 60) || 'SIEM',
          assetsAffected: m.assetsField ? Number(getPath(it, m.assetsField)) || undefined : undefined,
        };
      })
      .filter((i) => i.externalId),
  }),
});

export const genericVulnerability = makeGeneric({
  vendor: 'generic_vulnerability',
  displayName: 'Generic vulnerability scanner (REST JSON)',
  category: 'VULNERABILITY',
  description: 'Any scanner or exposure-management platform with a JSON findings API (Rapid7, Wiz, Snyk, Defender TVM, OpenVAS bridges…).',
  mapping: {
    idField: fieldPath.default('id'),
    hostField: fieldPath.default('asset.hostname'),
    ipField: fieldPath.default('asset.ip'),
    cveField: fieldPath.default('cve'),
    titleField: fieldPath.default('title'),
    severityField: fieldPath.default('severity'),
    cvssField: fieldPath.default('cvss'),
    discoveredField: fieldPath.default('first_seen'),
    stateField: fieldPath.default('state'),
    remediatedField: fieldPath.default('fixed_at'),
  },
  mappingFields: [
    map('idField', 'Finding ID field', 'id'),
    map('hostField', 'Hostname field', 'asset.hostname'),
    map('ipField', 'IP address field', 'asset.ip'),
    map('cveField', 'CVE field', 'cve'),
    map('titleField', 'Title field', 'title'),
    map('severityField', 'Severity field', 'severity'),
    map('cvssField', 'CVSS score field', 'cvss'),
    map('discoveredField', 'First-seen field', 'first_seen'),
    map('stateField', 'State field (fixed/closed = remediated)', 'state'),
    map('remediatedField', 'Fixed-at field', 'fixed_at'),
  ],
  normalise: (items, m) => ({
    vulnerabilities: items
      .map((it) => {
        const cvssRaw = Number(getPath(it, m.cvssField));
        const cvss = Number.isFinite(cvssRaw) && cvssRaw > 0 ? Math.min(10, cvssRaw) : null;
        const sevText = getPath(it, m.severityField);
        const title = str(getPath(it, m.titleField), 300);
        const fixed = /fix|remediat|closed|resolved/i.test(String(getPath(it, m.stateField) ?? ''));
        return {
          externalId: str(getPath(it, m.idField), 200),
          hostname: normHost(getPath(it, m.hostField)),
          ipAddress: str(getPath(it, m.ipField), 45) || null,
          cveId: extractCve(getPath(it, m.cveField), title),
          title: title || 'Vulnerability finding',
          severity: sevText != null && sevText !== '' ? severityFromText(sevText, severityFromScore(cvss)) : severityFromScore(cvss),
          cvss,
          discoveredAt: toDate(getPath(it, m.discoveredField)),
          fixed,
          remediatedAt: fixed ? optDate(getPath(it, m.remediatedField)) ?? new Date() : null,
        };
      })
      .filter((v) => v.externalId),
  }),
});

export const genericPatch = makeGeneric({
  vendor: 'generic_patch',
  displayName: 'Generic patch / endpoint management (REST JSON)',
  category: 'PATCH',
  description: 'Any patch or endpoint-management tool exposing per-device compliance (Intune, SCCM/MECM bridges, Tanium, ManageEngine, Automox…).',
  mapping: {
    hostField: fieldPath.default('hostname'),
    ipField: fieldPath.default('ip'),
    osField: fieldPath.default('os'),
    compliantField: fieldPath.default('compliant'),
    missingField: fieldPath.default('missing_patches'),
    lastPatchedField: fieldPath.default('last_patched'),
  },
  mappingFields: [
    map('hostField', 'Hostname field', 'hostname'),
    map('ipField', 'IP address field', 'ip'),
    map('osField', 'Operating system field', 'os'),
    map('compliantField', 'Compliant field (boolean or text)', 'compliant'),
    map('missingField', 'Missing-patch count field', 'missing_patches'),
    map('lastPatchedField', 'Last-patched field', 'last_patched'),
  ],
  normalise: (items, m) => ({
    patches: items
      .map((it) => {
        const missing = Math.max(0, Math.floor(Number(getPath(it, m.missingField)) || 0));
        const compliantRaw = getPath(it, m.compliantField);
        return {
          hostname: normHost(getPath(it, m.hostField)),
          ipAddress: str(getPath(it, m.ipField), 45) || null,
          os: str(getPath(it, m.osField), 120) || null,
          compliant: compliantRaw === undefined || compliantRaw === null || compliantRaw === '' ? missing === 0 : truthy(compliantRaw),
          missingPatches: missing,
          lastPatchedAt: optDate(getPath(it, m.lastPatchedField)),
        };
      })
      .filter((p) => p.hostname !== 'unknown-host'),
  }),
});

export const genericChange = makeGeneric({
  vendor: 'generic_change',
  displayName: 'Generic ITSM / change management (REST JSON)',
  category: 'CHANGE',
  description: 'Any ITSM tool exposing change requests over REST (BMC Helix, Freshservice, Cherwell, TOPdesk, GLPI…).',
  mapping: {
    keyField: fieldPath.default('number'),
    titleField: fieldPath.default('summary'),
    statusField: fieldPath.default('state'),
    urlField: fieldPath.default('url'),
    updatedField: fieldPath.default('updated_at'),
  },
  mappingFields: [
    map('keyField', 'Change key field', 'number'),
    map('titleField', 'Title field', 'summary'),
    map('statusField', 'Status field', 'state'),
    map('urlField', 'Ticket URL field (https only)', 'url'),
    map('updatedField', 'Updated-at field', 'updated_at'),
  ],
  normalise: (items, m) => ({
    changes: items
      .map((it) => {
        const url = str(getPath(it, m.urlField), 500);
        return {
          externalKey: str(getPath(it, m.keyField), 64),
          title: str(getPath(it, m.titleField), 300) || 'Change request',
          status: str(getPath(it, m.statusField), 40) || 'Unknown',
          url: /^https:\/\//i.test(url) ? url : null,
          updatedAt: optDate(getPath(it, m.updatedField)),
        };
      })
      .filter((c) => c.externalKey),
  }),
});
