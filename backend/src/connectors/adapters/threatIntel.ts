/** Threat intelligence connectors: CISA KEV, MISP, STIX/TAXII 2.1, generic commercial REST. */
import { z } from 'zod';
import type { Severity, ThreatType } from '@prisma/client';
import { defineAdapter, type NormThreat } from '../types.js';
import { asArray, extractCve, getPath, severityFromText, str, toDate } from './util.js';

function classify(tags: string[], text: string): ThreatType {
  const hay = `${tags.join(' ')} ${text}`.toLowerCase();
  if (/ransom/.test(hay)) return 'RANSOMWARE';
  if (/supply[- ]?chain|dependency|package|npm|pypi|third[- ]party/.test(hay)) return 'SUPPLY_CHAIN';
  if (/cve-\d{4}/.test(hay)) return 'CVE';
  return 'ADVISORY';
}

export const cisaKev = defineAdapter({
  vendor: 'cisa_kev',
  displayName: 'CISA Known Exploited Vulnerabilities',
  category: 'THREAT_INTEL',
  description: 'Public CISA KEV catalogue (no credentials). Flags known ransomware campaign use.',
  supportedAuth: ['NONE'],
  defaultPollSec: 21600,
  defaultBaseUrl: 'https://www.cisa.gov',
  settingsFields: [
    { key: 'path', label: 'Feed path', type: 'string', placeholder: '/sites/default/files/feeds/known_exploited_vulnerabilities.json' },
    { key: 'maxItems', label: 'Max items per poll', type: 'number' },
  ],
  settingsSchema: z
    .object({
      path: z.string().regex(/^\/[A-Za-z0-9/_.-]{1,200}$/).default('/sites/default/files/feeds/known_exploited_vulnerabilities.json'),
      maxItems: z.coerce.number().int().min(1).max(5000).default(300),
    })
    .strict(),
  async test({ http }, s) {
    const feed = await http.call<{ catalogVersion?: string; count?: number }>(s.path);
    return `KEV catalogue v${feed.catalogVersion ?? '?'} (${feed.count ?? 0} entries)`;
  },
  async sync({ http, since }, s) {
    const feed = await http.call<{ vulnerabilities?: Record<string, string>[] }>(s.path);
    const threats: NormThreat[] = (feed.vulnerabilities ?? [])
      .filter((v) => toDate(v.dateAdded) >= since)
      .slice(0, s.maxItems)
      .map((v) => {
        const ransomware = String(v.knownRansomwareCampaignUse).toLowerCase() === 'known';
        return {
          sourceRef: str(v.cveID, 32),
          type: ransomware ? 'RANSOMWARE' : 'CVE',
          title: `${str(v.cveID, 32)} — ${str(v.vulnerabilityName, 240)}`,
          summary: str(`${v.shortDescription ?? ''} Required action: ${v.requiredAction ?? ''} (due ${v.dueDate ?? 'n/a'})`, 2000),
          severity: ransomware ? 'CRITICAL' : 'HIGH',
          cveId: extractCve(v.cveID),
          publishedAt: toDate(v.dateAdded),
          tags: ['kev', str(v.vendorProject, 60), str(v.product, 60), ...(ransomware ? ['ransomware'] : [])].filter(Boolean),
        };
      });
    return { threats };
  },
});

export const misp = defineAdapter({
  vendor: 'misp',
  displayName: 'MISP Threat Sharing',
  category: 'THREAT_INTEL',
  description: 'Pulls published events via /events/restSearch.',
  supportedAuth: ['API_KEY', 'MTLS'],
  defaultPollSec: 900,
  settingsFields: [{ key: 'limit', label: 'Max events per poll', type: 'number' }],
  settingsSchema: z.object({ limit: z.coerce.number().int().min(1).max(5000).default(500) }).strict(),
  async test({ http }) {
    const v = await http.call<{ version?: string }>('/servers/getVersion');
    return `Connected to MISP ${v.version ?? ''}`.trim();
  },
  async sync({ http, since }, s) {
    const res = await http.call<{ response?: { Event: Record<string, any> }[] }>('/events/restSearch', {
      method: 'POST',
      json: { returnFormat: 'json', timestamp: Math.floor(since.getTime() / 1000), published: true, limit: s.limit, includeEventTags: true },
    });
    const levels: Record<string, Severity> = { '1': 'HIGH', '2': 'MEDIUM', '3': 'LOW', '4': 'INFO' };
    const threats: NormThreat[] = (res.response ?? []).map(({ Event: e }) => {
      const tags = asArray<{ name?: string }>(e.Tag).map((t) => str(t.name, 60)).filter(Boolean);
      const vulnAttr = asArray<Record<string, string>>(e.Attribute).find((a) => a.type === 'vulnerability');
      const title = str(e.info, 300);
      const type = vulnAttr ? 'CVE' : classify(tags, title);
      let severity = levels[String(e.threat_level_id)] ?? 'MEDIUM';
      if (type === 'RANSOMWARE' && severity !== 'CRITICAL') severity = 'CRITICAL';
      return {
        sourceRef: str(e.uuid ?? e.id, 64),
        type,
        title,
        summary: str(`MISP event ${e.id} from ${e.Orgc?.name ?? 'unknown org'}. ${asArray(e.Attribute).length} attributes.`, 2000),
        severity,
        cveId: extractCve(vulnAttr?.value, title),
        publishedAt: toDate(e.publish_timestamp ?? e.date),
        tags: tags.slice(0, 15),
      };
    });
    return { threats };
  },
});

export const taxii = defineAdapter({
  vendor: 'taxii',
  displayName: 'STIX / TAXII 2.1 Collection',
  category: 'THREAT_INTEL',
  description: 'Polls a TAXII 2.1 collection; maps STIX vulnerability, malware, report and indicator objects.',
  supportedAuth: ['API_KEY', 'BASIC', 'MTLS', 'OAUTH2'],
  defaultPollSec: 1800,
  settingsFields: [
    { key: 'apiRoot', label: 'API root path', type: 'string', required: true, placeholder: '/taxii2/api1/' },
    { key: 'collectionId', label: 'Collection ID', type: 'string', required: true },
    { key: 'limit', label: 'Max objects per poll', type: 'number' },
  ],
  settingsSchema: z
    .object({
      apiRoot: z.string().regex(/^\/[A-Za-z0-9/_.-]{0,200}\/$/),
      collectionId: z.string().regex(/^[A-Za-z0-9-]{1,100}$/),
      limit: z.coerce.number().int().min(1).max(5000).default(500),
    })
    .strict(),
  async test({ http }, s) {
    const c = await http.call<{ title?: string }>(`${s.apiRoot}collections/${s.collectionId}/`, {
      headers: { accept: 'application/taxii+json;version=2.1' },
    });
    return `TAXII collection "${c.title ?? s.collectionId}" reachable`;
  },
  async sync({ http, since }, s) {
    const env = await http.call<{ objects?: Record<string, any>[] }>(`${s.apiRoot}collections/${s.collectionId}/objects/`, {
      headers: { accept: 'application/taxii+json;version=2.1' },
      query: { added_after: since.toISOString(), limit: s.limit },
    });
    const threats: NormThreat[] = [];
    for (const o of env.objects ?? []) {
      const labels = asArray<string>(o.labels).map((l) => str(l, 60));
      const name = str(o.name ?? o.id, 300);
      let type: ThreatType;
      let severity: Severity = severityFromText(o.x_severity ?? o.severity, 'MEDIUM');
      switch (o.type) {
        case 'vulnerability':
          type = 'CVE';
          if (!o.x_severity) severity = 'HIGH';
          break;
        case 'malware':
          type = asArray<string>(o.malware_types).includes('ransomware') ? 'RANSOMWARE' : 'ADVISORY';
          if (type === 'RANSOMWARE') severity = 'CRITICAL';
          break;
        case 'report':
          type = classify(labels, name);
          break;
        case 'indicator':
          type = 'IOC';
          break;
        default:
          continue;
      }
      const cveRef = asArray<Record<string, string>>(o.external_references).find((r) => r.source_name === 'cve');
      threats.push({
        sourceRef: str(o.id, 120),
        type,
        title: name,
        summary: str(o.description ?? o.pattern ?? '', 2000),
        severity,
        cveId: extractCve(cveRef?.external_id, name),
        publishedAt: toDate(o.published ?? o.created),
        tags: labels.slice(0, 15),
      });
    }
    return { threats };
  },
});

export const genericRest = defineAdapter({
  vendor: 'generic_rest',
  displayName: 'Commercial Threat Intel API (generic JSON)',
  category: 'THREAT_INTEL',
  description: 'Field-mapped JSON feed for commercial providers (Recorded Future, Mandiant, CrowdStrike, etc.).',
  supportedAuth: ['API_KEY', 'OAUTH2', 'BASIC', 'MTLS'],
  defaultPollSec: 1800,
  settingsFields: [
    { key: 'path', label: 'Endpoint path', type: 'string', required: true, placeholder: '/v1/advisories' },
    { key: 'itemsPath', label: 'Items JSON path', type: 'string', placeholder: 'data.items' },
    { key: 'idField', label: 'ID field', type: 'string', placeholder: 'id' },
    { key: 'titleField', label: 'Title field', type: 'string', placeholder: 'title' },
    { key: 'summaryField', label: 'Summary field', type: 'string', placeholder: 'description' },
    { key: 'severityField', label: 'Severity field', type: 'string', placeholder: 'severity' },
    { key: 'publishedField', label: 'Published date field', type: 'string', placeholder: 'published' },
    { key: 'tagsField', label: 'Tags field', type: 'string', placeholder: 'tags' },
  ],
  settingsSchema: z
    .object({
      path: z.string().regex(/^\/[A-Za-z0-9/_.\-?=&]{0,300}$/),
      itemsPath: z.string().regex(/^[A-Za-z0-9_.]{0,100}$/).default(''),
      idField: z.string().regex(/^[A-Za-z0-9_.]{1,100}$/).default('id'),
      titleField: z.string().regex(/^[A-Za-z0-9_.]{1,100}$/).default('title'),
      summaryField: z.string().regex(/^[A-Za-z0-9_.]{1,100}$/).default('description'),
      severityField: z.string().regex(/^[A-Za-z0-9_.]{1,100}$/).default('severity'),
      publishedField: z.string().regex(/^[A-Za-z0-9_.]{1,100}$/).default('published'),
      tagsField: z.string().regex(/^[A-Za-z0-9_.]{1,100}$/).default('tags'),
    })
    .strict(),
  async test({ http }, s) {
    const body = await http.call(s.path);
    const items = getPath(body, s.itemsPath);
    return `Feed reachable (${Array.isArray(items) ? items.length : 0} items at "${s.itemsPath || '<root>'}")`;
  },
  async sync({ http }, s) {
    const body = await http.call(s.path);
    const items = asArray(getPath(body, s.itemsPath) as unknown[]);
    const threats: NormThreat[] = items.slice(0, 2000).map((it) => {
      const tags = asArray(getPath(it, s.tagsField) as unknown[]).map((t) => str(t, 60)).filter(Boolean);
      const title = str(getPath(it, s.titleField), 300);
      return {
        sourceRef: str(getPath(it, s.idField), 120),
        type: classify(tags, title),
        title,
        summary: str(getPath(it, s.summaryField), 2000),
        severity: severityFromText(getPath(it, s.severityField)),
        cveId: extractCve(title, tags.join(' ')),
        publishedAt: toDate(getPath(it, s.publishedField)),
        tags: tags.slice(0, 15),
      };
    });
    return { threats: threats.filter((t) => t.sourceRef) };
  },
});
