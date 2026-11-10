/** SIEM connectors: Splunk ES, Elastic Security, IBM QRadar → normalised incidents. */
import { z } from 'zod';
import type { IncidentStatus } from '@prisma/client';
import { defineAdapter, type NormIncident } from '../types.js';
import { optDate, severityFromText, str, toDate } from './util.js';

export const splunk = defineAdapter({
  vendor: 'splunk',
  displayName: 'Splunk Enterprise Security',
  category: 'SIEM',
  description: 'Pulls notable events via the REST search export endpoint.',
  supportedAuth: ['API_KEY', 'BASIC', 'MTLS'],
  defaultPollSec: 300,
  settingsFields: [
    { key: 'search', label: 'SPL search', type: 'textarea', required: true, placeholder: 'search `notable` | head 500' },
  ],
  settingsSchema: z.object({ search: z.string().min(5).max(2000).default('search `notable` | head 500') }).strict(),
  async test({ http }) {
    const info = await http.call<{ entry?: { content?: { version?: string } }[] }>('/services/server/info', { query: { output_mode: 'json' } });
    return `Connected to Splunk ${info.entry?.[0]?.content?.version ?? ''}`.trim();
  },
  async sync({ http, since }, s) {
    const text = await http.call<string>('/services/search/jobs/export', {
      method: 'POST',
      accept: 'text',
      form: { search: s.search, output_mode: 'json', earliest_time: String(Math.floor(since.getTime() / 1000)) },
    });
    const incidents: NormIncident[] = [];
    for (const line of text.split('\n')) {
      if (!line.trim()) continue;
      let row: { result?: Record<string, unknown> };
      try {
        row = JSON.parse(line);
      } catch {
        continue;
      }
      const r = row.result;
      if (!r) continue;
      const detected = toDate(r._time);
      const statusLabel = String(r.status_label ?? '').toLowerCase();
      incidents.push({
        externalId: str(r.event_id ?? r.event_hash ?? `${r._time}-${r.rule_name}`, 200),
        title: str(r.rule_name ?? r.search_name ?? r.source ?? 'Splunk notable event', 300),
        severity: severityFromText(r.urgency ?? r.severity),
        occurredAt: toDate(r.orig_time ?? r._time, detected),
        detectedAt: detected,
        status: statusLabel.includes('closed') || statusLabel.includes('resolved') ? 'RESOLVED' : 'NEW',
        resolvedAt: statusLabel.includes('closed') ? detected : null,
        category: str(r.security_domain ?? 'SIEM', 60),
      });
    }
    return { incidents };
  },
});

export const elastic = defineAdapter({
  vendor: 'elastic',
  displayName: 'Elastic Security',
  category: 'SIEM',
  description: 'Queries Elastic Security detection alerts index.',
  supportedAuth: ['API_KEY', 'BASIC', 'MTLS'],
  defaultPollSec: 300,
  settingsFields: [
    { key: 'index', label: 'Alerts index pattern', type: 'string', required: true, placeholder: '.alerts-security.alerts-default' },
    { key: 'size', label: 'Max alerts per poll', type: 'number' },
  ],
  settingsSchema: z
    .object({
      index: z.string().regex(/^[a-zA-Z0-9._*,-]{1,200}$/).default('.alerts-security.alerts-default'),
      size: z.coerce.number().int().min(1).max(5000).default(500),
    })
    .strict(),
  async test({ http }) {
    const info = await http.call<{ version?: { number?: string } }>('/');
    return `Connected to Elasticsearch ${info.version?.number ?? ''}`.trim();
  },
  async sync({ http, since }, s) {
    const res = await http.call<{ hits?: { hits?: { _id: string; _source: Record<string, unknown> }[] } }>(
      `/${encodeURIComponent(s.index).replace(/%2C/g, ',').replace(/%2A/g, '*')}/_search`,
      {
        method: 'POST',
        json: {
          size: s.size,
          sort: [{ '@timestamp': 'desc' }],
          query: { range: { '@timestamp': { gte: since.toISOString() } } },
        },
      },
    );
    const incidents: NormIncident[] = (res.hits?.hits ?? []).map((h) => {
      const src = h._source;
      const detected = toDate(src['@timestamp']);
      const wf = String(src['kibana.alert.workflow_status'] ?? 'open');
      const status: IncidentStatus = wf === 'closed' ? 'RESOLVED' : wf === 'acknowledged' ? 'TRIAGE' : 'NEW';
      return {
        externalId: h._id,
        title: str(src['kibana.alert.rule.name'] ?? 'Elastic alert', 300),
        severity: severityFromText(src['kibana.alert.severity']),
        occurredAt: toDate(src['kibana.alert.original_time'], detected),
        detectedAt: detected,
        status,
        respondedAt: status !== 'NEW' ? detected : null,
        resolvedAt: status === 'RESOLVED' ? optDate(src['kibana.alert.workflow_status_updated_at']) ?? detected : null,
        category: 'SIEM',
      };
    });
    return { incidents };
  },
});

export const qradar = defineAdapter({
  vendor: 'qradar',
  displayName: 'IBM QRadar SIEM',
  category: 'SIEM',
  description: 'Retrieves offenses through the QRadar REST API.',
  supportedAuth: ['API_KEY', 'MTLS'],
  defaultPollSec: 300,
  settingsFields: [
    { key: 'apiVersion', label: 'API version header', type: 'string', placeholder: '20.0' },
    { key: 'maxOffenses', label: 'Max offenses per poll', type: 'number' },
  ],
  settingsSchema: z
    .object({
      apiVersion: z.string().regex(/^\d+\.\d+$/).default('20.0'),
      maxOffenses: z.coerce.number().int().min(1).max(5000).default(500),
    })
    .strict(),
  apiKeyHeaders: (c) => ({ SEC: c.apiKey ?? '' }),
  async test({ http }, s) {
    const about = await http.call<{ external_version?: string }>('/api/system/about', { headers: { Version: s.apiVersion } });
    return `Connected to QRadar ${about.external_version ?? ''}`.trim();
  },
  async sync({ http, since }, s) {
    const offenses = await http.call<Record<string, unknown>[]>('/api/siem/offenses', {
      headers: { Version: s.apiVersion, Range: `items=0-${s.maxOffenses - 1}` },
      query: {
        filter: `last_updated_time > ${since.getTime()}`,
        fields: 'id,description,magnitude,start_time,first_persisted_time,last_updated_time,status,close_time,offense_type',
      },
    });
    const incidents: NormIncident[] = (offenses ?? []).map((o) => {
      const mag = Number(o.magnitude ?? 0);
      const closed = String(o.status) === 'CLOSED';
      return {
        externalId: String(o.id),
        title: str(o.description ?? `QRadar offense ${String(o.id)}`, 300),
        severity: mag >= 8 ? 'CRITICAL' : mag >= 6 ? 'HIGH' : mag >= 4 ? 'MEDIUM' : 'LOW',
        occurredAt: toDate(o.start_time),
        detectedAt: toDate(o.first_persisted_time ?? o.start_time),
        status: closed ? 'RESOLVED' : 'NEW',
        resolvedAt: closed ? optDate(o.close_time) : null,
        category: 'SIEM',
      };
    });
    return { incidents };
  },
});
