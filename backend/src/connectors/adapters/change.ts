/** Change management connectors: ServiceNow, Jira (Cloud & Data Center). */
import { z } from 'zod';
import { defineAdapter, type NormChange } from '../types.js';
import { optDate, str } from './util.js';

export const servicenow = defineAdapter({
  vendor: 'servicenow',
  displayName: 'ServiceNow Change Management',
  category: 'CHANGE',
  description: 'Reads change requests through the Table API for remediation linkage.',
  supportedAuth: ['BASIC', 'OAUTH2', 'MTLS'],
  defaultPollSec: 900,
  settingsFields: [
    { key: 'table', label: 'Table', type: 'string', placeholder: 'change_request' },
    { key: 'query', label: 'Encoded query', type: 'string', placeholder: 'active=true' },
    { key: 'limit', label: 'Max records', type: 'number' },
  ],
  settingsSchema: z
    .object({
      table: z.string().regex(/^[a-z0-9_]{1,80}$/).default('change_request'),
      query: z.string().max(1000).default('active=true'),
      limit: z.coerce.number().int().min(1).max(5000).default(500),
    })
    .strict(),
  async test({ http }, s) {
    await http.call(`/api/now/table/${s.table}`, { query: { sysparm_limit: 1, sysparm_fields: 'sys_id' } });
    return `ServiceNow table "${s.table}" is accessible`;
  },
  async sync({ http, since, baseUrl }, s) {
    const ts = since.toISOString().slice(0, 19).replace('T', ' ');
    const res = await http.call<{ result?: Record<string, string>[] }>(`/api/now/table/${s.table}`, {
      query: {
        sysparm_query: `${s.query}^sys_updated_on>=${ts}`,
        sysparm_fields: 'sys_id,number,short_description,state,sys_updated_on',
        sysparm_display_value: 'true',
        sysparm_limit: s.limit,
      },
    });
    const changes: NormChange[] = (res.result ?? []).map((r) => ({
      externalKey: str(r.number, 64),
      title: str(r.short_description, 300),
      status: str(r.state, 60),
      url: `${baseUrl.origin}/nav_to.do?uri=${encodeURIComponent(`${s.table}.do?sys_id=${r.sys_id}`)}`,
      updatedAt: optDate(r.sys_updated_on),
    }));
    return { changes };
  },
});

export const jira = defineAdapter({
  vendor: 'jira',
  displayName: 'Atlassian Jira',
  category: 'CHANGE',
  description: 'Runs a JQL query to import change / remediation tickets.',
  supportedAuth: ['BASIC', 'API_KEY', 'OAUTH2'],
  defaultPollSec: 900,
  settingsFields: [
    { key: 'jql', label: 'JQL', type: 'textarea', required: true, placeholder: 'project = CHG ORDER BY updated DESC' },
    { key: 'apiVersion', label: 'API version (3 = Cloud, 2 = Data Center)', type: 'string' },
    { key: 'maxResults', label: 'Max results', type: 'number' },
  ],
  settingsSchema: z
    .object({
      jql: z.string().min(3).max(2000),
      apiVersion: z.enum(['2', '3']).default('3'),
      maxResults: z.coerce.number().int().min(1).max(1000).default(200),
    })
    .strict(),
  async test({ http }, s) {
    const me = await http.call<{ displayName?: string }>(`/rest/api/${s.apiVersion}/myself`);
    return `Authenticated to Jira as ${me.displayName ?? 'API user'}`;
  },
  async sync({ http, baseUrl }, s) {
    const path = s.apiVersion === '3' ? '/rest/api/3/search/jql' : '/rest/api/2/search';
    const res = await http.call<{ issues?: { key: string; fields: Record<string, any> }[] }>(path, {
      method: 'POST',
      json: { jql: s.jql, maxResults: s.maxResults, fields: ['summary', 'status', 'updated'] },
    });
    const changes: NormChange[] = (res.issues ?? []).map((i) => ({
      externalKey: str(i.key, 64),
      title: str(i.fields.summary, 300),
      status: str(i.fields.status?.name, 60),
      url: `${baseUrl.origin}/browse/${encodeURIComponent(i.key)}`,
      updatedAt: optDate(i.fields.updated),
    }));
    return { changes };
  },
});
