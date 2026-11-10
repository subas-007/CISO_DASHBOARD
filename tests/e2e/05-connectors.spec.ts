import { readFileSync, mkdtempSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import os from 'node:os';
import path from 'node:path';
import { test, expect, compose, psql, waitFor, type Api } from './support/fixtures';
import { ROOT } from './support/env';

const TLS_CRT = readFileSync(path.join(ROOT, 'certs/tls.crt'), 'utf8');
const TLS_KEY = readFileSync(path.join(ROOT, 'certs/tls.key'), 'utf8');
const sim = (v: string) => `https://${v}.sim.test:8443`;
const RUN = process.env.E2E_RUN ?? 'local';

interface Case {
  vendor: string;
  host: string;
  authMode: string;
  credentials: Record<string, string>;
  settings: Record<string, string | number>;
  testMessage: RegExp;
  counts: Record<string, number>;
  requestOptions?: Record<string, unknown>;
}

// Generic REST adapters: the simulated vendor sits behind an API-gateway prefix and
// requires a version header and a tenant parameter, supplied as connector API parameters.
const GENERIC_CREDS = { apiKey: 'generic-sim-token', apiKeyPrefix: 'Bearer ' };
const GENERIC_RO = { pathPrefix: '/gw', headers: { 'X-Api-Version': '2' }, query: { tenant: 'emea' } };

const CASES: Case[] = [
  { vendor: 'splunk', host: 'splunk', authMode: 'API_KEY', credentials: { apiKey: 'splunk-sim-token', apiKeyPrefix: 'Bearer ' }, settings: { search: 'search `notable` | head 50' }, testMessage: /Splunk 9\.3\.1/, counts: { incidents: 4 } },
  { vendor: 'elastic', host: 'elastic', authMode: 'API_KEY', credentials: { apiKey: 'elastic-sim-key', apiKeyPrefix: 'ApiKey ' }, settings: {}, testMessage: /Elasticsearch 8\.15\.2/, counts: { incidents: 3 } },
  { vendor: 'qradar', host: 'qradar', authMode: 'API_KEY', credentials: { apiKey: 'qradar-sim-sec' }, settings: { apiVersion: '20.0' }, testMessage: /QRadar 7\.5\.0/, counts: { incidents: 3 } },
  { vendor: 'tenable', host: 'tenable', authMode: 'API_KEY', credentials: { apiKey: 'tenable-ak', apiSecret: 'tenable-sk' }, settings: {}, testMessage: /sim-api@tenable/, counts: { vulnerabilities: 4 } },
  { vendor: 'nessus', host: 'nessus', authMode: 'API_KEY', credentials: { apiKey: 'tenable-ak', apiSecret: 'tenable-sk' }, settings: { scanId: 42 }, testMessage: /ready/, counts: { vulnerabilities: 4 } },
  { vendor: 'qualys', host: 'qualys', authMode: 'BASIC', credentials: { username: 'qualys-user', password: 'qualys-pass' }, settings: {}, testMessage: /Qualys/, counts: { vulnerabilities: 3 } },
  { vendor: 'wsus', host: 'wsus', authMode: 'MTLS', credentials: { clientCert: TLS_CRT, clientKey: TLS_KEY }, settings: { reportPath: '/wsus/compliance.json' }, testMessage: /4 computers/, counts: { assets: 4 } },
  { vendor: 'ansible', host: 'awx', authMode: 'OAUTH2', credentials: { tokenUrl: `${sim('awx')}/oauth2/token/`, clientId: 'awx-client', clientSecret: 'awx-secret' }, settings: { inventoryId: 7 }, testMessage: /AWX\/AAP 24\.6\.1/, counts: { assets: 3 } },
  { vendor: 'satellite', host: 'satellite', authMode: 'BASIC', credentials: { username: 'sat-user', password: 'sat-pass' }, settings: {}, testMessage: /Satellite 6\.16\.0/, counts: { assets: 3 } },
  { vendor: 'servicenow', host: 'servicenow', authMode: 'BASIC', credentials: { username: 'snow-user', password: 'snow-pass' }, settings: { table: 'change_request', query: 'active=true' }, testMessage: /accessible/, counts: { changes: 3 } },
  { vendor: 'jira', host: 'jira', authMode: 'BASIC', credentials: { username: 'jira@example.test', password: 'jira-api-token' }, settings: { jql: 'project = CHG ORDER BY updated DESC' }, testMessage: /Sim Jira Bot/, counts: { changes: 2 } },
  { vendor: 'misp', host: 'misp', authMode: 'API_KEY', credentials: { apiKey: 'misp-sim-key' }, settings: {}, testMessage: /MISP 2\.4\.198/, counts: { threats: 3 } },
  { vendor: 'taxii', host: 'taxii', authMode: 'BASIC', credentials: { username: 'taxii-user', password: 'taxii-pass' }, settings: { apiRoot: '/taxii2/api1/', collectionId: 'sim-collection-1' }, testMessage: /Simulated Vendor Intel/, counts: { threats: 4 } },
  { vendor: 'generic_rest', host: 'intel', authMode: 'API_KEY', credentials: { apiKey: 'intel-sim-key', apiKeyHeader: 'X-Api-Key' }, settings: { path: '/v1/advisories', itemsPath: 'data.items' }, testMessage: /3 items/, counts: { threats: 3 } },
  { vendor: 'cisa_kev', host: 'kev', authMode: 'NONE', credentials: {}, settings: { path: '/feeds/kev.json' }, testMessage: /2099\.01\.01/, counts: { threats: 2 } },
  { vendor: 'generic_siem', host: 'generic', authMode: 'API_KEY', credentials: GENERIC_CREDS, requestOptions: GENERIC_RO, settings: { path: '/v2/alerts', testPath: '/v2/status', itemsPath: 'data', pagination: 'cursor', pageSize: 2, nextCursorPath: 'meta.next_cursor', assetsField: 'asset_count' }, testMessage: /reachable \(\/v2\/status\)/, counts: { incidents: 5 } },
  { vendor: 'generic_vulnerability', host: 'generic', authMode: 'API_KEY', credentials: GENERIC_CREDS, requestOptions: GENERIC_RO, settings: { path: '/v2/findings', itemsPath: 'results', pagination: 'page', pageSize: 2, pageSizeParam: 'per_page' }, testMessage: /items array found/, counts: { vulnerabilities: 5 } },
  { vendor: 'generic_patch', host: 'generic', authMode: 'API_KEY', credentials: GENERIC_CREDS, requestOptions: GENERIC_RO, settings: { path: '/v2/devices', itemsPath: 'items', pagination: 'offset', pageSize: 2 }, testMessage: /items array found/, counts: { assets: 3 } },
  { vendor: 'generic_change', host: 'generic', authMode: 'API_KEY', credentials: GENERIC_CREDS, requestOptions: GENERIC_RO, settings: { path: '/v2/changes', pagination: 'link', pageSize: 2 }, testMessage: /items array found/, counts: { changes: 3 } },
];

async function connectorId(api: Api, vendor: string): Promise<string> {
  const found = (await api('GET', '/integrations')).json.items.find((c: { name: string }) => c.name === `SIM ${vendor} ${RUN}`);
  if (!found) throw new Error(`connector SIM ${vendor} ${RUN} not found`);
  return found.id;
}

async function create(api: Api, name: string, vendor: string, baseUrl: string, authMode: string, credentials: object, settings: object = {}, extra: object = {}) {
  return api('POST', '/integrations', { name, vendor, baseUrl, authMode, pollIntervalSec: 3600, enabled: false, settings, credentials, ...extra });
}

test.describe('Connector framework — all 19 adapters against the vendor simulator', () => {
  test('catalog exposes 19 adapters across the 5 categories', async ({ as }) => {
    const { api } = await as('secops');
    const cat = (await api('GET', '/integrations/catalog')).json;
    expect(cat.items).toHaveLength(19);
    expect(cat.items.filter((i: { vendor: string }) => i.vendor.startsWith('generic_')).map((i: { category: string }) => i.category).sort()).toEqual(['CHANGE', 'PATCH', 'SIEM', 'THREAT_INTEL', 'VULNERABILITY']);
    expect(new Set(cat.items.map((i: { category: string }) => i.category))).toEqual(new Set(['SIEM', 'VULNERABILITY', 'PATCH', 'CHANGE', 'THREAT_INTEL']));
    expect(cat.egressPolicy.httpsOnly).toBe(true);
  });

  test('every adapter: create → test connection → sync → normalised data persisted', async ({ as }) => {
    test.setTimeout(240_000);
    // 19 connectors × (test + sync) = 38 heavy operations: spread over three users so the
    // per-user heavy-operation quota (30/min) is respected.
    const sessions = [await as('admin'), await as('secops'), await as('secops2')];
    const before = (await sessions[0]!.api('GET', '/kpi/summary')).json.kpis.totalAssets;
    const failures: string[] = [];
    for (const [i, c] of CASES.entries()) {
      const { api } = sessions[i % sessions.length]!;
      const name = `SIM ${c.vendor} ${RUN}`;
      const created = await create(api, name, c.vendor, sim(c.host), c.authMode, c.credentials, c.settings, c.requestOptions ? { requestOptions: c.requestOptions } : {});
      if (created.status !== 201) {
        failures.push(`${c.vendor}: create ${created.status} ${created.text}`);
        continue;
      }
      expect(created.text).not.toMatch(/sim-token|sim-key|-pass|PRIVATE KEY|awx-secret|tenable-sk/);
      const t = await api('POST', `/integrations/${created.json.id}/test`);
      if (!t.json?.ok || !c.testMessage.test(t.json.message)) failures.push(`${c.vendor}: test → ${t.text}`);
      const s = await api('POST', `/integrations/${created.json.id}/sync`);
      if (!s.json?.ok) failures.push(`${c.vendor}: sync → ${s.text}`);
      for (const [k, n] of Object.entries(c.counts)) {
        if (s.json?.counts?.[k] !== n) failures.push(`${c.vendor}: expected ${n} ${k}, got ${JSON.stringify(s.json?.counts)}`);
      }
      const after = (await api('GET', '/integrations')).json.items.find((x: { id: string }) => x.id === created.json.id);
      if (after.status !== 'DISABLED' || !after.lastSuccessAt || after.lastError) failures.push(`${c.vendor}: state ${JSON.stringify({ status: after.status, lastError: after.lastError })}`);
    }
    expect(failures, failures.join('\n')).toEqual([]);
    const afterAssets = (await sessions[0]!.api('GET', '/kpi/summary')).json.kpis.totalAssets;
    expect(afterAssets - before).toBeGreaterThanOrEqual(13); // new hosts from scanners + patch tools
  });

  test('ingested data is queryable and correctly classified', async ({ as }) => {
    const { api } = await as('ciso');
    const inc = (await api('GET', '/incidents?q=Brute%20force%20against%20VPN%20gateway')).json.items.find((i: { source: string }) => i.source.startsWith('SIM splunk'));
    expect(inc).toMatchObject({ severity: 'CRITICAL', status: 'NEW' });
    expect(new Date(inc.detectedAt).getTime()).toBeGreaterThan(new Date(inc.occurredAt).getTime());
    const qradarClosed = (await api('GET', '/incidents?q=Port%20scan%20from%20internal%20host')).json.items[0];
    expect(qradarClosed.status).toBe('RESOLVED');
    expect(qradarClosed.resolvedAt).toBeTruthy();

    const vpn = (await api('GET', '/vulnerabilities?q=vpn-edge&status=OPEN')).json;
    expect(vpn.total).toBe(2);
    expect(vpn.items.every((v: { cveId: string; severity: string; dueAt: string }) => v.cveId === 'CVE-2024-3400' && v.severity === 'CRITICAL' && v.dueAt)).toBe(true);
    const fixed = (await api('GET', '/vulnerabilities?q=app-tenable-02&status=REMEDIATED')).json;
    expect(fixed.total).toBe(1);
    const log4j = (await api('GET', '/vulnerabilities?q=db-nessus')).json.items;
    expect(log4j.some((v: { cveId: string }) => v.cveId === 'CVE-2021-44228')).toBe(true);

    const nonCompliant = (await api('GET', '/assets?q=sim.test&nonCompliant=true&limit=100')).json.items.map((a: { hostname: string }) => a.hostname);
    for (const h of ['ws-fin-002.sim.test', 'srv-print-01.sim.test', 'rhel-app-02.sim.test', 'rhel-db-02.sim.test']) expect(nonCompliant).toContain(h);
    const compliant = (await api('GET', '/assets?q=ws-fin-001')).json.items[0];
    expect(compliant.patchCompliant).toBe(true);

    const snow = (await api('GET', '/change-tickets?q=CHG00510')).json.items;
    expect(snow).toHaveLength(3);
    expect(snow[0].url).toMatch(/^https:\/\/servicenow\.sim\.test:8443\/nav_to\.do/);
    expect((await api('GET', '/change-tickets?q=CHG-120')).json.items).toHaveLength(2);

    const threat = async (q: string) => (await api('GET', `/threats?q=${encodeURIComponent(q)}`)).json.items[0];
    expect(await threat('Akira')).toMatchObject({ type: 'RANSOMWARE', severity: 'CRITICAL' });
    expect(await threat('Citrix Bleed exploitation')).toMatchObject({ type: 'CVE', cveId: 'CVE-2023-4966' });
    expect(await threat('Malicious npm package')).toMatchObject({ type: 'SUPPLY_CHAIN' });
    expect(await threat('BlackSuit')).toMatchObject({ type: 'RANSOMWARE' });
    expect(await threat('Compromised CI/CD')).toMatchObject({ type: 'SUPPLY_CHAIN' });
    expect(await threat('sim-c2.example')).toMatchObject({ type: 'IOC' });
    expect(await threat('FortiOS SSL VPN')).toMatchObject({ type: 'CVE', cveId: 'CVE-2024-21762' });
    expect(await threat('LockBit successor')).toMatchObject({ type: 'RANSOMWARE', severity: 'CRITICAL' });
    // Generic REST adapters: field mapping + pagination + classification
    const gen = async (q: string) => (await api('GET', `/incidents?q=${encodeURIComponent(q)}`)).json.items.find((i: { source: string }) => i.source.startsWith('SIM generic_siem'));
    expect(await gen('Ransomware behaviour on file server')).toMatchObject({ severity: 'CRITICAL', status: 'CONTAINED' });
    expect(await gen('Phishing link clicked')).toMatchObject({ severity: 'LOW', status: 'RESOLVED' });
    expect(await gen('Suspicious PowerShell download cradle')).toMatchObject({ status: 'TRIAGE' });
    expect((await api('GET', '/vulnerabilities?q=gen-db-02&status=REMEDIATED')).json.total).toBe(1);
    const genCrit = (await api('GET', '/vulnerabilities?q=gen-app-03')).json.items[0];
    expect(genCrit).toMatchObject({ cveId: 'CVE-2024-4577', severity: 'CRITICAL' });
    const genAssets = (await api('GET', '/assets?q=gen-&nonCompliant=true&limit=100')).json.items.map((a: { hostname: string }) => a.hostname);
    expect(genAssets.sort()).toEqual(['gen-app-03.corp.example', 'gen-db-02.corp.example']);
    const genChanges = (await api('GET', '/change-tickets?q=GCHG-100')).json.items;
    expect(genChanges).toHaveLength(3);
    expect(genChanges.find((c: { externalKey: string }) => c.externalKey === 'GCHG-1002').url).toBeNull(); // javascript: URL dropped

    const kev = (await api('GET', '/threats?q=CVE-2024-3400&type=RANSOMWARE')).json.items.find((t: { source: string }) => t.source.startsWith('SIM cisa_kev'));
    expect(kev.impactedAssetCount).toBeGreaterThanOrEqual(2); // correlated with Tenable findings
    expect(kev.tags).toContain('ransomware');
  });

  test('connector API parameters: required headers, retries with Retry-After, credential-like parameters rejected', async ({ as }) => {
    const { api } = await as('admin');
    const settings = { path: '/v2/flaky-alerts', itemsPath: 'data', pagination: 'cursor', pageSize: 2, nextCursorPath: 'meta.next_cursor' };
    // The flaky endpoint answers every other request with 503 + Retry-After: 1.
    const flaky = await create(api, `API flaky ${RUN}`, 'generic_siem', sim('generic'), 'API_KEY', GENERIC_CREDS, settings, { requestOptions: { ...GENERIC_RO, maxRetries: 2 } });
    expect(flaky.status).toBe(201);
    expect(flaky.json.requestOptions).toMatchObject({ pathPrefix: '/gw', headers: { 'X-Api-Version': '2' }, maxRetries: 2 });
    const synced = await api('POST', `/integrations/${flaky.json.id}/sync`);
    expect(synced.json).toMatchObject({ ok: true, counts: { incidents: 5 } });

    // Without the vendor's version header the same endpoint is rejected upstream.
    const noHeader = await api('PATCH', `/integrations/${flaky.json.id}`, { requestOptions: { pathPrefix: '/gw', query: { tenant: 'emea' } } });
    expect(noHeader.status).toBe(200);
    expect((await api('POST', `/integrations/${flaky.json.id}/test`)).json).toMatchObject({ ok: false, message: 'Upstream returned HTTP 400' });

    for (const bad of [{ headers: { Authorization: 'Bearer x' } }, { headers: { 'X-Api-Key': 'x' } }, { query: { access_token: 'x' } }, { headers: { 'X-A': 'a\r\nB: c' } }, { pathPrefix: '/../x' }]) {
      const r = await api('PATCH', `/integrations/${flaky.json.id}`, { requestOptions: bad });
      expect(r.status, JSON.stringify(bad)).toBe(400);
    }
    expect((await api('DELETE', `/integrations/${flaky.json.id}`)).status).toBe(204);
  });

  test('XML entity expansion is not performed (Qualys payload with entity bomb)', async () => {
    const r = psql(`SELECT count(*) FROM vulnerabilities WHERE source LIKE 'SIM qualys%' AND title = 'Qualys QID 38913';
                    SELECT count(*) FROM vulnerabilities WHERE title LIKE '%LOLLOL%' OR "remediationNote" LIKE '%LOLLOL%';`);
    expect(r.code).toBe(0);
    expect(r.out.trim().split(/\r?\n/)).toEqual(['1', '0']);
  });

  test('zero data retention: raw vendor payload never reaches logs or the database', async () => {
    const logs = compose(['logs', 'api', '--no-color']);
    expect(logs.code).toBe(0);
    expect(logs.out.length).toBeGreaterThan(1000);
    expect(logs.out).not.toContain('ZDR-CANARY');
    const dump = compose(['exec', '-T', 'postgres', 'sh', '-c', 'PGPASSWORD="$POSTGRES_PASSWORD" pg_dump -h 127.0.0.1 -U "$POSTGRES_USER" "$POSTGRES_DB"']);
    expect(dump.code).toBe(0);
    expect(dump.out.length).toBeGreaterThan(100_000);
    expect(dump.out).not.toContain('ZDR-CANARY');
    // Credentials are only present as ciphertext.
    for (const secret of ['splunk-sim-token', 'qualys-pass', 'awx-secret', 'tenable-sk', 'misp-sim-key', 'generic-sim-token', 'BEGIN PRIVATE KEY']) expect(dump.out).not.toContain(secret);
    const enc = psql(`SELECT count(*) FILTER (WHERE "secretEnc" LIKE 'enc:v%'), count(*) FILTER (WHERE "secretEnc" IS NOT NULL) FROM connectors WHERE name LIKE 'SIM %${RUN}'`);
    const [encrypted, withSecrets] = enc.out.trim().split('|').map(Number);
    expect(withSecrets).toBe(18); // every SIM connector except CISA KEV (no auth)
    expect(encrypted).toBe(18);
  });

  test('ciphertext is bound to its connector (AAD) — swapped secrets do not decrypt', async ({ as }) => {
    const { api } = await as('secops2');
    const elastic = await connectorId(api, 'elastic');
    const splunk = await connectorId(api, 'splunk');
    const original = psql(`SELECT "secretEnc" FROM connectors WHERE id = '${elastic}'`).out.trim();
    expect(psql(`UPDATE connectors SET "secretEnc" = (SELECT "secretEnc" FROM connectors WHERE id = '${splunk}') WHERE id = '${elastic}'`).code).toBe(0);
    const t = await api('POST', `/integrations/${elastic}/test`);
    expect(t.json).toMatchObject({ ok: false, message: 'Connector operation failed' });
    expect(psql(`UPDATE connectors SET "secretEnc" = '${original}' WHERE id = '${elastic}'`).code).toBe(0);
    expect((await api('POST', `/integrations/${elastic}/test`)).json.ok).toBe(true);
  });

  test('authentication failures and transport errors fail safely with generic messages', async ({ as }) => {
    const { api } = await as('secops2');
    const cases: [string, string, string, string, object, object, RegExp][] = [
      ['wrong QRadar SEC token', 'qradar', sim('qradar'), 'API_KEY', { apiKey: 'wrong' }, {}, /Upstream returned HTTP 401/],
      ['WSUS without client certificate', 'wsus', sim('wsus'), 'API_KEY', { apiKey: 'x' }, { reportPath: '/wsus/compliance.json' }, /Upstream returned HTTP 401/],
      ['OAuth2 wrong client secret', 'ansible', sim('awx'), 'OAUTH2', { tokenUrl: `${sim('awx')}/oauth2/token/`, clientId: 'awx-client', clientSecret: 'nope' }, { inventoryId: 7 }, /OAuth2 token endpoint returned HTTP 401/],
      ['redirect to cloud metadata is not followed', 'generic_rest', sim('redirect'), 'API_KEY', { apiKey: 'x' }, { path: '/v1/advisories' }, /Upstream returned HTTP 302/],
      ['DNS name resolving into an internal zone', 'generic_rest', 'https://ciso-dashboard-postgres-1:5432', 'API_KEY', { apiKey: 'x' }, { path: '/x' }, /blocked by egress policy/],
      ['unresolvable host', 'generic_rest', 'https://does-not-exist.sim.test:8443', 'API_KEY', { apiKey: 'x' }, { path: '/x' }, /could not be resolved/],
    ];
    const problems: string[] = [];
    for (const [label, vendor, url, mode, creds, settings, expected] of cases) {
      const c = await create(api, `NEG ${label.slice(0, 40)} ${RUN}`.replace(/[^A-Za-z0-9 _().-]/g, ''), vendor, url, mode, creds, settings);
      if (c.status !== 201) {
        problems.push(`${label}: create ${c.status} ${c.text}`);
        continue;
      }
      const t = await api('POST', `/integrations/${c.json.id}/test`);
      if (t.json?.ok !== false || !expected.test(t.json?.message)) problems.push(`${label}: ${t.text}`);
      await api('DELETE', `/integrations/${c.json.id}`);
    }
    expect(problems, problems.join('\n')).toEqual([]);
  });

  test('a custom CA that did not issue the server certificate is rejected (TLS pinning)', async ({ as }) => {
    const dir = mkdtempSync(path.join(os.tmpdir(), 'rogue-'));
    const r = spawnSync('openssl', ['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes', '-days', '1', '-subj', '/CN=Rogue CA', '-keyout', path.join(dir, 'k.pem'), '-out', path.join(dir, 'c.pem')], { encoding: 'utf8', env: { ...process.env, MSYS_NO_PATHCONV: '1' } });
    expect(r.status, r.stderr).toBe(0);
    const { api } = await as('secops2');
    const c = await create(api, `NEG rogue CA ${RUN}`, 'splunk', sim('splunk'), 'API_KEY', { apiKey: 'splunk-sim-token', apiKeyPrefix: 'Bearer ', caCert: readFileSync(path.join(dir, 'c.pem'), 'utf8') }, { search: 'search `notable`' });
    expect(c.status).toBe(201);
    const t = await api('POST', `/integrations/${c.json.id}/test`);
    expect(t.json.ok).toBe(false);
    expect(t.json.message).toMatch(/TLS verification failed|Connector operation failed/);
    await api('DELETE', `/integrations/${c.json.id}`);
  });

  test('configuration validation rejects unsafe or malformed parameters', async ({ as }) => {
    const { api } = await as('secops2');
    const base = { name: `VAL ${RUN}`, vendor: 'splunk', baseUrl: sim('splunk'), authMode: 'API_KEY', pollIntervalSec: 300, settings: { search: 'search index=x' }, credentials: { apiKey: 'k' } };
    const bad: [string, object][] = [
      ['loopback literal', { baseUrl: 'https://127.0.0.1' }],
      ['decimal-encoded loopback', { baseUrl: 'https://2130706433' }],
      ['IPv6 loopback', { baseUrl: 'https://[::1]' }],
      ['link-local metadata', { baseUrl: 'https://169.254.169.254' }],
      ['internal zone literal', { baseUrl: 'https://172.30.2.5' }],
      ['denied internal host', { baseUrl: 'https://keycloak:8443' }],
      ['plain http', { baseUrl: 'http://splunk.sim.test:8443' }],
      ['embedded credentials', { baseUrl: 'https://user:pw@splunk.sim.test:8443' }],
      ['query string in base URL', { baseUrl: 'https://splunk.sim.test:8443/?x=1' }],
      ['unsupported auth mode for vendor', { vendor: 'tenable', authMode: 'BASIC', credentials: { username: 'a', password: 'b' }, settings: {} }],
      ['missing credential for mode', { authMode: 'BASIC', credentials: { username: 'only' } }],
      ['CRLF header injection', { credentials: { apiKey: 'k', apiKeyPrefix: 'Bearer \r\nX-Evil: 1' } }],
      ['malformed PEM', { authMode: 'MTLS', credentials: { clientCert: 'not a pem', clientKey: 'x' } }],
      ['unknown credential field', { credentials: { apiKey: 'k', sudo: true } }],
      ['unknown top-level field', { createdById: 'me' }],
      ['vendor setting too short', { settings: { search: 'x' } }],
      ['unknown vendor setting', { settings: { search: 'search x', rce: 'yes' } }],
      ['poll interval below minimum', { pollIntervalSec: 5 }],
      ['unknown vendor', { vendor: 'evilcorp' }],
      ['invalid characters in name', { name: '<script>' }],
    ];
    const problems: string[] = [];
    for (const [label, patch] of bad) {
      const r = await api('POST', '/integrations', { ...base, ...patch });
      if (r.status !== 400) problems.push(`${label}: ${r.status} ${r.text.slice(0, 160)}`);
    }
    expect(problems, problems.join('\n')).toEqual([]);
  });

  test('scheduler polls enabled connectors automatically (lease-based)', async ({ as }) => {
    const { api } = await as('secops2');
    const c = await api('POST', '/integrations', { name: `SCHED misp ${RUN}`, vendor: 'misp', baseUrl: sim('misp'), authMode: 'API_KEY', pollIntervalSec: 60, enabled: true, settings: {}, credentials: { apiKey: 'misp-sim-key' } });
    expect(c.status).toBe(201);
    const synced = await waitFor(async () => {
      const x = (await api('GET', '/integrations')).json.items.find((i: { id: string }) => i.id === c.json.id);
      return x.lastSuccessAt && x.status === 'HEALTHY' ? x : null;
    }, 60_000, 3000);
    expect(synced.lastRecordCount).toBe(3);
    // Disabling stops polling and marks the connector DISABLED.
    expect((await api('PATCH', `/integrations/${c.json.id}`, { enabled: false })).json.status).toBe('DISABLED');
    // Changing the endpoint of a disabled connector keeps it DISABLED; re-enabling requires a fresh test.
    expect((await api('PATCH', `/integrations/${c.json.id}`, { baseUrl: sim('misp') })).json.status).toBe('DISABLED');
    expect((await api('PATCH', `/integrations/${c.json.id}`, { enabled: true, baseUrl: sim('misp') })).json.status).toBe('UNTESTED');
    await api('PATCH', `/integrations/${c.json.id}`, { enabled: false });
  });

  test('connector configuration changes are fully audited without secrets', async ({ as }) => {
    const { api } = await as('auditor');
    const log = (await api('GET', '/audit?action=integration.&limit=200')).json.items;
    const actions = new Set(log.map((l: { action: string }) => l.action));
    for (const a of ['integration.create', 'integration.test', 'integration.sync.manual', 'integration.update', 'integration.delete']) expect(actions).toContain(a);
    expect(JSON.stringify(log)).not.toMatch(/sim-token|sim-key|qualys-pass|awx-secret|PRIVATE KEY/);
  });
});
