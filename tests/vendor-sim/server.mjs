// Vendor API simulator for integration tests. Impersonates the security tool APIs the
// connector framework integrates with, dispatched by Host header (<vendor>.sim.test).
// Each vendor enforces its real authentication scheme and returns dummy data.
// Fields named *canary* carry a marker that must NEVER appear in API logs or the DB
// (zero-data-retention check) — they are not part of any normalised record.
import { readFileSync } from 'node:fs';
import https from 'node:https';

const PORT = Number(process.env.PORT ?? 8443);
const CANARY = 'ZDR-CANARY-7f3a9c';
const now = Date.now();
const iso = (msAgo) => new Date(now - msAgo).toISOString();
const H = 3_600_000;
const D = 24 * H;

const CREDS = {
  splunkToken: 'Bearer splunk-sim-token',
  elasticKey: 'ApiKey elastic-sim-key',
  qradarSec: 'qradar-sim-sec',
  tenableKeys: 'accessKey=tenable-ak;secretKey=tenable-sk',
  qualysBasic: 'Basic ' + Buffer.from('qualys-user:qualys-pass').toString('base64'),
  satelliteBasic: 'Basic ' + Buffer.from('sat-user:sat-pass').toString('base64'),
  snowBasic: 'Basic ' + Buffer.from('snow-user:snow-pass').toString('base64'),
  jiraBasic: 'Basic ' + Buffer.from('jira@example.test:jira-api-token').toString('base64'),
  taxiiBasic: 'Basic ' + Buffer.from('taxii-user:taxii-pass').toString('base64'),
  awxClient: 'Basic ' + Buffer.from('awx-client:awx-secret').toString('base64'),
  awxAccess: 'Bearer awx-sim-access-token',
  mispKey: 'misp-sim-key',
  intelKey: 'intel-sim-key',
  genericToken: 'Bearer generic-sim-token',
};

const exports = new Map();
const stats = {};

function send(res, status, body, type = 'application/json') {
  const payload = typeof body === 'string' ? body : JSON.stringify(body);
  res.writeHead(status, { 'content-type': type, 'content-length': Buffer.byteLength(payload) });
  res.end(payload);
}
const unauthorized = (res) => send(res, 401, { error: 'unauthorized' });
const notFound = (res) => send(res, 404, { error: 'not found' });

function readBody(req) {
  return new Promise((resolve) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
  });
}

const vendors = {
  async splunk(req, res, url) {
    if (req.headers.authorization !== CREDS.splunkToken) return unauthorized(res);
    if (url.pathname === '/services/server/info') return send(res, 200, { entry: [{ content: { version: '9.3.1' } }] });
    if (url.pathname === '/services/search/jobs/export' && req.method === 'POST') {
      const form = new URLSearchParams(await readBody(req));
      if (!form.get('search') || form.get('output_mode') !== 'json') return send(res, 400, { error: 'bad search' });
      const rows = [
        { event_id: 'spl-001', rule_name: 'Brute force against VPN gateway', urgency: 'critical', _time: iso(2 * H), orig_time: iso(3 * H), status_label: 'New', security_domain: 'Access', _raw: CANARY },
        { event_id: 'spl-002', rule_name: 'Malware beacon to known C2', urgency: 'high', _time: iso(5 * H), orig_time: iso(6.5 * H), status_label: 'In Progress', security_domain: 'Endpoint', _raw: CANARY },
        { event_id: 'spl-003', rule_name: 'Excessive failed logins on DC', urgency: 'medium', _time: iso(20 * H), orig_time: iso(21 * H), status_label: 'Closed', security_domain: 'Identity', _raw: CANARY },
        { event_id: 'spl-004', rule_name: 'Suspicious PowerShell download cradle', urgency: 'low', _time: iso(30 * H), orig_time: iso(30.5 * H), status_label: 'Resolved', security_domain: 'Endpoint', _raw: CANARY },
      ];
      return send(res, 200, rows.map((r) => JSON.stringify({ preview: false, result: r })).join('\n'), 'application/json');
    }
    return notFound(res);
  },

  async elastic(req, res, url) {
    if (req.headers.authorization !== CREDS.elasticKey) return unauthorized(res);
    if (url.pathname === '/') return send(res, 200, { version: { number: '8.15.2' } });
    if (url.pathname === '/.alerts-security.alerts-default/_search' && req.method === 'POST') {
      const q = JSON.parse((await readBody(req)) || '{}');
      if (!q.query?.range?.['@timestamp']?.gte) return send(res, 400, { error: 'missing range' });
      const hit = (id, name, sev, agoH, status) => ({
        _id: id,
        _source: { '@timestamp': iso(agoH * H), 'kibana.alert.original_time': iso((agoH + 1) * H), 'kibana.alert.rule.name': name, 'kibana.alert.severity': sev, 'kibana.alert.workflow_status': status, 'event.original': CANARY },
      });
      return send(res, 200, {
        hits: {
          hits: [
            hit('ela-001', 'Credential dumping via LSASS access', 'critical', 1, 'open'),
            hit('ela-002', 'Unusual parent-child process tree', 'high', 8, 'acknowledged'),
            hit('ela-003', 'Rare DNS tunnelling pattern', 'medium', 26, 'closed'),
          ],
        },
      });
    }
    return notFound(res);
  },

  async qradar(req, res, url) {
    if (req.headers.sec !== CREDS.qradarSec) return unauthorized(res);
    if (!req.headers.version) return send(res, 400, { message: 'Version header required' });
    if (url.pathname === '/api/system/about') return send(res, 200, { external_version: '7.5.0 UP10' });
    if (url.pathname === '/api/siem/offenses') {
      if (!url.searchParams.get('filter')?.startsWith('last_updated_time >')) return send(res, 422, { message: 'bad filter' });
      return send(res, 200, [
        { id: 9001, description: 'Multiple login failures followed by success', magnitude: 9, start_time: now - 4 * H, first_persisted_time: now - 3 * H, status: 'OPEN', canary: CANARY },
        { id: 9002, description: 'Possible data exfiltration over HTTPS', magnitude: 6, start_time: now - 12 * H, first_persisted_time: now - 11 * H, status: 'OPEN' },
        { id: 9003, description: 'Port scan from internal host', magnitude: 3, start_time: now - 30 * H, first_persisted_time: now - 29 * H, status: 'CLOSED', close_time: now - 20 * H },
      ]);
    }
    return notFound(res);
  },

  async tenable(req, res, url) {
    if (req.headers['x-apikeys'] !== CREDS.tenableKeys) return unauthorized(res);
    if (url.pathname === '/session') return send(res, 200, { username: 'sim-api@tenable' });
    if (url.pathname === '/vulns/export' && req.method === 'POST') {
      const uuid = `exp-${exports.size + 1}`;
      exports.set(uuid, 0);
      return send(res, 200, { export_uuid: uuid });
    }
    const m = /^\/vulns\/export\/([\w-]+)\/(status|chunks\/(\d+))$/.exec(url.pathname);
    if (m && exports.has(m[1])) {
      if (m[2] === 'status') {
        const polls = exports.get(m[1]) + 1;
        exports.set(m[1], polls);
        return send(res, 200, polls < 2 ? { status: 'PROCESSING' } : { status: 'FINISHED', chunks_available: [1] });
      }
      const v = (host, ip, pid, name, cve, score, sev, state, foundDaysAgo) => ({
        asset: { uuid: `uuid-${host}`, hostname: host, ipv4: ip },
        plugin: { id: pid, name, cve: [cve], cvss3_base_score: score },
        severity: sev,
        state,
        first_found: iso(foundDaysAgo * D),
        last_fixed: state === 'FIXED' ? iso(D) : undefined,
        output: CANARY,
      });
      return send(res, 200, [
        v('vpn-edge-01.sim.test', '10.50.0.10', 190001, 'Palo Alto PAN-OS GlobalProtect Command Injection', 'CVE-2024-3400', 10.0, 'critical', 'OPEN', 3),
        v('vpn-edge-02.sim.test', '10.50.0.11', 190001, 'Palo Alto PAN-OS GlobalProtect Command Injection', 'CVE-2024-3400', 10.0, 'critical', 'OPEN', 3),
        v('app-tenable-01.sim.test', '10.50.1.20', 190002, 'Apache ActiveMQ Deserialisation RCE', 'CVE-2023-46604', 10.0, 'critical', 'REOPENED', 25),
        v('app-tenable-02.sim.test', '10.50.1.21', 190003, 'OpenSSH regreSSHion race condition', 'CVE-2024-6387', 8.1, 'high', 'FIXED', 12),
      ]);
    }
    return notFound(res);
  },

  async nessus(req, res, url) {
    if (req.headers['x-apikeys'] !== CREDS.tenableKeys) return unauthorized(res);
    if (url.pathname === '/server/status') return send(res, 200, { status: 'ready' });
    if (url.pathname === '/scans/42') {
      return send(res, 200, { info: { scan_start: Math.floor((now - D) / 1000) }, hosts: [{ host_id: 1, hostname: 'db-nessus-01.sim.test' }, { host_id: 2, hostname: 'db-nessus-02.sim.test' }] });
    }
    const m = /^\/scans\/42\/hosts\/(\d)$/.exec(url.pathname);
    if (m) {
      return send(res, 200, {
        info: { 'host-fqdn': `db-nessus-0${m[1]}.sim.test`, 'host-ip': `10.60.0.${m[1]}` },
        vulnerabilities: [
          { plugin_id: 155999, plugin_name: 'Apache Log4j < 2.15.0 RCE (CVE-2021-44228)', severity: 4 },
          { plugin_id: 57582, plugin_name: 'SSL Self-Signed Certificate', severity: 2 },
          { plugin_id: 19506, plugin_name: 'Nessus Scan Information', severity: 0 },
        ],
        canary: CANARY,
      });
    }
    return notFound(res);
  },

  async qualys(req, res, url) {
    if (req.headers.authorization !== CREDS.qualysBasic) return unauthorized(res);
    if (!req.headers['x-requested-with']) return send(res, 400, '<ERROR>X-Requested-With header required</ERROR>', 'application/xml');
    await readBody(req);
    if (url.pathname === '/api/2.0/fo/asset/host/') return send(res, 200, '<?xml version="1.0"?><HOST_LIST_OUTPUT><RESPONSE/></HOST_LIST_OUTPUT>', 'application/xml');
    if (url.pathname === '/api/2.0/fo/asset/host/vm/detection/') {
      // Includes a DOCTYPE with an entity-expansion payload: the parser must not expand it.
      const xml = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE HOST_LIST_VM_DETECTION_OUTPUT [
  <!ENTITY a "LOLLOLLOLLOLLOLLOLLOLLOL">
  <!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">
  <!ENTITY c "&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;">
]>
<HOST_LIST_VM_DETECTION_OUTPUT><RESPONSE><HOST_LIST>
  <HOST><ID>1101</ID><IP>10.70.0.5</IP><DNS>erp-qualys-01.sim.test</DNS>
    <DETECTION_LIST>
      <DETECTION><QID>38913</QID><SEVERITY>5</SEVERITY><STATUS>Active</STATUS><FIRST_FOUND_DATETIME>${iso(9 * D)}</FIRST_FOUND_DATETIME><RESULTS>&c; ${CANARY}</RESULTS></DETECTION>
      <DETECTION><QID>11827</QID><SEVERITY>4</SEVERITY><STATUS>Fixed</STATUS><FIRST_FOUND_DATETIME>${iso(30 * D)}</FIRST_FOUND_DATETIME><LAST_FIXED_DATETIME>${iso(2 * D)}</LAST_FIXED_DATETIME></DETECTION>
    </DETECTION_LIST></HOST>
  <HOST><ID>1102</ID><IP>10.70.0.6</IP><DNS>hr-qualys-02.sim.test</DNS>
    <DETECTION_LIST>
      <DETECTION><QID>105484</QID><SEVERITY>3</SEVERITY><STATUS>New</STATUS><FIRST_FOUND_DATETIME>${iso(D)}</FIRST_FOUND_DATETIME></DETECTION>
    </DETECTION_LIST></HOST>
</HOST_LIST></RESPONSE></HOST_LIST_VM_DETECTION_OUTPUT>`;
      return send(res, 200, xml, 'application/xml');
    }
    return notFound(res);
  },

  async wsus(req, res, url) {
    // WSUS bridge requires a client certificate issued by the internal CA (mTLS).
    if (!req.socket.authorized) return unauthorized(res);
    if (url.pathname === '/wsus/compliance.json') {
      return send(res, 200, [
        { computerName: 'ws-fin-001.sim.test', ipAddress: '10.80.0.11', os: 'Windows 11 Enterprise', neededCount: 0, failedCount: 0, lastSyncTime: iso(2 * H), canary: CANARY },
        { computerName: 'ws-fin-002.sim.test', ipAddress: '10.80.0.12', os: 'Windows 11 Enterprise', neededCount: 4, failedCount: 1, lastSyncTime: iso(5 * D) },
        { computerName: 'srv-file-01.sim.test', ipAddress: '10.80.1.5', os: 'Windows Server 2022', neededCount: 0, failedCount: 0, lastSyncTime: iso(H) },
        { computerName: 'srv-print-01.sim.test', ipAddress: '10.80.1.6', os: 'Windows Server 2019', neededCount: 7, failedCount: 0, lastSyncTime: iso(9 * D) },
      ]);
    }
    return notFound(res);
  },

  async awx(req, res, url) {
    if (url.pathname === '/oauth2/token/' && req.method === 'POST') {
      const form = new URLSearchParams(await readBody(req));
      if (req.headers.authorization !== CREDS.awxClient || form.get('grant_type') !== 'client_credentials') return unauthorized(res);
      return send(res, 200, { access_token: CREDS.awxAccess.slice(7), token_type: 'Bearer', expires_in: 3600 });
    }
    if (req.headers.authorization !== CREDS.awxAccess) return unauthorized(res);
    if (url.pathname === '/api/v2/ping/') return send(res, 200, { version: '24.6.1' });
    if (url.pathname === '/api/v2/inventories/7/hosts/') {
      const host = (name, failing, status) => ({ name, has_active_failures: failing, summary_fields: { last_job: { status, finished: iso(6 * H) } }, variables: CANARY });
      if (url.searchParams.get('page') === '2') return send(res, 200, { next: null, results: [host('rhel-app-03.sim.test', false, 'successful')] });
      return send(res, 200, {
        next: '/api/v2/inventories/7/hosts/?page=2&page_size=200',
        results: [host('rhel-app-01.sim.test', false, 'successful'), host('rhel-app-02.sim.test', true, 'failed')],
      });
    }
    return notFound(res);
  },

  async satellite(req, res, url) {
    if (req.headers.authorization !== CREDS.satelliteBasic) return unauthorized(res);
    if (url.pathname === '/api/status') return send(res, 200, { satellite_version: '6.16.0' });
    if (url.pathname === '/api/v2/hosts') {
      const host = (name, ip, sec) => ({ name, ip, operatingsystem_name: 'RHEL 9.4', last_report: iso(3 * H), content_facet_attributes: { errata_counts: { security: sec, bugfix: 2 } }, comment: CANARY });
      return send(res, 200, { total: 3, per_page: 200, results: [host('rhel-db-01.sim.test', '10.90.0.1', 0), host('rhel-db-02.sim.test', '10.90.0.2', 5), host('rhel-web-01.sim.test', '10.90.0.3', 0)] });
    }
    return notFound(res);
  },

  async servicenow(req, res, url) {
    if (req.headers.authorization !== CREDS.snowBasic) return unauthorized(res);
    if (url.pathname === '/api/now/table/change_request') {
      if (url.searchParams.get('sysparm_limit') === '1') return send(res, 200, { result: [{ sys_id: 'x' }] });
      if (!url.searchParams.get('sysparm_query')?.includes('sys_updated_on>=')) return send(res, 400, { error: 'query' });
      const chg = (n, d, s) => ({ sys_id: `sys-${n}`, number: n, short_description: d, state: s, sys_updated_on: new Date(now - H).toISOString().slice(0, 19).replace('T', ' '), work_notes: CANARY });
      return send(res, 200, { result: [chg('CHG0051001', 'Emergency patch PAN-OS GlobalProtect (CVE-2024-3400)', 'Implement'), chg('CHG0051002', 'Upgrade ActiveMQ brokers to 5.18.3', 'Scheduled'), chg('CHG0051003', 'Rotate VPN certificates', 'Review')] });
    }
    return notFound(res);
  },

  async jira(req, res, url) {
    if (req.headers.authorization !== CREDS.jiraBasic) return unauthorized(res);
    if (url.pathname === '/rest/api/3/myself') return send(res, 200, { displayName: 'Sim Jira Bot' });
    if (url.pathname === '/rest/api/3/search/jql' && req.method === 'POST') {
      const q = JSON.parse((await readBody(req)) || '{}');
      if (!q.jql) return send(res, 400, { errorMessages: ['jql required'] });
      return send(res, 200, {
        issues: [
          { key: 'CHG-1201', fields: { summary: 'Patch OpenSSH on bastion hosts', status: { name: 'In Progress' }, updated: iso(2 * H), description: CANARY } },
          { key: 'CHG-1202', fields: { summary: 'Disable legacy TLS on load balancers', status: { name: 'Done' }, updated: iso(D) } },
        ],
      });
    }
    return notFound(res);
  },

  async misp(req, res, url) {
    if (req.headers.authorization !== CREDS.mispKey) return unauthorized(res);
    if (url.pathname === '/servers/getVersion') return send(res, 200, { version: '2.4.198' });
    if (url.pathname === '/events/restSearch' && req.method === 'POST') {
      await readBody(req);
      const ev = (id, info, level, tags, attrs = []) => ({ Event: { id, uuid: `misp-uuid-${id}`, info, threat_level_id: level, date: iso(D).slice(0, 10), publish_timestamp: String(Math.floor((now - 6 * H) / 1000)), Orgc: { name: 'FS-ISAC (sim)' }, Tag: tags.map((name) => ({ name })), Attribute: [...attrs, { type: 'comment', value: CANARY }] } });
      return send(res, 200, {
        response: [
          ev('501', 'Akira ransomware affiliates targeting Cisco ASA without MFA', '1', ['ransomware', 'tlp:amber']),
          ev('502', 'Citrix Bleed exploitation observed in financial sector', '1', ['exploited'], [{ type: 'vulnerability', value: 'CVE-2023-4966' }]),
          ev('503', 'Malicious npm package mimicking popular logging library', '2', ['supply-chain', 'npm']),
        ],
      });
    }
    return notFound(res);
  },

  async taxii(req, res, url) {
    if (req.headers.authorization !== CREDS.taxiiBasic) return unauthorized(res);
    if (!String(req.headers.accept).includes('application/taxii+json')) return send(res, 406, { title: 'Not Acceptable' });
    if (url.pathname === '/taxii2/api1/collections/sim-collection-1/') return send(res, 200, { id: 'sim-collection-1', title: 'Simulated Vendor Intel' });
    if (url.pathname === '/taxii2/api1/collections/sim-collection-1/objects/') {
      return send(res, 200, {
        more: false,
        objects: [
          { type: 'vulnerability', id: 'vulnerability--sim-0001', name: 'FortiOS SSL VPN out-of-bounds write', description: 'Actively exploited.', created: iso(D), external_references: [{ source_name: 'cve', external_id: 'CVE-2024-21762' }], x_canary: CANARY },
          { type: 'malware', id: 'malware--sim-0002', name: 'BlackSuit', malware_types: ['ransomware'], description: 'Ransomware family targeting ESXi.', created: iso(2 * D) },
          { type: 'report', id: 'report--sim-0003', name: 'Compromised CI/CD action leaks secrets', labels: ['supply-chain'], description: 'Rotate CI secrets.', published: iso(3 * D) },
          { type: 'indicator', id: 'indicator--sim-0004', name: 'C2 domain sim-c2.example', pattern: "[domain-name:value = 'sim-c2.example']", created: iso(4 * H) },
          { type: 'identity', id: 'identity--sim-0005', name: 'ignored object type' },
        ],
      });
    }
    return notFound(res);
  },

  async intel(req, res, url) {
    if (req.headers['x-api-key'] !== CREDS.intelKey) return unauthorized(res);
    if (url.pathname === '/v1/advisories') {
      return send(res, 200, {
        data: {
          items: [
            { id: 'adv-77', title: 'LockBit successor group leaks data from logistics firms', description: 'Ransomware double-extortion campaign.', severity: 'critical', published: iso(5 * H), tags: ['ransomware', 'lockbit'], raw: CANARY },
            { id: 'adv-78', title: 'Third-party SaaS provider breach exposes API tokens', description: 'Rotate integration tokens.', severity: 'high', published: iso(D), tags: ['third-party', 'saas'] },
            { id: 'adv-79', title: 'Phishing kit abusing QR codes', description: 'Quishing wave.', severity: 'medium', published: iso(2 * D), tags: ['phishing'] },
          ],
        },
      });
    }
    return notFound(res);
  },

  async kev(_req, res, url) {
    if (url.pathname === '/feeds/kev.json') {
      const today = new Date(now).toISOString().slice(0, 10);
      return send(res, 200, {
        catalogVersion: '2099.01.01',
        count: 2,
        vulnerabilities: [
          { cveID: 'CVE-2024-3400', vendorProject: 'Palo Alto Networks', product: 'PAN-OS', vulnerabilityName: 'PAN-OS Command Injection', dateAdded: today, shortDescription: 'GlobalProtect command injection.', requiredAction: 'Apply mitigations.', dueDate: today, knownRansomwareCampaignUse: 'Known', notes: CANARY },
          { cveID: 'CVE-2024-6387', vendorProject: 'OpenBSD', product: 'OpenSSH', vulnerabilityName: 'OpenSSH Signal Handler Race', dateAdded: today, shortDescription: 'regreSSHion.', requiredAction: 'Upgrade.', dueDate: today, knownRansomwareCampaignUse: 'Unknown' },
        ],
      });
    }
    return notFound(res);
  },

  // Generic REST/JSON vendor behind an API gateway prefix (/gw). Requires the version
  // header and tenant parameter that administrators configure as connector API parameters.
  async generic(req, res, url) {
    if (req.headers.authorization !== CREDS.genericToken) return unauthorized(res);
    if (!url.pathname.startsWith('/gw/')) return notFound(res);
    if (req.headers['x-api-version'] !== '2') return send(res, 400, { error: 'X-Api-Version: 2 required' });
    if (url.searchParams.get('tenant') !== 'emea') return send(res, 403, { error: 'tenant required' });
    const path = url.pathname.slice(3);
    const int = (k, d) => Number(url.searchParams.get(k) ?? d);

    if (path === '/v2/status') return send(res, 200, { status: 'ok' });

    // Cursor pagination (body meta.next_cursor), 5 alerts, page size from ?limit
    if (path === '/v2/alerts' || path === '/v2/flaky-alerts') {
      if (path === '/v2/flaky-alerts') {
        stats.genericFlaky = (stats.genericFlaky ?? 0) + 1;
        if (stats.genericFlaky % 2 === 1) {
          res.writeHead(503, { 'retry-after': '1', 'content-type': 'application/json' });
          return res.end('{"error":"temporarily unavailable"}');
        }
      }
      const all = [
        { id: 'gen-al-1', title: 'Impossible travel detected', severity: 'high', created_at: iso(6 * H), status: 'new', category: 'Identity', asset_count: 1, canary: CANARY },
        { id: 'gen-al-2', title: 'Ransomware behaviour on file server', severity: 9.6, created_at: iso(5 * H), status: 'contained', category: 'Malware', asset_count: 3 },
        { id: 'gen-al-3', title: 'Suspicious PowerShell download cradle', severity: 'medium', created_at: iso(4 * H), status: 'investigating', category: 'Execution' },
        { id: 'gen-al-4', title: 'Phishing link clicked', severity: 'low', created_at: iso(30 * H), status: 'closed', resolved_at: iso(20 * H), category: 'Phishing' },
        { id: 'gen-al-5', title: 'Data staged for exfiltration', severity: 'critical', created_at: iso(2 * H), status: 'new', category: 'Exfiltration' },
      ];
      const limit = int('limit', 100);
      const start = Number(url.searchParams.get('cursor')?.replace('c', '') ?? 0);
      const page = all.slice(start, start + limit);
      const next = start + limit < all.length ? `c${start + limit}` : null;
      return send(res, 200, { data: page, meta: { next_cursor: next } });
    }

    // Page-number pagination (?page=1&per_page=N), 5 findings
    if (path === '/v2/findings') {
      const all = [
        { id: 'gen-f-1', asset: { hostname: 'gen-web-01.corp.example', ip: '10.60.0.11' }, cve: 'CVE-2024-3400', title: 'PAN-OS command injection', severity: 'critical', cvss: 10, first_seen: iso(3 * D), state: 'open', canary: CANARY },
        { id: 'gen-f-2', asset: { hostname: 'gen-web-01.corp.example', ip: '10.60.0.11' }, cve: 'CVE-2024-6387', title: 'OpenSSH regreSSHion', cvss: 8.1, first_seen: iso(2 * D), state: 'open' },
        { id: 'gen-f-3', asset: { hostname: 'gen-db-02.corp.example', ip: '10.60.0.12' }, cve: 'CVE-2023-44487', title: 'HTTP/2 Rapid Reset', severity: 'high', cvss: 7.5, first_seen: iso(9 * D), state: 'fixed', fixed_at: iso(D) },
        { id: 'gen-f-4', asset: { hostname: 'gen-db-02.corp.example', ip: '10.60.0.12' }, title: 'TLS 1.0 enabled', severity: 'medium', cvss: 5.3, first_seen: iso(20 * D), state: 'open' },
        { id: 'gen-f-5', asset: { hostname: 'gen-app-03.corp.example', ip: '10.60.0.13' }, cve: 'CVE-2024-4577', title: 'PHP-CGI argument injection', severity: 'critical', cvss: 9.8, first_seen: iso(D), state: 'open' },
      ];
      const per = int('per_page', 100);
      const pageNo = int('page', 1);
      return send(res, 200, { results: all.slice((pageNo - 1) * per, pageNo * per) });
    }

    // Offset pagination (?offset=N&limit=M), 3 devices
    if (path === '/v2/devices') {
      const all = [
        { hostname: 'gen-web-01.corp.example', ip: '10.60.0.11', os: 'Ubuntu 24.04 LTS', compliant: true, missing_patches: 0, last_patched: iso(2 * D), canary: CANARY },
        { hostname: 'gen-db-02.corp.example', ip: '10.60.0.12', os: 'RHEL 9.4', compliant: 'non-compliant', missing_patches: 4, last_patched: iso(40 * D) },
        { hostname: 'gen-app-03.corp.example', ip: '10.60.0.13', os: 'Windows Server 2022', missing_patches: 2, last_patched: iso(15 * D) },
      ];
      const off = int('offset', 0);
      const lim = int('limit', 100);
      return send(res, 200, { items: all.slice(off, off + lim), total: all.length });
    }

    // RFC 8288 Link-header pagination, 3 changes over 2 pages
    if (path === '/v2/changes') {
      const all = [
        { number: 'GCHG-1001', summary: 'Patch PAN-OS gateways', state: 'Scheduled', url: 'https://itsm.example/changes/GCHG-1001', updated_at: iso(H), canary: CANARY },
        { number: 'GCHG-1002', summary: 'Disable TLS 1.0 on database tier', state: 'Approved', url: 'javascript:alert(1)', updated_at: iso(2 * H) },
        { number: 'GCHG-1003', summary: 'Upgrade OpenSSH fleet-wide', state: 'Implement', url: 'https://itsm.example/changes/GCHG-1003', updated_at: iso(3 * H) },
      ];
      const pageNo = int('page', 1);
      const size = int('limit', 2);
      const slice = all.slice((pageNo - 1) * size, pageNo * size);
      if (pageNo * size < all.length) {
        res.setHeader('link', `<https://${req.headers.host}/gw/v2/changes?page=${pageNo + 1}&limit=${size}&tenant=emea>; rel="next"`);
      }
      return send(res, 200, slice);
    }
    return notFound(res);
  },

  // Attempts to bounce the connector to cloud metadata — redirects must never be followed.
  async redirect(_req, res) {
    res.writeHead(302, { location: 'http://169.254.169.254/latest/meta-data/' });
    res.end();
  },
};

const server = https.createServer(
  {
    key: readFileSync('/certs/sim.key'),
    cert: readFileSync('/certs/sim.crt'),
    ca: readFileSync('/certs/ca.crt'),
    requestCert: true,
    rejectUnauthorized: false, // per-vendor decision (only WSUS demands mTLS)
    minVersion: 'TLSv1.2',
  },
  async (req, res) => {
    const host = String(req.headers.host ?? '').split(':')[0];
    const vendor = host.endsWith('.sim.test') ? host.split('.')[0] : '';
    const url = new URL(req.url ?? '/', `https://${host}`);
    if (url.pathname === '/__stats') return send(res, 200, stats);
    stats[vendor] = (stats[vendor] ?? 0) + 1;
    const fn = vendors[vendor];
    if (!fn) return notFound(res);
    try {
      await fn(req, res, url);
    } catch (err) {
      send(res, 500, { error: String(err) });
    }
    console.log(`${new Date().toISOString()} ${vendor} ${req.method} ${url.pathname} -> ${res.statusCode}`);
  },
);
server.listen(PORT, () => console.log(`vendor simulator listening on ${PORT}`));
