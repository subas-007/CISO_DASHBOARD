import { readFileSync, writeFileSync } from 'node:fs';
import { randomBytes } from 'node:crypto';
import tls from 'node:tls';
import http from 'node:http';
import path from 'node:path';
import { test, expect, compose, docker, psql, restartApi, waitFor } from './support/fixtures';
import { BASE, ROOT } from './support/env';

const host = new URL(BASE).hostname;
const port = Number(new URL(BASE).port || 443);

test.describe('Tamper-evident audit trail', () => {
  test('modification of an audit record is detected, and restoring it heals the chain', async ({ as }) => {
    const { api } = await as('auditor');
    expect((await api('GET', '/audit/verify')).json.valid).toBe(true);
    const id = psql(`SELECT id FROM audit_log WHERE outcome = 'SUCCESS' ORDER BY id LIMIT 1 OFFSET 3`).out.trim();
    // Even the owner needs to disable the trigger (superuser-only) to tamper.
    const tamper = psql(`ALTER TABLE audit_log DISABLE TRIGGER audit_log_no_update_delete;
                         UPDATE audit_log SET outcome = 'FAILURE' WHERE id = ${id};
                         ALTER TABLE audit_log ENABLE TRIGGER audit_log_no_update_delete;`);
    expect(tamper.code, tamper.out).toBe(0);
    const v = (await api('GET', '/audit/verify')).json;
    expect(v).toMatchObject({ valid: false, firstInvalidId: id, reason: 'Record content does not match its hash' });
    psql(`ALTER TABLE audit_log DISABLE TRIGGER audit_log_no_update_delete;
          UPDATE audit_log SET outcome = 'SUCCESS' WHERE id = ${id};
          ALTER TABLE audit_log ENABLE TRIGGER audit_log_no_update_delete;`);
    expect((await api('GET', '/audit/verify')).json.valid).toBe(true);
  });

  test('deletion of an audit record is detected (broken chain link)', async ({ as }) => {
    const { api } = await as('auditor');
    const id = psql(`SELECT id FROM audit_log ORDER BY id LIMIT 1 OFFSET 6`).out.trim();
    const r = psql(`CREATE TABLE IF NOT EXISTS audit_backup AS SELECT * FROM audit_log WHERE false;
                    INSERT INTO audit_backup SELECT * FROM audit_log WHERE id = ${id};
                    ALTER TABLE audit_log DISABLE TRIGGER audit_log_no_update_delete;
                    DELETE FROM audit_log WHERE id = ${id};
                    ALTER TABLE audit_log ENABLE TRIGGER audit_log_no_update_delete;`);
    expect(r.code, r.out).toBe(0);
    const v = (await api('GET', '/audit/verify')).json;
    expect(v.valid).toBe(false);
    expect(v.reason).toMatch(/Broken chain link/);
    psql(`INSERT INTO audit_log SELECT * FROM audit_backup WHERE id = ${id}; DROP TABLE audit_backup;`);
    expect((await api('GET', '/audit/verify')).json.valid).toBe(true);
  });

  test('UPDATE / DELETE / TRUNCATE are blocked by triggers even for the owner', async () => {
    for (const sql of ['UPDATE audit_log SET action = action', 'DELETE FROM audit_log', 'TRUNCATE audit_log']) {
      const r = psql(sql);
      expect(r.code).not.toBe(0);
      expect(r.out).toMatch(/append-only/);
    }
  });
});

test.describe('Database least privilege & transport', () => {
  test('runtime role ciso_app has DML only and cannot alter the audit trail or schema', async () => {
    const denied = [
      'UPDATE audit_log SET outcome = outcome',
      'DELETE FROM audit_log',
      'TRUNCATE audit_log',
      'CREATE TABLE evil (id int)',
      'DROP TABLE risks',
      'ALTER TABLE users ADD COLUMN x int',
      'SELECT count(*) FROM _prisma_migrations',
      'CREATE ROLE attacker',
    ];
    for (const sql of denied) {
      const r = psql(sql, 'app');
      expect(r.code, `${sql} should be denied`).not.toBe(0);
      expect(r.out).toMatch(/permission denied|must be owner|append-only/);
    }
    expect(psql('SELECT count(*) FROM risks', 'app').code).toBe(0);
  });

  test('non-TLS connections are refused and live sessions use TLS 1.3', async () => {
    const plain = compose(['exec', '-T', 'postgres', 'sh', '-c', 'PGPASSWORD="$POSTGRES_PASSWORD" psql "host=127.0.0.1 sslmode=disable user=$POSTGRES_USER dbname=$POSTGRES_DB" -c "select 1"']);
    expect(plain.code).not.toBe(0);
    expect(plain.out).toMatch(/pg_hba\.conf rejects connection|no encryption/);
    const r = psql(`SELECT DISTINCT s.version FROM pg_stat_ssl s JOIN pg_stat_activity a USING (pid) WHERE a.backend_type = 'client backend' AND a.usename IN ('ciso_app','keycloak')`);
    expect(r.out.trim().split(/\r?\n/)).toEqual(['TLSv1.3']);
    const unencrypted = psql(`SELECT count(*) FROM pg_stat_ssl s JOIN pg_stat_activity a USING (pid) WHERE a.backend_type = 'client backend' AND NOT s.ssl AND a.client_addr IS NOT NULL`);
    expect(unencrypted.out.trim()).toBe('0');
  });

  test('sensitive fields are AES-256-GCM ciphertext at rest', async () => {
    const r = psql(`SELECT
      (SELECT count(*) FROM users WHERE "emailEnc" IS NOT NULL AND "emailEnc" NOT LIKE 'enc:%'),
      (SELECT count(*) FROM incidents WHERE "descriptionEnc" IS NOT NULL AND "descriptionEnc" NOT LIKE 'enc:%'),
      (SELECT count(*) FROM risk_acceptances WHERE "justificationEnc" NOT LIKE 'enc:%'),
      (SELECT count(*) FROM sessions WHERE "idpRefreshEnc" IS NOT NULL AND "idpRefreshEnc" NOT LIKE 'enc:%'),
      (SELECT count(*) FROM users WHERE "emailEnc" LIKE '%@%')`);
    expect(r.out.trim()).toBe('0|0|0|0|0');
    const refresh = psql(`SELECT count(*) FROM sessions WHERE length("refreshHash") <> 64`);
    expect(refresh.out.trim()).toBe('0'); // only SHA-256 digests of refresh tokens are stored
  });
});

test.describe('Container hardening & network isolation', () => {
  test('services run non-root, read-only, with all capabilities dropped', async () => {
    const ps = compose(['ps', '-q']).out.trim().split(/\r?\n/);
    const info = JSON.parse(docker(['inspect', ...ps]).out) as { Name: string; Config: { User: string }; HostConfig: { ReadonlyRootfs: boolean; CapDrop: string[] | null; SecurityOpt: string[] | null } }[];
    const by = (svc: string) => info.find((c) => c.Name.includes(`-${svc}-`))!;
    for (const svc of ['api', 'gateway', 'keycloak', 'postgres', 'vendor-sim']) {
      const c = by(svc);
      expect(c.HostConfig.CapDrop, svc).toContain('ALL');
      expect(c.HostConfig.SecurityOpt?.join(','), svc).toContain('no-new-privileges');
    }
    for (const svc of ['api', 'gateway']) {
      expect(by(svc).HostConfig.ReadonlyRootfs, svc).toBe(true);
      expect(by(svc).Config.User, svc).toMatch(/^\d+:\d+$/);
      expect(by(svc).Config.User.startsWith('0:'), svc).toBe(false);
    }
    expect(compose(['exec', '-T', 'api', 'id', '-u']).out.trim()).not.toBe('0');
    expect(compose(['exec', '-T', 'api', 'sh', '-c', 'touch /app/pwned']).code).not.toBe(0);
    expect(compose(['exec', '-T', 'api', 'sh', '-c', 'command -v npm']).code).not.toBe(0); // no package manager at runtime
  });

  test('only the gateway is published; internal services are unreachable from the host', async () => {
    for (const [svc, p] of [['api', '8443'], ['postgres', '5432'], ['keycloak', '8443'], ['vendor-sim', '8443']]) {
      expect(compose(['port', svc!, p!]).out.trim(), `${svc}:${p}`).not.toMatch(/\d+\.\d+\.\d+\.\d+:\d+/);
    }
    expect(compose(['port', 'gateway', '8443']).out).toMatch(/:443/);
  });

  test('network zones: gateway cannot reach the database or the simulator', async () => {
    const pg = compose(['exec', '-T', 'gateway', 'sh', '-c', 'wget -q -T 3 -O /dev/null http://postgres:5432 2>&1; echo rc=$?']);
    expect(pg.out).toMatch(/bad address|unknown host|rc=[1-9]/i);
    const sim = compose(['exec', '-T', 'gateway', 'sh', '-c', 'wget -q -T 3 -O /dev/null https://kev.sim.test:8443/feeds/kev.json 2>&1; echo rc=$?']);
    expect(sim.out).toMatch(/bad address|unknown host|rc=[1-9]/i);
  });

  test('API requires a CA-issued client certificate (mTLS) even inside the app network', async () => {
    const certs = path.join(ROOT, 'certs').replace(/\\/g, '/');
    const script = `
      const https=require('https'),fs=require('fs');
      const go=(o)=>new Promise(r=>{const q=https.get({host:'api',port:8443,path:'/api/health',servername:'api',ca:fs.readFileSync('/certs/ca.crt'),...o},s=>r('HTTP '+s.statusCode));q.on('error',e=>r('ERR '+e.code));q.setTimeout(4000,()=>q.destroy())});
      (async()=>{console.log('nocert='+await go({}));console.log('withcert='+await go({cert:fs.readFileSync('/certs/tls.crt'),key:fs.readFileSync('/certs/tls.key')}));console.log('tls12='+await go({cert:fs.readFileSync('/certs/tls.crt'),key:fs.readFileSync('/certs/tls.key'),maxVersion:'TLSv1.2'}))})();`;
    const r = docker(['run', '--rm', '--network', 'ciso-dashboard_app', '-v', `${certs}:/certs:ro`, 'node:22-alpine', 'node', '-e', script]);
    expect(r.out).toMatch(/nocert=ERR/);
    expect(r.out).toMatch(/withcert=HTTP 200/);
    expect(r.out).toMatch(/tls12=ERR/);
  });

  test('secrets are delivered as files, never visible in container config or process environment', async () => {
    const jwt = readFileSync(path.join(ROOT, 'secrets/jwt_secret'), 'utf8').trim();
    const dek = readFileSync(path.join(ROOT, 'secrets/data_encryption_keys'), 'utf8').trim().split(',')[0]!.split(':')[1]!;
    const dbUrl = readFileSync(path.join(ROOT, 'secrets/database_url'), 'utf8').trim();
    const dbPw = /:\/\/[^:]+:([^@]+)@/.exec(dbUrl)![1]!;
    const inspect = docker(['inspect', compose(['ps', '-q', 'api']).out.trim()]).out;
    for (const s of [jwt, dek, dbPw]) expect(inspect).not.toContain(s);
    const environ = compose(['exec', '-T', 'api', 'sh', '-c', "cat /proc/[0-9]*/environ 2>/dev/null | tr '\\0' '\\n'"]).out;
    expect(environ).toContain('JWT_SECRET_FILE=');
    for (const s of [jwt, dek, dbPw]) expect(environ).not.toContain(s);
  });
});

test.describe('Edge & HTTP hardening', () => {
  test('TLS 1.2 is refused, TLS 1.3 negotiates an AEAD suite', async () => {
    const attempt = (opts: tls.ConnectionOptions) =>
      new Promise<string>((resolve) => {
        const s = tls.connect({ host, port, servername: host, rejectUnauthorized: false, ...opts }, () => {
          resolve(`${s.getProtocol()} ${s.getCipher().name}`);
          s.end();
        });
        s.on('error', (e) => resolve(`ERR ${(e as NodeJS.ErrnoException).code ?? e.message}`));
      });
    expect(await attempt({ maxVersion: 'TLSv1.2' })).toMatch(/^ERR/);
    expect(await attempt({})).toMatch(/^TLSv1\.3 TLS_(AES_256_GCM_SHA384|CHACHA20_POLY1305_SHA256|AES_128_GCM_SHA256)$/);
  });

  test('plain HTTP redirects to HTTPS', async () => {
    const res = await new Promise<http.IncomingMessage>((resolve) => http.get({ host, port: 80, path: '/risk' }, resolve));
    expect(res.statusCode).toBe(301);
    expect(res.headers.location).toBe(`https://${host}/risk`);
  });

  test('security headers on SPA, API and static assets', async ({ request }) => {
    const spa = await request.get('/');
    const h = spa.headers();
    expect(h['strict-transport-security']).toContain('max-age=63072000');
    expect(h['content-security-policy']).toContain("script-src 'self'");
    expect(h['content-security-policy']).toContain("frame-ancestors 'none'");
    expect(h['content-security-policy']).not.toContain('unsafe-inline');
    expect(h['x-frame-options']).toBe('DENY');
    expect(h['x-content-type-options']).toBe('nosniff');
    expect(h['referrer-policy']).toBe('no-referrer');
    expect(h['server']).toBe('nginx'); // no version disclosure
    const api = await request.get('/api/health');
    expect(api.headers()['cache-control']).toBe('no-store');
    expect(api.headers()['x-powered-by']).toBeUndefined();
    expect(api.headers()['x-request-id']).toMatch(/^[0-9a-f-]{36}$/);
    const html = await spa.text();
    const asset = /src="(\/assets\/[^"]+\.js)"/.exec(html)![1]!;
    const a = await request.get(asset);
    expect(a.headers()['cache-control']).toContain('immutable');
    expect(a.headers()['strict-transport-security']).toBeTruthy();
    expect(html).not.toMatch(/<script>(?!<\/script>)/); // no inline scripts
  });

  test('malformed, oversized and over-specified requests are rejected cleanly', async ({ as }) => {
    const { api, ctx } = await as('secops');
    const csrf = (await ctx.cookies(BASE)).find((c) => c.name === '__Host-ciso_csrf')!.value;
    const post = (data: string) => ctx.request.post(`${BASE}/api/risks`, { headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf, Origin: new URL(BASE).origin }, data, failOnStatusCode: false });
    expect((await post('{"title":')).status()).toBe(400);
    expect((await post(JSON.stringify({ title: 'x'.repeat(200_000) }))).status()).toBe(413);
    expect((await api('GET', '/threats?unexpected=1')).status).toBe(400);
    expect((await api('GET', '/audit?action=x;DROP TABLE users')).status).toBe(403); // secops lacks audit:read
    for (const q of ["' OR 1=1--", '"; DROP TABLE risks; --', '%27%20UNION%20SELECT%20*%20FROM%20users--', '${7*7}', '<script>alert(1)</script>']) {
      const r = await api('GET', `/threats?q=${encodeURIComponent(q)}`);
      expect(r.status, q).toBe(200);
      expect(r.json.items).toEqual([]);
    }
    const r = await api('GET', '/incidents?limit=100000');
    expect(r.status).toBe(400);
    const err = await api('GET', '/risks/not-a-uuid');
    expect(err.status).toBe(400);
    expect(err.text).not.toMatch(/stack|prisma|at \w+ \(/i);
  });
});

test.describe('Scheduled jobs', () => {
  test('expired acceptances re-open their risk and KRI breaches are recorded at evaluation', async ({ as }) => {
    const secops = await as('secops');
    const ciso = await as('ciso');
    const risk = (await secops.api('POST', '/risks', { title: `Expiry probe ${Date.now()}`, description: 'scheduler test', category: 'Test', likelihood: 3, impact: 3, ownerName: 'QA' })).json;
    const acc = (await secops.api('POST', `/risks/${risk.id}/acceptances`, { justification: 'Temporary acceptance for scheduler test run.', expiresInDays: 1 })).json;
    expect((await ciso.api('POST', `/risk-acceptances/${acc.id}/decision`, { decision: 'APPROVE', note: 'ok for test' })).status).toBe(200);
    expect((await ciso.api('GET', `/risks/${risk.id}`)).json.status).toBe('ACCEPTED');

    const kriBefore = (await ciso.api('GET', '/kri')).json.items.find((k: { key: string }) => k.key === 'open_critical');
    await ciso.api('PUT', '/kri/open_critical', { amberThreshold: 1, redThreshold: 2, enabled: true });
    psql(`UPDATE kri_breaches SET "acknowledgedAt" = now() WHERE "kriKey" = 'open_critical' AND "acknowledgedAt" IS NULL;
          UPDATE risk_acceptances SET "expiresAt" = now() - interval '1 day' WHERE id = '${acc.id}';`);

    await restartApi(); // jobs run shortly after boot
    const fresh = await as('ciso');
    await waitFor(async () => (await fresh.api('GET', `/risks/${risk.id}`)).json.status === 'OPEN', 40_000, 2000);
    const accNow = (await fresh.api('GET', '/risk-acceptances?status=EXPIRED')).json.items.find((a: { id: string }) => a.id === acc.id);
    expect(accNow).toBeTruthy();
    const breach = await waitFor(async () => (await fresh.api('GET', '/kri/breaches?open=true')).json.items.find((b: { kriKey: string }) => b.kriKey === 'open_critical'), 40_000, 2000);
    expect(breach.level).toBe('RED');
    expect((await fresh.api('GET', '/kpi/summary')).json.kris.find((k: { key: string }) => k.key === 'open_critical').status).toBe('RED');

    await fresh.api('PUT', '/kri/open_critical', { amberThreshold: kriBefore.amberThreshold, redThreshold: kriBefore.redThreshold, enabled: true });
  });
});

test.describe('Encryption key rotation', () => {
  test('new key becomes active without downtime; data under both keys stays readable', async ({ as }) => {
    test.setTimeout(300_000);
    const keyFile = path.join(ROOT, 'secrets/data_encryption_keys');
    const envFile = path.join(ROOT, '.env');
    const ring = readFileSync(keyFile, 'utf8').trim();
    const env = readFileSync(envFile, 'utf8');
    const setActive = (id: string) => writeFileSync(envFile, readFileSync(envFile, 'utf8').replace(/^DATA_ENCRYPTION_ACTIVE_KEY=.*$/m, `DATA_ENCRYPTION_ACTIVE_KEY=${id}`));
    try {
      if (!ring.includes('v2:')) writeFileSync(keyFile, `${ring},v2:${randomBytes(32).toString('base64')}`);
      setActive('v2');
      await restartApi();

      const s = await as('secops');
      const title = `Key rotation probe ${Date.now()}`;
      const created = await s.api('POST', '/incidents', { title, description: 'encrypted under v2', severity: 'LOW', category: 'Test', occurredAt: new Date().toISOString(), detectedAt: new Date().toISOString(), assetsAffected: 0 });
      expect(created.status).toBe(201);
      expect(psql(`SELECT left("descriptionEnc", 7) FROM incidents WHERE id = '${created.json.id}'`).out.trim()).toBe('enc:v2:');
      const seeded = (await s.api('GET', '/incidents?limit=200')).json.items.find((i: { description: string | null; source: string }) => i.source !== 'manual' && i.description?.startsWith('Seeded demo incident'));
      expect(seeded).toBeTruthy(); // v1 ciphertext still decrypts

      setActive('v1');
      await restartApi();
      const s2 = await as('secops');
      const back = (await s2.api('GET', `/incidents?q=${encodeURIComponent(title)}`)).json.items[0];
      expect(back.description).toBe('encrypted under v2'); // v2 ciphertext readable after switching back
    } finally {
      writeFileSync(envFile, env); // keep the extended ring (v2 data must remain decryptable)
    }
  });
});

test.describe('Rate limiting', () => {
  test('bursts against authentication endpoints are throttled with 429', async ({ playwright }) => {
    const ctx = await playwright.request.newContext({ baseURL: BASE, ignoreHTTPSErrors: true });
    const statuses = await Promise.all(Array.from({ length: 150 }, () => ctx.get('/api/auth/login', { maxRedirects: 0, failOnStatusCode: false }).then((r) => r.status())));
    await ctx.dispose();
    expect(statuses.filter((s) => s === 429).length).toBeGreaterThan(0);
    expect(statuses.filter((s) => s === 303).length).toBeGreaterThan(0);
    expect(statuses.every((s) => s === 429 || s === 303)).toBe(true);
  });
});
