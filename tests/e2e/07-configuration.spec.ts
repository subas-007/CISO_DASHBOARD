/**
 * Administrator-defined (dynamic) configuration: every parameter class is changed through
 * the API/UI and its effect is verified end to end — against the running gateway,
 * Keycloak, the database and the host tooling — then restored.
 */
import { mkdirSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { test, expect, compose, docker, kcSubmitLogin, psql, totp, waitFor, apiFor, type Api } from './support/fixtures';
import { BASE, ORIGIN, ROOT, SCREENSHOT_DIR } from './support/env';
import { realmRepresentation } from './support/keycloak';

const RUN = process.env.E2E_RUN ?? 'local';
const REPORTS = path.join(ROOT, 'tests/reports');

async function getSetting(api: Api, key: string): Promise<any> {
  return (await api('GET', '/admin/settings')).json.items.find((s: { key: string }) => s.key === key).value;
}
async function putSetting(api: Api, key: string, value: unknown) {
  return api('PUT', `/admin/settings/${key}`, { value });
}

/** Runs HTTPS requests from a throwaway container on the edge network (a client with a different source IP). */
function fromOtherClient(paths: string[]): Record<string, number> {
  const script = `
    const https = require('https');
    const get = (p) => new Promise((r) => https.get({ host: 'gateway', port: 8443, path: p, headers: { Host: 'localhost' }, rejectUnauthorized: false }, (res) => { res.resume(); r(res.statusCode); }).on('error', () => r(0)));
    (async () => { const out = {}; for (const p of ${JSON.stringify(paths)}) out[p] = await get(p); console.log(JSON.stringify(out)); })();`;
  const r = docker(['run', '--rm', '--network', 'ciso-dashboard_edge', '--entrypoint', 'node', 'ciso-dashboard/api:1.0.0', '-e', script]);
  const line = r.out.trim().split(/\r?\n/).pop() ?? '{}';
  return JSON.parse(line);
}

test.describe('Dynamic configuration (administrator-defined parameters)', () => {
  test('gateway: internal endpoints hidden, alternative host names redirected to the public URL', async ({ playwright }) => {
    const anon = await playwright.request.newContext({ baseURL: BASE, ignoreHTTPSErrors: true });
    expect((await anon.get('/api/internal/ip-gate/app', { failOnStatusCode: false })).status()).toBe(404);
    const alt = await anon.get('/risk?x=1', { headers: { Host: '127.0.0.1' }, maxRedirects: 0, failOnStatusCode: false });
    expect(alt.status()).toBe(308);
    expect(alt.headers()['location']).toBe(`${ORIGIN}/risk?x=1`);
    await anon.dispose();
  });

  test('demo administrator "admin" / "Admin@123!" signs in and must enrol an authenticator (HmacSHA1)', async ({ page, as }) => {
    await page.goto('/login');
    await page.getByRole('button', { name: /sign in with corporate sso/i }).click();
    await kcSubmitLogin(page, 'admin', 'Admin@123!');
    // Password accepted → Keycloak asks for authenticator enrolment (or a code if already enrolled).
    await expect(page.locator('#totp, #otp').first()).toBeVisible();
    if (await page.locator('#totp').isVisible()) {
      await expect(page.locator('body')).toContainText(/Microsoft Authenticator|Google Authenticator/);
      await page.locator('#mode-manual').click();
      await expect(page.locator('body')).toContainText(/SHA1/);
    }
    expect((await realmRepresentation()).otpPolicyAlgorithm).toBe('HmacSHA1');
    const { api } = await as('admin');
    const admin = (await api('GET', '/admin/identity/users?search=admin')).json.items.find((u: { username: string }) => u.username === 'admin');
    expect(admin).toMatchObject({ enabled: true, roles: ['ADMIN'] });
  });

  test('configuration page: every category for admin, read-only for auditor, hidden from SecOps', async ({ as }) => {
    const admin = await as('admin');
    await admin.page.goto('/configuration');
    await expect(admin.page.getByRole('heading', { level: 1, name: 'System Configuration' })).toBeVisible();
    const tabs = admin.page.getByRole('tab');
    await expect(tabs).toHaveCount(10);
    for (const label of ['Network access', 'Rate limiting', 'Sessions', 'Identity & enrolment', 'Integration defaults', 'Logging', 'Demo data', 'Deployment', 'Host operating system']) {
      await expect(admin.page.getByRole('tab', { name: label })).toBeVisible();
    }
    await admin.page.getByRole('tab', { name: 'Rate limiting' }).click();
    await expect(admin.page.getByRole('region', { name: 'API rate limits' })).toBeVisible();
    await expect(admin.page.getByLabel('Per user — API requests')).toBeEnabled();
    await admin.page.getByRole('tab', { name: 'Identity & enrolment' }).click();
    await expect(admin.page.getByLabel('TOTP algorithm')).toHaveValue('HmacSHA1');
    await admin.page.getByRole('tab', { name: 'Deployment' }).click();
    await expect(admin.page.getByRole('link', { name: /download deployment\.env/i })).toBeVisible();
    await admin.page.getByRole('tab', { name: 'Host operating system' }).click();
    await expect(admin.page.getByRole('link', { name: /ubuntu script/i })).toBeVisible();
    await admin.page.screenshot({ path: `${SCREENSHOT_DIR}/14-configuration-host.png`, fullPage: true });

    const auditor = await as('auditor');
    await auditor.page.goto('/configuration');
    await auditor.page.getByRole('tab', { name: 'Rate limiting' }).click();
    await expect(auditor.page.getByLabel('Per user — API requests')).toBeDisabled();
    await expect(auditor.page.getByRole('button', { name: /^Save/ })).toHaveCount(0);
    expect((await auditor.api('PUT', '/admin/settings/rateLimits', { value: {} })).status).toBe(403);

    const secops = await as('secops');
    await secops.page.goto('/configuration');
    await expect(secops.page.getByText('Access restricted')).toBeVisible();
  });

  test('rate limits are live and per user: a throttled user gets 429, a colleague on the same IP does not', async ({ as }) => {
    const admin = await as('admin');
    const original = await getSetting(admin.api, 'rateLimits');
    try {
      const saved = await putSetting(admin.api, 'rateLimits', { ...original, perUserPerMin: 40 });
      expect(saved.json.applied).toMatchObject({ mode: 'live', ok: true });
      const secops = await as('secops');
      const statuses: number[] = [];
      let throttled: { status: number; json: any; headers: Record<string, string> } | null = null;
      for (let i = 0; i < 50; i++) {
        const r = await secops.api('GET', '/kri');
        statuses.push(r.status);
        if (r.status === 429 && !throttled) throttled = r;
      }
      expect(statuses.filter((s) => s === 200).length).toBeLessThanOrEqual(40);
      expect(throttled, 'expected a 429').not.toBeNull();
      expect(throttled!.json.error.code).toBe('RATE_LIMITED');
      expect(throttled!.headers['ratelimit-policy']).toMatch(/^40;w=60/);
      expect(Number(throttled!.headers['retry-after'])).toBeGreaterThan(0);
      // Same source IP (office NAT), different user → unaffected.
      const ciso = await as('ciso');
      expect((await ciso.api('GET', '/kri')).status).toBe(200);
    } finally {
      expect((await putSetting(admin.api, 'rateLimits', original)).status).toBe(200);
    }
    const audit = await admin.api('GET', '/audit?action=setting.update&limit=5');
    expect(audit.json.items.some((i: { targetId: string; details: any }) => i.targetId === 'rateLimits' && i.details.after.perUserPerMin === 40)).toBe(true);
  });

  test('network access: lockout prevented, client and admin-console allowlists enforced at the gateway', async ({ as }) => {
    const { api } = await as('admin');
    const original = await getSetting(api, 'networkAccess');
    const paths = ['/api/auth/me', '/auth/realms/ciso/.well-known/openid-configuration', '/auth/admin/master/console/'];
    try {
      // Saving a list that excludes the administrator's own address is refused.
      const lock = await putSetting(api, 'networkAccess', { allowedClientCidrs: ['203.0.113.0/24'], adminConsoleCidrs: [] });
      expect(lock.status).toBe(400);
      expect(lock.json.error.code).toBe('LOCKOUT_PREVENTED');
      const myIp = /\(([^)]+)\)/.exec(lock.json.error.message)![1]!;

      // Baseline from another client: API answers 401 (not signed in), IdP reachable, admin console denied.
      expect(fromOtherClient(paths)).toEqual({ [paths[0]!]: 401, [paths[1]!]: 200, [paths[2]!]: 403 });

      const saved = await putSetting(api, 'networkAccess', { allowedClientCidrs: [myIp], adminConsoleCidrs: ['172.30.0.0/24'] });
      expect(saved.status).toBe(200);
      expect(saved.json.value.allowedClientCidrs).toEqual([`${myIp}/32`]);
      // Other client: API and sign-in blocked; admin console now allowed by the dynamic list.
      expect(fromOtherClient(paths)).toEqual({ [paths[0]!]: 403, [paths[1]!]: 403, [paths[2]!]: 200 });
      // The administrator's own network keeps working.
      expect((await api('GET', '/kri')).status).toBe(200);
    } finally {
      expect((await putSetting(api, 'networkAccess', original)).status).toBe(200);
    }
    expect(fromOtherClient(paths)).toEqual({ [paths[0]!]: 401, [paths[1]!]: 200, [paths[2]!]: 403 });
  });

  test('identity policy is pushed to Keycloak (TOTP algorithm, password policy, lockout, session lifetimes)', async ({ as }) => {
    const { api } = await as('admin');
    const identity = await getSetting(api, 'identity');
    const session = await getSetting(api, 'sessionPolicy');
    try {
      const r = await putSetting(api, 'identity', { ...identity, otpAlgorithm: 'HmacSHA256', passwordMinLength: 14, lockoutMaxFailures: 4 });
      expect(r.status).toBe(200);
      expect(r.json.applied).toMatchObject({ mode: 'identity', ok: true });
      expect(r.json.warnings.join(' ')).toMatch(/Google Authenticator and Microsoft Authenticator only support HmacSHA1/);
      const realm = await realmRepresentation();
      expect(realm).toMatchObject({ otpPolicyAlgorithm: 'HmacSHA256', failureFactor: 4, bruteForceProtected: true });
      expect(realm.passwordPolicy).toContain('length(14)');

      const s = await putSetting(api, 'sessionPolicy', { ...session, idleTimeoutSec: 600 });
      expect(s.json.applied.ok).toBe(true);
      expect((await realmRepresentation()).ssoSessionIdleTimeout).toBe(600);

      const bad = await putSetting(api, 'identity', { ...identity, lockoutWaitSec: 600, lockoutMaxWaitSec: 60 });
      expect(bad.status).toBe(400);
      expect(bad.json.error.issues[0].path).toBe('value.lockoutMaxWaitSec');
    } finally {
      expect((await putSetting(api, 'identity', identity)).json.applied.ok).toBe(true);
      expect((await putSetting(api, 'sessionPolicy', session)).json.applied.ok).toBe(true);
    }
    const realm = await realmRepresentation();
    expect(realm.otpPolicyAlgorithm).toBe('HmacSHA1');
    expect(realm.ssoSessionIdleTimeout).toBe(session.idleTimeoutSec);
    const status = (await api('GET', '/admin/identity/status')).json;
    expect(status).toMatchObject({ configured: true, sync: { ok: true } });
  });

  test('enrolment: admin enrols a user in the UI; first sign-in forces password change + authenticator; roles, MFA reset, disable, delete', async ({ as, browser }) => {
    test.setTimeout(180_000);
    const admin = await as('admin');
    const username = `e2e-enrol-${RUN}`.toLowerCase().slice(0, 60);
    await admin.page.goto('/admin');
    await admin.page.getByRole('button', { name: 'Enrol user' }).click();
    const dialog = admin.page.getByRole('dialog', { name: 'Enrol user' });
    await dialog.getByLabel('Username').fill(username);
    await dialog.getByLabel('Email').fill(`${username}@example.test`);
    await dialog.getByLabel('First name').fill('Enrolled');
    await dialog.getByLabel('Last name').fill('Tester');
    await dialog.getByRole('button', { name: 'Enrol', exact: true }).click();
    const otpBox = admin.page.getByTestId('one-time-password');
    await expect(otpBox).toBeVisible();
    const oneTime = (await otpBox.innerText()).trim();
    expect(oneTime.length).toBeGreaterThanOrEqual(16);
    await admin.page.getByRole('button', { name: 'Done' }).click();
    const id = (await admin.api('GET', `/admin/identity/users?search=${username}`)).json.items.find((u: { username: string }) => u.username === username)?.id as string;
    expect(id).toBeTruthy();

    try {
      // First sign-in of the new user.
      const ctx = await browser.newContext({ ignoreHTTPSErrors: true });
      const page = await ctx.newPage();
      await page.goto('/login');
      await page.getByRole('button', { name: /sign in with corporate sso/i }).click();
      await kcSubmitLogin(page, username, oneTime);
      let secret = '';
      let changedPassword = false;
      for (let step = 0; step < 5 && new URL(page.url()).pathname.startsWith('/auth/'); step++) {
        if (await page.locator('#password-new').isVisible().catch(() => false)) {
          await page.locator('#password-new').fill(`New-${oneTime}`);
          await page.locator('#password-confirm').fill(`New-${oneTime}`);
          await page.locator('input[type=submit], button[type=submit]').first().click();
          changedPassword = true;
        } else if (await page.locator('#totp').isVisible().catch(() => false)) {
          await page.locator('#mode-manual').click();
          secret = (await page.locator('#kc-totp-secret-key').innerText()).trim();
          await page.locator('#totp').fill(totp(secret));
          if (await page.locator('#userLabel').isVisible().catch(() => false)) await page.locator('#userLabel').fill('e2e-phone');
          await page.locator('#saveTOTPBtn, input[type=submit]').first().click();
        }
        await page.waitForLoadState('domcontentloaded');
        await page.waitForTimeout(750);
      }
      expect(changedPassword).toBe(true);
      expect(secret).not.toBe('');
      await page.waitForURL((u) => u.origin === ORIGIN && !u.pathname.startsWith('/auth') && !u.pathname.startsWith('/login'));
      const user = apiFor(ctx);
      expect((await user('GET', '/auth/me')).json.user.roles).toEqual(['AUDITOR']);

      const listed = (await admin.api('GET', `/admin/identity/users?search=${username}`)).json.items[0];
      expect(listed).toMatchObject({ mfaConfigured: true, roles: ['AUDITOR'], requiredActions: [] });

      // Changing roles ends the user's live dashboard session.
      const roles = await admin.api('PATCH', `/admin/identity/users/${id}`, { roles: ['SECOPS'] });
      expect(roles.json.roles).toEqual(['SECOPS']);
      expect((await user('GET', '/kri')).status).toBe(401);

      // MFA reset → re-enrolment required at next sign-in.
      expect((await admin.api('POST', `/admin/identity/users/${id}/reset-mfa`)).json.removedAuthenticators).toBe(1);
      const afterReset = (await admin.api('GET', `/admin/identity/users?search=${username}`)).json.items[0];
      expect(afterReset).toMatchObject({ mfaConfigured: false, requiredActions: ['CONFIGURE_TOTP'] });

      // Password reset issues a new one-time password satisfying policy.
      const pw = await admin.api('POST', `/admin/identity/users/${id}/reset-password`);
      expect(pw.json.temporaryPassword).toMatch(/^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[^A-Za-z0-9]).{16,}$/);

      expect((await admin.api('PATCH', `/admin/identity/users/${id}`, { enabled: false })).json.enabled).toBe(false);
      await ctx.close();
    } finally {
      expect((await admin.api('DELETE', `/admin/identity/users/${id}`)).status).toBe(204);
    }
    expect((await admin.api('GET', `/admin/identity/users?search=${username}`)).json.items).toHaveLength(0);

    // Safeguards: no self-modification; enrolment input is validated.
    const me = (await admin.api('GET', '/admin/identity/users?search=e2e-admin')).json.items.find((u: { username: string }) => u.username === 'e2e-admin');
    const self = await admin.api('PATCH', `/admin/identity/users/${me.id}`, { roles: ['AUDITOR'] });
    expect(self.json.error.code).toBe('SELF_MODIFICATION');
    expect((await admin.api('POST', '/admin/identity/users', { username: 'x', email: 'bad', firstName: '<b>', lastName: 'y', roles: [] })).status).toBe(400);

    const actions = (await admin.api('GET', '/audit?limit=200')).json.items.filter((i: { targetId: string }) => i.targetId === id).map((i: { action: string }) => i.action);
    for (const a of ['identity.user.enrol', 'identity.user.roles', 'identity.user.mfa.reset', 'identity.user.password.reset', 'identity.user.disable', 'identity.user.delete']) expect(actions).toContain(a);
    const enrol = (await admin.api('GET', '/audit?action=identity.user.enrol&limit=5')).json.items[0];
    expect(JSON.stringify(enrol)).not.toContain(oneTime);
  });

  test('integration egress allowlist is applied live', async ({ as }) => {
    const { api } = await as('admin');
    const original = await getSetting(api, 'connectorDefaults');
    try {
      expect((await putSetting(api, 'connectorDefaults', { ...original, allowedHosts: ['*.sim.test'] })).json.applied.ok).toBe(true);
      const outside = await api('POST', '/integrations', { name: `EGR ${RUN}`, vendor: 'misp', baseUrl: 'https://misp.example.com', authMode: 'API_KEY', pollIntervalSec: 3600, settings: {}, credentials: { apiKey: 'x' } });
      expect(outside.status).toBe(400);
      expect(outside.json.error.message).toMatch(/not on the connector allowlist/);
      expect((await api('GET', '/integrations/catalog')).json.egressPolicy.allowlist).toEqual(['*.sim.test']);
    } finally {
      await putSetting(api, 'connectorDefaults', original);
    }
    expect((await api('GET', '/integrations/catalog')).json.egressPolicy.allowlist).toEqual([]);
  });

  test('deployment profile & host OS baseline: drift shown, bundles valid, apply script verifies and validates', async ({ as }) => {
    test.setTimeout(240_000);
    const { api } = await as('admin');
    const deployment = await getSetting(api, 'deployment');
    const hostOs = await getSetting(api, 'hostOs');
    mkdirSync(REPORTS, { recursive: true });
    try {
      // Hosting on a server: public IP + DNS alias behind a load balancer.
      const saved = await putSetting(api, 'deployment', { ...deployment, publicBaseUrl: 'https://10.20.5.15', alternativeNames: ['ciso.corp.example'], trustedUpstreamProxies: ['10.20.0.10'] });
      expect(saved.json.applied).toMatchObject({ mode: 'redeploy', ok: true });
      const status = (await api('GET', '/admin/config/status')).json;
      expect(status.deployment.redeployRequired).toBe(true);
      expect(status.deployment.differences.map((d: { field: string }) => d.field)).toEqual(expect.arrayContaining(['publicBaseUrl', 'trustedUpstreamProxies', 'certificateSans']));

      for (const bad of ['http://10.20.5.15', 'https://x.example/$(reboot)', 'https://a.example/path']) {
        expect((await putSetting(api, 'deployment', { ...deployment, publicBaseUrl: bad })).status, bad).toBe(400);
      }

      const profile = await api('GET', '/admin/config/bundle/deployment');
      expect(profile.headers['content-disposition']).toContain('deployment.env');
      expect(profile.text).toContain('PUBLIC_BASE_URL=https://10.20.5.15');
      expect(profile.text).toContain('CERT_SANS=10.20.5.15,ciso.corp.example');
      expect(profile.text).toContain('TRUSTED_UPSTREAM_PROXIES=10.20.0.10/32');
      const file = path.join(REPORTS, 'deployment.env');
      writeFileSync(file, profile.text);
      const dry = spawnSync('bash', ['scripts/apply-deployment.sh', file, '--dry-run'], { cwd: ROOT, encoding: 'utf8' });
      expect(dry.status, dry.stderr).toBe(0);
      expect(dry.stdout).toMatch(/PUBLIC_BASE_URL\s+https:\/\/localhost\s+→\s+https:\/\/10\.20\.5\.15/);
      expect(dry.stdout).toContain('certificate is missing name: 10.20.5.15');
      expect(dry.stdout).toContain('Dry run');
      // A tampered profile is refused (checksum) and unknown keys are rejected.
      writeFileSync(file, profile.text.replace('HTTPS_PORT=443', 'HTTPS_PORT=8443'));
      expect(spawnSync('bash', ['scripts/apply-deployment.sh', file, '--dry-run'], { cwd: ROOT, encoding: 'utf8' }).stderr).toMatch(/Checksum mismatch/);
      writeFileSync(file, `${profile.text}LD_PRELOAD=/tmp/x.so\n`);
      expect(spawnSync('bash', ['scripts/apply-deployment.sh', file, '--dry-run', '--allow-edited'], { cwd: ROOT, encoding: 'utf8' }).stderr).toMatch(/unknown key 'LD_PRELOAD'/);

      // Host OS baseline with SIEM forwarding, edge firewall and SSH restriction.
      const host = await putSetting(api, 'hostOs', {
        ...hostOs,
        timezone: 'Europe/London',
        ntpServers: ['ntp.corp.example'],
        syslog: { enabled: true, host: 'siem.corp.example', port: 6514, protocol: 'tls' },
        firewall: { enabled: true, httpsAllowedCidrs: ['10.0.0.0/8'], sshAllowedCidrs: ['10.20.5.0/24'], sshPort: 22 },
      });
      expect(host.json.applied.mode).toBe('host');
      expect((await putSetting(api, 'hostOs', { ...hostOs, ntpServers: ['pool.ntp.org; reboot'] })).status).toBe(400);

      for (const [os, image] of [['ubuntu', 'ubuntu:24.04'], ['rhel', 'rockylinux:9']] as const) {
        const script = await api('GET', `/admin/config/bundle/host?os=${os}`);
        expect(script.status).toBe(200);
        expect(script.text).toContain("timedatectl set-timezone 'Europe/London'");
        expect(script.text).toContain('StreamDriverPermittedPeers="siem.corp.example"');
        expect(script.text).toContain('-s 10.0.0.0/8 -j RETURN');
        expect(script.text).toContain(os === 'ubuntu' ? "ufw allow from '10.20.5.0/24' to any port 22" : 'source address="10.20.5.0/24" port port="22"');
        const syntax = spawnSync('bash', ['-n'], { input: script.text, encoding: 'utf8' });
        expect(syntax.status, syntax.stderr).toBe(0);
        // Dry run on the real target distribution (skipped if the image cannot be pulled).
        const run = docker(['run', '--rm', '-i', '--network', 'none', image, 'bash', '-s', '--', '--dry-run', '--app-dir', '/opt/ciso-dashboard'], script.text);
        if (/Unable to find image|pull access denied|error pulling/i.test(run.out) && run.code !== 0) {
          test.info().annotations.push({ type: 'skipped', description: `${image} not available for dry run` });
          continue;
        }
        expect(run.code, run.out).toBe(0);
        expect(run.out).toContain('Host baseline applied');
        expect(run.out).toContain('[dry-run]');
      }
    } finally {
      expect((await putSetting(api, 'deployment', deployment)).status).toBe(200);
      expect((await putSetting(api, 'hostOs', hostOs)).status).toBe(200);
    }
    expect((await api('GET', '/admin/config/status')).json.deployment.redeployRequired).toBe(false);
    const audit = (await api('GET', '/audit?limit=100')).json.items.map((i: { action: string }) => i.action);
    expect(audit).toEqual(expect.arrayContaining(['config.bundle.deployment', 'config.bundle.host']));
  });

  test('live demo data: simulator creates and progresses records; the scheduler runs it automatically', async ({ as }) => {
    test.setTimeout(150_000);
    const { api } = await as('admin');
    const demo = await getSetting(api, 'demoData');
    const count = async (sql: string) => Number(psql(sql).out.trim());
    try {
      // Deterministic per-tick volumes: rate × interval / 3600.
      await putSetting(api, 'demoData', { ...demo, liveSimulation: false, intervalSec: 60, incidentsPerHour: 120, threatsPerHour: 120, vulnerabilitiesPerHour: 600, remediationsPerHour: 600 });
      const before = {
        incidents: await count(`SELECT count(*) FROM incidents WHERE source = 'Demo simulator'`),
        vulns: await count(`SELECT count(*) FROM vulnerabilities WHERE source = 'Demo simulator'`),
        remediated: await count(`SELECT count(*) FROM vulnerabilities WHERE status = 'REMEDIATED'`),
        threats: await count(`SELECT count(*) FROM threat_items WHERE source LIKE 'Demo simulator%'`),
      };
      const tick = await api('POST', '/admin/config/demo/tick');
      expect(tick.json.counts).toMatchObject({ incidentsCreated: 2, threatsCreated: 2, vulnerabilitiesCreated: 10, vulnerabilitiesRemediated: 10 });
      expect(await count(`SELECT count(*) FROM incidents WHERE source = 'Demo simulator'`)).toBe(before.incidents + 2);
      expect(await count(`SELECT count(*) FROM vulnerabilities WHERE source = 'Demo simulator'`)).toBe(before.vulns + 10);
      expect(await count(`SELECT count(*) FROM vulnerabilities WHERE status = 'REMEDIATED'`)).toBe(before.remediated + 10);
      expect(await count(`SELECT count(*) FROM threat_items WHERE source LIKE 'Demo simulator%'`)).toBe(before.threats + 2);
      // New findings get SLA due dates from the parameters.
      expect(await count(`SELECT count(*) FROM vulnerabilities WHERE source = 'Demo simulator' AND "dueAt" IS NULL AND severity IN ('CRITICAL','HIGH')`)).toBe(0);

      // Automatic simulation by the scheduler.
      const ticks0 = (await api('GET', '/admin/config/status')).json.demo.ticks;
      await putSetting(api, 'demoData', { ...demo, liveSimulation: true, intervalSec: 15 });
      const later = await waitFor(async () => {
        const s = (await api('GET', '/admin/config/status')).json.demo;
        return s.ticks >= ticks0 + 2 ? s : null;
      }, 90_000, 3000);
      expect(later.liveSimulation).toBe(true);
    } finally {
      await putSetting(api, 'demoData', { ...demo, liveSimulation: false });
    }
  });

  test('gateway keeps routing when the API container is recreated with a new IP (no 502)', async ({ playwright }) => {
    test.setTimeout(180_000);
    const ipOf = () => docker(['inspect', '-f', '{{(index .NetworkSettings.Networks "ciso-dashboard_app").IPAddress}}', 'ciso-dashboard-api-1']).out.trim();
    const oldIp = ipOf();
    expect(oldIp).toMatch(/^172\.30\.1\.\d+$/);
    try {
      expect(compose(['stop', 'api']).code).toBe(0);
      expect(compose(['rm', '-f', 'api']).code).toBe(0);
      // Occupy the old address so the new container must get a different one.
      const squat = docker(['run', '-d', '--name', 'ciso-ip-squatter', '--network', 'ciso-dashboard_app', '--ip', oldIp, '--entrypoint', 'sleep', 'ciso-dashboard/api:1.0.0', '600']);
      expect(squat.code, squat.out).toBe(0);
      const up = compose(['up', '-d', '--no-deps', '--wait', 'api']);
      expect(up.code, up.out).toBe(0);
      const newIp = ipOf();
      expect(newIp).not.toBe(oldIp);

      const anon = await playwright.request.newContext({ baseURL: BASE, ignoreHTTPSErrors: true });
      // The API is already healthy (--wait): the gateway must route to the new address within
      // ~1 s (resolver TTL), for the API and for the IdP sign-in page (network gate).
      await waitFor(async () => (await anon.get('/api/health', { failOnStatusCode: false })).status() === 200, 3_000, 250);
      const statuses: number[] = [];
      for (let i = 0; i < 10; i++) {
        statuses.push((await anon.get('/api/health', { failOnStatusCode: false })).status());
        statuses.push((await anon.get('/auth/realms/ciso/.well-known/openid-configuration', { failOnStatusCode: false })).status());
      }
      expect(statuses.every((s) => s === 200), statuses.join(',')).toBe(true);
      await anon.dispose();
    } finally {
      docker(['rm', '-f', 'ciso-ip-squatter']);
      compose(['up', '-d', '--no-deps', '--wait', 'api']);
    }
  });

  test('demo dataset regeneration uses the administrator-defined sizes', async ({ as }) => {
    test.setTimeout(240_000);
    const { api } = await as('admin');
    const demo = await getSetting(api, 'demoData');
    const counts = () => psql(`SELECT count(*) FROM assets; SELECT count(*) FROM vulnerabilities; SELECT count(*) FROM incidents; SELECT count(DISTINCT date_trunc('day', "capturedAt")) FROM metric_snapshots;`).out.trim().split(/\r?\n/).map(Number);
    try {
      await putSetting(api, 'demoData', { ...demo, liveSimulation: false, datasetAssets: 30, datasetVulnerabilities: 120, datasetIncidents: 40, historyDays: 30 });
      expect((await api('POST', '/admin/config/demo/regenerate', { confirm: 'yes' })).json.error.code).toBe('CONFIRMATION_REQUIRED');
      const r = await api('POST', '/admin/config/demo/regenerate', { confirm: 'REGENERATE' });
      expect(r.json).toMatchObject({ ok: true, assets: 30, vulnerabilities: 120, incidents: 40, historyDays: 30 });
      const [assets, vulns, incidents, days] = counts();
      expect([assets, vulns, incidents]).toEqual([30, 120, 40]);
      expect(days).toBeGreaterThanOrEqual(30);
      const kpis = (await api('GET', '/kpi/summary')).json.kpis;
      expect(kpis.totalAssets).toBe(30);
      // Audit chain is untouched by regeneration.
      expect((await api('GET', '/audit/verify')).json.valid).toBe(true);
    } finally {
      // Restore the standard demo dataset for anyone using the stack afterwards.
      await putSetting(api, 'demoData', { ...demo, liveSimulation: false });
      expect((await api('POST', '/admin/config/demo/regenerate', { confirm: 'REGENERATE' })).json.ok).toBe(true);
    }
    expect(counts().slice(0, 3)).toEqual([demo.datasetAssets, demo.datasetVulnerabilities, demo.datasetIncidents]);
  });

  // Must stay last: it flags every test identity for authenticator enrolment.
  test('"Enforce MFA for existing users" flags every identity without an authenticator', async ({ as }) => {
    const { api } = await as('admin');
    const r = await api('POST', '/admin/identity/enforce-mfa');
    expect(r.status).toBe(200);
    expect(r.json.flagged).toBeGreaterThanOrEqual(1);
    const auditor = (await api('GET', '/admin/identity/users?search=e2e-auditor')).json.items[0];
    expect(auditor.requiredActions).toContain('CONFIGURE_TOTP');
    expect((await api('GET', '/audit?action=identity.mfa.enforce&limit=1')).json.items[0].details.flagged).toBe(r.json.flagged);
  });
});
