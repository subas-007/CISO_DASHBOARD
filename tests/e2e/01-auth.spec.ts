import { test, expect, login, kcSubmitLogin, testUsers, totp, apiFor, waitFor } from './support/fixtures';
import { BASE, ORIGIN, SCREENSHOT_DIR } from './support/env';
import { realmOtpAlgorithm } from './support/keycloak';
import type { RoleKey } from './support/global-setup';

/** Independent statement of the RBAC policy (README table) — must match the server. */
const ALL = ['dashboard:read', 'kpi:read', 'kri:read', 'risk:read', 'threat:read', 'incident:read', 'vuln:read'];
const EXPECTED: Record<string, string[]> = {
  ciso: [...ALL, 'kri:acknowledge', 'parameters:manage', 'risk:write', 'risk:acceptance:request', 'risk:acceptance:approve', 'threat:triage', 'integration:read', 'users:read', 'audit:read', 'compliance:read'],
  admin: [...ALL, 'kri:acknowledge', 'parameters:manage', 'integration:read', 'integration:manage', 'users:read', 'users:manage', 'system:manage', 'audit:read', 'compliance:read'],
  secops: [...ALL, 'kri:acknowledge', 'risk:write', 'risk:acceptance:request', 'threat:triage', 'incident:write', 'integration:read', 'integration:manage'],
  patch: [...ALL, 'risk:acceptance:request', 'remediation:write', 'change:link'],
  auditor: [...ALL, 'audit:read', 'compliance:read'],
};
const APP_ROLE: Record<string, string> = { ciso: 'CISO', admin: 'ADMIN', secops: 'SECOPS', patch: 'PATCH_ADMIN', auditor: 'AUDITOR' };

test.describe('Authentication & identity', () => {
  test('unauthenticated visitors are sent to the SSO login page', async ({ page }) => {
    await page.goto('/');
    await expect(page).toHaveURL(/\/login$/);
    await expect(page.getByRole('heading', { name: 'CISO Executive Dashboard' })).toBeVisible();
    await expect(page.getByText(/authorised personnel only/i)).toBeVisible();
    await page.screenshot({ path: `${SCREENSHOT_DIR}/00-login.png` });
  });

  for (const role of Object.keys(EXPECTED)) {
    test(`OIDC login as ${role} yields exactly the expected role & permissions`, async ({ as }) => {
      const { api } = await as(role as RoleKey);
      const me = await api('GET', '/auth/me');
      expect(me.status).toBe(200);
      expect(me.json.user.roles).toEqual([APP_ROLE[role]]);
      expect([...me.json.user.permissions].sort()).toEqual([...EXPECTED[role]!].sort());
    });
  }

  test('auth cookies are __Host-, Secure, HttpOnly and SameSite=Strict; CSRF cookie readable', async ({ as }) => {
    const { ctx } = await as('auditor');
    const cookies = await ctx.cookies(BASE);
    const at = cookies.find((c) => c.name === '__Host-ciso_at')!;
    const rt = cookies.find((c) => c.name === '__Host-ciso_rt')!;
    const csrf = cookies.find((c) => c.name === '__Host-ciso_csrf')!;
    for (const c of [at, rt]) {
      expect(c.httpOnly).toBe(true);
      expect(c.secure).toBe(true);
      expect(c.sameSite).toBe('Strict');
      expect(c.path).toBe('/');
    }
    expect(csrf.httpOnly).toBe(false);
    expect(at.expires - Date.now() / 1000).toBeLessThanOrEqual(605); // ≤ 10 min access token
  });

  test('a user with no mapped role is denied and the denial is explained', async ({ page }) => {
    const { password, users } = testUsers();
    await page.goto('/login');
    await page.getByRole('button', { name: /sign in with corporate sso/i }).click();
    await kcSubmitLogin(page, users.norole.username, password);
    await expect(page).toHaveURL(/\/login\?error=no_authorized_role/);
    await expect(page.getByRole('alert')).toContainText(/no role assigned/i);
  });

  test('wrong password is rejected by the IdP', async ({ page }) => {
    const { users } = testUsers();
    await page.goto('/login');
    await page.getByRole('button', { name: /sign in with corporate sso/i }).click();
    await kcSubmitLogin(page, users.auditor.username, 'Wrong-Password-123!');
    await expect(page.locator('#input-error, .kc-feedback-text, [id*="error"]').first()).toBeVisible();
    expect(new URL(page.url()).pathname.startsWith('/auth/')).toBe(true);
  });

  test('realm TOTP uses SHA-1 so mainstream authenticator apps work', async () => {
    expect(await realmOtpAlgorithm()).toBe('HmacSHA1');
  });

  test('first login forces password change + TOTP enrolment, then MFA is required on every login', async ({ page }) => {
    const { password, users } = testUsers();
    const newPassword = `${password}Nx`;
    await page.goto('/login');
    await page.getByRole('button', { name: /sign in with corporate sso/i }).click();
    await kcSubmitLogin(page, users.mfa.username, password);

    let secret = '';
    for (let step = 0; step < 4 && new URL(page.url()).pathname.startsWith('/auth/'); step++) {
      if (await page.locator('#password-new').isVisible().catch(() => false)) {
        await page.locator('#password-new').fill(newPassword);
        await page.locator('#password-confirm').fill(newPassword);
        await page.locator('input[type=submit], button[type=submit]').first().click();
      } else if (await page.locator('#totp').isVisible().catch(() => false)) {
        await expect(page.locator('body')).toContainText(/Google Authenticator/);
        await page.locator('#mode-manual').click();
        secret = (await page.locator('#kc-totp-secret-key').innerText()).trim();
        expect(secret.replace(/\s/g, '')).toMatch(/^[A-Z2-7]{16,}$/);
        await page.locator('#totp').fill(totp(secret));
        if (await page.locator('#userLabel').isVisible().catch(() => false)) await page.locator('#userLabel').fill('e2e-device');
        await page.locator('#saveTOTPBtn, input[type=submit]').first().click();
      }
      // (not 'networkidle': the app keeps an SSE connection open)
      await page.waitForLoadState('domcontentloaded');
      await page.waitForTimeout(750);
    }
    expect(secret).not.toBe('');
    await page.waitForURL((u) => u.origin === ORIGIN && !u.pathname.startsWith('/auth') && !u.pathname.startsWith('/login'));
    await expect(page.getByRole('button', { name: /sign out/i })).toBeVisible();

    // Sign out and back in: second factor now mandatory.
    await page.getByRole('button', { name: /sign out/i }).click();
    await page.waitForURL(/\/login/);
    await page.getByRole('button', { name: /sign in with corporate sso/i }).click();
    await kcSubmitLogin(page, users.mfa.username, newPassword);
    await expect(page.locator('#otp')).toBeVisible();
    await page.locator('#otp').fill('000000');
    await page.locator('#kc-login').click();
    await expect(page.locator('#otp')).toBeVisible(); // wrong code rejected
    // wait for a fresh TOTP window to avoid replay protection on the enrolment code
    await page.waitForTimeout(31_000 - (Date.now() % 30_000));
    await page.locator('#otp').fill(totp(secret));
    await page.locator('#kc-login').click();
    await page.waitForURL((u) => u.origin === ORIGIN && !u.pathname.startsWith('/auth'));
    await expect(page.getByRole('button', { name: /sign out/i })).toBeVisible();
  });

  test('returnTo cannot be abused as an open redirect', async ({ page }) => {
    const { password, users } = testUsers();
    await page.goto('/api/auth/login?returnTo=//evil.example/steal');
    await kcSubmitLogin(page, users.auditor.username, password);
    await page.waitForURL((u) => !u.pathname.startsWith('/auth'));
    expect(new URL(page.url()).origin).toBe(ORIGIN);
    expect(new URL(page.url()).pathname).toBe('/');
  });

  test('deep links survive login (returnTo of a safe path)', async ({ page }) => {
    const { password, users } = testUsers();
    await page.goto('/api/auth/login?returnTo=/threats');
    await kcSubmitLogin(page, users.auditor.username, password);
    await page.waitForURL(`${BASE}/threats`);
    await expect(page.getByRole('heading', { name: /Threat Intelligence/ })).toBeVisible();
  });

  test('logout revokes the session server-side and ends the IdP session', async ({ as }) => {
    const { page, ctx, api } = await as('auditor');
    const before = await ctx.cookies(BASE);
    await page.getByRole('button', { name: /sign out/i }).click();
    await page.waitForURL(/\/login/);
    // Replaying the old cookies must not work.
    const replay = await ctx.browser()!.newContext({ ignoreHTTPSErrors: true });
    await replay.addCookies(before);
    expect((await apiFor(replay)('GET', '/auth/me')).status).toBe(401);
    await replay.close();
    // IdP session is gone too: SSO button leads to the credential form again.
    await page.getByRole('button', { name: /sign in with corporate sso/i }).click();
    await expect(page.locator('#username')).toBeVisible();
    expect((await api('GET', '/auth/me')).status).toBe(401);
  });

  test('administrator kill switch: disabling a user terminates their live session', async ({ as }) => {
    const victim = await as('victim');
    expect((await victim.api('GET', '/kpi/summary')).status).toBe(200);
    const admin = await as('admin');
    const users = await admin.api('GET', '/admin/users');
    const row = users.json.items.find((u: { displayName: string }) => /victim/i.test(u.displayName));
    expect(row).toBeTruthy();

    await admin.page.goto('/admin');
    const tr = admin.page.locator('tr', { hasText: row.displayName });
    admin.page.once('dialog', (d) => d.accept());
    await tr.getByRole('button', { name: /disable/i }).click();
    await expect(tr.getByText('Disabled')).toBeVisible();

    // Session validity is cached ≤15 s on the API.
    await waitFor(async () => (await victim.api('GET', '/kpi/summary')).status === 401, 25_000, 2000);
    await victim.page.reload();
    await expect(victim.page).toHaveURL(/\/login/);

    // Re-enable for later specs.
    await tr.getByRole('button', { name: /enable/i }).click();
    await expect(tr.getByText('Active')).toBeVisible();
  });
});
