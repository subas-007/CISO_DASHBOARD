import { test, expect } from './support/fixtures';
import { SCREENSHOT_DIR } from './support/env';
import type { RoleKey } from './support/global-setup';

const PAGES = [
  { path: '/', nav: 'Overview', perm: 'dashboard:read', heading: 'Executive Security Overview', shot: '01-overview' },
  { path: '/risk', nav: 'Risk Matrix', perm: 'risk:read', heading: 'ISO 31000 Risk Matrix', shot: '02-risk-matrix' },
  { path: '/acceptances', nav: 'Risk Acceptance', perm: 'risk:read', heading: 'Risk Acceptance', shot: '03-risk-acceptance' },
  { path: '/threats', nav: 'Threat Intel Stream', perm: 'threat:read', heading: 'Threat Intelligence & Incident Stream', shot: '04-threat-stream' },
  { path: '/incidents', nav: 'Incidents', perm: 'incident:read', heading: 'Incidents', shot: '05-incidents' },
  { path: '/remediation', nav: 'Remediation', perm: 'vuln:read', heading: 'Vulnerability Remediation', shot: '06-remediation' },
  { path: '/parameters', nav: 'KRI & Parameters', perm: 'kri:read', heading: 'KRI Thresholds & Parameter Definitions', shot: '07-kri-parameters' },
  { path: '/compliance', nav: 'Compliance Report', perm: 'compliance:read', heading: 'Compliance Evidence Report', shot: '08-compliance' },
  { path: '/audit', nav: 'Audit Log', perm: 'audit:read', heading: 'Immutable Security Audit Log', shot: '09-audit-log' },
  { path: '/integrations', nav: 'Integrations', perm: 'integration:read', heading: 'Integration Layer', shot: '10-integrations' },
  { path: '/admin', nav: 'System & Users', perm: 'users:read', heading: 'System Management & Users', shot: '11-system-users' },
  { path: '/configuration', nav: 'Configuration', perm: 'config:read', heading: 'System Configuration', shot: '13-configuration' },
];

const SCREENSHOT_ROLE: Record<string, RoleKey> = {
  '01-overview': 'ciso', '02-risk-matrix': 'ciso', '03-risk-acceptance': 'ciso', '04-threat-stream': 'secops',
  '05-incidents': 'secops', '06-remediation': 'patch', '07-kri-parameters': 'ciso', '08-compliance': 'auditor',
  '09-audit-log': 'auditor', '10-integrations': 'admin', '11-system-users': 'admin', '13-configuration': 'admin',
};

test.describe('Every page for every role', () => {
  for (const role of ['ciso', 'admin', 'secops', 'patch', 'auditor'] as RoleKey[]) {
    test(`${role}: navigation, rendering, access restrictions, no console/CSP errors`, async ({ as }) => {
      const { page, api, console: con } = await as(role);
      const perms: string[] = (await api('GET', '/auth/me')).json.user.permissions;
      const nav = page.getByRole('navigation', { name: 'Main' });

      for (const p of PAGES) {
        const allowed = perms.includes(p.perm);
        // Sidebar shows exactly the permitted areas.
        await expect(nav.getByRole('link', { name: p.nav, exact: true })).toHaveCount(allowed ? 1 : 0);

        await page.goto(p.path);
        if (allowed) {
          await expect(page.getByRole('heading', { level: 1, name: p.heading })).toBeVisible();
          await expect(page.getByRole('status')).toHaveCount(0, { timeout: 20_000 }); // spinners finished
          await expect(page.getByRole('alert').filter({ hasText: /error|failed|unable/i })).toHaveCount(0);
          if (SCREENSHOT_ROLE[p.shot] === role) {
            // Content scrolls inside <main>; grow the viewport to capture the whole page.
            const h = await page.evaluate(() => (document.querySelector('header')?.clientHeight ?? 0) + (document.querySelector('main')?.scrollHeight ?? 900));
            await page.setViewportSize({ width: 1440, height: Math.min(Math.max(h, 900), 4000) });
            await page.waitForTimeout(400); // charts re-measure
            await page.screenshot({ path: `${SCREENSHOT_DIR}/${p.shot}.png` });
            await page.setViewportSize({ width: 1440, height: 900 });
          }
        } else {
          await expect(page.getByText('Access restricted')).toBeVisible();
        }
      }
      expect(con.csp, `CSP violations: ${con.csp.join('\n')}`).toEqual([]);
      expect(con.errors, `Console errors: ${con.errors.join('\n')}`).toEqual([]);
    });
  }

  test('mobile layout (390×844) renders the overview without horizontal overflow', async ({ as }) => {
    const { page } = await as('ciso');
    await page.setViewportSize({ width: 390, height: 844 });
    await page.goto('/');
    await expect(page.getByRole('heading', { level: 1, name: 'Executive Security Overview' })).toBeVisible();
    await expect(page.getByRole('navigation', { name: 'Mobile' })).toBeVisible();
    await expect(page.getByRole('status')).toHaveCount(0, { timeout: 20_000 });
    const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
    expect(overflow).toBeLessThanOrEqual(1);
    await page.screenshot({ path: `${SCREENSHOT_DIR}/12-mobile-overview.png`, fullPage: true });
  });

  test('unknown client routes fall back to the overview', async ({ as }) => {
    const { page } = await as('auditor');
    await page.goto('/does/not/exist');
    await expect(page).toHaveURL(/\/$/);
    await expect(page.getByRole('heading', { level: 1, name: 'Executive Security Overview' })).toBeVisible();
  });
});
