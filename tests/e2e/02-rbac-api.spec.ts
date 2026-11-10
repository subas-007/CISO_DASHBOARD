import { test, expect } from './support/fixtures';
import { BASE, FAKE_ID, ORIGIN } from './support/env';
import type { RoleKey } from './support/global-setup';

interface Endpoint {
  method: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';
  path: string;
  perm: string;
  body?: unknown;
}

// Every protected route. Bodies are intentionally invalid / ids fake so that an
// *authorised* call fails validation (400) or lookup (404) without side effects,
// while an *unauthorised* call must be rejected with 403 before validation runs.
const F = FAKE_ID;
const ENDPOINTS: Endpoint[] = [
  { method: 'GET', path: '/kpi/summary', perm: 'kpi:read' },
  { method: 'GET', path: '/kpi/trends?days=30', perm: 'kpi:read' },
  { method: 'GET', path: '/kri', perm: 'kri:read' },
  { method: 'GET', path: '/kri/breaches', perm: 'kri:read' },
  { method: 'PUT', path: '/kri/open_critical', perm: 'parameters:manage', body: {} },
  { method: 'POST', path: `/kri/breaches/${F}/acknowledge`, perm: 'kri:acknowledge' },
  { method: 'GET', path: '/risks', perm: 'risk:read' },
  { method: 'GET', path: '/risks/matrix', perm: 'risk:read' },
  { method: 'GET', path: `/risks/${F}`, perm: 'risk:read' },
  { method: 'POST', path: '/risks', perm: 'risk:write', body: {} },
  { method: 'PATCH', path: `/risks/${F}`, perm: 'risk:write', body: {} },
  { method: 'POST', path: `/risks/${F}/acceptances`, perm: 'risk:acceptance:request', body: {} },
  { method: 'GET', path: '/risk-acceptances', perm: 'risk:read' },
  { method: 'POST', path: `/risk-acceptances/${F}/decision`, perm: 'risk:acceptance:approve', body: {} },
  { method: 'POST', path: `/risk-acceptances/${F}/revoke`, perm: 'risk:acceptance:approve', body: {} },
  { method: 'GET', path: '/threats', perm: 'threat:read' },
  { method: 'GET', path: '/threats/sources', perm: 'threat:read' },
  { method: 'PATCH', path: `/threats/${F}`, perm: 'threat:triage', body: {} },
  { method: 'GET', path: '/incidents', perm: 'incident:read' },
  { method: 'POST', path: '/incidents', perm: 'incident:write', body: {} },
  { method: 'PATCH', path: `/incidents/${F}`, perm: 'incident:write', body: {} },
  { method: 'GET', path: '/vulnerabilities', perm: 'vuln:read' },
  { method: 'PATCH', path: `/vulnerabilities/${F}`, perm: 'remediation:write', body: {} },
  { method: 'POST', path: `/vulnerabilities/${F}/change-ticket`, perm: 'change:link', body: {} },
  { method: 'GET', path: '/assets', perm: 'vuln:read' },
  { method: 'GET', path: '/change-tickets', perm: 'vuln:read' },
  { method: 'GET', path: '/integrations/catalog', perm: 'integration:read' },
  { method: 'GET', path: '/integrations', perm: 'integration:read' },
  { method: 'POST', path: '/integrations', perm: 'integration:manage', body: {} },
  { method: 'PATCH', path: `/integrations/${F}`, perm: 'integration:manage', body: {} },
  { method: 'PUT', path: `/integrations/${F}/credentials`, perm: 'integration:manage', body: {} },
  { method: 'DELETE', path: `/integrations/${F}`, perm: 'integration:manage' },
  { method: 'POST', path: `/integrations/${F}/test`, perm: 'integration:manage' },
  { method: 'POST', path: `/integrations/${F}/sync`, perm: 'integration:manage' },
  { method: 'GET', path: '/admin/users', perm: 'users:read' },
  { method: 'PATCH', path: `/admin/users/${F}`, perm: 'users:manage', body: {} },
  { method: 'POST', path: `/admin/users/${F}/revoke-sessions`, perm: 'users:manage' },
  { method: 'GET', path: '/admin/settings', perm: 'dashboard:read' },
  { method: 'PUT', path: '/admin/settings/riskAppetiteScore', perm: 'parameters:manage', body: {} },
  { method: 'PUT', path: '/admin/settings/threatRetentionDays', perm: 'system:manage', body: {} },
  { method: 'GET', path: '/admin/system', perm: 'system:manage' },
  { method: 'GET', path: '/admin/sessions', perm: 'system:manage' },
  { method: 'GET', path: '/audit?limit=5', perm: 'audit:read' },
  { method: 'GET', path: '/audit/actions', perm: 'audit:read' },
  { method: 'GET', path: '/audit/verify', perm: 'audit:read' },
  { method: 'GET', path: '/audit/export', perm: 'audit:read' },
  { method: 'GET', path: '/compliance/report', perm: 'compliance:read' },
];

test.describe('RBAC enforcement on every endpoint', () => {
  for (const role of ['ciso', 'admin', 'secops', 'patch', 'auditor'] as RoleKey[]) {
    test(`${role}: ${ENDPOINTS.length} endpoints allow/deny exactly per permission`, async ({ as }) => {
      const { api } = await as(role);
      const perms: string[] = (await api('GET', '/auth/me')).json.user.permissions;
      const mismatches: string[] = [];
      for (const e of ENDPOINTS) {
        const r = await api(e.method, e.path, e.body);
        const allowed = perms.includes(e.perm);
        const ok = allowed ? r.status !== 403 && r.status < 500 : r.status === 403;
        if (!ok) mismatches.push(`${e.method} ${e.path} [${e.perm}] allowed=${allowed} → ${r.status} ${r.text.slice(0, 120)}`);
      }
      expect(mismatches, mismatches.join('\n')).toEqual([]);
    });
  }

  test('denied requests are written to the audit log', async ({ as }) => {
    const auditor = await as('auditor');
    await auditor.api('POST', '/risks', {});
    const ciso = await as('ciso');
    const log = await ciso.api('GET', '/audit?action=access.denied&limit=50');
    expect(log.status).toBe(200);
    expect(log.json.items.some((i: { actorName: string; targetId: string }) => /auditor/i.test(i.actorName) && i.targetId.includes('POST /api/risks'))).toBe(true);
  });

  test('every endpoint rejects unauthenticated callers', async ({ playwright }) => {
    const anon = await playwright.request.newContext({ baseURL: BASE, ignoreHTTPSErrors: true });
    const failures: string[] = [];
    for (const e of ENDPOINTS) {
      const r = await anon.fetch(`/api${e.path}`, {
        method: e.method,
        headers: { Origin: ORIGIN, 'Content-Type': 'application/json' },
        data: e.body ? JSON.stringify(e.body) : undefined,
        failOnStatusCode: false,
      });
      // Safe methods → 401; unsafe methods are stopped even earlier by CSRF (403).
      const expected = e.method === 'GET' ? 401 : 403;
      if (r.status() !== expected) failures.push(`${e.method} ${e.path} → ${r.status()}`);
    }
    const stream = await anon.get('/api/stream', { failOnStatusCode: false });
    if (stream.status() !== 401) failures.push(`GET /stream → ${stream.status()}`);
    await anon.dispose();
    expect(failures, failures.join('\n')).toEqual([]);
  });

  test('forged / tampered access tokens are rejected', async ({ as }) => {
    const { ctx, api } = await as('auditor');
    const at = (await ctx.cookies(BASE)).find((c) => c.name === '__Host-ciso_at')!;
    const [h, p, s] = at.value.split('.');
    const payload = JSON.parse(Buffer.from(p!, 'base64url').toString());
    payload.roles = ['ADMIN']; // privilege escalation attempt
    const forged = `${h}.${Buffer.from(JSON.stringify(payload)).toString('base64url')}.${s}`;
    const noneAlg = `${Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64url')}.${Buffer.from(JSON.stringify(payload)).toString('base64url')}.`;
    for (const value of [forged, noneAlg, 'garbage']) {
      await ctx.addCookies([{ ...at, value }]);
      expect((await api('GET', '/admin/system')).status).toBe(401);
    }
  });
});
