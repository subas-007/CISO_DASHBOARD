import { mkdirSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { randomBytes } from 'node:crypto';
import { request } from '@playwright/test';
import { BASE, USERS_FILE } from './env';
import { createUser } from './keycloak';
import { setLiveSimulation } from './demo';

export type RoleKey = 'ciso' | 'ciso2' | 'admin' | 'secops' | 'secops2' | 'patch' | 'auditor' | 'norole' | 'victim' | 'mfa';

const ROLE_MAP: Record<RoleKey, string[]> = {
  ciso: ['ciso'],
  ciso2: ['ciso'],
  admin: ['administrator'],
  secops: ['secops_analyst'],
  secops2: ['secops_analyst'],
  patch: ['patch_admin'],
  auditor: ['auditor'],
  norole: [],
  victim: ['secops_analyst'],
  mfa: ['ciso'],
};

export default async function globalSetup(): Promise<void> {
  // Run id shared by all workers (survives worker restarts after a failure).
  process.env.E2E_RUN = Date.now().toString(36);
  // Stack must be up.
  const ctx = await request.newContext({ baseURL: BASE, ignoreHTTPSErrors: true });
  const health = await ctx.get('/api/health');
  if (!health.ok()) throw new Error(`Stack not reachable at ${BASE} (HTTP ${health.status()})`);
  await ctx.dispose();

  // Deterministic specs run on a still dataset; 07-configuration exercises the live
  // simulator explicitly. Teardown switches it back on.
  setLiveSimulation(false);

  // Password satisfies the realm policy (length 14, upper, lower, digit, special).
  const password = `E2e-${randomBytes(8).toString('hex')}!Q7`;
  const users: Record<string, { username: string; id: string }> = {};
  for (const [key, roles] of Object.entries(ROLE_MAP) as [RoleKey, string[]][]) {
    const username = `e2e-${key}`;
    const id = await createUser(
      key === 'mfa'
        ? { username, password, realmRoles: roles, temporary: true, requiredActions: ['CONFIGURE_TOTP'] }
        : { username, password, realmRoles: roles },
    );
    users[key] = { username, id };
  }
  mkdirSync(path.dirname(USERS_FILE), { recursive: true });
  writeFileSync(USERS_FILE, JSON.stringify({ password, users }, null, 2), { mode: 0o600 });
}
