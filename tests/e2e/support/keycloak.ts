/** Keycloak admin REST helpers (used only to provision ephemeral test identities). */
import { request, type APIRequestContext } from '@playwright/test';
import { BASE, ENV } from './env';

export async function adminApi(): Promise<{ ctx: APIRequestContext; token: string }> {
  const ctx = await request.newContext({ baseURL: BASE, ignoreHTTPSErrors: true });
  const res = await ctx.post('/auth/realms/master/protocol/openid-connect/token', {
    form: {
      grant_type: 'password',
      client_id: 'admin-cli',
      username: ENV.KC_BOOTSTRAP_ADMIN_USERNAME ?? 'kcadmin',
      password: ENV.KC_BOOTSTRAP_ADMIN_PASSWORD!,
    },
  });
  if (!res.ok()) throw new Error(`Keycloak admin login failed: ${res.status()}`);
  return { ctx, token: (await res.json()).access_token as string };
}

export interface NewUser {
  username: string;
  password: string;
  realmRoles: string[];
  temporary?: boolean;
  requiredActions?: string[];
}

export async function createUser(u: NewUser): Promise<string> {
  const { ctx, token } = await adminApi();
  const headers = { Authorization: `Bearer ${token}` };
  const existing = await ctx.get(`/auth/admin/realms/ciso/users?username=${encodeURIComponent(u.username)}&exact=true`, { headers });
  for (const old of (await existing.json()) as { id: string }[]) {
    await ctx.delete(`/auth/admin/realms/ciso/users/${old.id}`, { headers });
  }
  const created = await ctx.post('/auth/admin/realms/ciso/users', {
    headers,
    data: {
      username: u.username,
      enabled: true,
      emailVerified: true,
      email: `${u.username}@example.test`,
      firstName: 'E2E',
      lastName: u.username.replace('e2e-', ''),
      requiredActions: u.requiredActions ?? [],
      credentials: [{ type: 'password', value: u.password, temporary: !!u.temporary }],
    },
  });
  if (created.status() !== 201) throw new Error(`create ${u.username}: ${created.status()} ${await created.text()}`);
  const id = String(created.headers()['location']).split('/').pop()!;
  if (u.realmRoles.length) {
    const roles = [];
    for (const r of u.realmRoles) roles.push(await (await ctx.get(`/auth/admin/realms/ciso/roles/${r}`, { headers })).json());
    const map = await ctx.post(`/auth/admin/realms/ciso/users/${id}/role-mappings/realm`, { headers, data: roles });
    if (!map.ok()) throw new Error(`role mapping ${u.username}: ${map.status()}`);
  }
  await ctx.dispose();
  return id;
}

export async function deleteUser(id: string): Promise<void> {
  const { ctx, token } = await adminApi();
  await ctx.delete(`/auth/admin/realms/ciso/users/${id}`, { headers: { Authorization: `Bearer ${token}` } });
  await ctx.dispose();
}

export async function realmOtpAlgorithm(): Promise<string> {
  const { ctx, token } = await adminApi();
  const realm = await (await ctx.get('/auth/admin/realms/ciso', { headers: { Authorization: `Bearer ${token}` } })).json();
  await ctx.dispose();
  return realm.otpPolicyAlgorithm as string;
}
