import { readFileSync } from 'node:fs';
import { createHmac } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { test as base, expect, type BrowserContext, type Page } from '@playwright/test';
import { BASE, ENV, ORIGIN, ROOT, USERS_FILE } from './env';
import type { RoleKey } from './global-setup';

export { expect };

export function testUsers(): { password: string; users: Record<RoleKey, { username: string; id: string }> } {
  return JSON.parse(readFileSync(USERS_FILE, 'utf8'));
}

/* ------------------------------- OIDC login ------------------------------- */

export async function kcSubmitLogin(page: Page, username: string, password: string): Promise<void> {
  await page.locator('#username').fill(username);
  await page.locator('#password').fill(password);
  await page.locator('#kc-login').click();
}

export async function login(page: Page, role: RoleKey): Promise<void> {
  const { password, users } = testUsers();
  await page.goto('/login');
  await page.getByRole('button', { name: /sign in with corporate sso/i }).click();
  await kcSubmitLogin(page, users[role].username, password);
  await page.waitForURL((u) => u.origin === ORIGIN && !u.pathname.startsWith('/auth') && !u.pathname.startsWith('/login'));
  await expect(page.getByRole('button', { name: /sign out/i })).toBeVisible();
}

/* --------------------------- CSRF-aware API client --------------------------- */

export interface ApiResult<T = any> {
  status: number;
  json: T;
  text: string;
  headers: Record<string, string>;
}

export function apiFor(ctx: BrowserContext) {
  return async function call<T = any>(method: string, path: string, body?: unknown): Promise<ApiResult<T>> {
    const cookies = await ctx.cookies(BASE);
    const csrf = cookies.find((c) => c.name === '__Host-ciso_csrf')?.value ?? '';
    const res = await ctx.request.fetch(`${BASE}/api${path}`, {
      method,
      headers: { 'X-CSRF-Token': csrf, Origin: ORIGIN, ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}) },
      data: body !== undefined ? JSON.stringify(body) : undefined,
      failOnStatusCode: false,
      maxRedirects: 0,
    });
    const text = await res.text();
    let json: any = null;
    try {
      json = JSON.parse(text);
    } catch {
      /* non-JSON */
    }
    return { status: res.status(), json, text, headers: res.headers() };
  };
}
export type Api = ReturnType<typeof apiFor>;

/* --------------------------------- Console --------------------------------- */

export function watchConsole(page: Page): { errors: string[]; csp: string[] } {
  const errors: string[] = [];
  const csp: string[] = [];
  page.on('pageerror', (e) => errors.push(`pageerror: ${e.message}`));
  page.on('console', (m) => {
    if (m.type() !== 'error') return;
    const t = m.text();
    if (/Content Security Policy|Refused to/i.test(t)) csp.push(t);
    else if (!/Failed to load resource/i.test(t)) errors.push(t);
  });
  return { errors, csp };
}

/* --------------------------------- Fixtures --------------------------------- */

interface Session {
  page: Page;
  ctx: BrowserContext;
  api: Api;
  console: { errors: string[]; csp: string[] };
}

export const test = base.extend<{ as: (role: RoleKey) => Promise<Session> }>({
  as: async ({ browser }, use) => {
    const opened: BrowserContext[] = [];
    await use(async (role) => {
      const ctx = await browser.newContext({ ignoreHTTPSErrors: true, viewport: { width: 1440, height: 900 }, acceptDownloads: true });
      opened.push(ctx);
      const page = await ctx.newPage();
      const console = watchConsole(page);
      await login(page, role);
      return { page, ctx, api: apiFor(ctx), console };
    });
    for (const c of opened) await c.close();
  },
});

/* ------------------------------ TOTP (RFC 6238) ------------------------------ */

function base32Decode(input: string): Buffer {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const clean = input.replace(/[\s=]/g, '').toUpperCase();
  let bits = '';
  for (const ch of clean) bits += alphabet.indexOf(ch).toString(2).padStart(5, '0');
  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) bytes.push(parseInt(bits.slice(i, i + 8), 2));
  return Buffer.from(bytes);
}

export function totp(secret: string, at = Date.now(), algo: 'sha1' | 'sha256' = 'sha1'): string {
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(at / 1000 / 30)));
  const h = createHmac(algo, base32Decode(secret)).update(counter).digest();
  const o = h[h.length - 1]! & 0xf;
  const code = ((h.readUInt32BE(o) & 0x7fffffff) % 1_000_000).toString().padStart(6, '0');
  return code;
}

/* ------------------------------ Docker helpers ------------------------------ */

const COMPOSE = ['compose', '-f', 'docker-compose.yml', '-f', 'docker-compose.test.yml'];

export function docker(args: string[], input?: string): { code: number; out: string } {
  const r = spawnSync('docker', args, { cwd: ROOT, input, encoding: 'utf8', maxBuffer: 256 * 1024 * 1024 });
  return { code: r.status ?? 1, out: `${r.stdout ?? ''}${r.stderr ?? ''}` };
}

export const compose = (args: string[], input?: string) => docker([...COMPOSE, ...args], input);

/** Runs SQL as the schema owner (superuser) or the least-privilege runtime role. */
export function psql(sql: string, as: 'owner' | 'app' = 'owner'): { code: number; out: string } {
  const user = as === 'owner' ? ENV.POSTGRES_USER ?? 'ciso_owner' : 'ciso_app';
  const pw = as === 'owner' ? ENV.POSTGRES_PASSWORD! : ENV.APP_DB_PASSWORD!;
  return compose(['exec', '-T', '-e', `PGPASSWORD=${pw}`, 'postgres', 'psql', '-h', '127.0.0.1', '-U', user, '-d', ENV.POSTGRES_DB ?? 'ciso', '-tA', '-v', 'ON_ERROR_STOP=1'], sql);
}

export async function waitFor<T>(fn: () => Promise<T | undefined | null | false>, timeoutMs = 30_000, intervalMs = 1000): Promise<T> {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const v = await fn();
    if (v) return v;
    if (Date.now() > deadline) throw new Error('waitFor: timed out');
    await new Promise((r) => setTimeout(r, intervalMs));
  }
}

export async function restartApi(): Promise<void> {
  const r = compose(['up', '-d', '--force-recreate', '--no-deps', '--wait', 'api']);
  if (r.code !== 0) throw new Error(`api restart failed: ${r.out}`);
}
