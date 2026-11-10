import http from 'node:http';
import { mkdtempSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import type { AddressInfo } from 'node:net';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { loadSecrets } from '../src/config/secrets.js';

let server: http.Server;
let addr = '';
const calls: string[] = [];

beforeAll(async () => {
  server = http.createServer((req, res) => {
    calls.push(`${req.method} ${req.url} token=${req.headers['x-vault-token'] ?? '-'}`);
    let body = '';
    req.on('data', (c) => (body += c));
    req.on('end', () => {
      res.setHeader('content-type', 'application/json');
      if (req.url === '/v1/auth/approle/login' && req.method === 'POST') {
        const { role_id, secret_id } = JSON.parse(body);
        if (role_id !== 'role-123' || secret_id !== 'secret-456') return res.writeHead(403).end('{}');
        return res.end(JSON.stringify({ auth: { client_token: 'vault-client-token' } }));
      }
      if (req.url === '/v1/kv/data/apps/ciso') {
        if (req.headers['x-vault-token'] !== 'vault-client-token') return res.writeHead(403).end('{}');
        return res.end(JSON.stringify({ data: { data: { JWT_SECRET: 'from-vault-jwt', AUDIT_HMAC_KEY: 'from-vault-audit', IGNORED_KEY: 'x' } } }));
      }
      return res.writeHead(404).end('{}');
    });
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  addr = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

afterAll(() => server.close());

describe('secrets loading', () => {
  it('reads *_FILE secrets (Docker / Kubernetes secrets convention)', async () => {
    const dir = mkdtempSync(path.join(os.tmpdir(), 'sec-'));
    const file = path.join(dir, 'blind');
    writeFileSync(file, '  from-file-value \n');
    const saved = { ...process.env };
    delete process.env.BLIND_INDEX_KEY;
    process.env.BLIND_INDEX_KEY_FILE = file;
    process.env.SECRETS_PROVIDER = 'env';
    await loadSecrets();
    expect(process.env.BLIND_INDEX_KEY).toBe('from-file-value');
    process.env = saved;
  });

  it('loads secrets from Vault KV v2 via AppRole and only for known keys', async () => {
    const saved = { ...process.env };
    Object.assign(process.env, {
      SECRETS_PROVIDER: 'vault',
      VAULT_ADDR: addr,
      VAULT_KV_MOUNT: 'kv',
      VAULT_KV_PATH: 'apps/ciso',
      VAULT_ROLE_ID: 'role-123',
      VAULT_SECRET_ID: 'secret-456',
    });
    delete process.env.VAULT_TOKEN;
    await loadSecrets();
    expect(process.env.JWT_SECRET).toBe('from-vault-jwt');
    expect(process.env.AUDIT_HMAC_KEY).toBe('from-vault-audit');
    expect(process.env.IGNORED_KEY).toBeUndefined();
    expect(calls).toContain('POST /v1/auth/approle/login token=-');
    expect(calls).toContain('GET /v1/kv/data/apps/ciso token=vault-client-token');
    process.env = saved;
  });

  it('fails closed when Vault rejects the AppRole credentials', async () => {
    const saved = { ...process.env };
    Object.assign(process.env, { SECRETS_PROVIDER: 'vault', VAULT_ADDR: addr, VAULT_KV_MOUNT: 'kv', VAULT_KV_PATH: 'apps/ciso', VAULT_ROLE_ID: 'role-123', VAULT_SECRET_ID: 'wrong' });
    delete process.env.VAULT_TOKEN;
    await expect(loadSecrets()).rejects.toThrow(/AppRole login failed/);
    process.env = saved;
  });

  it('refuses a non-TLS Vault address in production', async () => {
    const saved = { ...process.env };
    Object.assign(process.env, { NODE_ENV: 'production', SECRETS_PROVIDER: 'vault', VAULT_ADDR: addr, VAULT_TOKEN: 't' });
    await expect(loadSecrets()).rejects.toThrow(/https/);
    process.env = saved;
  });
});
