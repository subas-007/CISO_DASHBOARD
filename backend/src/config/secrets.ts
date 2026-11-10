/**
 * Secrets loading — no secret is ever hardcoded.
 *
 * Resolution order for each secret key (first match wins):
 *   1. HashiCorp Vault KV v2 (SECRETS_PROVIDER=vault)
 *   2. `<KEY>_FILE` → file contents (Docker / Kubernetes secrets, e.g. /run/secrets/jwt_secret)
 *   3. `<KEY>` plain environment variable (populated from a git-ignored .env file)
 *
 * After the configuration is validated, secret values are scrubbed from process.env
 * (see scrubSecretsFromEnv) so they cannot leak into child processes or crash dumps.
 */
import { readFile } from 'node:fs/promises';

export const SECRET_KEYS = [
  'DATABASE_URL',
  'DATABASE_REPLICA_URLS',
  'OIDC_CLIENT_SECRET',
  'JWT_SECRET',
  'STATE_ENCRYPTION_KEY',
  'DATA_ENCRYPTION_KEYS',
  'BLIND_INDEX_KEY',
  'AUDIT_HMAC_KEY',
  'IDP_PROVISIONER_CLIENT_SECRET',
  'IDP_BOOTSTRAP_ADMIN_PASSWORD',
  'DEMO_ADMIN_PASSWORD',
] as const;

async function readSecretFile(path: string): Promise<string> {
  return (await readFile(path, 'utf8')).trim();
}

async function loadFromFiles(): Promise<void> {
  for (const key of [...SECRET_KEYS, 'VAULT_TOKEN', 'VAULT_SECRET_ID']) {
    const filePath = process.env[`${key}_FILE`];
    if (filePath && !process.env[key]) {
      process.env[key] = await readSecretFile(filePath);
    }
  }
}

interface VaultLoginResponse {
  auth?: { client_token?: string };
}
interface VaultKvResponse {
  data?: { data?: Record<string, unknown> };
}

async function vaultToken(addr: string): Promise<string> {
  if (process.env.VAULT_TOKEN) return process.env.VAULT_TOKEN;
  const roleId = process.env.VAULT_ROLE_ID;
  const secretId = process.env.VAULT_SECRET_ID;
  if (!roleId || !secretId) {
    throw new Error('Vault provider requires VAULT_TOKEN or VAULT_ROLE_ID + VAULT_SECRET_ID');
  }
  const res = await fetch(`${addr}/v1/auth/approle/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ role_id: roleId, secret_id: secretId }),
    signal: AbortSignal.timeout(10_000),
  });
  if (!res.ok) throw new Error(`Vault AppRole login failed (HTTP ${res.status})`);
  const body = (await res.json()) as VaultLoginResponse;
  const token = body.auth?.client_token;
  if (!token) throw new Error('Vault AppRole login returned no token');
  return token;
}

async function loadFromVault(): Promise<void> {
  const addr = (process.env.VAULT_ADDR ?? '').replace(/\/+$/, '');
  if (!addr) throw new Error('SECRETS_PROVIDER=vault requires VAULT_ADDR');
  if (!addr.startsWith('https://') && process.env.NODE_ENV === 'production') {
    throw new Error('VAULT_ADDR must use https:// in production');
  }
  const mount = process.env.VAULT_KV_MOUNT ?? 'secret';
  const path = process.env.VAULT_KV_PATH ?? 'ciso-dashboard';
  const token = await vaultToken(addr);
  const res = await fetch(`${addr}/v1/${encodeURIComponent(mount)}/data/${path.split('/').map(encodeURIComponent).join('/')}`, {
    headers: { 'X-Vault-Token': token },
    signal: AbortSignal.timeout(10_000),
  });
  if (!res.ok) throw new Error(`Vault KV read failed (HTTP ${res.status})`);
  const body = (await res.json()) as VaultKvResponse;
  const data = body.data?.data ?? {};
  for (const key of SECRET_KEYS) {
    const value = data[key];
    if (typeof value === 'string' && value.length > 0) process.env[key] = value;
  }
}

export async function loadSecrets(): Promise<void> {
  await loadFromFiles();
  if ((process.env.SECRETS_PROVIDER ?? 'env') === 'vault') {
    await loadFromVault();
  }
}

export function scrubSecretsFromEnv(): void {
  for (const key of [...SECRET_KEYS, 'VAULT_TOKEN', 'VAULT_SECRET_ID']) {
    delete process.env[key];
  }
}
