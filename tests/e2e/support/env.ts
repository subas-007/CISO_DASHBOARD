import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';

export const ROOT = path.resolve(__dirname, '../../..');

function parseEnv(file: string): Record<string, string> {
  if (!existsSync(file)) throw new Error(`${file} not found — run scripts/generate-secrets.sh first`);
  const out: Record<string, string> = {};
  for (const line of readFileSync(file, 'utf8').split(/\r?\n/)) {
    const m = /^([A-Z0-9_]+)=(.*)$/.exec(line.trim());
    if (m) out[m[1]!] = m[2]!;
  }
  return out;
}

export const ENV = parseEnv(path.join(ROOT, '.env'));
export const BASE = (process.env.BASE_URL ?? ENV.PUBLIC_BASE_URL ?? 'https://localhost').replace(/\/+$/, '');
export const ORIGIN = new URL(BASE).origin;
export const CA_PEM = readFileSync(path.join(ROOT, 'certs/ca.crt'), 'utf8');
export const USERS_FILE = path.join(ROOT, 'tests/.auth/users.json');
export const SCREENSHOT_DIR = path.join(ROOT, 'docs/screenshots');
export const FAKE_ID = '00000000-0000-4000-8000-000000000000';
