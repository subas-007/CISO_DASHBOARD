/**
 * Application-layer cryptography.
 *
 *  - AES-256-GCM authenticated encryption with a versioned key ring (supports rotation).
 *    Ciphertext format:  enc:<keyId>:<iv b64url>:<tag b64url>:<ciphertext b64url>
 *    Optional AAD binds a ciphertext to its owning record (prevents row-swapping attacks).
 *  - HMAC-SHA256 blind indexes ("tokenized fields") allow equality lookups on encrypted
 *    columns without storing plaintext.
 */
import {
  createCipheriv,
  createDecipheriv,
  createHash,
  createHmac,
  randomBytes,
  timingSafeEqual,
} from 'node:crypto';
import { env } from '../config/env.js';

const ALGO = 'aes-256-gcm';
const PREFIX = 'enc';

function parseKeyRing(spec: string): Map<string, Buffer> {
  const ring = new Map<string, Buffer>();
  for (const entry of spec.split(',').map((s) => s.trim()).filter(Boolean)) {
    const idx = entry.indexOf(':');
    if (idx <= 0) throw new Error('DATA_ENCRYPTION_KEYS entries must be "<keyId>:<base64key>"');
    const id = entry.slice(0, idx);
    const key = Buffer.from(entry.slice(idx + 1), 'base64');
    if (key.length !== 32) throw new Error(`Encryption key "${id}" must be exactly 32 bytes (AES-256)`);
    ring.set(id, key);
  }
  return ring;
}

const keyRing = parseKeyRing(env.DATA_ENCRYPTION_KEYS);
const activeKeyId = env.DATA_ENCRYPTION_ACTIVE_KEY;
if (!keyRing.has(activeKeyId)) {
  throw new Error(`DATA_ENCRYPTION_ACTIVE_KEY "${activeKeyId}" not present in key ring`);
}

export function activeEncryptionKeyId(): string {
  return activeKeyId;
}

export function encrypt(plaintext: string, aad = ''): string {
  const key = keyRing.get(activeKeyId)!;
  const iv = randomBytes(12);
  const cipher = createCipheriv(ALGO, key, iv);
  if (aad) cipher.setAAD(Buffer.from(aad, 'utf8'));
  const ct = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return [PREFIX, activeKeyId, iv.toString('base64url'), tag.toString('base64url'), ct.toString('base64url')].join(':');
}

export function decrypt(token: string, aad = ''): string {
  const parts = token.split(':');
  if (parts.length !== 5 || parts[0] !== PREFIX) throw new Error('Malformed ciphertext');
  const [, keyId, ivB64, tagB64, ctB64] = parts as [string, string, string, string, string];
  const key = keyRing.get(keyId);
  if (!key) throw new Error(`Unknown encryption key id "${keyId}"`);
  const decipher = createDecipheriv(ALGO, key, Buffer.from(ivB64, 'base64url'));
  if (aad) decipher.setAAD(Buffer.from(aad, 'utf8'));
  decipher.setAuthTag(Buffer.from(tagB64, 'base64url'));
  return Buffer.concat([decipher.update(Buffer.from(ctB64, 'base64url')), decipher.final()]).toString('utf8');
}

export function encryptJson(value: unknown, aad = ''): string {
  return encrypt(JSON.stringify(value), aad);
}

export function decryptJson<T>(token: string, aad = ''): T {
  return JSON.parse(decrypt(token, aad)) as T;
}

export function encryptOptional(value: string | null | undefined, aad = ''): string | null {
  return value == null || value === '' ? null : encrypt(value, aad);
}

export function decryptOptional(token: string | null | undefined, aad = ''): string | null {
  if (!token) return null;
  try {
    return decrypt(token, aad);
  } catch {
    return null;
  }
}

/** True when the ciphertext was produced by a non-active key and should be re-encrypted. */
export function needsReencryption(token: string): boolean {
  return token.split(':')[1] !== activeKeyId;
}

/** Deterministic keyed hash used to look up encrypted values (e.g. email). */
export function blindIndex(value: string, context: string): string {
  return createHmac('sha256', env.BLIND_INDEX_KEY)
    .update(`${context}:${value.normalize('NFKC').trim().toLowerCase()}`)
    .digest('hex');
}

export function sha256Hex(value: string): string {
  return createHash('sha256').update(value).digest('hex');
}

export function hmacHex(key: string, value: string): string {
  return createHmac('sha256', key).update(value).digest('hex');
}

export function randomToken(bytes = 32): string {
  return randomBytes(bytes).toString('base64url');
}

export function safeEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  return ab.length === bb.length && timingSafeEqual(ab, bb);
}
