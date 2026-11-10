import { describe, expect, it } from 'vitest';
import { blindIndex, decrypt, encrypt, needsReencryption } from '../src/lib/crypto.js';
import { can, permissionsFor } from '../src/auth/rbac.js';
import { assertUrlAllowed, isBlockedAddress } from '../src/connectors/egress.js';
import { canonicalJson, computeAuditHash, sanitizeDetails, AUDIT_GENESIS_HASH } from '../src/audit/audit.service.js';
import { csvCell } from '../src/audit/audit.routes.js';
import { signAccessToken, verifyAccessToken, sealOidcState, openOidcState } from '../src/auth/tokens.js';

describe('AES-256-GCM field encryption', () => {
  it('round-trips and binds ciphertext to its AAD', () => {
    const ct = encrypt('top secret', 'connector:1');
    expect(ct.startsWith('enc:v2:')).toBe(true);
    expect(decrypt(ct, 'connector:1')).toBe('top secret');
    expect(() => decrypt(ct, 'connector:2')).toThrow();
  });

  it('uses a fresh IV per encryption and detects tampering', () => {
    const a = encrypt('x');
    const b = encrypt('x');
    expect(a).not.toBe(b);
    const parts = a.split(':');
    parts[4] = Buffer.from('tampered').toString('base64url');
    expect(() => decrypt(parts.join(':'))).toThrow();
  });

  it('flags ciphertext from rotated keys', () => {
    expect(needsReencryption(encrypt('x'))).toBe(false);
    expect(needsReencryption('enc:v1:a:b:c')).toBe(true);
  });

  it('produces stable, normalised blind indexes', () => {
    expect(blindIndex('Alice@Example.com ', 'email')).toBe(blindIndex('alice@example.com', 'email'));
    expect(blindIndex('alice@example.com', 'email')).not.toBe(blindIndex('alice@example.com', 'other'));
  });
});

describe('RBAC', () => {
  it('enforces least privilege and separation of duties', () => {
    expect(can(['AUDITOR'], 'audit:read')).toBe(true);
    expect(can(['AUDITOR'], 'risk:write')).toBe(false);
    expect(can(['ADMIN'], 'risk:acceptance:approve')).toBe(false);
    expect(can(['CISO'], 'risk:acceptance:approve')).toBe(true);
    expect(can(['SECOPS'], 'integration:manage')).toBe(true);
    expect(can(['PATCH_ADMIN'], 'integration:manage')).toBe(false);
    expect(can(['PATCH_ADMIN'], 'remediation:write')).toBe(true);
  });

  it('auditor permissions are read-only', () => {
    const perms = permissionsFor(['AUDITOR']);
    expect(perms.every((p) => p.endsWith(':read'))).toBe(true);
  });
});

describe('Connector egress policy (SSRF)', () => {
  it('blocks loopback, link-local metadata and configured internal ranges', () => {
    expect(isBlockedAddress('127.0.0.1')).toBe(true);
    expect(isBlockedAddress('169.254.169.254')).toBe(true);
    expect(isBlockedAddress('::1')).toBe(true);
    expect(isBlockedAddress('::ffff:127.0.0.1')).toBe(true);
    expect(isBlockedAddress('172.30.1.10')).toBe(true);
    expect(isBlockedAddress('8.8.8.8')).toBe(false);
  });

  it('rejects non-https, embedded credentials and denied hosts', () => {
    expect(() => assertUrlAllowed(new URL('http://siem.example.com'))).toThrow();
    expect(() => assertUrlAllowed(new URL('https://user:pw@siem.example.com'))).toThrow();
    expect(() => assertUrlAllowed(new URL('https://postgres:5432'))).toThrow();
    expect(() => assertUrlAllowed(new URL('https://169.254.169.254/latest'))).toThrow();
    expect(() => assertUrlAllowed(new URL('https://siem.example.com'))).not.toThrow();
  });
});

describe('Audit chain', () => {
  const record = {
    ts: '2026-01-01T00:00:00.000Z',
    actorId: 'u1',
    actorName: 'Alice',
    actorRoles: ['CISO'],
    action: 'risk.update',
    targetType: 'risk',
    targetId: 'r1',
    outcome: 'SUCCESS',
    ip: '10.0.0.1',
    userAgent: null,
    details: { b: 1, a: { d: 2, c: 3 } },
  };

  it('canonical JSON is key-order independent', () => {
    expect(canonicalJson({ b: 1, a: 2 })).toBe(canonicalJson({ a: 2, b: 1 }));
  });

  it('hash changes when any field or the previous hash changes', () => {
    const h = computeAuditHash(AUDIT_GENESIS_HASH, record);
    expect(h).toMatch(/^[0-9a-f]{64}$/);
    expect(computeAuditHash(AUDIT_GENESIS_HASH, { ...record, outcome: 'FAILURE' })).not.toBe(h);
    expect(computeAuditHash('f'.repeat(64), record)).not.toBe(h);
    expect(computeAuditHash(AUDIT_GENESIS_HASH, { ...record, details: { a: { c: 3, d: 2 }, b: 1 } })).toBe(h);
  });

  it('never stores secrets in audit details', () => {
    expect(sanitizeDetails({ apiKey: 'x', nested: { clientSecret: 'y', ok: 1 } })).toEqual({
      apiKey: '[REDACTED]',
      nested: { clientSecret: '[REDACTED]', ok: 1 },
    });
  });

  it('CSV export neutralises formula injection', () => {
    expect(csvCell('=HYPERLINK("http://evil")')).toBe(`"'=HYPERLINK(""http://evil"")"`);
    expect(csvCell('normal')).toBe('"normal"');
  });
});

describe('Tokens', () => {
  it('signs and verifies short-lived access tokens', async () => {
    const t = await signAccessToken({
      userId: '11111111-1111-4111-8111-111111111111',
      sessionId: '22222222-2222-4222-8222-222222222222',
      name: 'Alice',
      roles: ['CISO'],
    });
    const c = await verifyAccessToken(t);
    expect(c.roles).toEqual(['CISO']);
    await expect(verifyAccessToken(`${t.slice(0, -2)}xx`)).rejects.toThrow();
  });

  it('encrypts OIDC state', async () => {
    const sealed = await sealOidcState({ state: 's', nonce: 'n', codeVerifier: 'v', returnTo: '/' });
    expect(sealed).not.toContain('codeVerifier');
    expect((await openOidcState(sealed)).nonce).toBe('n');
  });
});
