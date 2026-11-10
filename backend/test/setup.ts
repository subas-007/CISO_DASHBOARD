import { randomBytes } from 'node:crypto';

// Ephemeral, test-only key material generated per run — never committed.
Object.assign(process.env, {
  NODE_ENV: 'test',
  LOG_LEVEL: 'fatal',
  PUBLIC_BASE_URL: 'https://localhost',
  DATABASE_URL: 'postgresql://test:test@127.0.0.1:5432/test',
  OIDC_ISSUER_URL: 'https://localhost/auth/realms/ciso',
  OIDC_CLIENT_ID: 'ciso-dashboard',
  OIDC_CLIENT_SECRET: randomBytes(24).toString('hex'),
  JWT_SECRET: randomBytes(48).toString('hex'),
  STATE_ENCRYPTION_KEY: randomBytes(32).toString('base64'),
  DATA_ENCRYPTION_KEYS: `v1:${randomBytes(32).toString('base64')},v2:${randomBytes(32).toString('base64')}`,
  DATA_ENCRYPTION_ACTIVE_KEY: 'v2',
  BLIND_INDEX_KEY: randomBytes(32).toString('hex'),
  AUDIT_HMAC_KEY: randomBytes(32).toString('hex'),
  CONNECTOR_BLOCKED_CIDRS: '172.30.0.0/16',
  SCHEDULER_ENABLED: 'false',
});
