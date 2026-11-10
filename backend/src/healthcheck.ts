/**
 * Container HEALTHCHECK. Uses the same client certificate as the gateway when mTLS is
 * enforced. Kept dependency-free so it does not load application configuration.
 */
import { readFileSync } from 'node:fs';
import https from 'node:https';
import http from 'node:http';

const port = Number(process.env.PORT ?? 8443);
const tls = !!process.env.TLS_CERT_FILE;
const read = (p?: string) => (p ? readFileSync(p) : undefined);

const req = (tls ? https : http).request(
  {
    host: '127.0.0.1',
    port,
    path: '/api/health',
    method: 'GET',
    timeout: 4000,
    ...(tls
      ? {
          cert: read(process.env.TLS_CERT_FILE),
          key: read(process.env.TLS_KEY_FILE),
          ca: read(process.env.TLS_CA_FILE),
          servername: 'api', // certificate SAN includes "api"; chain + hostname are verified
        }
      : {}),
  },
  (res) => process.exit(res.statusCode === 200 ? 0 : 1),
);
req.on('error', () => process.exit(1));
req.on('timeout', () => {
  req.destroy();
  process.exit(1);
});
req.end();
