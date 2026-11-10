import { readFileSync } from 'node:fs';
import http from 'node:http';
import https from 'node:https';
import { env } from './config/env.js';
import { logger } from './lib/logger.js';
import { prisma } from './lib/prisma.js';
import { createApp } from './app.js';
import { startScheduler, stopScheduler } from './scheduler/scheduler.js';
import { ensureDefaultSettings } from './modules/settings/settings.service.js';
import { audit } from './audit/audit.service.js';
import { applyLiveSettings } from './modules/config/apply.js';
import { syncIdentityPolicy } from './idp/identity.service.js';

async function main(): Promise<void> {
  await prisma.$connect();
  await ensureDefaultSettings();
  await applyLiveSettings();
  const app = createApp();

  let server: http.Server | https.Server;
  if (env.TLS_CERT_FILE && env.TLS_KEY_FILE) {
    server = https.createServer(
      {
        cert: readFileSync(env.TLS_CERT_FILE),
        key: readFileSync(env.TLS_KEY_FILE),
        ca: env.TLS_CA_FILE ? readFileSync(env.TLS_CA_FILE) : undefined,
        minVersion: 'TLSv1.3',
        // Zero trust: only the gateway (holding a CA-issued client cert) may call the API.
        requestCert: env.TLS_REQUIRE_CLIENT_CERT,
        rejectUnauthorized: env.TLS_REQUIRE_CLIENT_CERT,
      },
      app,
    );
  } else {
    if (env.NODE_ENV === 'production') logger.warn('API listener is plain HTTP — terminate TLS upstream and isolate the network');
    server = http.createServer(app);
  }
  server.headersTimeout = 30_000;
  server.requestTimeout = 60_000;
  server.keepAliveTimeout = 65_000;

  server.listen(env.PORT, () => {
    logger.info({ port: env.PORT, tls: !!env.TLS_CERT_FILE, mtls: env.TLS_REQUIRE_CLIENT_CERT }, 'CISO dashboard API listening');
  });
  if (env.SCHEDULER_ENABLED) startScheduler();
  // Converge the identity provider on the stored policy (non-blocking; retried by the scheduler).
  void syncIdentityPolicy();
  await audit({ action: 'system.start', outcome: 'SUCCESS', details: { version: env.APP_VERSION } }, { bestEffort: true });

  const shutdown = (signal: string) => {
    logger.info({ signal }, 'shutting down');
    stopScheduler();
    server.close(() => {
      void prisma.$disconnect().finally(() => process.exit(0));
    });
    setTimeout(() => process.exit(1), 10_000).unref();
  };
  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));
}

process.on('unhandledRejection', (reason) => logger.error({ err: reason }, 'unhandled rejection'));

main().catch((err: unknown) => {
  logger.fatal({ err }, 'failed to start');
  process.exit(1);
});
