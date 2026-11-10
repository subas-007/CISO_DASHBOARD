import express, { type NextFunction, type Request, type Response } from 'express';
import cookieParser from 'cookie-parser';
import { pinoHttp } from 'pino-http';
import { randomUUID } from 'node:crypto';
import { Prisma } from '@prisma/client';
import { ZodError } from 'zod';
import { env } from './config/env.js';
import { logger } from './lib/logger.js';
import { HttpError } from './lib/errors.js';
import { prisma } from './lib/prisma.js';
import { securityHeaders } from './security/headers.js';
import { csrfProtection } from './security/csrf.js';
import { globalRateLimit, userRateLimit } from './security/rateLimit.js';
import { authenticate } from './auth/middleware.js';
import { authRouter } from './auth/auth.routes.js';
import { auditRouter } from './audit/audit.routes.js';
import { kpiRouter, kriRouter } from './modules/kpi/kpi.routes.js';
import { acceptanceRouter, riskRouter } from './modules/risk/risk.routes.js';
import { threatsRouter } from './modules/threats/threats.routes.js';
import { incidentsRouter } from './modules/incidents/incidents.routes.js';
import { assetsRouter, changeTicketsRouter, vulnerabilitiesRouter } from './modules/remediation/remediation.routes.js';
import { integrationsRouter } from './modules/integrations/integrations.routes.js';
import { adminRouter } from './modules/admin/admin.routes.js';
import { complianceRouter } from './modules/compliance/compliance.routes.js';
import { streamRouter } from './modules/stream/stream.routes.js';

export function createApp() {
  const app = express();
  app.disable('x-powered-by');
  app.set('etag', false);
  app.set('trust proxy', env.TRUST_PROXY_HOPS);
  app.set('query parser', 'simple'); // no nested objects in query strings

  app.use(
    pinoHttp({
      logger,
      genReqId: (req, res) => {
        const id = randomUUID();
        res.setHeader('X-Request-Id', id);
        return id;
      },
      serializers: {
        req: (req: { id: string; method: string; url: string }) => ({ id: req.id, method: req.method, path: req.url.split('?')[0] }),
        res: (res: { statusCode: number }) => ({ statusCode: res.statusCode }),
      },
      autoLogging: { ignore: (req) => req.url === '/api/health' },
    }),
  );
  app.use(securityHeaders());
  app.use(express.json({ limit: '100kb', strict: true, type: 'application/json' }));
  app.use(cookieParser());

  app.get('/api/health', (_req, res) => {
    res.json({ status: 'ok' });
  });
  app.get('/api/ready', async (_req, res) => {
    await prisma.$queryRaw`SELECT 1`;
    res.json({ status: 'ready' });
  });

  app.use('/api', globalRateLimit);
  app.use('/api', csrfProtection);
  app.use('/api/auth', authRouter);

  // Everything below requires an authenticated, live session.
  app.use('/api', authenticate);
  app.use('/api', userRateLimit);
  app.use('/api/kpi', kpiRouter);
  app.use('/api/kri', kriRouter);
  app.use('/api/risks', riskRouter);
  app.use('/api/risk-acceptances', acceptanceRouter);
  app.use('/api/threats', threatsRouter);
  app.use('/api/incidents', incidentsRouter);
  app.use('/api/vulnerabilities', vulnerabilitiesRouter);
  app.use('/api/assets', assetsRouter);
  app.use('/api/change-tickets', changeTicketsRouter);
  app.use('/api/integrations', integrationsRouter);
  app.use('/api/admin', adminRouter);
  app.use('/api/audit', auditRouter);
  app.use('/api/compliance', complianceRouter);
  app.use('/api/stream', streamRouter);

  app.use((_req, res) => {
    res.status(404).json({ error: { code: 'NOT_FOUND', message: 'Not found' } });
  });

  // Central error handler: never leaks stack traces, SQL or upstream payloads.
  app.use((err: unknown, req: Request, res: Response, _next: NextFunction) => {
    if (res.headersSent) return;
    if (err instanceof HttpError) {
      res.status(err.status).json({ error: { code: err.code, message: err.message } });
      return;
    }
    if (err instanceof ZodError) {
      res.status(400).json({
        error: {
          code: 'VALIDATION_FAILED',
          message: 'Request validation failed',
          issues: err.issues.slice(0, 20).map((i) => ({ path: i.path.join('.'), message: i.message })),
        },
      });
      return;
    }
    if (err instanceof Prisma.PrismaClientKnownRequestError) {
      if (err.code === 'P2025') {
        res.status(404).json({ error: { code: 'NOT_FOUND', message: 'Resource not found' } });
        return;
      }
      if (err.code === 'P2002') {
        res.status(409).json({ error: { code: 'CONFLICT', message: 'A record with the same unique value already exists' } });
        return;
      }
    }
    const status = (err as { status?: number; type?: string }).status;
    if (status === 400 || status === 413 || status === 415) {
      res.status(status).json({ error: { code: 'BAD_REQUEST', message: status === 413 ? 'Payload too large' : 'Malformed request' } });
      return;
    }
    req.log?.error({ err }, 'unhandled error');
    res.status(500).json({ error: { code: 'INTERNAL', message: 'Internal server error', requestId: req.id } });
  });

  return app;
}
