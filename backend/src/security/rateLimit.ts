/**
 * Rate limiting. Limits are administrator-defined (Configuration → Rate limiting) and
 * evaluated per request, so a change applies within seconds without a restart.
 *
 *  - Authenticated traffic is keyed by *user*, so colleagues behind one office NAT
 *    address do not share a quota.
 *  - Per-IP limits exist only as a flood ceiling and for unauthenticated sign-in
 *    endpoints (credential stuffing). Keycloak additionally locks accounts.
 *  - Every throttled call returns HTTP 429 + Retry-After + RateLimit headers.
 */
import type { Request, Response } from 'express';
import { rateLimit } from 'express-rate-limit';
import { getSetting } from '../modules/settings/settings.service.js';

const handler = (_req: Request, res: Response) =>
  res.status(429).json({ error: { code: 'RATE_LIMITED', message: 'Too many requests — slow down and retry after the Retry-After interval' } });

const common = { windowMs: 60_000, standardHeaders: 'draft-7' as const, legacyHeaders: false, handler };
const limits = () => getSetting('rateLimits');

/** Coarse per-IP ceiling (flood protection). */
export const globalRateLimit = rateLimit({ ...common, limit: async () => (await limits()).perIpPerMin });

/** Per-IP limit on login/callback/refresh (unauthenticated endpoints). */
export const authRateLimit = rateLimit({ ...common, limit: async () => (await limits()).authPerIpPerMin });

/** Per-user quota for authenticated API traffic. */
export const userRateLimit = rateLimit({
  ...common,
  limit: async () => (await limits()).perUserPerMin,
  keyGenerator: (req: Request) => `user:${req.auth?.userId ?? 'anonymous'}`,
});

/** Expensive operations (connector test/sync, audit verification, exports) — per user. */
export const heavyRateLimit = rateLimit({
  ...common,
  limit: async () => (await limits()).heavyPerUserPerMin,
  keyGenerator: (req: Request) => `heavy:${req.auth?.userId ?? 'anonymous'}`,
});
