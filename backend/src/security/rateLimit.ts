import type { Request } from 'express';
import { rateLimit } from 'express-rate-limit';
import { env } from '../config/env.js';

const handler = (_req: unknown, res: { status: (n: number) => { json: (b: unknown) => void } }) =>
  res.status(429).json({ error: { code: 'RATE_LIMITED', message: 'Too many requests' } });

const common = { windowMs: 60_000, standardHeaders: 'draft-7' as const, legacyHeaders: false, handler };

/** Coarse per-IP ceiling (flood protection). Generous because offices share NAT IPs. */
export const globalRateLimit = rateLimit({ ...common, limit: env.RATE_LIMIT_PER_MIN });

/**
 * Per-IP limit on login/callback/refresh. Password brute force is additionally
 * throttled per account by the IdP's lockout policy.
 */
export const authRateLimit = rateLimit({ ...common, limit: 120 });

/** Per-user quota for authenticated API traffic (fair use regardless of shared IPs). */
export const userRateLimit = rateLimit({
  ...common,
  limit: env.RATE_LIMIT_PER_USER_MIN,
  keyGenerator: (req: Request) => `user:${req.auth?.userId ?? 'anonymous'}`,
});

/** Expensive operations (connector test/sync, audit verification, exports) — per user. */
export const heavyRateLimit = rateLimit({
  ...common,
  limit: 30,
  keyGenerator: (req: Request) => `heavy:${req.auth?.userId ?? 'anonymous'}`,
});
