import type { NextFunction, Request, Response } from 'express';
import { env } from '../config/env.js';
import { safeEqual } from '../lib/crypto.js';
import { HttpError } from '../lib/errors.js';
import { COOKIE } from '../auth/tokens.js';

const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);
const allowedOrigin = new URL(env.PUBLIC_BASE_URL).origin;

/**
 * CSRF defence in depth for state-changing requests:
 *  1. SameSite=Strict auth cookies
 *  2. Origin / Sec-Fetch-Site verification
 *  3. Double-submit token (cookie value must equal X-CSRF-Token header)
 */
export function csrfProtection(req: Request, _res: Response, next: NextFunction): void {
  if (SAFE_METHODS.has(req.method)) return next();

  const fetchSite = req.get('sec-fetch-site');
  if (fetchSite && fetchSite !== 'same-origin') throw new HttpError(403, 'CSRF', 'Cross-site request blocked');

  const origin = req.get('origin');
  if (origin && origin !== allowedOrigin) throw new HttpError(403, 'CSRF', 'Origin not allowed');

  const cookie: unknown = req.cookies?.[COOKIE.csrf];
  const header = req.get('x-csrf-token');
  if (typeof cookie !== 'string' || !header || !safeEqual(cookie, header)) {
    throw new HttpError(403, 'CSRF', 'CSRF token missing or invalid');
  }
  next();
}
