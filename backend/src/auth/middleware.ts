import type { NextFunction, Request, RequestHandler, Response } from 'express';
import type { Role } from '@prisma/client';
import { audit, auditContext } from '../audit/audit.service.js';
import { forbidden, unauthorized } from '../lib/errors.js';
import { can, type Permission } from './rbac.js';
import { isSessionValid } from './session.service.js';
import { COOKIE, verifyAccessToken } from './tokens.js';

/** Verifies the access JWT AND that the server-side session is still live (zero trust). */
export async function authenticate(req: Request, _res: Response, next: NextFunction): Promise<void> {
  const token: unknown = req.cookies?.[COOKIE.access];
  if (typeof token !== 'string' || token.length === 0) throw unauthorized();
  let claims;
  try {
    claims = await verifyAccessToken(token);
  } catch {
    throw unauthorized('Invalid or expired token');
  }
  if (!(await isSessionValid(claims.sid))) throw unauthorized('Session no longer valid');
  req.auth = {
    userId: claims.sub,
    sessionId: claims.sid,
    name: claims.name,
    roles: claims.roles as Role[],
    exp: claims.exp,
  };
  next();
}

/** Route guard: caller must hold ALL listed permissions. Denials are audited. */
export function requirePermission(...permissions: Permission[]): RequestHandler {
  return async (req, _res, next) => {
    const roles = req.auth?.roles ?? [];
    const missing = permissions.filter((p) => !can(roles, p));
    if (missing.length > 0) {
      await audit(
        {
          ...auditContext(req),
          action: 'access.denied',
          outcome: 'DENIED',
          targetType: 'endpoint',
          targetId: `${req.method} ${req.baseUrl}${req.route?.path ?? ''}`,
          details: { missing },
        },
        { bestEffort: true },
      );
      throw forbidden();
    }
    next();
  };
}
