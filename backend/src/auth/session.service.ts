/**
 * Server-side sessions with rotating, single-use refresh tokens.
 *
 *  - Refresh tokens are 256-bit random values; only their SHA-256 hash is stored.
 *  - Every refresh rotates the token (new session row, same family).
 *  - Re-use of an already-rotated token revokes the entire family (token theft detection).
 *  - Idle timeout (REFRESH_IDLE_TTL_SEC) and absolute timeout (SESSION_ABSOLUTE_TTL_SEC).
 *  - Continuous verification: on refresh the IdP refresh token is exchanged, so a user
 *    disabled or de-provisioned at the IdP loses access at the next rotation.
 */
import { randomUUID } from 'node:crypto';
import type { Role, User } from '@prisma/client';
import type { Response } from 'express';
import { env } from '../config/env.js';
import { decryptOptional, encryptOptional, randomToken, sha256Hex } from '../lib/crypto.js';
import { unauthorized } from '../lib/errors.js';
import { logger } from '../lib/logger.js';
import { prisma } from '../lib/prisma.js';
import { audit } from '../audit/audit.service.js';
import { getOidcClient, mapRoles, resolveClaims } from './oidc.js';
import { COOKIE, signAccessToken } from './tokens.js';

export interface IssuedSession {
  sessionId: string;
  refreshToken: string;
  user: User;
}

interface CreateOpts {
  idpRefreshToken?: string | null;
  idToken?: string | null;
  ip?: string | null;
  userAgent?: string | null;
  familyId?: string;
  absoluteExpiresAt?: Date;
}

export async function createSession(user: User, opts: CreateOpts): Promise<IssuedSession> {
  const id = randomUUID();
  const refreshToken = randomToken(32);
  const now = Date.now();
  await prisma.session.create({
    data: {
      id,
      userId: user.id,
      familyId: opts.familyId ?? randomUUID(),
      refreshHash: sha256Hex(refreshToken),
      idpRefreshEnc: encryptOptional(opts.idpRefreshToken, `session:${id}:idp_rt`),
      idTokenEnc: encryptOptional(opts.idToken, `session:${id}:id_token`),
      ip: opts.ip ?? null,
      userAgent: opts.userAgent?.slice(0, 256) ?? null,
      expiresAt: new Date(now + env.REFRESH_IDLE_TTL_SEC * 1000),
      absoluteExpiresAt: opts.absoluteExpiresAt ?? new Date(now + env.SESSION_ABSOLUTE_TTL_SEC * 1000),
    },
  });
  return { sessionId: id, refreshToken, user };
}

export async function rotateSession(refreshToken: string, ctx: { ip?: string | null; userAgent?: string | null }): Promise<IssuedSession> {
  const session = await prisma.session.findUnique({
    where: { refreshHash: sha256Hex(refreshToken) },
    include: { user: true },
  });
  if (!session) throw unauthorized('Invalid session');

  if (session.revokedAt) {
    if (session.revokeReason === 'ROTATED') {
      // A rotated token was presented again → probable theft. Kill the whole family.
      await prisma.session.updateMany({
        where: { familyId: session.familyId, revokedAt: null },
        data: { revokedAt: new Date(), revokeReason: 'REFRESH_REUSE_DETECTED' },
      });
      await audit(
        {
          action: 'auth.refresh_token_reuse',
          outcome: 'DENIED',
          actor: { id: session.userId, name: session.user.displayName, roles: session.user.roles },
          targetType: 'session_family',
          targetId: session.familyId,
          ip: ctx.ip,
          userAgent: ctx.userAgent,
        },
        { bestEffort: true },
      );
    }
    throw unauthorized('Session revoked');
  }

  const now = new Date();
  if (session.expiresAt < now || session.absoluteExpiresAt < now || !session.user.active) {
    await revokeSession(session.id, 'EXPIRED');
    throw unauthorized('Session expired');
  }

  // Continuous verification against the IdP.
  let roles: Role[] = session.user.roles;
  let idpRefresh = decryptOptional(session.idpRefreshEnc, `session:${session.id}:idp_rt`);
  let idToken = decryptOptional(session.idTokenEnc, `session:${session.id}:id_token`);
  if (idpRefresh) {
    try {
      const client = await getOidcClient();
      const ts = await client.refresh(idpRefresh);
      const claims = await resolveClaims(client, ts);
      roles = mapRoles(claims);
      if (roles.length === 0) throw new Error('No mapped roles after refresh');
      idpRefresh = ts.refresh_token ?? idpRefresh;
      idToken = ts.id_token ?? idToken;
    } catch (err) {
      logger.warn({ err: (err as Error).message, userId: session.userId }, 'IdP re-verification failed');
      await revokeSession(session.id, 'IDP_REVERIFY_FAILED');
      throw unauthorized('Identity provider re-verification failed');
    }
  }

  const user = await prisma.user.update({ where: { id: session.userId }, data: { roles } });
  await prisma.session.update({ where: { id: session.id }, data: { revokedAt: now, revokeReason: 'ROTATED' } });
  return createSession(user, {
    idpRefreshToken: idpRefresh,
    idToken,
    ip: ctx.ip,
    userAgent: ctx.userAgent,
    familyId: session.familyId,
    absoluteExpiresAt: session.absoluteExpiresAt,
  });
}

export async function revokeSession(sessionId: string, reason: string): Promise<void> {
  await prisma.session.updateMany({ where: { id: sessionId, revokedAt: null }, data: { revokedAt: new Date(), revokeReason: reason } });
  sessionCache.delete(sessionId);
}

export async function revokeUserSessions(userId: string, reason: string): Promise<number> {
  const res = await prisma.session.updateMany({ where: { userId, revokedAt: null }, data: { revokedAt: new Date(), revokeReason: reason } });
  sessionCache.clear();
  return res.count;
}

export async function getIdTokenForLogout(sessionId: string): Promise<string | null> {
  const s = await prisma.session.findUnique({ where: { id: sessionId }, select: { idTokenEnc: true } });
  return decryptOptional(s?.idTokenEnc, `session:${sessionId}:id_token`);
}

/* ---------- Per-request session validation (zero trust) with a short cache ---------- */

const SESSION_CACHE_TTL_MS = 15_000;
const sessionCache = new Map<string, { ok: boolean; until: number }>();

export async function isSessionValid(sessionId: string): Promise<boolean> {
  const cached = sessionCache.get(sessionId);
  if (cached && cached.until > Date.now()) return cached.ok;
  const s = await prisma.session.findUnique({
    where: { id: sessionId },
    select: { revokedAt: true, absoluteExpiresAt: true, user: { select: { active: true } } },
  });
  const ok = !!s && !s.revokedAt && s.absoluteExpiresAt > new Date() && s.user.active;
  if (sessionCache.size > 10_000) sessionCache.clear();
  sessionCache.set(sessionId, { ok, until: Date.now() + SESSION_CACHE_TTL_MS });
  return ok;
}

/* ---------------------------------- Cookies ---------------------------------- */

const baseCookie = () => ({ httpOnly: true, secure: env.COOKIE_SECURE, sameSite: 'strict' as const, path: '/' });

export async function issueAuthCookies(res: Response, s: IssuedSession): Promise<void> {
  const access = await signAccessToken({
    userId: s.user.id,
    sessionId: s.sessionId,
    name: s.user.displayName,
    roles: s.user.roles,
  });
  res.cookie(COOKIE.access, access, { ...baseCookie(), maxAge: env.ACCESS_TOKEN_TTL_SEC * 1000 });
  res.cookie(COOKIE.refresh, s.refreshToken, { ...baseCookie(), maxAge: env.REFRESH_IDLE_TTL_SEC * 1000 });
  // Double-submit CSRF token: readable by the SPA, echoed back in X-CSRF-Token.
  res.cookie(COOKIE.csrf, randomToken(24), { ...baseCookie(), httpOnly: false, maxAge: env.SESSION_ABSOLUTE_TTL_SEC * 1000 });
}

export function clearAuthCookies(res: Response): void {
  for (const name of [COOKIE.access, COOKIE.refresh, COOKIE.csrf]) {
    res.clearCookie(name, { ...baseCookie(), httpOnly: name !== COOKIE.csrf });
  }
}
