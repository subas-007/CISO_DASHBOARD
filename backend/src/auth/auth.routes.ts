import { Router, type Request } from 'express';
import { generators } from 'openid-client';
import { env } from '../config/env.js';
import { audit } from '../audit/audit.service.js';
import { blindIndex, encryptOptional } from '../lib/crypto.js';
import { unauthorized } from '../lib/errors.js';
import { logger } from '../lib/logger.js';
import { prisma } from '../lib/prisma.js';
import { authRateLimit } from '../security/rateLimit.js';
import { authenticate } from './middleware.js';
import { getOidcClient, mapRoles, redirectUri, resolveClaims } from './oidc.js';
import { permissionsFor } from './rbac.js';
import {
  clearAuthCookies,
  createSession,
  getIdTokenForLogout,
  issueAuthCookies,
  revokeSession,
  rotateSession,
} from './session.service.js';
import { COOKIE, openOidcState, sealOidcState } from './tokens.js';

export const authRouter = Router();
// Throttle only the credential-bearing endpoints; /me and /logout are cheap and
// called on every page load (many users can share one NAT IP).
authRouter.use(['/login', '/callback', '/refresh'], authRateLimit);

const origin = (req: Request) => ({ ip: req.ip ?? null, userAgent: req.get('user-agent') ?? null });

/** Only allow same-origin relative return paths (prevents open redirects). */
function safeReturnTo(value: unknown): string {
  if (typeof value !== 'string') return '/';
  if (!/^\/[A-Za-z0-9/_\-?=&.]*$/.test(value) || value.startsWith('//')) return '/';
  return value.slice(0, 200);
}

const oidcCookie = { httpOnly: true, secure: env.COOKIE_SECURE, sameSite: 'lax' as const, path: '/', maxAge: 10 * 60 * 1000 };

authRouter.get('/login', async (req, res) => {
  const client = await getOidcClient();
  const state = generators.state();
  const nonce = generators.nonce();
  const codeVerifier = generators.codeVerifier();
  res.cookie(COOKIE.oidc, await sealOidcState({ state, nonce, codeVerifier, returnTo: safeReturnTo(req.query.returnTo) }), oidcCookie);
  res.redirect(
    303,
    client.authorizationUrl({
      scope: env.OIDC_SCOPES,
      state,
      nonce,
      code_challenge: generators.codeChallenge(codeVerifier),
      code_challenge_method: 'S256',
    }),
  );
});

authRouter.get('/callback', async (req, res) => {
  const sealed: unknown = req.cookies?.[COOKIE.oidc];
  res.clearCookie(COOKIE.oidc, { ...oidcCookie, maxAge: undefined });
  const fail = async (reason: string, details: Record<string, unknown> = {}) => {
    await audit({ action: 'auth.login', outcome: 'FAILURE', ...origin(req), details: { reason, ...details } }, { bestEffort: true });
    res.redirect(303, `/login?error=${encodeURIComponent(reason)}`);
  };

  if (typeof sealed !== 'string') return fail('missing_state');
  let st;
  try {
    st = await openOidcState(sealed);
  } catch {
    return fail('invalid_state');
  }

  try {
    const client = await getOidcClient();
    const params = client.callbackParams(req);
    if (params.error) return fail('idp_error', { idpError: String(params.error).slice(0, 64) });
    const tokenSet = await client.callback(redirectUri, params, {
      state: st.state,
      nonce: st.nonce,
      code_verifier: st.codeVerifier,
      response_type: 'code',
    });
    const claims = await resolveClaims(client, tokenSet);
    const subject = String(claims.sub ?? '');
    if (!subject) return fail('missing_subject');
    const roles = mapRoles(claims);
    if (roles.length === 0) return fail('no_authorized_role', { subject });

    const email = typeof claims.email === 'string' ? claims.email : null;
    const displayName = String(claims.name ?? claims.preferred_username ?? 'Unknown user').slice(0, 120);
    const existing = await prisma.user.findUnique({ where: { subject } });
    if (existing && !existing.active) return fail('account_disabled', { subject });

    const userId = existing?.id;
    const user = await prisma.user.upsert({
      where: { subject },
      create: {
        subject,
        displayName,
        roles,
        emailIndex: email ? blindIndex(email, 'user.email') : null,
        emailEnc: email ? encryptOptional(email, `user:${subject}:email`) : null,
        lastLoginAt: new Date(),
      },
      update: {
        displayName,
        roles,
        emailIndex: email ? blindIndex(email, 'user.email') : null,
        emailEnc: email ? encryptOptional(email, `user:${subject}:email`) : null,
        lastLoginAt: new Date(),
      },
    });

    const session = await createSession(user, {
      idpRefreshToken: tokenSet.refresh_token ?? null,
      idToken: tokenSet.id_token ?? null,
      ...origin(req),
    });
    await issueAuthCookies(res, session);
    await audit({
      action: userId ? 'auth.login' : 'auth.login.first',
      outcome: 'SUCCESS',
      actor: { id: user.id, name: user.displayName, roles: user.roles },
      targetType: 'session',
      targetId: session.sessionId,
      ...origin(req),
      details: { amr: claims.amr ?? null, acr: claims.acr ?? null },
    });
    return res.redirect(303, st.returnTo);
  } catch (err) {
    logger.warn({ err: (err as Error).message }, 'OIDC callback failed');
    return fail('callback_failed');
  }
});

authRouter.post('/refresh', async (req, res) => {
  const token: unknown = req.cookies?.[COOKIE.refresh];
  if (typeof token !== 'string' || token.length < 20) throw unauthorized();
  try {
    const session = await rotateSession(token, origin(req));
    await issueAuthCookies(res, session);
    res.json({ ok: true });
  } catch (err) {
    clearAuthCookies(res);
    throw err;
  }
});

authRouter.post('/logout', authenticate, async (req, res) => {
  const auth = req.auth!;
  const idToken = await getIdTokenForLogout(auth.sessionId);
  await revokeSession(auth.sessionId, 'LOGOUT');
  clearAuthCookies(res);
  await audit({
    action: 'auth.logout',
    outcome: 'SUCCESS',
    actor: { id: auth.userId, name: auth.name, roles: auth.roles },
    targetType: 'session',
    targetId: auth.sessionId,
    ...origin(req),
  });
  let logoutUrl = '/login';
  try {
    const client = await getOidcClient();
    logoutUrl = client.endSessionUrl({
      id_token_hint: idToken ?? undefined,
      post_logout_redirect_uri: `${env.PUBLIC_BASE_URL}/`,
    });
  } catch {
    /* IdP unreachable — local session is already revoked */
  }
  res.json({ logoutUrl });
});

authRouter.get('/me', authenticate, async (req, res) => {
  const auth = req.auth!;
  const user = await prisma.user.findUniqueOrThrow({
    where: { id: auth.userId },
    select: { id: true, displayName: true, roles: true, lastLoginAt: true },
  });
  res.json({
    user: {
      id: user.id,
      name: user.displayName,
      roles: user.roles,
      permissions: permissionsFor(user.roles),
      lastLoginAt: user.lastLoginAt,
    },
    session: { expiresAt: new Date(auth.exp * 1000).toISOString() },
  });
});
