/**
 * Short-lived access JWTs (HS512, default 10 min) and encrypted OIDC state (JWE dir/A256GCM).
 * Tokens are only ever transported in __Host- prefixed, httpOnly, Secure, SameSite=Strict cookies.
 */
import { randomUUID } from 'node:crypto';
import { EncryptJWT, SignJWT, jwtDecrypt, jwtVerify } from 'jose';
import { z } from 'zod';
import { env } from '../config/env.js';
import { ROLES } from './rbac.js';

const ISSUER = 'ciso-dashboard-api';
const AUDIENCE = 'ciso-dashboard';
const accessKey = new TextEncoder().encode(env.JWT_SECRET);
const stateKey = new Uint8Array(Buffer.from(env.STATE_ENCRYPTION_KEY, 'base64'));

export const COOKIE = {
  access: '__Host-ciso_at',
  refresh: '__Host-ciso_rt',
  csrf: '__Host-ciso_csrf',
  oidc: '__Host-ciso_oidc',
} as const;

const AccessClaims = z.object({
  sub: z.string().uuid(),
  sid: z.string().uuid(),
  name: z.string(),
  roles: z.array(z.enum(ROLES as [string, ...string[]])).min(1),
  exp: z.number(),
});
export type AccessClaims = z.infer<typeof AccessClaims>;

export async function signAccessToken(claims: { userId: string; sessionId: string; name: string; roles: string[] }): Promise<string> {
  return new SignJWT({ sid: claims.sessionId, name: claims.name, roles: claims.roles })
    .setProtectedHeader({ alg: 'HS512', typ: 'JWT' })
    .setSubject(claims.userId)
    .setIssuer(ISSUER)
    .setAudience(AUDIENCE)
    .setIssuedAt()
    .setJti(randomUUID())
    .setExpirationTime(`${env.ACCESS_TOKEN_TTL_SEC}s`)
    .sign(accessKey);
}

export async function verifyAccessToken(token: string): Promise<AccessClaims> {
  const { payload } = await jwtVerify(token, accessKey, {
    issuer: ISSUER,
    audience: AUDIENCE,
    algorithms: ['HS512'],
    clockTolerance: 5,
  });
  return AccessClaims.parse(payload);
}

export interface OidcState {
  state: string;
  nonce: string;
  codeVerifier: string;
  returnTo: string;
}

export async function sealOidcState(value: OidcState): Promise<string> {
  return new EncryptJWT({ ...value })
    .setProtectedHeader({ alg: 'dir', enc: 'A256GCM' })
    .setIssuedAt()
    .setExpirationTime('10m')
    .encrypt(stateKey);
}

export async function openOidcState(token: string): Promise<OidcState> {
  const { payload } = await jwtDecrypt(token, stateKey, { clockTolerance: 5 });
  return z
    .object({ state: z.string(), nonce: z.string(), codeVerifier: z.string(), returnTo: z.string() })
    .parse(payload);
}
