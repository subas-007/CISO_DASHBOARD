/**
 * OpenID Connect relying party (Authorization Code + PKCE S256, state, nonce).
 * Works with any compliant IdP (Keycloak, Entra ID, Okta, Ping). Roles are taken from
 * a configurable claim and mapped onto application roles; unmapped users are denied.
 */
import type { Role } from '@prisma/client';
import { Issuer, custom, type BaseClient, type TokenSet } from 'openid-client';
import { env } from '../config/env.js';
import { logger } from '../lib/logger.js';
import { isRole } from './rbac.js';

export const redirectUri = `${env.PUBLIC_BASE_URL}/api/auth/callback`;

custom.setHttpOptionsDefaults({ timeout: 10_000 });

let clientPromise: Promise<BaseClient> | null = null;

export function getOidcClient(): Promise<BaseClient> {
  if (!clientPromise) {
    clientPromise = (async () => {
      const issuer = await Issuer.discover(env.OIDC_DISCOVERY_URL ?? env.OIDC_ISSUER_URL);
      if (issuer.metadata.issuer !== env.OIDC_ISSUER_URL) {
        throw new Error(`OIDC issuer mismatch: expected ${env.OIDC_ISSUER_URL}, got ${String(issuer.metadata.issuer)}`);
      }
      const client = new issuer.Client({
        client_id: env.OIDC_CLIENT_ID,
        client_secret: env.OIDC_CLIENT_SECRET,
        redirect_uris: [redirectUri],
        post_logout_redirect_uris: [`${env.PUBLIC_BASE_URL}/`],
        response_types: ['code'],
        token_endpoint_auth_method: 'client_secret_basic',
      });
      client[custom.clock_tolerance] = 5;
      logger.info({ issuer: issuer.metadata.issuer }, 'OIDC issuer discovered');
      return client;
    })().catch((err: unknown) => {
      clientPromise = null; // allow retry on next request
      throw err;
    });
  }
  return clientPromise;
}

const roleMapping: Map<string, Role> = new Map(
  env.OIDC_ROLE_MAPPING.split(',')
    .map((pair) => pair.split(':').map((s) => s.trim()))
    .filter((p): p is [string, string] => p.length === 2 && !!p[0] && isRole(p[1] ?? ''))
    .map(([idpRole, appRole]) => [idpRole.toLowerCase(), appRole as Role]),
);

function readClaimPath(claims: Record<string, unknown>, path: string): unknown {
  return path.split('.').reduce<unknown>((acc, key) => {
    if (acc && typeof acc === 'object') return (acc as Record<string, unknown>)[key];
    return undefined;
  }, claims);
}

export function mapRoles(claims: Record<string, unknown>): Role[] {
  const raw = readClaimPath(claims, env.OIDC_ROLE_CLAIM);
  const values = Array.isArray(raw) ? raw : typeof raw === 'string' ? raw.split(/[ ,]+/) : [];
  const roles = new Set<Role>();
  for (const v of values) {
    if (typeof v !== 'string') continue;
    const mapped = roleMapping.get(v.toLowerCase());
    if (mapped) roles.add(mapped);
  }
  return [...roles];
}

/** Resolve identity claims from a token set, falling back to the userinfo endpoint. */
export async function resolveClaims(client: BaseClient, tokenSet: TokenSet): Promise<Record<string, unknown>> {
  let claims: Record<string, unknown> = tokenSet.id_token ? { ...tokenSet.claims() } : {};
  if (mapRoles(claims).length === 0 && tokenSet.access_token) {
    const info = await client.userinfo(tokenSet.access_token);
    claims = { ...claims, ...info };
  }
  return claims;
}
