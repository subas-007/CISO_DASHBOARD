/**
 * Identity provider administration used by the API at runtime: policy synchronisation
 * (MFA, TOTP algorithm, password rules, lockout, SSO session lifetimes) and user
 * enrolment. Disabled when IDP_ADMIN_URL / provisioner secret are not configured
 * (e.g. when the IdP is Entra ID or Okta and enrolment is managed there).
 */
import { randomInt } from 'node:crypto';
import type { Role } from '@prisma/client';
import { env } from '../config/env.js';
import { logger } from '../lib/logger.js';
import { getSetting } from '../modules/settings/settings.service.js';
import { applyIdentityPolicy, clientCredentialsToken, IdpError, KeycloakAdmin, type KcUser } from './keycloakAdmin.js';

let client: KeycloakAdmin | null = null;

export function idpConfigured(): boolean {
  return !!(env.IDP_ADMIN_URL && env.IDP_PROVISIONER_CLIENT_SECRET);
}

export function idpAdmin(): KeycloakAdmin {
  if (!idpConfigured()) throw new IdpError('Identity provider administration is not configured (IDP_ADMIN_URL / provisioner secret)', 503);
  if (!client) {
    const base = env.IDP_ADMIN_URL!.replace(/\/+$/, '');
    client = new KeycloakAdmin(base, env.IDP_REALM, clientCredentialsToken(base, env.IDP_REALM, env.IDP_PROVISIONER_CLIENT_ID, env.IDP_PROVISIONER_CLIENT_SECRET!));
  }
  return client;
}

/* ------------------------------ Role mapping ------------------------------ */

const mapping: [string, Role][] = env.OIDC_ROLE_MAPPING.split(',')
  .map((pair) => pair.split(':').map((s) => s.trim()))
  .filter((p): p is [string, Role] => p.length === 2 && !!p[0] && !!p[1])
  .map(([idp, app]) => [idp, app as Role]);

export const idpRoleFor = (role: Role): string | undefined => mapping.find(([, app]) => app === role)?.[0];
export const appRoleFor = (idpRole: string): Role | undefined => mapping.find(([idp]) => idp.toLowerCase() === idpRole.toLowerCase())?.[1];
export const ADMIN_IDP_ROLE = idpRoleFor('ADMIN') ?? 'administrator';

/* ------------------------------ Policy sync ------------------------------ */

export const idpSyncState = {
  lastAttemptAt: null as Date | null,
  lastSuccessAt: null as Date | null,
  ok: null as boolean | null,
  message: 'not yet synchronised',
};

export async function syncIdentityPolicy(): Promise<{ ok: boolean; message: string }> {
  if (!idpConfigured()) return { ok: false, message: 'Identity provider administration not configured' };
  idpSyncState.lastAttemptAt = new Date();
  try {
    const [policy, session] = await Promise.all([getSetting('identity'), getSetting('sessionPolicy')]);
    await applyIdentityPolicy(idpAdmin(), policy, session);
    idpSyncState.ok = true;
    idpSyncState.lastSuccessAt = new Date();
    idpSyncState.message = `Synchronised: TOTP ${policy.otpAlgorithm}/${policy.otpDigits}/${policy.otpPeriodSec}s, MFA ${policy.mfaRequired ? 'required' : 'optional'}, password ≥ ${policy.passwordMinLength}`;
    return { ok: true, message: idpSyncState.message };
  } catch (err) {
    idpSyncState.ok = false;
    idpSyncState.message = err instanceof IdpError ? err.message : 'Identity provider unreachable';
    logger.warn({ error: idpSyncState.message }, 'identity policy sync failed');
    return { ok: false, message: idpSyncState.message };
  }
}

/** Adds the CONFIGURE_TOTP required action to every enabled user without an authenticator. */
export async function enforceMfaForExistingUsers(): Promise<{ checked: number; flagged: number }> {
  const kc = idpAdmin();
  let checked = 0;
  let flagged = 0;
  for (let first = 0; first < 5000; first += 100) {
    const page = await kc.listUsers({ first, max: 100 });
    for (const u of page) {
      if (!u.enabled || u.username.startsWith('service-account-')) continue;
      checked++;
      const creds = await kc.credentials(u.id);
      const actions = u.requiredActions ?? [];
      if (!creds.some((c) => c.type === 'otp') && !actions.includes('CONFIGURE_TOTP')) {
        await kc.updateUser(u.id, { requiredActions: [...actions, 'CONFIGURE_TOTP'] });
        flagged++;
      }
    }
    if (page.length < 100) break;
  }
  return { checked, flagged };
}

/* ------------------------------ Enrolment ------------------------------ */

const UPPER = 'ABCDEFGHJKLMNPQRSTUVWXYZ';
const LOWER = 'abcdefghijkmnopqrstuvwxyz';
const DIGIT = '23456789';
const SPECIAL = '!@#$%^&*-_=+?';

/** CSPRNG one-time password that satisfies any policy the catalogue allows. */
export function generateTemporaryPassword(minLength: number): string {
  const length = Math.max(minLength, 16);
  const all = UPPER + LOWER + DIGIT + SPECIAL;
  const chars = [UPPER, LOWER, DIGIT, SPECIAL].map((set) => set[randomInt(set.length)]!);
  while (chars.length < length) chars.push(all[randomInt(all.length)]!);
  for (let i = chars.length - 1; i > 0; i--) {
    const j = randomInt(i + 1);
    [chars[i], chars[j]] = [chars[j]!, chars[i]!];
  }
  return chars.join('');
}

export interface IdentityUser {
  id: string;
  username: string;
  email: string | null;
  firstName: string | null;
  lastName: string | null;
  enabled: boolean;
  createdAt: string | null;
  roles: Role[];
  mfaConfigured: boolean;
  requiredActions: string[];
}

export async function describeUser(kc: KeycloakAdmin, u: KcUser): Promise<IdentityUser> {
  const [roles, creds] = await Promise.all([kc.userRealmRoles(u.id), kc.credentials(u.id)]);
  return {
    id: u.id,
    username: u.username,
    email: u.email ?? null,
    firstName: u.firstName ?? null,
    lastName: u.lastName ?? null,
    enabled: u.enabled,
    createdAt: u.createdTimestamp ? new Date(u.createdTimestamp).toISOString() : null,
    roles: [...new Set(roles.map((r) => appRoleFor(r.name)).filter((r): r is Role => !!r))],
    mfaConfigured: creds.some((c) => c.type === 'otp'),
    requiredActions: u.requiredActions ?? [],
  };
}

/** Number of enabled users holding the administrator role (optionally excluding one). */
export async function enabledAdminCount(kc: KeycloakAdmin, excludingId?: string): Promise<number> {
  const users = await kc.roleUsers(ADMIN_IDP_ROLE);
  return users.filter((u) => u.enabled && u.id !== excludingId).length;
}
