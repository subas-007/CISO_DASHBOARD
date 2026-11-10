/**
 * Identity & enrolment administration (Keycloak via the provisioner service account).
 *
 * Safeguards:
 *  - administrators cannot change, disable or delete their own identity
 *  - the last enabled administrator cannot be demoted, disabled or deleted
 *  - one-time passwords are generated server-side (CSPRNG), shown once, never stored
 *    or logged, and must be changed at first sign-in; MFA enrolment follows policy
 *  - every action is audited (without secrets) and revokes the user's live sessions
 *    where access is reduced
 */
import { Router, type Request } from 'express';
import { z } from 'zod';
import type { Role } from '@prisma/client';
import { requirePermission } from '../../auth/middleware.js';
import { ROLES } from '../../auth/rbac.js';
import { revokeUserSessions } from '../../auth/session.service.js';
import { audit, auditContext } from '../../audit/audit.service.js';
import { badRequest, HttpError } from '../../lib/errors.js';
import { prisma } from '../../lib/prisma.js';
import { heavyRateLimit } from '../../security/rateLimit.js';
import { getSetting } from '../settings/settings.service.js';
import { IdpError } from '../../idp/keycloakAdmin.js';
import {
  describeUser,
  enabledAdminCount,
  enforceMfaForExistingUsers,
  generateTemporaryPassword,
  idpAdmin,
  idpConfigured,
  idpRoleFor,
  idpSyncState,
  syncIdentityPolicy,
} from '../../idp/identity.service.js';

export const identityRouter = Router();

const KcId = z.object({ id: z.string().uuid() }).strict();
const RoleList = z.array(z.enum(ROLES as [Role, ...Role[]])).min(1).max(ROLES.length);
const name = (max: number) => z.string().trim().min(1).max(max).regex(/^[\p{L}\p{M} .'()-]+$/u, 'letters, spaces and . \' ( ) - only');

/** Maps Keycloak failures onto safe HTTP errors. */
async function idp<T>(fn: () => Promise<T>): Promise<T> {
  try {
    return await fn();
  } catch (err) {
    if (err instanceof IdpError) {
      if (err.status === 404) throw new HttpError(404, 'NOT_FOUND', 'User not found in the identity provider');
      if (err.status === 409) throw new HttpError(409, 'CONFLICT', 'A user with this username or email already exists');
      if (err.status === 400) throw badRequest(err.message, 'IDP_REJECTED');
      if (err.status === 503) throw new HttpError(503, 'IDP_NOT_CONFIGURED', err.message);
      throw new HttpError(502, 'IDP_UNAVAILABLE', 'The identity provider rejected or failed the request');
    }
    throw err;
  }
}

async function assertNotSelf(req: Request, kcUserId: string): Promise<void> {
  const me = await prisma.user.findUnique({ where: { id: req.auth!.userId }, select: { subject: true } });
  if (me?.subject === kcUserId) throw badRequest('You cannot change your own identity, roles or MFA from here', 'SELF_MODIFICATION');
}

async function assertAdminRemains(kcUserId: string): Promise<void> {
  if ((await idp(() => enabledAdminCount(idpAdmin(), kcUserId))) < 1) {
    throw badRequest('At least one enabled administrator must remain', 'LAST_ADMIN');
  }
}

/** Revokes dashboard sessions of the dashboard user bound to this IdP identity. */
async function revokeDashboardSessions(kcUserId: string, reason: string): Promise<number> {
  const user = await prisma.user.findUnique({ where: { subject: kcUserId }, select: { id: true } });
  return user ? revokeUserSessions(user.id, reason) : 0;
}

identityRouter.get('/status', requirePermission('config:read'), async (_req, res) => {
  const policy = await getSetting('identity');
  res.json({ configured: idpConfigured(), sync: idpSyncState, policy });
});

identityRouter.post('/sync', heavyRateLimit, requirePermission('system:manage'), async (req, res) => {
  const result = await syncIdentityPolicy();
  await audit({ ...auditContext(req), action: 'identity.policy.sync', outcome: result.ok ? 'SUCCESS' : 'FAILURE', targetType: 'identity-provider', details: { message: result.message } });
  res.status(result.ok ? 200 : 502).json(result);
});

identityRouter.post('/enforce-mfa', heavyRateLimit, requirePermission('system:manage'), async (req, res) => {
  const result = await idp(() => enforceMfaForExistingUsers());
  await audit({ ...auditContext(req), action: 'identity.mfa.enforce', outcome: 'SUCCESS', targetType: 'identity-provider', details: result });
  res.json(result);
});

identityRouter.get('/users', requirePermission('users:read'), async (req, res) => {
  const q = z
    .object({ search: z.string().trim().max(100).optional(), first: z.coerce.number().int().min(0).max(10_000).default(0) })
    .strict()
    .parse(req.query);
  const kc = idpAdmin();
  const page = await idp(() => kc.listUsers({ search: q.search, first: q.first, max: 50 }));
  const users = await idp(() => Promise.all(page.filter((u) => !u.username.startsWith('service-account-')).map((u) => describeUser(kc, u))));
  const local = await prisma.user.findMany({ where: { subject: { in: users.map((u) => u.id) } }, select: { subject: true, lastLoginAt: true, active: true } });
  const bySubject = new Map(local.map((l) => [l.subject, l]));
  res.json({
    items: users.map((u) => ({ ...u, lastLoginAt: bySubject.get(u.id)?.lastLoginAt ?? null, dashboardActive: bySubject.get(u.id)?.active ?? null })),
    first: q.first,
    hasMore: page.length === 50,
  });
});

const Enrol = z
  .object({
    username: z.string().trim().toLowerCase().regex(/^[a-z0-9][a-z0-9._-]{2,63}$/, '3-64 characters: a-z, 0-9, . _ -'),
    email: z.string().trim().toLowerCase().email().max(254),
    firstName: name(64),
    lastName: name(64),
    roles: RoleList,
  })
  .strict();

identityRouter.post('/users', heavyRateLimit, requirePermission('users:manage'), async (req, res) => {
  const body = Enrol.parse(req.body);
  const policy = await getSetting('identity');
  const kc = idpAdmin();
  const temporaryPassword = generateTemporaryPassword(policy.passwordMinLength);
  const id = await idp(() =>
    kc.createUser({
      username: body.username,
      email: body.email,
      firstName: body.firstName,
      lastName: body.lastName,
      enabled: true,
      emailVerified: true,
      requiredActions: ['UPDATE_PASSWORD', ...(policy.mfaRequired ? ['CONFIGURE_TOTP'] : [])],
      credentials: [{ type: 'password', value: temporaryPassword, temporary: true }],
    }),
  );
  try {
    const roles = await idp(() => Promise.all(body.roles.map((r) => kc.getRealmRole(idpRoleFor(r)!))));
    await idp(() => kc.addUserRealmRoles(id, roles));
  } catch (err) {
    await kc.deleteUser(id).catch(() => undefined); // no half-enrolled identities
    throw err;
  }
  await audit({
    ...auditContext(req),
    action: 'identity.user.enrol',
    outcome: 'SUCCESS',
    targetType: 'idp-user',
    targetId: id,
    details: { username: body.username, roles: body.roles, mfaRequired: policy.mfaRequired },
  });
  res.status(201).json({ id, username: body.username, temporaryPassword, requiredActions: ['UPDATE_PASSWORD', ...(policy.mfaRequired ? ['CONFIGURE_TOTP'] : [])] });
});

identityRouter.patch('/users/:id', requirePermission('users:manage'), async (req, res) => {
  const { id } = KcId.parse(req.params);
  const body = z.object({ enabled: z.boolean().optional(), roles: RoleList.optional() }).strict().refine((b) => b.enabled !== undefined || b.roles, 'nothing to change').parse(req.body);
  await assertNotSelf(req, id);
  const kc = idpAdmin();
  const before = await idp(async () => describeUser(kc, await kc.getUser(id)));
  const losesAdmin = before.roles.includes('ADMIN') && (body.enabled === false || (body.roles && !body.roles.includes('ADMIN')));
  if (losesAdmin) await assertAdminRemains(id);

  if (body.roles) {
    const desired = new Set(body.roles);
    const current = new Set(before.roles);
    const add = [...desired].filter((r) => !current.has(r));
    const remove = [...current].filter((r) => !desired.has(r));
    if (add.length) await idp(async () => kc.addUserRealmRoles(id, await Promise.all(add.map((r) => kc.getRealmRole(idpRoleFor(r)!)))));
    if (remove.length) await idp(async () => kc.removeUserRealmRoles(id, await Promise.all(remove.map((r) => kc.getRealmRole(idpRoleFor(r)!)))));
  }
  if (body.enabled !== undefined) await idp(() => kc.updateUser(id, { enabled: body.enabled }));

  const reduced = body.enabled === false || (body.roles && before.roles.some((r) => !body.roles!.includes(r)));
  let revoked = 0;
  if (reduced) {
    await kc.logoutUser(id).catch(() => undefined);
    revoked = await revokeDashboardSessions(id, body.enabled === false ? 'IDP_USER_DISABLED' : 'ROLES_CHANGED');
  }
  await audit({
    ...auditContext(req),
    action: body.roles ? 'identity.user.roles' : body.enabled ? 'identity.user.enable' : 'identity.user.disable',
    outcome: 'SUCCESS',
    targetType: 'idp-user',
    targetId: id,
    details: { username: before.username, before: { roles: before.roles, enabled: before.enabled }, after: { roles: body.roles ?? before.roles, enabled: body.enabled ?? before.enabled }, sessionsRevoked: revoked },
  });
  const after = await idp(async () => describeUser(kc, await kc.getUser(id)));
  res.json(after);
});

identityRouter.post('/users/:id/reset-password', heavyRateLimit, requirePermission('users:manage'), async (req, res) => {
  const { id } = KcId.parse(req.params);
  await assertNotSelf(req, id);
  const kc = idpAdmin();
  const user = await idp(() => kc.getUser(id));
  const temporaryPassword = generateTemporaryPassword((await getSetting('identity')).passwordMinLength);
  await idp(() => kc.resetPassword(id, temporaryPassword, true));
  await kc.logoutUser(id).catch(() => undefined);
  const revoked = await revokeDashboardSessions(id, 'PASSWORD_RESET');
  await audit({ ...auditContext(req), action: 'identity.user.password.reset', outcome: 'SUCCESS', targetType: 'idp-user', targetId: id, details: { username: user.username, sessionsRevoked: revoked } });
  res.json({ temporaryPassword });
});

identityRouter.post('/users/:id/reset-mfa', requirePermission('users:manage'), async (req, res) => {
  const { id } = KcId.parse(req.params);
  await assertNotSelf(req, id);
  const kc = idpAdmin();
  const user = await idp(() => kc.getUser(id));
  const creds = await idp(() => kc.credentials(id));
  const otp = creds.filter((c) => c.type === 'otp');
  for (const c of otp) await idp(() => kc.deleteCredential(id, c.id));
  const actions = new Set(user.requiredActions ?? []);
  actions.add('CONFIGURE_TOTP');
  await idp(() => kc.updateUser(id, { requiredActions: [...actions] }));
  await kc.logoutUser(id).catch(() => undefined);
  const revoked = await revokeDashboardSessions(id, 'MFA_RESET');
  await audit({ ...auditContext(req), action: 'identity.user.mfa.reset', outcome: 'SUCCESS', targetType: 'idp-user', targetId: id, details: { username: user.username, removedAuthenticators: otp.length, sessionsRevoked: revoked } });
  res.json({ removedAuthenticators: otp.length });
});

identityRouter.delete('/users/:id', requirePermission('users:manage'), async (req, res) => {
  const { id } = KcId.parse(req.params);
  await assertNotSelf(req, id);
  const kc = idpAdmin();
  const user = await idp(async () => describeUser(kc, await kc.getUser(id)));
  if (user.roles.includes('ADMIN')) await assertAdminRemains(id);
  await idp(() => kc.deleteUser(id));
  const revoked = await revokeDashboardSessions(id, 'IDP_USER_DELETED');
  await prisma.user.updateMany({ where: { subject: id }, data: { active: false } });
  await audit({ ...auditContext(req), action: 'identity.user.delete', outcome: 'SUCCESS', targetType: 'idp-user', targetId: id, details: { username: user.username, roles: user.roles, sessionsRevoked: revoked } });
  res.status(204).end();
});
