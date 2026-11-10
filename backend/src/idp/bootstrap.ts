/**
 * One-shot identity-provider bootstrap (compose service `idp-init`, runs on every deploy):
 *
 *  1. Ensures the least-privilege `ciso-provisioner` service account exists and its
 *     secret matches the Docker secret (rotation = change the file and redeploy).
 *  2. Points the dashboard OIDC client at the current PUBLIC_BASE_URL (redirect URI,
 *     web origin, post-logout URI) — required when the public address changes, e.g.
 *     moving from https://localhost to a server IP or DNS name.
 *  3. Applies the administrator-defined identity policy (MFA/TOTP, password, lockout,
 *     SSO session) stored in the database.
 *  4. Demo profile only: creates the demo administrator account if it does not exist.
 *
 * Only this job ever holds the Keycloak bootstrap administrator password.
 */
import { env } from '../config/env.js';
import { logger } from '../lib/logger.js';
import { prisma } from '../lib/prisma.js';
import { audit } from '../audit/audit.service.js';
import { ensureDefaultSettings, getSetting } from '../modules/settings/settings.service.js';
import { applyIdentityPolicy, KeycloakAdmin, passwordGrantToken } from './keycloakAdmin.js';
import { ADMIN_IDP_ROLE } from './identity.service.js';

const PROVISIONER_ROLES = ['view-users', 'manage-users', 'query-users', 'view-realm', 'manage-realm'];

async function ensureProvisioner(kc: KeycloakAdmin, secret: string): Promise<'created' | 'updated'> {
  const rep = {
    clientId: env.IDP_PROVISIONER_CLIENT_ID,
    name: 'CISO Dashboard provisioning (service account)',
    description: 'Least-privilege service account used by the dashboard API for MFA policy sync and user enrolment.',
    enabled: true,
    protocol: 'openid-connect',
    publicClient: false,
    clientAuthenticatorType: 'client-secret',
    secret,
    serviceAccountsEnabled: true,
    standardFlowEnabled: false,
    implicitFlowEnabled: false,
    directAccessGrantsEnabled: false,
    frontchannelLogout: false,
    attributes: { 'access.token.lifespan': '300' },
  };
  let client = await kc.findClient(env.IDP_PROVISIONER_CLIENT_ID);
  let outcome: 'created' | 'updated' = 'updated';
  if (!client) {
    await kc.createClient(rep);
    client = await kc.findClient(env.IDP_PROVISIONER_CLIENT_ID);
    outcome = 'created';
  } else {
    await kc.updateClient(client.id, { ...client, ...rep });
  }
  if (!client) throw new Error('provisioner client could not be created');
  const realmMgmt = await kc.findClient('realm-management');
  if (!realmMgmt) throw new Error('realm-management client missing');
  const sa = await kc.serviceAccountUser(client.id);
  const roles = await Promise.all(PROVISIONER_ROLES.map((r) => kc.clientRole(realmMgmt.id, r)));
  await kc.addClientRolesToUser(sa.id, realmMgmt.id, roles);
  return outcome;
}

async function syncDashboardClient(kc: KeycloakAdmin): Promise<string> {
  const client = await kc.findClient(env.OIDC_CLIENT_ID);
  if (!client) throw new Error(`OIDC client "${env.OIDC_CLIENT_ID}" not found in realm`);
  const base = env.PUBLIC_BASE_URL;
  // Never echo the client secret back (it may be masked in the representation).
  const { secret: _secret, ...rest } = client;
  const attributes = { ...((rest.attributes as Record<string, string>) ?? {}), 'post.logout.redirect.uris': `${base}/` };
  await kc.updateClient(client.id, { ...rest, redirectUris: [`${base}/api/auth/callback`], webOrigins: [base], attributes });
  return `${base}/api/auth/callback`;
}

async function ensureDemoAdmin(kc: KeycloakAdmin, mfaRequired: boolean): Promise<'created' | 'exists' | 'skipped'> {
  const username = env.DEMO_ADMIN_USERNAME;
  const password = env.DEMO_ADMIN_PASSWORD;
  if (!env.DEMO_MODE || !username || !password) return 'skipped';
  if (await kc.findUserByUsername(username)) return 'exists';
  const id = await kc.createUser({
    username,
    email: `${username}@demo.example`,
    firstName: 'Demo',
    lastName: 'Administrator',
    enabled: true,
    emailVerified: true,
    requiredActions: mfaRequired ? ['CONFIGURE_TOTP'] : [],
    credentials: [{ type: 'password', value: password, temporary: false }],
  });
  await kc.addUserRealmRoles(id, [await kc.getRealmRole(ADMIN_IDP_ROLE)]);
  if (!/^https:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/.test(env.PUBLIC_BASE_URL)) {
    logger.warn({ username }, 'DEMO administrator with a published password is enabled on a non-local address — disable it before production use');
  }
  return 'created';
}

async function main(): Promise<void> {
  if (!env.IDP_ADMIN_URL) {
    logger.info('IDP_ADMIN_URL not set — external identity provider, nothing to bootstrap');
    return;
  }
  if (!env.IDP_BOOTSTRAP_ADMIN_PASSWORD || !env.IDP_PROVISIONER_CLIENT_SECRET) {
    throw new Error('idp-init requires IDP_BOOTSTRAP_ADMIN_PASSWORD and IDP_PROVISIONER_CLIENT_SECRET');
  }
  const base = env.IDP_ADMIN_URL.replace(/\/+$/, '');
  const kc = new KeycloakAdmin(base, env.IDP_REALM, passwordGrantToken(base, env.IDP_BOOTSTRAP_ADMIN_USERNAME ?? 'kcadmin', env.IDP_BOOTSTRAP_ADMIN_PASSWORD));

  await ensureDefaultSettings();
  const provisioner = await ensureProvisioner(kc, env.IDP_PROVISIONER_CLIENT_SECRET);
  const redirectUri = await syncDashboardClient(kc);
  const [policy, session] = await Promise.all([getSetting('identity'), getSetting('sessionPolicy')]);
  await applyIdentityPolicy(kc, policy, session);
  const demoAdmin = await ensureDemoAdmin(kc, policy.mfaRequired);

  logger.info({ provisioner, redirectUri, demoAdmin, otpAlgorithm: policy.otpAlgorithm }, 'identity provider bootstrap complete');
  await audit({
    action: 'idp.bootstrap',
    outcome: 'SUCCESS',
    targetType: 'identity-provider',
    targetId: env.IDP_REALM,
    details: { provisioner, redirectUri, demoAdmin, otpAlgorithm: policy.otpAlgorithm, mfaRequired: policy.mfaRequired },
  });
}

main()
  .catch((err: unknown) => {
    logger.fatal({ error: err instanceof Error ? err.message : String(err) }, 'identity provider bootstrap failed');
    process.exitCode = 1;
  })
  .finally(() => prisma.$disconnect());
