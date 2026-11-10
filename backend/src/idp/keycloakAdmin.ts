/**
 * Minimal Keycloak Admin REST client (realm-scoped).
 *
 * The long-running API authenticates as the `ciso-provisioner` service account
 * (client-credentials grant, realm-management roles: view/manage-users, query-users,
 * view/manage-realm — no client management, no master-realm access). The one-shot
 * bootstrap job uses the bootstrap administrator only to create that service account.
 *
 * Error messages from Keycloak are surfaced only when they are short validation texts
 * (e.g. "Password policy not met"); bodies are never logged.
 */
export class IdpError extends Error {
  constructor(message: string, public readonly status?: number) {
    super(message);
    this.name = 'IdpError';
  }
}

export type TokenProvider = () => Promise<string>;

const TIMEOUT_MS = 10_000;

async function readError(res: Response): Promise<string> {
  try {
    const body = (await res.json()) as { errorMessage?: unknown; error_description?: unknown; error?: unknown };
    const msg = body.errorMessage ?? body.error_description ?? body.error;
    if (typeof msg === 'string' && msg.length < 200) return msg;
  } catch {
    /* ignore */
  }
  return `HTTP ${res.status}`;
}

export function clientCredentialsToken(base: string, realm: string, clientId: string, clientSecret: string): TokenProvider {
  let cached: { value: string; until: number } | null = null;
  return async () => {
    if (cached && cached.until > Date.now()) return cached.value;
    const res = await fetch(`${base}/realms/${encodeURIComponent(realm)}/protocol/openid-connect/token`, {
      method: 'POST',
      headers: {
        'content-type': 'application/x-www-form-urlencoded',
        authorization: `Basic ${Buffer.from(`${encodeURIComponent(clientId)}:${encodeURIComponent(clientSecret)}`).toString('base64')}`,
      },
      body: new URLSearchParams({ grant_type: 'client_credentials' }).toString(),
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });
    if (!res.ok) throw new IdpError(`Identity provider rejected the provisioning client (${await readError(res)})`, res.status);
    const body = (await res.json()) as { access_token: string; expires_in?: number };
    cached = { value: body.access_token, until: Date.now() + Math.max(10, (body.expires_in ?? 60) - 30) * 1000 };
    return body.access_token;
  };
}

export function passwordGrantToken(base: string, username: string, password: string): TokenProvider {
  return async () => {
    const res = await fetch(`${base}/realms/master/protocol/openid-connect/token`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ grant_type: 'password', client_id: 'admin-cli', username, password }).toString(),
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });
    if (!res.ok) throw new IdpError(`Bootstrap administrator login failed (${await readError(res)})`, res.status);
    return ((await res.json()) as { access_token: string }).access_token;
  };
}

export interface KcUser {
  id: string;
  username: string;
  email?: string;
  firstName?: string;
  lastName?: string;
  enabled: boolean;
  emailVerified?: boolean;
  createdTimestamp?: number;
  requiredActions?: string[];
  attributes?: Record<string, string[]>;
}
export interface KcRole {
  id: string;
  name: string;
}
export interface KcCredential {
  id: string;
  type: string;
  createdDate?: number;
}
export interface KcClient {
  id: string;
  clientId: string;
  [k: string]: unknown;
}

export class KeycloakAdmin {
  constructor(
    private readonly base: string,
    readonly realm: string,
    private readonly token: TokenProvider,
  ) {}

  private async req<T>(method: string, path: string, body?: unknown): Promise<T> {
    const res = await fetch(`${this.base}/admin/realms/${encodeURIComponent(this.realm)}${path}`, {
      method,
      headers: {
        authorization: `Bearer ${await this.token()}`,
        accept: 'application/json',
        ...(body !== undefined ? { 'content-type': 'application/json' } : {}),
      },
      body: body !== undefined ? JSON.stringify(body) : undefined,
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });
    if (res.status === 404) throw new IdpError('Not found in identity provider', 404);
    if (res.status === 409) throw new IdpError(await readError(res), 409);
    if (!res.ok) throw new IdpError(`Identity provider: ${await readError(res)}`, res.status);
    if (res.status === 201) return (res.headers.get('location')?.split('/').pop() ?? '') as T;
    const text = await res.text();
    return (text ? JSON.parse(text) : undefined) as T;
  }

  /* realm */
  getRealm = () => this.req<Record<string, unknown>>('GET', '');
  updateRealm = (partial: Record<string, unknown>) => this.req<void>('PUT', '', partial);
  getRequiredAction = (alias: string) => this.req<Record<string, unknown>>('GET', `/authentication/required-actions/${encodeURIComponent(alias)}`);
  updateRequiredAction = (alias: string, rep: Record<string, unknown>) => this.req<void>('PUT', `/authentication/required-actions/${encodeURIComponent(alias)}`, rep);
  getRealmRole = (name: string) => this.req<KcRole>('GET', `/roles/${encodeURIComponent(name)}`);
  roleUsers = (name: string) => this.req<KcUser[]>('GET', `/roles/${encodeURIComponent(name)}/users?first=0&max=1000`);

  /* clients */
  findClient = async (clientId: string) => (await this.req<KcClient[]>('GET', `/clients?clientId=${encodeURIComponent(clientId)}`))[0] ?? null;
  createClient = (rep: Record<string, unknown>) => this.req<string>('POST', '/clients', rep);
  updateClient = (id: string, rep: Record<string, unknown>) => this.req<void>('PUT', `/clients/${id}`, rep);
  clientRole = (clientUuid: string, role: string) => this.req<KcRole>('GET', `/clients/${clientUuid}/roles/${encodeURIComponent(role)}`);
  serviceAccountUser = (clientUuid: string) => this.req<KcUser>('GET', `/clients/${clientUuid}/service-account-user`);
  addClientRolesToUser = (userId: string, clientUuid: string, roles: KcRole[]) => this.req<void>('POST', `/users/${userId}/role-mappings/clients/${clientUuid}`, roles);

  /* users */
  listUsers = (opts: { search?: string; first?: number; max?: number }) => {
    const q = new URLSearchParams({ first: String(opts.first ?? 0), max: String(opts.max ?? 100), briefRepresentation: 'false' });
    if (opts.search) q.set('search', opts.search);
    return this.req<KcUser[]>('GET', `/users?${q.toString()}`);
  };
  findUserByUsername = async (username: string) =>
    (await this.req<KcUser[]>('GET', `/users?exact=true&username=${encodeURIComponent(username)}`)).find((u) => u.username === username.toLowerCase()) ?? null;
  getUser = (id: string) => this.req<KcUser>('GET', `/users/${id}`);
  createUser = (rep: Record<string, unknown>) => this.req<string>('POST', '/users', rep);
  updateUser = (id: string, rep: Partial<KcUser>) => this.req<void>('PUT', `/users/${id}`, rep);
  deleteUser = (id: string) => this.req<void>('DELETE', `/users/${id}`);
  logoutUser = (id: string) => this.req<void>('POST', `/users/${id}/logout`);
  credentials = (id: string) => this.req<KcCredential[]>('GET', `/users/${id}/credentials`);
  deleteCredential = (id: string, credId: string) => this.req<void>('DELETE', `/users/${id}/credentials/${credId}`);
  resetPassword = (id: string, value: string, temporary: boolean) => this.req<void>('PUT', `/users/${id}/reset-password`, { type: 'password', value, temporary });
  userRealmRoles = (id: string) => this.req<KcRole[]>('GET', `/users/${id}/role-mappings/realm`);
  addUserRealmRoles = (id: string, roles: KcRole[]) => this.req<void>('POST', `/users/${id}/role-mappings/realm`, roles);
  removeUserRealmRoles = (id: string, roles: KcRole[]) => this.req<void>('DELETE', `/users/${id}/role-mappings/realm`, roles);
}

/* --------------------------- Policy translation --------------------------- */

export interface IdentityPolicy {
  mfaRequired: boolean;
  otpAlgorithm: string;
  otpDigits: number;
  otpPeriodSec: number;
  passwordMinLength: number;
  requireUppercase: boolean;
  requireLowercase: boolean;
  requireDigit: boolean;
  requireSpecial: boolean;
  passwordHistory: number;
  passwordExpiryDays: number;
  lockoutMaxFailures: number;
  lockoutWaitSec: number;
  lockoutMaxWaitSec: number;
  permanentLockout: boolean;
}

export function passwordPolicyString(p: IdentityPolicy): string {
  const parts = [`length(${p.passwordMinLength})`];
  if (p.requireUppercase) parts.push('upperCase(1)');
  if (p.requireLowercase) parts.push('lowerCase(1)');
  if (p.requireDigit) parts.push('digits(1)');
  if (p.requireSpecial) parts.push('specialChars(1)');
  parts.push('notUsername', 'notEmail');
  if (p.passwordHistory > 0) parts.push(`passwordHistory(${p.passwordHistory})`);
  if (p.passwordExpiryDays > 0) parts.push(`forceExpiredPasswordChange(${p.passwordExpiryDays})`);
  return parts.join(' and ');
}

export function realmPolicyRepresentation(p: IdentityPolicy, session: { idleTimeoutSec: number; absoluteTimeoutSec: number }): Record<string, unknown> {
  return {
    otpPolicyType: 'totp',
    otpPolicyAlgorithm: p.otpAlgorithm,
    otpPolicyDigits: p.otpDigits,
    otpPolicyPeriod: p.otpPeriodSec,
    otpPolicyLookAheadWindow: 1,
    passwordPolicy: passwordPolicyString(p),
    bruteForceProtected: true,
    failureFactor: p.lockoutMaxFailures,
    waitIncrementSeconds: p.lockoutWaitSec,
    maxFailureWaitSeconds: p.lockoutMaxWaitSec,
    permanentLockout: p.permanentLockout,
    ssoSessionIdleTimeout: session.idleTimeoutSec,
    ssoSessionMaxLifespan: session.absoluteTimeoutSec,
  };
}

/** Applies MFA / password / lockout / session policy to the realm. */
export async function applyIdentityPolicy(kc: KeycloakAdmin, p: IdentityPolicy, session: { idleTimeoutSec: number; absoluteTimeoutSec: number }): Promise<void> {
  await kc.updateRealm(realmPolicyRepresentation(p, session));
  const totp = await kc.getRequiredAction('CONFIGURE_TOTP');
  if (totp.enabled !== true || totp.defaultAction !== p.mfaRequired) {
    await kc.updateRequiredAction('CONFIGURE_TOTP', { ...totp, enabled: true, defaultAction: p.mfaRequired });
  }
}
