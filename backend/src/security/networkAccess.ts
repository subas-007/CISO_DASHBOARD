/**
 * Source-network restrictions defined by the administrator (Configuration → Network access).
 *
 *  - networkAccessGuard: enforced on every /api request (incl. sign-in), so a client
 *    outside the allowed networks can neither authenticate nor read data.
 *  - ipGateRouter: answers NGINX `auth_request` sub-requests so the same policy also
 *    protects the identity provider's pages and the Keycloak admin console, without
 *    reloading the gateway when the lists change.
 *
 * The client IP is the address NGINX observed (or the address forwarded by a trusted
 * upstream load balancer, see Deployment → trusted proxies); clients cannot spoof it
 * because the gateway overwrites X-Forwarded-For.
 */
import { Router, type NextFunction, type Request, type Response } from 'express';
import { HttpError } from '../lib/errors.js';
import { ipInCidrs } from '../lib/net.js';
import { getSetting } from '../modules/settings/settings.service.js';

export async function isClientNetworkAllowed(ip: string | null | undefined): Promise<boolean> {
  const { allowedClientCidrs } = await getSetting('networkAccess');
  return allowedClientCidrs.length === 0 || ipInCidrs(ip, allowedClientCidrs);
}

export async function networkAccessGuard(req: Request, _res: Response, next: NextFunction): Promise<void> {
  if (await isClientNetworkAllowed(req.ip)) return next();
  throw new HttpError(403, 'NETWORK_NOT_ALLOWED', 'Access from your network is not permitted');
}

export const ipGateRouter = Router();

ipGateRouter.get('/app', async (req, res) => {
  res.status((await isClientNetworkAllowed(req.ip)) ? 204 : 403).end();
});

ipGateRouter.get('/admin-console', async (req, res) => {
  const { adminConsoleCidrs } = await getSetting('networkAccess');
  res.status(ipInCidrs(req.ip, adminConsoleCidrs) ? 204 : 403).end();
});
