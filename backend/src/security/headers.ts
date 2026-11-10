import helmet from 'helmet';
import type { RequestHandler } from 'express';

/**
 * API security headers. The API only ever returns JSON / SSE, so the CSP is fully
 * locked down. The SPA's own CSP is set by the NGINX gateway.
 */
export function securityHeaders(): RequestHandler[] {
  return [
    helmet({
      contentSecurityPolicy: {
        useDefaults: false,
        directives: {
          defaultSrc: ["'none'"],
          frameAncestors: ["'none'"],
          baseUri: ["'none'"],
          formAction: ["'none'"],
        },
      },
      crossOriginEmbedderPolicy: { policy: 'require-corp' },
      crossOriginOpenerPolicy: { policy: 'same-origin' },
      crossOriginResourcePolicy: { policy: 'same-origin' },
      frameguard: { action: 'deny' },
      hsts: { maxAge: 63_072_000, includeSubDomains: true, preload: true },
      noSniff: true,
      referrerPolicy: { policy: 'no-referrer' },
      xDnsPrefetchControl: { allow: false },
      xPermittedCrossDomainPolicies: { permittedPolicies: 'none' },
    }),
    (_req, res, next) => {
      res.setHeader('Cache-Control', 'no-store');
      res.setHeader('Pragma', 'no-cache');
      res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=(), usb=()');
      next();
    },
  ];
}
