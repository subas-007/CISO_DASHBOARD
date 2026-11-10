/**
 * Per-connector API parameters that adapt any adapter to a vendor's deployment without
 * code changes: API gateway path prefixes, version headers (e.g. QRadar `Version`,
 * Elastic `elastic-api-version`), tenant query parameters, timeouts and retries.
 *
 * Secrets never belong here — header names that look like credentials are rejected so
 * that keys cannot bypass encrypted credential storage.
 */
import { z } from 'zod';

const FORBIDDEN_HEADER = /^(host|content-length|content-type|transfer-encoding|connection|te|upgrade|proxy-.*|x-forwarded-.*|forwarded|cookie|set-cookie)$/i;
const SECRET_LOOKING = /(auth|token|secret|passw|api[-_]?key|session|cookie|signature)/i;
const noCrLf = z.string().max(500).regex(/^[^\r\n\0]*$/, 'must be a single line');

const headerMap = z
  .record(z.string().regex(/^[A-Za-z0-9-]{1,64}$/, 'invalid header name'), noCrLf)
  .refine((h) => Object.keys(h).length <= 20, 'at most 20 headers')
  .refine((h) => Object.keys(h).every((k) => !FORBIDDEN_HEADER.test(k)), 'header not allowed (hop-by-hop, routing or cookie header)')
  .refine((h) => Object.keys(h).every((k) => !SECRET_LOOKING.test(k)), 'credential-like headers must be configured as encrypted credentials, not plain parameters');

const queryMap = z
  .record(z.string().regex(/^[A-Za-z0-9_.\-[\]]{1,64}$/, 'invalid parameter name'), noCrLf)
  .refine((q) => Object.keys(q).length <= 20, 'at most 20 query parameters')
  .refine((q) => Object.keys(q).every((k) => !SECRET_LOOKING.test(k)), 'credential-like parameters must be configured as encrypted credentials');

export const RequestOptionsSchema = z
  .object({
    pathPrefix: z
      .string()
      .max(200)
      // Segments may not start with "." (no "." / ".." traversal segments).
      .regex(/^(\/[A-Za-z0-9_~-][A-Za-z0-9._~-]*)*$/, 'must look like /gateway/splunk (no trailing slash, query or dot segments)')
      .default(''),
    headers: headerMap.default({}),
    query: queryMap.default({}),
    timeoutMs: z.number().int().min(1000).max(300_000).optional(),
    maxRetries: z.number().int().min(0).max(5).optional(),
  })
  .strict();

export type RequestOptions = z.infer<typeof RequestOptionsSchema>;
export const DEFAULT_REQUEST_OPTIONS: RequestOptions = RequestOptionsSchema.parse({});
