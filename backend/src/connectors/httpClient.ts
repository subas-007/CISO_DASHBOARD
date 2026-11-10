/**
 * Hardened outbound HTTP client for connectors.
 *
 *  - Auth modes: API key, Basic, OAuth2 client-credentials, mutual TLS (client certificate)
 *  - TLS verification always on (custom CA supported), minimum TLS 1.2 for third parties
 *  - SSRF guard: URL policy + connect-time IP checks; requests are pinned to the
 *    configured origin and redirects are never followed
 *  - Response size cap, timeouts and bounded retries with exponential back-off
 *    (429 / 502 / 503 / 504 / transient network errors; honours Retry-After)
 *  - Administrator-defined API parameters per connector (path prefix, version headers,
 *    tenant query parameters, timeout, retries) — see requestOptions.ts
 *  - Zero data retention: the raw response buffer is zero-filled immediately after
 *    parsing; raw payloads are never logged or persisted
 */
import { Agent, request } from 'undici';
import type { AuthMode } from '@prisma/client';
import { XMLParser } from 'fast-xml-parser';
import { assertUrlAllowed, egressPolicy, guardedLookup } from './egress.js';
import { DEFAULT_REQUEST_OPTIONS, type RequestOptions as ConnectorRequestOptions } from './requestOptions.js';
import type { Credentials } from './types.js';

export class ConnectorError extends Error {
  constructor(message: string, public readonly status?: number) {
    super(message);
    this.name = 'ConnectorError';
  }
}

type Accept = 'json' | 'text' | 'xml';

export interface RequestOptions {
  method?: 'GET' | 'POST';
  query?: Record<string, string | number | undefined>;
  json?: unknown;
  form?: Record<string, string>;
  headers?: Record<string, string>;
  accept?: Accept;
}

export interface CallResult<T> {
  body: T;
  status: number;
  headers: Record<string, string | string[] | undefined>;
}

const RETRY_STATUS = new Set([429, 502, 503, 504]);
const RETRY_CODES = new Set(['ECONNRESET', 'ETIMEDOUT', 'EPIPE', 'UND_ERR_SOCKET', 'UND_ERR_CONNECT_TIMEOUT', 'UND_ERR_HEADERS_TIMEOUT', 'UND_ERR_BODY_TIMEOUT']);
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

function retryAfterMs(value: string | string[] | undefined): number | null {
  const v = Array.isArray(value) ? value[0] : value;
  if (!v) return null;
  if (/^\d+$/.test(v)) return Number(v) * 1000;
  const at = Date.parse(v);
  return Number.isNaN(at) ? null : Math.max(0, at - Date.now());
}

const xml = new XMLParser({
  ignoreAttributes: true,
  processEntities: false, // no entity expansion → no XXE / billion-laughs
  parseTagValue: true,
  isArray: (name) => ['HOST', 'DETECTION', 'item'].includes(name),
});

export class ConnectorHttpClient {
  private readonly dispatcher: Agent;
  private oauthToken: { value: string; expiresAt: number } | null = null;
  private readonly timeoutMs: number;
  private readonly maxRetries: number;
  private readonly maxBytes: number;

  constructor(
    private readonly baseUrl: URL,
    private readonly authMode: AuthMode,
    private readonly creds: Credentials,
    private readonly apiKeyHeaders?: (c: Credentials) => Record<string, string>,
    private readonly options: ConnectorRequestOptions = DEFAULT_REQUEST_OPTIONS,
  ) {
    assertUrlAllowed(baseUrl);
    const policy = egressPolicy();
    this.timeoutMs = options.timeoutMs ?? policy.timeoutMs;
    this.maxRetries = options.maxRetries ?? policy.maxRetries;
    this.maxBytes = policy.maxResponseBytes;
    const tls =
      authMode === 'MTLS'
        ? { cert: creds.clientCert, key: creds.clientKey, passphrase: creds.passphrase }
        : {};
    this.dispatcher = new Agent({
      connect: {
        lookup: guardedLookup,
        rejectUnauthorized: true,
        minVersion: 'TLSv1.2',
        ...(creds.caCert ? { ca: creds.caCert } : {}),
        ...tls,
      },
      headersTimeout: this.timeoutMs,
      bodyTimeout: this.timeoutMs,
      connections: 4,
    });
  }

  async close(): Promise<void> {
    await this.dispatcher.close().catch(() => undefined);
    this.oauthToken = null;
  }

  private async authHeaders(): Promise<Record<string, string>> {
    const c = this.creds;
    switch (this.authMode) {
      case 'NONE':
        return {};
      case 'API_KEY':
        if (this.apiKeyHeaders) return this.apiKeyHeaders(c);
        if (!c.apiKey) throw new ConnectorError('API key not configured');
        return { [c.apiKeyHeader || 'Authorization']: `${c.apiKeyPrefix ?? ''}${c.apiKey}` };
      case 'BASIC':
        if (!c.username || !c.password) throw new ConnectorError('Username/password not configured');
        return { Authorization: `Basic ${Buffer.from(`${c.username}:${c.password}`).toString('base64')}` };
      case 'OAUTH2':
        return { Authorization: `Bearer ${await this.oauth2Token()}` };
      case 'MTLS':
        // Client certificate is presented at the TLS layer; an API key may be layered on top.
        return c.apiKey ? { [c.apiKeyHeader || 'Authorization']: `${c.apiKeyPrefix ?? ''}${c.apiKey}` } : {};
      default:
        return {};
    }
  }

  private async oauth2Token(): Promise<string> {
    if (this.oauthToken && this.oauthToken.expiresAt > Date.now() + 30_000) return this.oauthToken.value;
    const c = this.creds;
    if (!c.tokenUrl || !c.clientId || !c.clientSecret) throw new ConnectorError('OAuth2 client credentials not configured');
    const tokenUrl = new URL(c.tokenUrl);
    assertUrlAllowed(tokenUrl);
    const form = new URLSearchParams({ grant_type: 'client_credentials' });
    if (c.scope) form.set('scope', c.scope);
    const res = await request(tokenUrl, {
      method: 'POST',
      dispatcher: this.dispatcher,
      headers: {
        'content-type': 'application/x-www-form-urlencoded',
        authorization: `Basic ${Buffer.from(`${encodeURIComponent(c.clientId)}:${encodeURIComponent(c.clientSecret)}`).toString('base64')}`,
        accept: 'application/json',
      },
      body: form.toString(),
    });
    const buf = await this.readCapped(res.body);
    try {
      if (res.statusCode >= 400) throw new ConnectorError(`OAuth2 token endpoint returned HTTP ${res.statusCode}`, res.statusCode);
      const body = JSON.parse(buf.toString('utf8')) as { access_token?: string; expires_in?: number };
      if (!body.access_token) throw new ConnectorError('OAuth2 token response missing access_token');
      this.oauthToken = { value: body.access_token, expiresAt: Date.now() + (body.expires_in ?? 300) * 1000 };
      return body.access_token;
    } finally {
      buf.fill(0);
    }
  }

  private async readCapped(body: AsyncIterable<Buffer | Uint8Array>): Promise<Buffer> {
    const chunks: Buffer[] = [];
    let size = 0;
    for await (const chunk of body) {
      size += chunk.length;
      if (size > this.maxBytes) {
        chunks.forEach((c) => c.fill(0));
        throw new ConnectorError('Response exceeded maximum allowed size');
      }
      chunks.push(Buffer.from(chunk));
    }
    const buf = Buffer.concat(chunks);
    chunks.forEach((c) => c.fill(0));
    return buf;
  }

  /** Resolves an adapter path (or same-origin absolute next-page URL) against the connector. */
  private resolve(path: string, query?: Record<string, string | number | undefined>): URL {
    const isAbsolute = /^https?:\/\//i.test(path);
    const url = isAbsolute ? new URL(path) : new URL(path.startsWith('/') ? `${this.options.pathPrefix}${path}` : path, this.baseUrl);
    if (url.origin !== this.baseUrl.origin) throw new ConnectorError('Cross-origin request blocked');
    if (!isAbsolute) {
      // Administrator parameters first; adapter parameters take precedence.
      for (const [k, v] of Object.entries(this.options.query)) if (!url.searchParams.has(k)) url.searchParams.set(k, v);
    }
    for (const [k, v] of Object.entries(query ?? {})) if (v !== undefined) url.searchParams.set(k, String(v));
    return url;
  }

  /** Performs a request and returns the parsed body plus status and response headers. */
  async callWithMeta<T = unknown>(path: string, opts: RequestOptions = {}): Promise<CallResult<T>> {
    const url = this.resolve(path, opts.query);
    const accept = opts.accept ?? 'json';
    const method = opts.method ?? 'GET';
    const headers: Record<string, string> = {
      accept: accept === 'json' ? 'application/json' : accept === 'xml' ? 'application/xml' : 'text/plain, application/json',
      'user-agent': 'ciso-dashboard-connector/1.0',
      ...this.options.headers,
      ...(await this.authHeaders()),
      ...(opts.headers ?? {}),
    };
    let body: string | undefined;
    if (opts.json !== undefined) {
      headers['content-type'] = 'application/json';
      body = JSON.stringify(opts.json);
    } else if (opts.form) {
      headers['content-type'] = 'application/x-www-form-urlencoded';
      body = new URLSearchParams(opts.form).toString();
    }

    const { retryBackoffMs } = egressPolicy();
    for (let attempt = 0; ; attempt++) {
      let res;
      try {
        res = await request(url, { method, headers, body, dispatcher: this.dispatcher });
      } catch (err) {
        const code = (err as { code?: string }).code ?? '';
        if (attempt < this.maxRetries && RETRY_CODES.has(code)) {
          await sleep(Math.min(30_000, retryBackoffMs * 2 ** attempt) + Math.random() * 250);
          continue;
        }
        throw err;
      }
      if (RETRY_STATUS.has(res.statusCode) && attempt < this.maxRetries) {
        await res.body.dump().catch(() => undefined); // discard unread body
        const hinted = retryAfterMs(res.headers['retry-after']);
        await sleep(Math.min(60_000, hinted ?? retryBackoffMs * 2 ** attempt) + Math.random() * 250);
        continue;
      }
      const buf = await this.readCapped(res.body);
      try {
        if (res.statusCode >= 300) {
          // Never echo the upstream body (could contain sensitive data).
          throw new ConnectorError(`Upstream returned HTTP ${res.statusCode}`, res.statusCode);
        }
        const text = buf.toString('utf8');
        const parsed = accept === 'text' ? text : accept === 'xml' ? xml.parse(text) : text.length ? JSON.parse(text) : null;
        return { body: parsed as T, status: res.statusCode, headers: res.headers };
      } catch (err) {
        if (err instanceof ConnectorError) throw err;
        throw new ConnectorError('Upstream response could not be parsed');
      } finally {
        buf.fill(0); // zero-retention: wipe raw payload bytes
      }
    }
  }

  /** Performs a request against the connector's configured origin and returns the parsed body. */
  async call<T = unknown>(path: string, opts: RequestOptions = {}): Promise<T> {
    return (await this.callWithMeta<T>(path, opts)).body;
  }
}
