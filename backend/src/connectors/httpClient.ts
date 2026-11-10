/**
 * Hardened outbound HTTP client for connectors.
 *
 *  - Auth modes: API key, Basic, OAuth2 client-credentials, mutual TLS (client certificate)
 *  - TLS verification always on (custom CA supported), minimum TLS 1.2 for third parties
 *  - SSRF guard: URL policy + connect-time IP checks; requests are pinned to the
 *    configured origin and redirects are never followed
 *  - Response size cap and timeouts
 *  - Zero data retention: the raw response buffer is zero-filled immediately after
 *    parsing; raw payloads are never logged or persisted
 */
import { Agent, request } from 'undici';
import type { AuthMode } from '@prisma/client';
import { XMLParser } from 'fast-xml-parser';
import { env } from '../config/env.js';
import { assertUrlAllowed, guardedLookup } from './egress.js';
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

const xml = new XMLParser({
  ignoreAttributes: true,
  processEntities: false, // no entity expansion → no XXE / billion-laughs
  parseTagValue: true,
  isArray: (name) => ['HOST', 'DETECTION', 'item'].includes(name),
});

export class ConnectorHttpClient {
  private readonly dispatcher: Agent;
  private oauthToken: { value: string; expiresAt: number } | null = null;

  constructor(
    private readonly baseUrl: URL,
    private readonly authMode: AuthMode,
    private readonly creds: Credentials,
    private readonly apiKeyHeaders?: (c: Credentials) => Record<string, string>,
  ) {
    assertUrlAllowed(baseUrl);
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
      headersTimeout: env.CONNECTOR_TIMEOUT_MS,
      bodyTimeout: env.CONNECTOR_TIMEOUT_MS,
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
      if (size > env.CONNECTOR_MAX_RESPONSE_BYTES) {
        chunks.forEach((c) => c.fill(0));
        throw new ConnectorError('Response exceeded maximum allowed size');
      }
      chunks.push(Buffer.from(chunk));
    }
    const buf = Buffer.concat(chunks);
    chunks.forEach((c) => c.fill(0));
    return buf;
  }

  /** Performs a request against the connector's configured origin and returns the parsed body. */
  async call<T = unknown>(path: string, opts: RequestOptions = {}): Promise<T> {
    const url = new URL(path, this.baseUrl);
    if (url.origin !== this.baseUrl.origin) throw new ConnectorError('Cross-origin request blocked');
    for (const [k, v] of Object.entries(opts.query ?? {})) if (v !== undefined) url.searchParams.set(k, String(v));

    const accept = opts.accept ?? 'json';
    const headers: Record<string, string> = {
      accept: accept === 'json' ? 'application/json' : accept === 'xml' ? 'application/xml' : 'text/plain, application/json',
      'user-agent': 'ciso-dashboard-connector/1.0',
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

    const res = await request(url, { method: opts.method ?? 'GET', headers, body, dispatcher: this.dispatcher });
    const buf = await this.readCapped(res.body);
    try {
      if (res.statusCode >= 300) {
        // Never echo the upstream body (could contain sensitive data).
        throw new ConnectorError(`Upstream returned HTTP ${res.statusCode}`, res.statusCode);
      }
      const text = buf.toString('utf8');
      if (accept === 'text') return text as T;
      if (accept === 'xml') return xml.parse(text) as T;
      return (text.length ? JSON.parse(text) : null) as T;
    } catch (err) {
      if (err instanceof ConnectorError) throw err;
      throw new ConnectorError('Upstream response could not be parsed');
    } finally {
      buf.fill(0); // zero-retention: wipe raw payload bytes
    }
  }
}
