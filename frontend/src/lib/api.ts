/**
 * API client. Auth is carried exclusively by httpOnly cookies (never readable by JS);
 * state-changing requests echo the double-submit CSRF token. On 401 the client attempts
 * a single silent refresh (rotating refresh token) before giving up.
 */
const CSRF_COOKIE = '__Host-ciso_csrf';

export class ApiError extends Error {
  constructor(
    public readonly status: number,
    message: string,
    public readonly code?: string,
    public readonly issues?: { path: string; message: string }[],
  ) {
    super(message);
  }
}

function csrfToken(): string {
  const entry = document.cookie.split('; ').find((c) => c.startsWith(`${CSRF_COOKIE}=`));
  return entry ? decodeURIComponent(entry.slice(CSRF_COOKIE.length + 1)) : '';
}

let refreshing: Promise<boolean> | null = null;

export function refreshSession(): Promise<boolean> {
  if (!refreshing) {
    refreshing = fetch('/api/auth/refresh', {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'X-CSRF-Token': csrfToken() },
    })
      .then((r) => r.ok)
      .catch(() => false)
      .finally(() => {
        setTimeout(() => (refreshing = null), 0);
      });
  }
  return refreshing;
}

type Query = Record<string, string | number | boolean | undefined | null | string[]>;

function buildUrl(path: string, query?: Query): string {
  const qs = new URLSearchParams();
  for (const [k, v] of Object.entries(query ?? {})) {
    if (v === undefined || v === null || v === '') continue;
    if (Array.isArray(v)) {
      if (v.length) qs.set(k, v.join(','));
    } else qs.set(k, String(v));
  }
  const s = qs.toString();
  return `/api${path}${s ? `?${s}` : ''}`;
}

export interface RequestOpts {
  method?: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';
  body?: unknown;
  query?: Query;
}

export async function api<T>(path: string, opts: RequestOpts = {}): Promise<T> {
  const method = opts.method ?? 'GET';
  const doFetch = () => {
    const headers: Record<string, string> = { Accept: 'application/json' };
    if (method !== 'GET') {
      headers['X-CSRF-Token'] = csrfToken();
      if (opts.body !== undefined) headers['Content-Type'] = 'application/json';
    }
    return fetch(buildUrl(path, opts.query), {
      method,
      headers,
      credentials: 'same-origin',
      body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
    });
  };

  let res = await doFetch();
  if (res.status === 401 && !path.startsWith('/auth/')) {
    if (await refreshSession()) res = await doFetch();
  }
  if (res.status === 401) {
    window.dispatchEvent(new CustomEvent('auth:expired'));
  }
  if (!res.ok) {
    const body = (await res.json().catch(() => ({}))) as { error?: { message?: string; code?: string; issues?: { path: string; message: string }[] } };
    throw new ApiError(res.status, body.error?.message ?? res.statusText, body.error?.code, body.error?.issues);
  }
  if (res.status === 204) return undefined as T;
  return (await res.json()) as T;
}

/** Download a file from an authenticated endpoint without exposing tokens. */
export async function download(path: string, query: Query, filename: string): Promise<void> {
  const res = await fetch(buildUrl(path, query), { credentials: 'same-origin' });
  if (!res.ok) throw new ApiError(res.status, 'Download failed');
  const blob = await res.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.rel = 'noopener';
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export function errorMessage(err: unknown): string {
  if (err instanceof ApiError) {
    if (err.issues?.length) return `${err.message}: ${err.issues.map((i) => `${i.path || 'body'} ${i.message}`).join('; ')}`;
    return err.message;
  }
  return err instanceof Error ? err.message : 'Unexpected error';
}
