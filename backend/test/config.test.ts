import { spawnSync } from 'node:child_process';
import { describe, expect, it } from 'vitest';
import { SETTINGS, settingWarnings } from '../src/modules/settings/settings.service.js';
import { renderDeploymentEnv, renderHostScript, q } from '../src/modules/config/bundle.js';
import { passwordPolicyString, realmPolicyRepresentation } from '../src/idp/keycloakAdmin.js';
import { generateTemporaryPassword } from '../src/idp/identity.service.js';
import { RequestOptionsSchema } from '../src/connectors/requestOptions.js';
import { fetchAllItems } from '../src/connectors/adapters/generic.js';
import { ipInCidrs } from '../src/lib/net.js';
import type { AdapterContext } from '../src/connectors/types.js';

const parse = <K extends keyof typeof SETTINGS>(k: K, v: unknown) => SETTINGS[k].schema.safeParse(v);
const host = () => SETTINGS.hostOs.schema.parse(SETTINGS.hostOs.default);
const deploy = (over: Record<string, unknown> = {}) => SETTINGS.deployment.schema.parse({ ...SETTINGS.deployment.default, ...over });

describe('Configuration catalogue validation', () => {
  it('every default satisfies its own schema', () => {
    for (const [key, def] of Object.entries(SETTINGS)) {
      expect(def.schema.safeParse(def.default).success, key).toBe(true);
      if ('demoDefault' in def && def.demoDefault) expect(def.schema.safeParse(def.demoDefault).success, `${key} demo`).toBe(true);
    }
  });

  it('every editable field path exists in the default value', () => {
    for (const [key, def] of Object.entries(SETTINGS)) {
      for (const f of def.fields) {
        const v = f.path ? f.path.split('.').reduce<unknown>((a, k) => (a as Record<string, unknown>)?.[k], def.default) : def.default;
        expect(v, `${key}.${f.path}`).not.toBeUndefined();
      }
    }
  });

  it('rate limits enforce cross-field ordering and sane minimums', () => {
    expect(parse('rateLimits', { perIpPerMin: 3000, authPerIpPerMin: 120, perUserPerMin: 600, heavyPerUserPerMin: 30 }).success).toBe(true);
    expect(parse('rateLimits', { perIpPerMin: 100, authPerIpPerMin: 200, perUserPerMin: 600, heavyPerUserPerMin: 30 }).success).toBe(false);
    expect(parse('rateLimits', { perIpPerMin: 3000, authPerIpPerMin: 120, perUserPerMin: 5, heavyPerUserPerMin: 5 }).success).toBe(false);
  });

  it('network lists accept IPs/CIDRs only and normalise single addresses', () => {
    const ok = SETTINGS.networkAccess.schema.safeParse({ allowedClientCidrs: ['10.20.0.0/16', '192.0.2.7', '2001:db8::/32'], adminConsoleCidrs: [] });
    expect(ok.success && ok.data.allowedClientCidrs).toEqual(['10.20.0.0/16', '192.0.2.7/32', '2001:db8::/32']);
    for (const bad of ['10.0.0.0/33', 'example.com', '10.0.0.1; reboot', '10.0.0.0/8\nallow all', '']) {
      expect(parse('networkAccess', { allowedClientCidrs: [bad], adminConsoleCidrs: [] }).success, bad).toBe(false);
    }
  });

  it('public URL must be https with a hostname or IP and no path', () => {
    expect(deploy({ publicBaseUrl: 'https://10.20.5.15' }).publicBaseUrl).toBe('https://10.20.5.15');
    expect(deploy({ publicBaseUrl: 'https://ciso.corp.example:8443/' }).publicBaseUrl).toBe('https://ciso.corp.example:8443');
    for (const bad of ['http://10.0.0.1', 'https://a.example/path', 'https://user:pw@a.example', 'https://a.example?x=1', 'javascript:alert(1)']) {
      expect(parse('deployment', { ...SETTINGS.deployment.default, publicBaseUrl: bad }).success, bad).toBe(false);
    }
  });

  it('host OS values reject shell metacharacters', () => {
    const base = SETTINGS.hostOs.default;
    expect(parse('hostOs', { ...base, timezone: 'Europe/London' }).success).toBe(true);
    for (const tz of ['UTC; reboot', '$(id)', '../../etc/passwd']) expect(parse('hostOs', { ...base, timezone: tz }).success, tz).toBe(false);
    for (const ntp of ['pool.ntp.org; rm -rf /', '`id`', 'a b']) expect(parse('hostOs', { ...base, ntpServers: [ntp] }).success, ntp).toBe(false);
    expect(parse('hostOs', { ...base, syslog: { enabled: true, host: '', port: 514, protocol: 'tcp' } }).success).toBe(false);
  });

  it('identity warnings flag authenticator-app incompatibility and weak policy', () => {
    const v = SETTINGS.identity.schema.parse({ ...SETTINGS.identity.default, otpAlgorithm: 'HmacSHA256', passwordMinLength: 10, mfaRequired: false });
    const w = settingWarnings('identity', v).join(' ');
    expect(w).toMatch(/Google Authenticator and Microsoft Authenticator only support HmacSHA1/);
    expect(w).toMatch(/8\.3\.6/);
    expect(w).toMatch(/8\.4\.2/);
    expect(settingWarnings('identity', SETTINGS.identity.schema.parse(SETTINGS.identity.default))).toEqual([]);
  });
});

describe('Identity provider policy translation', () => {
  it('builds the Keycloak password policy and realm representation', () => {
    const p = SETTINGS.identity.schema.parse(SETTINGS.identity.default);
    expect(passwordPolicyString(p)).toBe('length(12) and upperCase(1) and lowerCase(1) and digits(1) and specialChars(1) and notUsername and notEmail and passwordHistory(12)');
    const rep = realmPolicyRepresentation(p, { idleTimeoutSec: 900, absoluteTimeoutSec: 28_800 });
    expect(rep).toMatchObject({ otpPolicyAlgorithm: 'HmacSHA1', otpPolicyDigits: 6, otpPolicyPeriod: 30, failureFactor: 5, ssoSessionIdleTimeout: 900, bruteForceProtected: true });
  });

  it('generates one-time passwords that satisfy every character class', () => {
    for (let i = 0; i < 50; i++) {
      const pw = generateTemporaryPassword(12);
      expect(pw.length).toBe(16);
      expect(pw).toMatch(/[A-Z]/);
      expect(pw).toMatch(/[a-z]/);
      expect(pw).toMatch(/[0-9]/);
      expect(pw).toMatch(/[^A-Za-z0-9]/);
    }
    expect(generateTemporaryPassword(40)).toHaveLength(40);
  });
});

describe('Deployment and host bundles', () => {
  it('deployment profile contains only whitelisted, non-secret keys', () => {
    const env = renderDeploymentEnv(deploy({ publicBaseUrl: 'https://10.20.5.15', alternativeNames: ['ciso.corp.example'], trustedUpstreamProxies: ['10.20.0.10/32'] }), 'Alex Admin');
    const keys = env.split('\n').filter((l) => l && !l.startsWith('#')).map((l) => l.split('=')[0]);
    expect(keys).toEqual(['PUBLIC_BASE_URL', 'HTTPS_PORT', 'HTTP_PORT', 'CERT_SANS', 'TRUSTED_UPSTREAM_PROXIES', 'EDGE_RATE_LIMIT_RPS', 'EDGE_AUTH_RATE_LIMIT_RPS', 'API_MEMORY', 'KEYCLOAK_MEMORY', 'POSTGRES_MEMORY']);
    expect(env).toContain('CERT_SANS=10.20.5.15,ciso.corp.example');
    expect(env).not.toMatch(/PASSWORD|SECRET|KEY=/);
  });

  it('shell quoting neutralises quotes', () => {
    expect(q("a'b")).toBe(`'a'\\''b'`);
  });

  for (const os of ['ubuntu', 'rhel'] as const) {
    it(`host script for ${os} is syntactically valid bash and covers each control`, () => {
      const h = { ...host(), targetOs: os, dnsServers: ['10.20.0.53'], syslog: { enabled: true, host: 'siem.corp.example', port: 6514, protocol: 'tls' as const }, firewall: { enabled: true, httpsAllowedCidrs: ['10.0.0.0/8', '2001:db8::/32'], sshAllowedCidrs: ['10.20.5.0/24'], sshPort: 22 } };
      const script = renderHostScript(h, deploy(), 'Alex Admin');
      expect(script.startsWith('#!/usr/bin/env bash')).toBe(true);
      for (const needle of ['timedatectl set-timezone', 'chrony', 'StreamDriver="gtls"', 'CISO-EDGE', '--ctorigdstport 443', 'ip6tables', 'sysctl --system', 'augenrules', 'daemon.json']) {
        expect(script, needle).toContain(needle);
      }
      expect(script).toContain(os === 'ubuntu' ? 'ufw allow from' : 'firewall-cmd --permanent --add-rich-rule');
      const bash = spawnSync('bash', ['-n'], { input: script, encoding: 'utf8' });
      if (!bash.error) expect(bash.stderr).toBe('');
    });
  }

  it('leaves SSH untouched when no SSH networks are defined and skips edge filtering when open', () => {
    const script = renderHostScript(host(), deploy(), 'x');
    expect(script).toContain('SSH firewall rules left unchanged');
    expect(script).not.toContain('ufw --force enable');
    expect(script).toContain('removing any previous edge restriction');
  });
});

describe('Connector API parameters', () => {
  it('accepts version headers / tenant parameters and rejects credentials or CRLF', () => {
    expect(RequestOptionsSchema.safeParse({ pathPrefix: '/gw/splunk', headers: { Version: '20.0', 'elastic-api-version': '2023-10-31' }, query: { tenant: 'emea' } }).success).toBe(true);
    for (const bad of [
      { headers: { Authorization: 'Bearer x' } },
      { headers: { 'X-Api-Key': 'abc' } },
      { headers: { 'X-Token': 'abc' } },
      { headers: { Host: 'evil' } },
      { headers: { 'X-Test': 'a\r\nInjected: 1' } },
      { query: { api_key: 'abc' } },
      { pathPrefix: '/../admin' },
      { pathPrefix: 'gw?x=1' },
      { timeoutMs: 10 },
    ]) {
      expect(RequestOptionsSchema.safeParse(bad).success, JSON.stringify(bad)).toBe(false);
    }
  });

  const pages = (style: string) => {
    const calls: { path: string; query: Record<string, unknown> }[] = [];
    const http = {
      async callWithMeta(path: string, opts: { query?: Record<string, unknown> } = {}) {
        calls.push({ path, query: opts.query ?? {} });
        const n = calls.length;
        if (style === 'cursor') return { status: 200, headers: {}, body: { data: n < 3 ? [{ id: n }, { id: n + 10 }] : [{ id: 99 }], next: n < 3 ? `c${n}` : '' } };
        if (style === 'link') return { status: 200, headers: n < 3 ? { link: `<https://api.example/items?page=${n + 1}>; rel="next"` } : {}, body: [{ id: n }] };
        return { status: 200, headers: {}, body: { data: n < 3 ? [{ id: 1 }, { id: 2 }] : [{ id: 3 }] } };
      },
    };
    return { calls, ctx: { http, since: new Date('2026-01-01T00:00:00Z'), baseUrl: new URL('https://api.example'), connectorId: 'x' } as unknown as AdapterContext };
  };
  const base = { path: '/items', testPath: '', itemsPath: 'data', pageSize: 2, pageSizeParam: 'limit', offsetParam: 'offset', pageParam: 'page', firstPage: 1, cursorParam: 'cursor', nextCursorPath: 'next', maxPages: 10, sinceParam: 'since', sinceFormat: 'epoch' as const };

  it('paginates by page number until a short page', async () => {
    const { calls, ctx } = pages('page');
    const items = await fetchAllItems(ctx, { ...base, pagination: 'page' });
    expect(items).toHaveLength(5);
    expect(calls.map((c) => c.query.page)).toEqual([1, 2, 3]);
    expect(calls[0]!.query.since).toBe('1767225600');
  });

  it('follows body cursors and RFC 8288 Link headers', async () => {
    const c = pages('cursor');
    expect(await fetchAllItems(c.ctx, { ...base, pagination: 'cursor' })).toHaveLength(5);
    expect(c.calls.map((x) => x.query.cursor)).toEqual([undefined, 'c1', 'c2']);
    const l = pages('link');
    expect(await fetchAllItems(l.ctx, { ...base, itemsPath: '', pagination: 'link' })).toHaveLength(3);
    expect(l.calls[1]!.path).toBe('https://api.example/items?page=2');
  });

  it('respects maxPages', async () => {
    const { calls, ctx } = pages('cursor');
    await fetchAllItems(ctx, { ...base, pagination: 'cursor', maxPages: 2 });
    expect(calls).toHaveLength(2);
  });
});

describe('Network membership', () => {
  it('matches IPv4, IPv6 and IPv4-mapped addresses', () => {
    expect(ipInCidrs('10.20.5.15', ['10.20.0.0/16'])).toBe(true);
    expect(ipInCidrs('::ffff:10.20.5.15', ['10.20.0.0/16'])).toBe(true);
    expect(ipInCidrs('2001:db8::1', ['2001:db8::/32'])).toBe(true);
    expect(ipInCidrs('192.0.2.1', ['10.20.0.0/16'])).toBe(false);
    expect(ipInCidrs('10.0.0.1', [])).toBe(false);
  });
});
