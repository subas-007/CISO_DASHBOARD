/**
 * Strict validators for network-shaped configuration values (CIDRs, hostnames, origins).
 * Every value an administrator can enter that later reaches NGINX, Keycloak or a
 * generated host script passes through one of these — no free-form strings.
 */
import net from 'node:net';
import { z } from 'zod';

const LABEL = '[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?';
export const HOSTNAME_RE = new RegExp(`^(?=.{1,253}$)${LABEL}(?:\\.${LABEL})*$`);
export const HOST_PATTERN_RE = new RegExp(`^(?=.{1,253}$)(?:\\*\\.)?${LABEL}(?:\\.${LABEL})*$`);

export interface ParsedCidr {
  addr: string;
  prefix: number;
  family: 'ipv4' | 'ipv6';
}

export function parseCidr(input: string): ParsedCidr | null {
  const [addr, prefixRaw, ...rest] = input.trim().split('/');
  if (!addr || rest.length) return null;
  const version = net.isIP(addr);
  if (!version) return null;
  const max = version === 4 ? 32 : 128;
  if (prefixRaw !== undefined && !/^\d{1,3}$/.test(prefixRaw)) return null;
  const prefix = prefixRaw === undefined ? max : Number(prefixRaw);
  if (prefix < 0 || prefix > max) return null;
  return { addr, prefix, family: version === 4 ? 'ipv4' : 'ipv6' };
}

/** "10.0.0.1" → "10.0.0.1/32"; rejects anything that is not an IP or CIDR. */
export const cidr = z
  .string()
  .trim()
  .max(64)
  .refine((v) => parseCidr(v) !== null, 'must be an IPv4/IPv6 address or CIDR (e.g. 10.20.0.0/16)')
  .transform((v) => {
    const p = parseCidr(v)!;
    return `${p.addr}/${p.prefix}`;
  });

export const ipAddress = z.string().trim().max(45).refine((v) => net.isIP(v) !== 0, 'must be an IPv4 or IPv6 address');
export const hostname = z.string().trim().toLowerCase().max(253).regex(HOSTNAME_RE, 'must be a valid DNS hostname');
export const hostOrIp = z
  .string()
  .trim()
  .toLowerCase()
  .max(253)
  .refine((v) => net.isIP(v) !== 0 || HOSTNAME_RE.test(v), 'must be a hostname or IP address');
export const hostPattern = z.string().trim().toLowerCase().max(253).regex(HOST_PATTERN_RE, 'must be a hostname, optionally prefixed with *.');

export function uniqueList<T extends z.ZodTypeAny>(item: T, max: number) {
  return z
    .array(item)
    .max(max)
    .transform((arr) => [...new Set(arr as unknown[])] as z.infer<T>[]);
}

/** BlockList-backed membership test; an empty list never matches. */
export function ipInCidrs(ip: string | null | undefined, cidrs: readonly string[]): boolean {
  if (!ip || cidrs.length === 0) return false;
  const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(ip);
  const addr = mapped ? mapped[1]! : ip;
  const family = net.isIPv6(addr) ? 'ipv6' : net.isIPv4(addr) ? 'ipv4' : null;
  if (!family) return false;
  const list = new net.BlockList();
  for (const c of cidrs) {
    const p = parseCidr(c);
    if (p) list.addSubnet(p.addr, p.prefix, p.family);
  }
  return list.check(addr, family);
}

/** Public base URL: https, host (name or IP), optional port, no path/query/credentials. */
export const publicBaseUrl = z
  .string()
  .trim()
  .max(300)
  .refine((v) => {
    try {
      const u = new URL(v);
      const host = u.hostname.replace(/^\[|\]$/g, '');
      return (
        u.protocol === 'https:' &&
        !u.username &&
        !u.password &&
        (u.pathname === '/' || u.pathname === '') &&
        !u.search &&
        !u.hash &&
        (net.isIP(host) !== 0 || HOSTNAME_RE.test(host))
      );
    } catch {
      return false;
    }
  }, 'must be https://<hostname-or-ip>[:port] without a path')
  .transform((v) => new URL(v).origin);
