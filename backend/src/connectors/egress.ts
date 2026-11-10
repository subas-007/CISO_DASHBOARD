/**
 * Egress policy for connectors (SSRF defence, OWASP A10).
 *
 *  - https:// only (unless explicitly allowed for development)
 *  - optional hostname allowlist (supports *.example.com) and denylist
 *  - the lists and private-network blocking are administrator-defined at runtime
 *    (Configuration → Integration defaults); the environment values are a floor that
 *    the UI can extend but never weaken (internal zones, metadata endpoints)
 *  - IP checks happen at *connect time* inside the socket lookup, so DNS rebinding
 *    cannot swap in a forbidden address after validation.
 */
import dns from 'node:dns';
import net from 'node:net';
import { env } from '../config/env.js';

const list = (s: string) => s.split(',').map((x) => x.trim().toLowerCase()).filter(Boolean);
const envAllowedHosts = list(env.CONNECTOR_ALLOWED_HOSTS);
const envDeniedHosts = list(env.CONNECTOR_DENIED_HOSTS);

/** Effective runtime policy (env floor + administrator settings). */
export interface EgressPolicy {
  allowedHosts: string[];
  deniedHosts: string[];
  blockPrivateNetworks: boolean;
  timeoutMs: number;
  maxResponseBytes: number;
  maxRetries: number;
  retryBackoffMs: number;
}
let policy: EgressPolicy = {
  allowedHosts: envAllowedHosts,
  deniedHosts: envDeniedHosts,
  blockPrivateNetworks: env.CONNECTOR_BLOCK_PRIVATE_NETWORKS,
  timeoutMs: env.CONNECTOR_TIMEOUT_MS,
  maxResponseBytes: env.CONNECTOR_MAX_RESPONSE_BYTES,
  maxRetries: 2,
  retryBackoffMs: 1000,
};

export function egressPolicy(): Readonly<EgressPolicy> {
  return policy;
}

export function applyEgressPolicy(s: {
  allowedHosts: string[];
  deniedHosts: string[];
  blockPrivateNetworks: boolean;
  requestTimeoutMs: number;
  maxResponseMb: number;
  maxRetries: number;
  retryBackoffMs: number;
}): void {
  policy = {
    // An administrator allowlist replaces the env allowlist; when both are empty, any public host.
    allowedHosts: s.allowedHosts.length ? s.allowedHosts : envAllowedHosts,
    deniedHosts: [...new Set([...envDeniedHosts, ...s.deniedHosts])],
    blockPrivateNetworks: env.CONNECTOR_BLOCK_PRIVATE_NETWORKS || s.blockPrivateNetworks,
    timeoutMs: s.requestTimeoutMs,
    maxResponseBytes: Math.min(s.maxResponseMb * 1_048_576, 512 * 1_048_576),
    maxRetries: s.maxRetries,
    retryBackoffMs: s.retryBackoffMs,
  };
}

export async function refreshEgressPolicy(): Promise<void> {
  const { getSetting } = await import('../modules/settings/settings.service.js');
  applyEgressPolicy(await getSetting('connectorDefaults'));
}

const blockList = new net.BlockList();
// Always blocked: loopback, link-local (cloud metadata), unspecified, multicast, reserved.
for (const [addr, prefix] of [
  ['0.0.0.0', 8],
  ['127.0.0.0', 8],
  ['169.254.0.0', 16],
  ['100.100.100.200', 32],
  ['224.0.0.0', 4],
  ['240.0.0.0', 4],
] as const) blockList.addSubnet(addr, prefix, 'ipv4');
for (const [addr, prefix] of [
  ['::', 128],
  ['::1', 128],
  ['fe80::', 10],
  ['ff00::', 8],
  ['fd00:ec2::254', 128],
] as const) blockList.addSubnet(addr, prefix, 'ipv6');

const privateList = new net.BlockList();
for (const [addr, prefix] of [
  ['10.0.0.0', 8],
  ['172.16.0.0', 12],
  ['192.168.0.0', 16],
  ['100.64.0.0', 10],
] as const) privateList.addSubnet(addr, prefix, 'ipv4');
privateList.addSubnet('fc00::', 7, 'ipv6');

for (const cidr of list(env.CONNECTOR_BLOCKED_CIDRS)) {
  const [addr, prefix] = cidr.split('/');
  if (addr && prefix && net.isIP(addr)) {
    blockList.addSubnet(addr, Number(prefix), net.isIPv6(addr) ? 'ipv6' : 'ipv4');
  }
}

export function isBlockedAddress(address: string): boolean {
  // Normalise IPv4-mapped IPv6 (::ffff:127.0.0.1)
  const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(address);
  const ip = mapped ? mapped[1]! : address;
  const family = net.isIPv6(ip) ? 'ipv6' : 'ipv4';
  return blockList.check(ip, family) || (policy.blockPrivateNetworks && privateList.check(ip, family));
}

function hostMatches(host: string, pattern: string): boolean {
  if (pattern.startsWith('*.')) return host.endsWith(pattern.slice(1)) && host.length > pattern.length - 1;
  return host === pattern;
}

export class EgressPolicyError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'EgressPolicyError';
  }
}

/** Validates a connector URL against the static policy (scheme, host lists, no userinfo). */
export function assertUrlAllowed(url: URL): void {
  if (url.protocol !== 'https:' && !(env.CONNECTOR_ALLOW_INSECURE_HTTP && url.protocol === 'http:')) {
    throw new EgressPolicyError('Only https:// endpoints are permitted');
  }
  if (url.username || url.password) throw new EgressPolicyError('Credentials must not be embedded in URLs');
  const host = url.hostname.toLowerCase().replace(/^\[|\]$/g, '');
  if (policy.deniedHosts.some((p) => hostMatches(host, p))) throw new EgressPolicyError(`Host "${host}" is not permitted`);
  if (policy.allowedHosts.length > 0 && !policy.allowedHosts.some((p) => hostMatches(host, p))) {
    throw new EgressPolicyError(`Host "${host}" is not on the connector allowlist`);
  }
  if (net.isIP(host) && isBlockedAddress(host)) throw new EgressPolicyError('Destination address is blocked');
}

type LookupCallback = (err: NodeJS.ErrnoException | null, address: string | dns.LookupAddress[], family?: number) => void;

/** Socket-level DNS lookup that refuses blocked addresses (prevents DNS rebinding). */
export function guardedLookup(hostname: string, options: dns.LookupOptions, callback: LookupCallback): void {
  dns.lookup(hostname, { ...options, all: true }, (err, addresses) => {
    if (err) return callback(err, '');
    const list = addresses as dns.LookupAddress[];
    if (list.length === 0) return callback(Object.assign(new Error(`No address for ${hostname}`), { code: 'ENOTFOUND' }), '');
    if (list.some((a) => isBlockedAddress(a.address))) {
      return callback(Object.assign(new Error(`Destination for ${hostname} resolves to a blocked address`), { code: 'EBLOCKED' }), '');
    }
    if (options.all) return callback(null, list);
    return callback(null, list[0]!.address, list[0]!.family);
  });
}
