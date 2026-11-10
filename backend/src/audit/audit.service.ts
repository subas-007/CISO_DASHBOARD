/**
 * Immutable, tamper-evident security audit log.
 *
 * Controls supported:
 *   NIST SP 800-53: AU-2 (event logging), AU-3 (content), AU-8 (timestamps),
 *                   AU-9 (protection), AU-10 (non-repudiation), AU-12 (generation)
 *   PCI DSS v4.0.1: 10.2.1.x (events), 10.2.2 (content), 10.3.2 (protection), 10.3.4 (integrity)
 *
 * Every record carries prevHash and hash = HMAC-SHA256(AUDIT_HMAC_KEY, prevHash|canonical(record)).
 * Writes are serialised with a transaction-scoped advisory lock so the chain is linear.
 * The table itself is append-only (DB triggers + revoked UPDATE/DELETE privileges).
 */
import type { Request } from 'express';
import type { Prisma } from '@prisma/client';
import { env } from '../config/env.js';
import { hmacHex } from '../lib/crypto.js';
import { logger } from '../lib/logger.js';
import { prisma, type Tx } from '../lib/prisma.js';

export const AUDIT_GENESIS_HASH = '0'.repeat(64);
const AUDIT_LOCK_KEY = 7243001;

export type AuditOutcome = 'SUCCESS' | 'FAILURE' | 'DENIED';

export interface AuditActor {
  id?: string | null;
  name?: string | null;
  roles?: readonly string[];
}

export interface AuditEvent {
  action: string;
  outcome: AuditOutcome;
  actor?: AuditActor;
  targetType?: string;
  targetId?: string;
  ip?: string | null;
  userAgent?: string | null;
  details?: Record<string, unknown>;
}

const SENSITIVE_KEY = /(password|secret|token|apikey|api_key|credential|passphrase|clientkey|private)/i;

/** Remove anything credential-like from audit details (audit logs must never hold secrets). */
export function sanitizeDetails(value: unknown, depth = 0): unknown {
  if (depth > 6) return '[depth-limit]';
  if (Array.isArray(value)) return value.slice(0, 100).map((v) => sanitizeDetails(v, depth + 1));
  if (value && typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      out[k] = SENSITIVE_KEY.test(k) ? '[REDACTED]' : sanitizeDetails(v, depth + 1);
    }
    return out;
  }
  if (typeof value === 'string') return value.length > 2000 ? `${value.slice(0, 2000)}…` : value;
  if (value instanceof Date) return value.toISOString();
  return value ?? null;
}

/** Deterministic JSON (sorted keys) so the hash is reproducible after a DB round-trip. */
export function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value ?? null);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  const entries = Object.entries(value as Record<string, unknown>)
    .filter(([, v]) => v !== undefined)
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${canonicalJson(v)}`).join(',')}}`;
}

export interface HashableAuditRecord {
  ts: string;
  actorId: string | null;
  actorName: string | null;
  actorRoles: string[];
  action: string;
  targetType: string | null;
  targetId: string | null;
  outcome: string;
  ip: string | null;
  userAgent: string | null;
  details: unknown;
}

export function computeAuditHash(prevHash: string, record: HashableAuditRecord): string {
  return hmacHex(env.AUDIT_HMAC_KEY, `${prevHash}|${canonicalJson(record)}`);
}

/** Append an audit record inside an existing transaction (atomic with the audited change). */
export async function writeAudit(tx: Tx, event: AuditEvent): Promise<void> {
  await tx.$executeRaw`SELECT pg_advisory_xact_lock(${AUDIT_LOCK_KEY})`;
  const last = await tx.auditLog.findFirst({ orderBy: { id: 'desc' }, select: { hash: true } });
  const prevHash = last?.hash ?? AUDIT_GENESIS_HASH;
  const ts = new Date();
  const record: HashableAuditRecord = {
    ts: ts.toISOString(),
    actorId: event.actor?.id ?? null,
    actorName: event.actor?.name ?? null,
    actorRoles: [...(event.actor?.roles ?? [])],
    action: event.action,
    targetType: event.targetType ?? null,
    targetId: event.targetId ?? null,
    outcome: event.outcome,
    ip: event.ip ?? null,
    userAgent: event.userAgent ? event.userAgent.slice(0, 256) : null,
    details: sanitizeDetails(event.details ?? {}),
  };
  const hash = computeAuditHash(prevHash, record);
  await tx.auditLog.create({
    data: {
      ...record,
      ts,
      details: record.details as Prisma.InputJsonValue,
      prevHash,
      hash,
    },
  });
}

/** Standalone audit write. Throws on failure (fail-closed) unless `bestEffort` is set. */
export async function audit(event: AuditEvent, opts: { bestEffort?: boolean } = {}): Promise<void> {
  try {
    await prisma.$transaction((tx) => writeAudit(tx, event));
  } catch (err) {
    logger.error({ err, action: event.action }, 'AUDIT WRITE FAILED');
    if (!opts.bestEffort) throw err;
  }
}

/** Build actor + origin information from an authenticated request. */
export function auditContext(req: Request): Pick<AuditEvent, 'actor' | 'ip' | 'userAgent'> {
  return {
    actor: req.auth ? { id: req.auth.userId, name: req.auth.name, roles: req.auth.roles } : undefined,
    ip: req.ip ?? null,
    userAgent: req.get('user-agent') ?? null,
  };
}

export interface ChainVerification {
  valid: boolean;
  checked: number;
  firstInvalidId: string | null;
  reason: string | null;
  lastHash: string | null;
}

/** Recompute the entire hash chain. Detects modification, deletion and re-ordering. */
export async function verifyAuditChain(): Promise<ChainVerification> {
  let prevHash = AUDIT_GENESIS_HASH;
  let checked = 0;
  let cursor: bigint | undefined;
  const pageSize = 1000;
  for (;;) {
    const rows = await prisma.auditLog.findMany({
      where: cursor !== undefined ? { id: { gt: cursor } } : undefined,
      orderBy: { id: 'asc' },
      take: pageSize,
    });
    if (rows.length === 0) break;
    for (const row of rows) {
      if (row.prevHash !== prevHash) {
        return { valid: false, checked, firstInvalidId: row.id.toString(), reason: 'Broken chain link (record missing or re-ordered)', lastHash: prevHash };
      }
      const expected = computeAuditHash(prevHash, {
        ts: row.ts.toISOString(),
        actorId: row.actorId,
        actorName: row.actorName,
        actorRoles: row.actorRoles,
        action: row.action,
        targetType: row.targetType,
        targetId: row.targetId,
        outcome: row.outcome,
        ip: row.ip,
        userAgent: row.userAgent,
        details: row.details,
      });
      if (expected !== row.hash) {
        return { valid: false, checked, firstInvalidId: row.id.toString(), reason: 'Record content does not match its hash', lastHash: prevHash };
      }
      prevHash = row.hash;
      checked += 1;
    }
    cursor = rows[rows.length - 1]!.id;
  }
  return { valid: true, checked, firstInvalidId: null, reason: null, lastHash: checked ? prevHash : null };
}
