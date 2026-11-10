import type { Severity } from '@prisma/client';

export function severityFromScore(score: number | null | undefined): Severity {
  if (score == null || Number.isNaN(score)) return 'MEDIUM';
  if (score >= 9) return 'CRITICAL';
  if (score >= 7) return 'HIGH';
  if (score >= 4) return 'MEDIUM';
  if (score > 0) return 'LOW';
  return 'INFO';
}

export function severityFromText(value: unknown, fallback: Severity = 'MEDIUM'): Severity {
  const v = String(value ?? '').toLowerCase();
  if (/crit|urgent|emergency|^5$/.test(v)) return 'CRITICAL';
  if (/high|severe|^4$/.test(v)) return 'HIGH';
  if (/med|moderate|^3$/.test(v)) return 'MEDIUM';
  if (/low|minor|^2$/.test(v)) return 'LOW';
  if (/info|none|^1$|^0$/.test(v)) return 'INFO';
  return fallback;
}

export function toDate(value: unknown, fallback: Date = new Date()): Date {
  if (value instanceof Date) return value;
  if (typeof value === 'number') return new Date(value < 1e12 ? value * 1000 : value);
  if (typeof value === 'string' && value) {
    const n = Number(value);
    if (!Number.isNaN(n) && /^\d+(\.\d+)?$/.test(value)) return toDate(n, fallback);
    const d = new Date(value);
    if (!Number.isNaN(d.getTime())) return d;
  }
  return fallback;
}

export function optDate(value: unknown): Date | null {
  if (value == null || value === '' || value === 0) return null;
  const d = toDate(value, new Date(NaN));
  return Number.isNaN(d.getTime()) ? null : d;
}

export function str(value: unknown, max = 500): string {
  if (value == null) return '';
  return String(value).replace(/[\u0000-\u001F\u007F]/g, ' ').trim().slice(0, max);
}

export function getPath(obj: unknown, path: string): unknown {
  if (!path) return obj;
  return path.split('.').reduce<unknown>((acc, key) => {
    if (acc && typeof acc === 'object') return (acc as Record<string, unknown>)[key];
    return undefined;
  }, obj);
}

const CVE_RE = /CVE-\d{4}-\d{4,7}/i;
export function extractCve(...values: unknown[]): string | null {
  for (const v of values) {
    const m = CVE_RE.exec(String(v ?? ''));
    if (m) return m[0].toUpperCase();
  }
  return null;
}

export function normHost(value: unknown): string {
  return str(value, 253).toLowerCase() || 'unknown-host';
}

export const asArray = <T>(v: T | T[] | undefined | null): T[] => (v == null ? [] : Array.isArray(v) ? v : [v]);
