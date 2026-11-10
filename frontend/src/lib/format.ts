import type { Rag, RiskLevel, Severity } from './types';

export const fmtNumber = (n: number | null | undefined, dp = 1): string =>
  n == null ? '—' : n.toLocaleString(undefined, { maximumFractionDigits: dp });

export const fmtDate = (iso: string | null | undefined): string =>
  iso ? new Date(iso).toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: '2-digit' }) : '—';

export const fmtDateTime = (iso: string | null | undefined): string =>
  iso
    ? new Date(iso).toLocaleString(undefined, { year: 'numeric', month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit' })
    : '—';

export function timeAgo(iso: string | null | undefined): string {
  if (!iso) return 'never';
  const s = Math.round((Date.now() - new Date(iso).getTime()) / 1000);
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.round(s / 60)}m ago`;
  if (s < 86400) return `${Math.round(s / 3600)}h ago`;
  return `${Math.round(s / 86400)}d ago`;
}

export const severityClass: Record<Severity, string> = {
  CRITICAL: 'bg-rose-500/15 text-rose-300 ring-rose-500/40',
  HIGH: 'bg-orange-500/15 text-orange-300 ring-orange-500/40',
  MEDIUM: 'bg-amber-500/15 text-amber-200 ring-amber-500/40',
  LOW: 'bg-sky-500/15 text-sky-300 ring-sky-500/40',
  INFO: 'bg-slate-500/15 text-slate-300 ring-slate-500/40',
};

export const ragClass: Record<Rag, string> = {
  GREEN: 'bg-emerald-500/15 text-emerald-300 ring-emerald-500/40',
  AMBER: 'bg-amber-500/15 text-amber-200 ring-amber-500/40',
  RED: 'bg-rose-500/15 text-rose-300 ring-rose-500/40',
};

export const ragDot: Record<Rag, string> = {
  GREEN: 'bg-emerald-400',
  AMBER: 'bg-amber-400',
  RED: 'bg-rose-500',
};

export const riskCellClass: Record<RiskLevel, string> = {
  LOW: 'bg-emerald-600/25 hover:bg-emerald-600/40 border-emerald-500/30',
  MEDIUM: 'bg-amber-500/25 hover:bg-amber-500/40 border-amber-400/30',
  HIGH: 'bg-orange-600/30 hover:bg-orange-600/45 border-orange-500/30',
  CRITICAL: 'bg-rose-600/35 hover:bg-rose-600/50 border-rose-500/40',
};

export const LIKELIHOOD_LABELS = ['', 'Rare', 'Unlikely', 'Possible', 'Likely', 'Almost certain'];
export const IMPACT_LABELS = ['', 'Insignificant', 'Minor', 'Moderate', 'Major', 'Severe'];

export const ROLE_LABELS: Record<string, string> = {
  ADMIN: 'Administrator',
  CISO: 'CISO / Executive',
  SECOPS: 'SecOps Analyst',
  PATCH_ADMIN: 'IT / Patch Admin',
  AUDITOR: 'Auditor',
};

export const humanize = (s: string) => s.replace(/_/g, ' ').toLowerCase().replace(/^\w/, (c) => c.toUpperCase());
