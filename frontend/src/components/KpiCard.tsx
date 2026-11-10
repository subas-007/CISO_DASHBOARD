import clsx from 'clsx';
import type { LucideIcon } from 'lucide-react';
import { ArrowDownRight, ArrowUpRight, Minus } from 'lucide-react';
import { fmtNumber } from '../lib/format';

interface Props {
  label: string;
  value: number | null;
  unit?: string;
  delta?: number | null;
  /** Whether a decrease is an improvement (e.g. MTTR). */
  lowerIsBetter?: boolean;
  icon: LucideIcon;
  hint?: string;
  accent?: string;
}

export function KpiCard({ label, value, unit, delta, lowerIsBetter, icon: Icon, hint, accent = 'text-sky-400' }: Props) {
  const improving = delta == null || delta === 0 ? null : lowerIsBetter ? delta < 0 : delta > 0;
  const DeltaIcon = delta == null || delta === 0 ? Minus : delta > 0 ? ArrowUpRight : ArrowDownRight;
  return (
    <div className="card flex flex-col justify-between p-4">
      <div className="flex items-start justify-between">
        <span className="text-xs font-medium uppercase tracking-wide text-slate-400">{label}</span>
        <Icon className={clsx('h-5 w-5', accent)} aria-hidden />
      </div>
      <div className="mt-3 flex items-baseline gap-1">
        <span className="text-3xl font-semibold tabular-nums text-white">{fmtNumber(value)}</span>
        {unit && value != null && <span className="text-sm text-slate-400">{unit}</span>}
      </div>
      <div className="mt-2 flex items-center justify-between text-xs">
        <span
          className={clsx(
            'inline-flex items-center gap-1 tabular-nums',
            improving == null ? 'text-slate-500' : improving ? 'text-emerald-400' : 'text-rose-400',
          )}
          title="Change vs. 7 days ago"
        >
          <DeltaIcon className="h-3.5 w-3.5" />
          {delta == null ? 'no baseline' : `${delta > 0 ? '+' : ''}${fmtNumber(delta)} vs 7d`}
        </span>
        {hint && <span className="text-slate-500">{hint}</span>}
      </div>
    </div>
  );
}
