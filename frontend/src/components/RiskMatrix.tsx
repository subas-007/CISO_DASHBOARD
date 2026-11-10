import clsx from 'clsx';
import { IMPACT_LABELS, LIKELIHOOD_LABELS, riskCellClass } from '../lib/format';
import type { MatrixCell } from '../lib/types';

interface Props {
  cells: MatrixCell[];
  selected?: { likelihood: number; impact: number } | null;
  onSelect?: (cell: MatrixCell) => void;
  compact?: boolean;
}

/** Interactive 5x5 ISO 31000 likelihood × impact heat map. */
export function RiskMatrix({ cells, selected, onSelect, compact }: Props) {
  const rows = [5, 4, 3, 2, 1];
  const cols = [1, 2, 3, 4, 5];
  const get = (l: number, i: number) => cells.find((c) => c.likelihood === l && c.impact === i);

  return (
    <div className="flex gap-2">
      <div className="flex items-center">
        <span className="-rotate-180 text-xs font-semibold uppercase tracking-wider text-slate-400 [writing-mode:vertical-rl]">Likelihood →</span>
      </div>
      <div className="flex-1">
        <div className="grid grid-cols-[auto_repeat(5,minmax(0,1fr))] gap-1.5" role="grid" aria-label="Risk matrix">
          {rows.map((l) => (
            <div key={l} className="contents" role="row">
              <div className="flex items-center justify-end pr-2 text-right text-[11px] leading-tight text-slate-400">
                {compact ? l : (
                  <span>
                    <span className="font-semibold text-slate-300">{l}</span> {LIKELIHOOD_LABELS[l]}
                  </span>
                )}
              </div>
              {cols.map((i) => {
                const cell = get(l, i);
                const isSel = selected?.likelihood === l && selected?.impact === i;
                if (!cell) return <div key={i} />;
                return (
                  <button
                    key={i}
                    role="gridcell"
                    type="button"
                    disabled={!onSelect}
                    onClick={() => onSelect?.(cell)}
                    aria-label={`Likelihood ${l}, impact ${i}: ${cell.count} risks, ${cell.level}`}
                    className={clsx(
                      'relative flex flex-col items-center justify-center rounded-md border transition',
                      compact ? 'h-10' : 'h-16 sm:h-20',
                      riskCellClass[cell.level],
                      isSel && 'ring-2 ring-white',
                      cell.aboveAppetite && 'border-dashed',
                    )}
                  >
                    <span className={clsx('font-semibold tabular-nums text-white', compact ? 'text-sm' : 'text-xl')}>{cell.count || ''}</span>
                    {!compact && <span className="absolute bottom-1 right-1.5 text-[10px] text-white/50">{cell.score}</span>}
                  </button>
                );
              })}
            </div>
          ))}
          <div />
          {cols.map((i) => (
            <div key={i} className="pt-1 text-center text-[11px] leading-tight text-slate-400">
              {compact ? i : (
                <span>
                  <span className="font-semibold text-slate-300">{i}</span> {IMPACT_LABELS[i]}
                </span>
              )}
            </div>
          ))}
        </div>
        <div className="mt-2 text-center text-xs font-semibold uppercase tracking-wider text-slate-400">Impact →</div>
      </div>
    </div>
  );
}
