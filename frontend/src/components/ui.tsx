import { useEffect, useId, useRef, type ReactNode } from 'react';
import clsx from 'clsx';
import { AlertTriangle, Loader2, X } from 'lucide-react';
import { ragClass, ragDot, severityClass } from '../lib/format';
import type { Rag, Severity } from '../lib/types';

export function Card({ title, actions, children, className, bodyClass }: { title?: ReactNode; actions?: ReactNode; children: ReactNode; className?: string; bodyClass?: string }) {
  return (
    <section className={clsx('card', className)}>
      {(title || actions) && (
        <header className="flex items-center justify-between gap-3 border-b border-surface-700/60 px-4 py-3">
          <h2 className="text-sm font-semibold text-slate-100">{title}</h2>
          {actions && <div className="flex items-center gap-2">{actions}</div>}
        </header>
      )}
      <div className={clsx('p-4', bodyClass)}>{children}</div>
    </section>
  );
}

export function PageHeader({ title, subtitle, actions }: { title: string; subtitle?: string; actions?: ReactNode }) {
  return (
    <div className="mb-6 flex flex-wrap items-end justify-between gap-4">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight text-white">{title}</h1>
        {subtitle && <p className="mt-1 text-sm text-slate-400">{subtitle}</p>}
      </div>
      {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
    </div>
  );
}

export function Badge({ children, className }: { children: ReactNode; className?: string }) {
  return <span className={clsx('inline-flex items-center gap-1 whitespace-nowrap rounded-md px-2 py-0.5 text-xs font-medium ring-1 ring-inset', className ?? 'bg-slate-500/15 text-slate-300 ring-slate-500/30')}>{children}</span>;
}

export const SeverityBadge = ({ severity }: { severity: Severity }) => <Badge className={severityClass[severity]}>{severity}</Badge>;

export function RagBadge({ status }: { status: Rag | null }) {
  if (!status) return <Badge>N/A</Badge>;
  return (
    <Badge className={ragClass[status]}>
      <span className={clsx('h-2 w-2 rounded-full', ragDot[status])} />
      {status}
    </Badge>
  );
}

export function Spinner({ label = 'Loading…' }: { label?: string }) {
  return (
    <div className="flex items-center justify-center gap-2 py-10 text-sm text-slate-400" role="status">
      <Loader2 className="h-4 w-4 animate-spin" /> {label}
    </div>
  );
}

export function ErrorBox({ message, onRetry }: { message: string; onRetry?: () => void }) {
  return (
    <div className="flex items-center justify-between gap-3 rounded-lg border border-rose-500/30 bg-rose-500/10 px-4 py-3 text-sm text-rose-200" role="alert">
      <span className="flex items-center gap-2">
        <AlertTriangle className="h-4 w-4 shrink-0" /> {message}
      </span>
      {onRetry && (
        <button className="btn-secondary" onClick={onRetry}>
          Retry
        </button>
      )}
    </div>
  );
}

export function Empty({ children }: { children: ReactNode }) {
  return <div className="py-10 text-center text-sm text-slate-500">{children}</div>;
}

export function Modal({ open, title, onClose, children, footer, wide }: { open: boolean; title: string; onClose: () => void; children: ReactNode; footer?: ReactNode; wide?: boolean }) {
  const ref = useRef<HTMLDialogElement>(null);
  const titleId = useId();
  useEffect(() => {
    const d = ref.current;
    if (!d) return;
    if (open && !d.open) d.showModal();
    if (!open && d.open) d.close();
  }, [open]);
  return (
    <dialog
      ref={ref}
      onClose={onClose}
      aria-labelledby={titleId}
      className={clsx(
        'm-auto max-h-[90vh] w-[calc(100%-2rem)] overflow-hidden rounded-xl border border-surface-700 bg-surface-900 p-0 text-slate-200 shadow-2xl backdrop:bg-black/70',
        wide ? 'max-w-5xl' : 'max-w-xl',
      )}
    >
      {open && (
        <div className="flex max-h-[90vh] flex-col">
          <header className="flex items-center justify-between border-b border-surface-700 px-5 py-3">
            <h3 id={titleId} className="text-base font-semibold text-white">{title}</h3>
            <button className="btn-ghost p-1" onClick={onClose} aria-label="Close">
              <X className="h-4 w-4" />
            </button>
          </header>
          <div className="overflow-y-auto px-5 py-4">{children}</div>
          {footer && <footer className="flex justify-end gap-2 border-t border-surface-700 px-5 py-3">{footer}</footer>}
        </div>
      )}
    </dialog>
  );
}

export function Field({ label, children, hint }: { label: string; children: ReactNode; hint?: string }) {
  return (
    <label className="block">
      <span className="label">{label}</span>
      {children}
      {hint && <span className="mt-1 block text-xs text-slate-500">{hint}</span>}
    </label>
  );
}

export function Toggle({ checked, onChange, label, disabled }: { checked: boolean; onChange: (v: boolean) => void; label: string; disabled?: boolean }) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      aria-label={label}
      disabled={disabled}
      onClick={() => onChange(!checked)}
      className={clsx('relative inline-flex h-5 w-9 shrink-0 items-center rounded-full transition disabled:opacity-50', checked ? 'bg-sky-500' : 'bg-surface-700')}
    >
      <span className={clsx('inline-block h-4 w-4 transform rounded-full bg-white transition', checked ? 'translate-x-4' : 'translate-x-0.5')} />
    </button>
  );
}

export function Notice({ kind = 'info', children }: { kind?: 'info' | 'success' | 'error'; children: ReactNode }) {
  const cls = {
    info: 'border-sky-500/30 bg-sky-500/10 text-sky-200',
    success: 'border-emerald-500/30 bg-emerald-500/10 text-emerald-200',
    error: 'border-rose-500/30 bg-rose-500/10 text-rose-200',
  }[kind];
  return <div className={clsx('rounded-lg border px-3 py-2 text-sm', cls)}>{children}</div>;
}
