/**
 * Renders any configuration parameter from the server-provided field descriptors, so new
 * parameters appear in the UI without frontend changes. Validation is authoritative on
 * the server; field-level issues are shown next to the inputs.
 */
import { useEffect, useState } from 'react';
import clsx from 'clsx';
import { AlertTriangle, Check, CloudCog, Loader2, Save, Server, ShieldCheck, Zap } from 'lucide-react';
import { api, ApiError, errorMessage } from '../lib/api';
import type { ApplyMode, SettingField, SettingItem, SettingSaveResult } from '../lib/types';
import { Badge, Notice, Toggle } from './ui';

export const APPLY_LABEL: Record<ApplyMode, { label: string; className: string; icon: typeof Zap; help: string }> = {
  live: { label: 'Live', className: 'bg-emerald-500/15 text-emerald-300 ring-emerald-500/40', icon: Zap, help: 'Takes effect within seconds, no restart' },
  identity: { label: 'IdP sync', className: 'bg-violet-500/15 text-violet-300 ring-violet-500/40', icon: ShieldCheck, help: 'Pushed to the identity provider immediately' },
  redeploy: { label: 'Redeploy', className: 'bg-amber-500/15 text-amber-300 ring-amber-500/40', icon: CloudCog, help: 'Applied on the Docker host with scripts/apply-deployment.sh' },
  host: { label: 'Host script', className: 'bg-sky-500/15 text-sky-300 ring-sky-500/40', icon: Server, help: 'Applied by running the generated host baseline script' },
};

export function ApplyBadge({ mode }: { mode: ApplyMode }) {
  const a = APPLY_LABEL[mode];
  const Icon = a.icon;
  return (
    <span title={a.help}>
      <Badge className={a.className}>
        <Icon className="h-3 w-3" /> {a.label}
      </Badge>
    </span>
  );
}

const getPath = (obj: unknown, path: string): unknown => (path ? path.split('.').reduce<unknown>((a, k) => (a as Record<string, unknown> | undefined)?.[k], obj) : obj);

function setPath(obj: unknown, path: string, value: unknown): unknown {
  if (!path) return value;
  const [head, ...rest] = path.split('.');
  const base = (obj ?? {}) as Record<string, unknown>;
  return { ...base, [head!]: setPath(base[head!], rest.join('.'), value) };
}

function FieldInput({ field, value, disabled, onChange, ariaLabel, bare }: { field: SettingField; value: unknown; disabled: boolean; onChange: (v: unknown) => void; ariaLabel: string; bare?: boolean }) {
  switch (field.type) {
    case 'boolean':
      return <Toggle label={ariaLabel} checked={value === true} disabled={disabled} onChange={onChange} />;
    case 'select': {
      const numeric = typeof field.options?.[0]?.value === 'number';
      return (
        <select className="input" aria-label={ariaLabel} disabled={disabled} value={String(value ?? '')} onChange={(e) => onChange(numeric ? Number(e.target.value) : e.target.value)}>
          {field.options?.map((o) => <option key={String(o.value)} value={String(o.value)}>{o.label}</option>)}
        </select>
      );
    }
    case 'list':
      return (
        <ListInput ariaLabel={ariaLabel} disabled={disabled} placeholder={field.placeholder} value={Array.isArray(value) ? (value as string[]) : []} onChange={onChange} />
      );
    case 'number': {
      const input = (
        <input
          className="input"
          type="number"
          aria-label={ariaLabel}
          disabled={disabled}
          min={field.min}
          max={field.max}
          value={value === undefined || value === null ? '' : String(value)}
          onChange={(e) => onChange(e.target.value === '' ? '' : Number(e.target.value))}
        />
      );
      if (bare || !field.unit) return input;
      return (
        <div className="flex items-center gap-2">
          {input}
          <span className="shrink-0 text-xs text-slate-500">{field.unit}</span>
        </div>
      );
    }
    default:
      return <input className="input font-mono text-sm" aria-label={ariaLabel} disabled={disabled} placeholder={field.placeholder} value={String(value ?? '')} onChange={(e) => onChange(e.target.value)} />;
  }
}

/** One entry per line; keeps the raw text while editing so blank lines don't jump. */
function ListInput({ value, onChange, disabled, placeholder, ariaLabel }: { value: string[]; onChange: (v: string[]) => void; disabled: boolean; placeholder?: string; ariaLabel: string }) {
  const [text, setText] = useState(value.join('\n'));
  useEffect(() => {
    if (text.split('\n').map((s) => s.trim()).filter(Boolean).join('\n') !== value.join('\n')) setText(value.join('\n'));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [value.join('\n')]);
  return (
    <textarea
      className="input min-h-20 font-mono text-xs"
      aria-label={ariaLabel}
      spellCheck={false}
      disabled={disabled}
      placeholder={placeholder ? `${placeholder}\n(one per line)` : 'one per line'}
      value={text}
      onChange={(e) => {
        setText(e.target.value);
        onChange(e.target.value.split('\n').map((s) => s.trim()).filter(Boolean));
      }}
    />
  );
}

export function SettingForm({ item, onSaved, compact }: { item: SettingItem; onSaved?: (r: SettingSaveResult) => void; compact?: boolean }) {
  const [draft, setDraft] = useState<unknown>(item.value);
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<SettingSaveResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [issues, setIssues] = useState<Record<string, string>>({});
  const dirty = JSON.stringify(draft) !== JSON.stringify(item.value);

  useEffect(() => setDraft(item.value), [item.value]);

  const save = async () => {
    setBusy(true);
    setError(null);
    setIssues({});
    setResult(null);
    try {
      const r = await api<SettingSaveResult>(`/admin/settings/${item.key}`, { method: 'PUT', body: { value: draft } });
      setResult(r);
      onSaved?.(r);
    } catch (e) {
      setError(errorMessage(e));
      if (e instanceof ApiError && e.issues) {
        setIssues(Object.fromEntries(e.issues.map((i) => [i.path.replace(/^value\.?/, ''), i.message])));
      }
    } finally {
      setBusy(false);
    }
  };

  const saveButton = item.editable && (
    <button className="btn-secondary" disabled={busy || !dirty} onClick={() => void save()} aria-label="Save" title={`Save ${item.label}`}>
      {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : result?.applied.ok ? <Check className="h-4 w-4 text-emerald-300" /> : <Save className="h-4 w-4" />}
      {!compact && ' Save'}
    </button>
  );

  // Compact scalar layout (e.g. KRI & Parameters page): label, input and save button on one row.
  if (compact && item.fields.length === 1 && item.fields[0]!.path === '') {
    const f = item.fields[0]!;
    return (
      <div>
        <div className="label">{item.label}</div>
        <div className="flex gap-2">
          <FieldInput bare field={f} ariaLabel={item.label} value={draft} disabled={!item.editable} onChange={setDraft} />
          {saveButton}
        </div>
        {!item.editable && <div className="mt-1 text-xs text-slate-500">Requires {item.permission}</div>}
        {error && <div className="mt-1 text-xs text-rose-300">{error}</div>}
      </div>
    );
  }

  return (
    <section className="card" aria-label={item.label}>
      <header className="flex flex-wrap items-start justify-between gap-3 border-b border-surface-700/60 px-4 py-3">
        <div className="min-w-0">
          <h3 className="text-sm font-semibold text-slate-100">{item.label}</h3>
          <p className="mt-1 max-w-3xl text-xs text-slate-400">{item.description}</p>
        </div>
        <div className="flex items-center gap-2">
          <ApplyBadge mode={item.apply} />
          {saveButton}
        </div>
      </header>
      <div className="space-y-3 p-4">
        {(result?.warnings ?? item.warnings).map((w) => (
          <div key={w} className="flex items-start gap-2 rounded-lg border border-amber-500/30 bg-amber-500/10 px-3 py-2 text-xs text-amber-200" role="note">
            <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0" /> {w}
          </div>
        ))}
        <div className="grid grid-cols-1 gap-x-6 gap-y-4 md:grid-cols-2">
          {item.fields.map((f) => {
            const id = f.path || item.key;
            return (
              <div key={id} className={clsx(f.type === 'list' && 'md:col-span-1', f.type === 'boolean' && 'flex items-center justify-between gap-3 rounded-lg border border-surface-700/60 px-3 py-2')}>
                <div className={clsx(f.type !== 'boolean' && 'label')}>
                  <span className={clsx(f.type === 'boolean' && 'text-sm text-slate-200')}>{f.label}</span>
                  {f.type === 'boolean' && f.help && <span className="block text-xs text-slate-500">{f.help}</span>}
                </div>
                <FieldInput field={f} ariaLabel={f.label} value={getPath(draft, f.path)} disabled={!item.editable} onChange={(v) => setDraft(setPath(draft, f.path, v))} />
                {f.type !== 'boolean' && f.help && <div className="mt-1 text-xs text-slate-500">{f.help}</div>}
                {issues[f.path] && <div className="mt-1 text-xs text-rose-300">{issues[f.path]}</div>}
              </div>
            );
          })}
        </div>
        {!item.editable && <div className="text-xs text-slate-500">Read-only — requires {item.permission}</div>}
        {error && <Notice kind="error">{error}</Notice>}
        {result && <Notice kind={result.applied.ok ? 'success' : 'error'}>{result.applied.message}</Notice>}
      </div>
    </section>
  );
}
