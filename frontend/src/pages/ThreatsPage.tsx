import { useEffect, useState } from 'react';
import clsx from 'clsx';
import { Bug, Link2, Package, Radar, Search, ShieldAlert, Skull } from 'lucide-react';
import { api, errorMessage } from '../lib/api';
import { useApi } from '../hooks/useApi';
import { useLiveRefresh } from '../hooks/useEventStream';
import { Can } from '../auth/AuthContext';
import { Badge, Card, Empty, ErrorBox, Notice, PageHeader, SeverityBadge, Spinner } from '../components/ui';
import { fmtDateTime, timeAgo } from '../lib/format';
import type { Severity, ThreatItem } from '../lib/types';

const TYPES: { key: ThreatItem['type']; label: string; icon: typeof Bug }[] = [
  { key: 'CVE', label: 'CVEs', icon: Bug },
  { key: 'RANSOMWARE', label: 'Ransomware', icon: Skull },
  { key: 'SUPPLY_CHAIN', label: 'Supply chain', icon: Package },
  { key: 'ADVISORY', label: 'Advisories', icon: ShieldAlert },
  { key: 'IOC', label: 'IOCs', icon: Link2 },
];
const TYPE_LABEL: Record<ThreatItem['type'], string> = {
  CVE: 'CVE',
  RANSOMWARE: 'Ransomware',
  SUPPLY_CHAIN: 'Supply chain',
  ADVISORY: 'Advisory',
  IOC: 'IOC',
};
const SEVERITIES: Severity[] =['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];

interface ThreatPage {
  items: ThreatItem[];
  nextCursor: string | null;
  facets: { severity: Record<string, number>; type: Record<string, number> };
}

export function ThreatsPage() {
  const [types, setTypes] = useState<string[]>([]);
  const [severities, setSeverities] = useState<string[]>([]);
  const [status, setStatus] = useState('');
  const [source, setSource] = useState('');
  const [q, setQ] = useState('');
  const [debouncedQ, setDebouncedQ] = useState('');
  const [impactedOnly, setImpactedOnly] = useState(false);
  const [newCount, setNewCount] = useState(0);
  const [items, setItems] = useState<ThreatItem[]>([]);
  const [cursor, setCursor] = useState<string | null>(null);

  useEffect(() => {
    const t = setTimeout(() => setDebouncedQ(q.trim()), 350);
    return () => clearTimeout(t);
  }, [q]);

  const query = { type: types, severity: severities, status, source, q: debouncedQ, impactedOnly: impactedOnly ? 'true' : undefined, limit: 50 };
  const page = useApi(() => api<ThreatPage>('/threats', { query }), [types.join(), severities.join(), status, source, debouncedQ, impactedOnly]);
  const sources = useApi(() => api<{ items: { source: string; count: number }[] }>('/threats/sources'));

  useEffect(() => {
    if (page.data) {
      setItems(page.data.items);
      setCursor(page.data.nextCursor);
      setNewCount(0);
    }
  }, [page.data]);

  useLiveRefresh(['threats'], () => {
    setNewCount((n) => n + 1);
    void page.reload(true);
    void sources.reload(true);
  });

  const loadMore = async () => {
    if (!cursor) return;
    const next = await api<ThreatPage>('/threats', { query: { ...query, cursor } });
    setItems((prev) => [...prev, ...next.items]);
    setCursor(next.nextCursor);
  };

  const toggle = (list: string[], set: (v: string[]) => void, v: string) => set(list.includes(v) ? list.filter((x) => x !== v) : [...list, v]);

  return (
    <div className="space-y-6">
      <PageHeader
        title="Threat Intelligence & Incident Stream"
        subtitle="Real-time feed of CVEs, ransomware advisories and supply-chain risks, correlated with your asset inventory."
        actions={newCount > 0 ? <Badge className="bg-sky-500/15 text-sky-200 ring-sky-500/40">Live update received</Badge> : undefined}
      />

      <Card bodyClass="space-y-3">
        <div className="flex flex-wrap items-center gap-2">
          <div className="relative min-w-60 flex-1">
            <Search className="pointer-events-none absolute left-3 top-2.5 h-4 w-4 text-slate-500" />
            <input className="input pl-9" placeholder="Search title, CVE or tag…" maxLength={120} value={q} onChange={(e) => setQ(e.target.value)} />
          </div>
          <select className="input w-52" value={source} onChange={(e) => setSource(e.target.value)} aria-label="Source">
            <option value="">All sources</option>
            {sources.data?.items.map((s) => (
              <option key={s.source} value={s.source}>
                {s.source} ({s.count})
              </option>
            ))}
          </select>
          <select className="input w-40" value={status} onChange={(e) => setStatus(e.target.value)} aria-label="Status">
            <option value="">Any status</option>
            {['NEW', 'TRIAGED', 'ACTIONED', 'DISMISSED'].map((s) => (
              <option key={s}>{s}</option>
            ))}
          </select>
          <label className="flex items-center gap-2 text-sm text-slate-300">
            <input type="checkbox" checked={impactedOnly} onChange={(e) => setImpactedOnly(e.target.checked)} /> Impacting my assets
          </label>
        </div>
        <div className="flex flex-wrap gap-2">
          {TYPES.map(({ key, label, icon: Icon }) => (
            <button key={key} className={clsx('btn px-2.5 py-1 text-xs', types.includes(key) ? 'bg-sky-500/20 text-sky-200 ring-1 ring-sky-500/50' : 'border border-surface-700 text-slate-300')} onClick={() => toggle(types, setTypes, key)}>
              <Icon className="h-3.5 w-3.5" /> {label}
              <span className="text-slate-500">{page.data?.facets.type[key] ?? 0}</span>
            </button>
          ))}
          <span className="mx-1 w-px bg-surface-700" />
          {SEVERITIES.map((s) => (
            <button key={s} className={clsx('btn px-2.5 py-1 text-xs', severities.includes(s) ? 'bg-sky-500/20 text-sky-200 ring-1 ring-sky-500/50' : 'border border-surface-700 text-slate-300')} onClick={() => toggle(severities, setSeverities, s)}>
              {s} <span className="text-slate-500">{page.data?.facets.severity[s] ?? 0}</span>
            </button>
          ))}
        </div>
      </Card>

      {page.error && <ErrorBox message={page.error} onRetry={() => void page.reload()} />}
      {page.loading && !page.data ? (
        <Spinner />
      ) : items.length === 0 ? (
        <Card>
          <Empty>No intelligence matches these filters.</Empty>
        </Card>
      ) : (
        <div className="space-y-3">
          {items.map((t) => (
            <ThreatRow key={t.id} item={t} onChanged={(u) => setItems((prev) => prev.map((x) => (x.id === u.id ? u : x)))} />
          ))}
          {cursor && (
            <div className="text-center">
              <button className="btn-secondary" onClick={() => void loadMore()}>
                Load more
              </button>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function ThreatRow({ item, onChanged }: { item: ThreatItem; onChanged: (t: ThreatItem) => void }) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const TypeIcon = TYPES.find((t) => t.key === item.type)?.icon ?? Radar;

  const triage = async (status: ThreatItem['status']) => {
    setBusy(true);
    setError(null);
    try {
      onChanged(await api<ThreatItem>(`/threats/${item.id}`, { method: 'PATCH', body: { status } }));
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <article className={clsx('card flex gap-4 p-4', item.status === 'DISMISSED' && 'opacity-60')}>
      <TypeIcon className="mt-1 h-5 w-5 shrink-0 text-sky-400" aria-hidden />
      <div className="min-w-0 flex-1">
        <div className="flex flex-wrap items-start justify-between gap-2">
          <h3 className="text-sm font-semibold text-white">{item.title}</h3>
          <div className="flex items-center gap-2">
            <SeverityBadge severity={item.severity} />
            <Badge>{TYPE_LABEL[item.type]}</Badge>
            <Badge>{item.status}</Badge>
          </div>
        </div>
        <p className="mt-1 line-clamp-3 text-sm text-slate-400">{item.summary}</p>
        <div className="mt-2 flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-slate-500">
          <span title="Source attribution">
            Source: <span className="text-slate-300">{item.source}</span>
          </span>
          <span title={fmtDateTime(item.publishedAt)}>Published {timeAgo(item.publishedAt)}</span>
          {item.cveId && <span className="font-mono text-slate-300">{item.cveId}</span>}
          <span className={item.impactedAssetCount > 0 ? 'font-medium text-rose-300' : ''}>Impacted assets: {item.impactedAssetCount}</span>
          {item.tags.slice(0, 6).map((t) => (
            <span key={t} className="rounded bg-surface-800 px-1.5 py-0.5 text-slate-400">
              #{t}
            </span>
          ))}
        </div>
        {error && (
          <div className="mt-2">
            <Notice kind="error">{error}</Notice>
          </div>
        )}
      </div>
      <Can permission="threat:triage">
        <div className="flex shrink-0 flex-col gap-1">
          {item.status !== 'TRIAGED' && (
            <button className="btn-secondary px-2 py-1 text-xs" disabled={busy} onClick={() => void triage('TRIAGED')}>
              Triage
            </button>
          )}
          {item.status !== 'ACTIONED' && (
            <button className="btn-secondary px-2 py-1 text-xs" disabled={busy} onClick={() => void triage('ACTIONED')}>
              Actioned
            </button>
          )}
          {item.status !== 'DISMISSED' && (
            <button className="btn-ghost px-2 py-1 text-xs" disabled={busy} onClick={() => void triage('DISMISSED')}>
              Dismiss
            </button>
          )}
        </div>
      </Can>
    </article>
  );
}
