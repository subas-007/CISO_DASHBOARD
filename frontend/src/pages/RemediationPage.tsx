import { useEffect, useState } from 'react';
import { ExternalLink, Link2, Search } from 'lucide-react';
import { api, errorMessage } from '../lib/api';
import { useApi } from '../hooks/useApi';
import { useLiveRefresh } from '../hooks/useEventStream';
import { Can, useAuth } from '../auth/AuthContext';
import { Badge, Card, Empty, ErrorBox, Field, Modal, Notice, PageHeader, SeverityBadge, Spinner } from '../components/ui';
import { fmtDate } from '../lib/format';
import type { Vulnerability } from '../lib/types';

const STATUSES = ['OPEN', 'IN_PROGRESS', 'REMEDIATED', 'RISK_ACCEPTED', 'FALSE_POSITIVE'];
const PAGE = 50;

export function RemediationPage() {
  const [status, setStatus] = useState('OPEN,IN_PROGRESS');
  const [severity, setSeverity] = useState('');
  const [overdue, setOverdue] = useState(false);
  const [q, setQ] = useState('');
  const [dq, setDq] = useState('');
  const [offset, setOffset] = useState(0);
  const [linking, setLinking] = useState<Vulnerability | null>(null);
  const { can } = useAuth();

  useEffect(() => {
    const t = setTimeout(() => { setDq(q.trim()); setOffset(0); }, 350);
    return () => clearTimeout(t);
  }, [q]);

  const list = useApi(
    () => api<{ total: number; items: Vulnerability[] }>('/vulnerabilities', { query: { status, severity, q: dq, overdue: overdue ? 'true' : undefined, limit: PAGE, offset } }),
    [status, severity, dq, overdue, offset],
  );
  useLiveRefresh(['vulnerabilities'], () => void list.reload(true));

  const setVulnStatus = async (v: Vulnerability, s: string) => {
    try {
      await api(`/vulnerabilities/${v.id}`, { method: 'PATCH', body: { status: s } });
      void list.reload(true);
    } catch (e) {
      alert(errorMessage(e));
    }
  };

  return (
    <div className="space-y-6">
      <PageHeader title="Vulnerability Remediation" subtitle="Remediation status tracking with SLA due dates and change-ticket linkage (ServiceNow / Jira)." />
      <Card bodyClass="flex flex-wrap items-center gap-2">
        <div className="relative min-w-60 flex-1">
          <Search className="pointer-events-none absolute left-3 top-2.5 h-4 w-4 text-slate-500" />
          <input className="input pl-9" placeholder="Search CVE, title or hostname…" maxLength={120} value={q} onChange={(e) => setQ(e.target.value)} />
        </div>
        <select className="input w-52" value={status} onChange={(e) => { setOffset(0); setStatus(e.target.value); }} aria-label="Status">
          <option value="OPEN,IN_PROGRESS">Open & in progress</option>
          <option value="">All statuses</option>
          {STATUSES.map((s) => <option key={s} value={s}>{s}</option>)}
        </select>
        <select className="input w-40" value={severity} onChange={(e) => { setOffset(0); setSeverity(e.target.value); }} aria-label="Severity">
          <option value="">All severities</option>
          {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((s) => <option key={s}>{s}</option>)}
        </select>
        <label className="flex items-center gap-2 text-sm text-slate-300">
          <input type="checkbox" checked={overdue} onChange={(e) => { setOffset(0); setOverdue(e.target.checked); }} /> Past SLA only
        </label>
      </Card>

      {list.error && <ErrorBox message={list.error} />}
      <Card bodyClass="p-0">
        {list.loading && !list.data ? (
          <Spinner />
        ) : !list.data?.items.length ? (
          <Empty>No findings match.</Empty>
        ) : (
          <div className="overflow-x-auto">
            <table className="table-base">
              <thead>
                <tr>
                  <th>Severity</th>
                  <th>Finding</th>
                  <th>Asset</th>
                  <th>Due (SLA)</th>
                  <th>Change ticket</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
                {list.data.items.map((v) => {
                  const overdueRow = v.dueAt && new Date(v.dueAt) < new Date() && ['OPEN', 'IN_PROGRESS'].includes(v.status);
                  return (
                    <tr key={v.id}>
                      <td><SeverityBadge severity={v.severity} /></td>
                      <td>
                        <div className="text-slate-100">{v.title}</div>
                        <div className="font-mono text-xs text-slate-500">{v.cveId ?? '—'}{v.cvss != null && ` · CVSS ${v.cvss}`} · {v.source}</div>
                      </td>
                      <td>
                        <div className="font-mono text-xs text-slate-300">{v.asset?.hostname}</div>
                        <div className="text-xs text-slate-500">{v.asset?.businessUnit} · crit {v.asset?.criticality}</div>
                      </td>
                      <td className={overdueRow ? 'text-xs font-medium text-rose-300' : 'text-xs text-slate-400'}>{fmtDate(v.dueAt)}{overdueRow && ' (overdue)'}</td>
                      <td>
                        {v.changeTicket ? (
                          <span className="inline-flex items-center gap-1 text-xs">
                            <Badge>{v.changeTicket.system}</Badge>
                            {v.changeTicket.url?.startsWith('https://') ? (
                              <a className="inline-flex items-center gap-1 text-sky-300 hover:underline" href={v.changeTicket.url} target="_blank" rel="noopener noreferrer">
                                {v.changeTicket.externalKey} <ExternalLink className="h-3 w-3" />
                              </a>
                            ) : (
                              <span className="text-slate-300">{v.changeTicket.externalKey}</span>
                            )}
                          </span>
                        ) : (
                          <Can permission="change:link" fallback={<span className="text-xs text-slate-500">—</span>}>
                            <button className="btn-ghost px-2 py-1 text-xs" onClick={() => setLinking(v)}>
                              <Link2 className="h-3.5 w-3.5" /> Link
                            </button>
                          </Can>
                        )}
                      </td>
                      <td>
                        {can('remediation:write') && v.status !== 'RISK_ACCEPTED' ? (
                          <select className="input w-36 py-1 text-xs" value={v.status} onChange={(e) => void setVulnStatus(v, e.target.value)} aria-label="Remediation status">
                            {['OPEN', 'IN_PROGRESS', 'REMEDIATED', 'FALSE_POSITIVE'].map((s) => <option key={s}>{s}</option>)}
                          </select>
                        ) : (
                          <Badge>{v.status}</Badge>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
        {list.data && list.data.total > PAGE && (
          <div className="flex items-center justify-between border-t border-surface-800 px-4 py-2 text-xs text-slate-400">
            <span>{offset + 1}–{Math.min(offset + PAGE, list.data.total)} of {list.data.total}</span>
            <div className="flex gap-2">
              <button className="btn-secondary px-2 py-1" disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - PAGE))}>Previous</button>
              <button className="btn-secondary px-2 py-1" disabled={offset + PAGE >= list.data.total} onClick={() => setOffset(offset + PAGE)}>Next</button>
            </div>
          </div>
        )}
      </Card>
      {linking && <LinkTicketModal vuln={linking} onClose={() => setLinking(null)} onDone={() => void list.reload(true)} />}
    </div>
  );
}

function LinkTicketModal({ vuln, onClose, onDone }: { vuln: Vulnerability; onClose: () => void; onDone: () => void }) {
  const [form, setForm] = useState({ system: 'ServiceNow', externalKey: '', title: '', url: '' });
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const tickets = useApi(() => api<{ items: { id: string; system: string; externalKey: string; title: string; status: string; url: string | null }[] }>('/change-tickets'));
  const submit = async () => {
    setBusy(true);
    setError(null);
    try {
      await api(`/vulnerabilities/${vuln.id}/change-ticket`, {
        method: 'POST',
        body: { system: form.system, externalKey: form.externalKey, title: form.title || undefined, url: form.url || undefined },
      });
      onDone();
      onClose();
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setBusy(false);
    }
  };
  return (
    <Modal open title={`Link change ticket — ${vuln.cveId ?? vuln.title}`} onClose={onClose} footer={<><button className="btn-secondary" onClick={onClose}>Cancel</button><button className="btn-primary" disabled={busy || !form.externalKey} onClick={() => void submit()}>Link ticket</button></>}>
      <div className="space-y-4">
        {error && <Notice kind="error">{error}</Notice>}
        {!!tickets.data?.items.length && (
          <Field label="Pick an existing ticket">
            <select className="input" value="" onChange={(e) => {
              const t = tickets.data!.items.find((x) => x.id === e.target.value);
              if (t) setForm({ system: t.system, externalKey: t.externalKey, title: t.title, url: t.url ?? '' });
            }}>
              <option value="">— select —</option>
              {tickets.data.items.map((t) => <option key={t.id} value={t.id}>{t.system} {t.externalKey} — {t.title} ({t.status})</option>)}
            </select>
          </Field>
        )}
        <div className="grid grid-cols-2 gap-4">
          <Field label="System"><input className="input" maxLength={80} value={form.system} onChange={(e) => setForm({ ...form, system: e.target.value })} /></Field>
          <Field label="Ticket key"><input className="input" maxLength={64} placeholder="CHG0041234" value={form.externalKey} onChange={(e) => setForm({ ...form, externalKey: e.target.value })} /></Field>
        </div>
        <Field label="Title (optional)"><input className="input" maxLength={300} value={form.title} onChange={(e) => setForm({ ...form, title: e.target.value })} /></Field>
        <Field label="URL (optional, https only)"><input className="input" maxLength={500} value={form.url} onChange={(e) => setForm({ ...form, url: e.target.value })} /></Field>
      </div>
    </Modal>
  );
}
