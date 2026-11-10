import { useState } from 'react';
import { Plus } from 'lucide-react';
import { api, errorMessage } from '../lib/api';
import { useApi } from '../hooks/useApi';
import { useLiveRefresh } from '../hooks/useEventStream';
import { Can, useAuth } from '../auth/AuthContext';
import { Badge, Card, Empty, ErrorBox, Field, Modal, Notice, PageHeader, SeverityBadge, Spinner } from '../components/ui';
import { fmtDateTime } from '../lib/format';
import type { Incident, Severity } from '../lib/types';

const STATUSES: Incident['status'][] = ['NEW', 'TRIAGE', 'CONTAINED', 'RESOLVED', 'CLOSED'];
const hours = (a: string, b: string | null) => (b ? ((new Date(b).getTime() - new Date(a).getTime()) / 3_600_000).toFixed(1) : '—');

export function IncidentsPage() {
  const [status, setStatus] = useState('');
  const [severity, setSeverity] = useState('');
  const [offset, setOffset] = useState(0);
  const list = useApi(() => api<{ total: number; items: Incident[] }>('/incidents', { query: { status, severity, limit: 50, offset } }), [status, severity, offset]);
  const [creating, setCreating] = useState(false);
  const { can } = useAuth();
  useLiveRefresh(['incidents'], () => void list.reload(true));

  const update = async (id: string, newStatus: Incident['status']) => {
    try {
      await api(`/incidents/${id}`, { method: 'PATCH', body: { status: newStatus } });
      void list.reload(true);
    } catch (e) {
      alert(errorMessage(e));
    }
  };

  return (
    <div className="space-y-6">
      <PageHeader
        title="Incidents"
        subtitle="Incidents from SIEM integrations and analyst logging. Lifecycle timestamps feed MTTD / MTTR."
        actions={
          <>
            <select className="input w-40" value={status} onChange={(e) => { setOffset(0); setStatus(e.target.value); }} aria-label="Status">
              <option value="">All statuses</option>
              {STATUSES.map((s) => <option key={s}>{s}</option>)}
            </select>
            <select className="input w-36" value={severity} onChange={(e) => { setOffset(0); setSeverity(e.target.value); }} aria-label="Severity">
              <option value="">All severities</option>
              {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].map((s) => <option key={s}>{s}</option>)}
            </select>
            <Can permission="incident:write">
              <button className="btn-primary" onClick={() => setCreating(true)}>
                <Plus className="h-4 w-4" /> Log incident
              </button>
            </Can>
          </>
        }
      />
      {list.error && <ErrorBox message={list.error} />}
      <Card bodyClass="p-0">
        {list.loading && !list.data ? (
          <Spinner />
        ) : !list.data?.items.length ? (
          <Empty>No incidents.</Empty>
        ) : (
          <div className="overflow-x-auto">
            <table className="table-base">
              <thead>
                <tr>
                  <th>Severity</th>
                  <th>Incident</th>
                  <th>Detected</th>
                  <th className="text-right">TTD (h)</th>
                  <th className="text-right">TTR (h)</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
                {list.data.items.map((i) => (
                  <tr key={i.id}>
                    <td><SeverityBadge severity={i.severity} /></td>
                    <td>
                      <div className="font-medium text-slate-100">{i.title}</div>
                      <div className="text-xs text-slate-500">{i.category} · {i.source} · {i.assetsAffected} assets</div>
                      {i.description && <div className="mt-1 line-clamp-2 text-xs text-slate-400">{i.description}</div>}
                    </td>
                    <td className="whitespace-nowrap text-xs text-slate-400">{fmtDateTime(i.detectedAt)}</td>
                    <td className="text-right tabular-nums">{hours(i.occurredAt, i.detectedAt)}</td>
                    <td className="text-right tabular-nums">{hours(i.detectedAt, i.resolvedAt)}</td>
                    <td>
                      {can('incident:write') ? (
                        <select className="input w-32 py-1 text-xs" value={i.status} onChange={(e) => void update(i.id, e.target.value as Incident['status'])} aria-label="Update status">
                          {STATUSES.map((s) => <option key={s}>{s}</option>)}
                        </select>
                      ) : (
                        <Badge>{i.status}</Badge>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        {list.data && list.data.total > 50 && (
          <div className="flex items-center justify-between border-t border-surface-800 px-4 py-2 text-xs text-slate-400">
            <span>
              {offset + 1}–{Math.min(offset + 50, list.data.total)} of {list.data.total}
            </span>
            <div className="flex gap-2">
              <button className="btn-secondary px-2 py-1" disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - 50))}>Previous</button>
              <button className="btn-secondary px-2 py-1" disabled={offset + 50 >= list.data.total} onClick={() => setOffset(offset + 50)}>Next</button>
            </div>
          </div>
        )}
      </Card>
      {creating && <CreateIncident onClose={() => setCreating(false)} onCreated={() => void list.reload(true)} />}
    </div>
  );
}

const localNow = () => new Date(Date.now() - new Date().getTimezoneOffset() * 60_000).toISOString().slice(0, 16);

function CreateIncident({ onClose, onCreated }: { onClose: () => void; onCreated: () => void }) {
  const [form, setForm] = useState({ title: '', description: '', severity: 'HIGH' as Severity, category: 'General', occurredAt: localNow(), detectedAt: localNow(), assetsAffected: 1 });
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const set = <K extends keyof typeof form>(k: K, v: (typeof form)[K]) => setForm((f) => ({ ...f, [k]: v }));
  const submit = async () => {
    setBusy(true);
    setError(null);
    try {
      await api('/incidents', {
        method: 'POST',
        body: {
          ...form,
          description: form.description || undefined,
          occurredAt: new Date(form.occurredAt).toISOString(),
          detectedAt: new Date(form.detectedAt).toISOString(),
        },
      });
      onCreated();
      onClose();
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setBusy(false);
    }
  };
  return (
    <Modal open title="Log security incident" onClose={onClose} footer={<><button className="btn-secondary" onClick={onClose}>Cancel</button><button className="btn-primary" disabled={busy} onClick={() => void submit()}>Create incident</button></>}>
      <div className="grid grid-cols-2 gap-4">
        {error && <div className="col-span-2"><Notice kind="error">{error}</Notice></div>}
        <div className="col-span-2"><Field label="Title"><input className="input" maxLength={200} value={form.title} onChange={(e) => set('title', e.target.value)} /></Field></div>
        <div className="col-span-2"><Field label="Description" hint="Encrypted at rest."><textarea className="input min-h-24" maxLength={8000} value={form.description} onChange={(e) => set('description', e.target.value)} /></Field></div>
        <Field label="Severity">
          <select className="input" value={form.severity} onChange={(e) => set('severity', e.target.value as Severity)}>
            {['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].map((s) => <option key={s}>{s}</option>)}
          </select>
        </Field>
        <Field label="Category"><input className="input" maxLength={60} value={form.category} onChange={(e) => set('category', e.target.value)} /></Field>
        <Field label="Occurred at"><input className="input" type="datetime-local" value={form.occurredAt} onChange={(e) => set('occurredAt', e.target.value)} /></Field>
        <Field label="Detected at"><input className="input" type="datetime-local" value={form.detectedAt} onChange={(e) => set('detectedAt', e.target.value)} /></Field>
        <Field label="Assets affected"><input className="input" type="number" min={0} value={form.assetsAffected} onChange={(e) => set('assetsAffected', Number(e.target.value))} /></Field>
      </div>
    </Modal>
  );
}
