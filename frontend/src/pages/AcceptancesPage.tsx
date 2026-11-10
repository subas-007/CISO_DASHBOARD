import { useState } from 'react';
import { Check, Undo2, X } from 'lucide-react';
import { api, errorMessage } from '../lib/api';
import { useApi } from '../hooks/useApi';
import { useLiveRefresh } from '../hooks/useEventStream';
import { useAuth } from '../auth/AuthContext';
import { Badge, Card, Empty, ErrorBox, Field, Modal, Notice, PageHeader, Spinner } from '../components/ui';
import { fmtDate } from '../lib/format';
import type { Acceptance } from '../lib/types';

const STATUS_CLASS: Record<Acceptance['status'], string> = {
  PENDING: 'bg-amber-500/15 text-amber-200 ring-amber-500/40',
  APPROVED: 'bg-emerald-500/15 text-emerald-300 ring-emerald-500/40',
  REJECTED: 'bg-rose-500/15 text-rose-300 ring-rose-500/40',
  EXPIRED: 'bg-slate-500/15 text-slate-300 ring-slate-500/40',
  REVOKED: 'bg-slate-500/15 text-slate-300 ring-slate-500/40',
};

export function AcceptancesPage() {
  const [status, setStatus] = useState<string>('');
  const list = useApi(() => api<{ items: Acceptance[] }>('/risk-acceptances', { query: { status } }), [status]);
  const { can, me } = useAuth();
  const [action, setAction] = useState<{ item: Acceptance; kind: 'APPROVE' | 'REJECT' | 'REVOKE' } | null>(null);
  useLiveRefresh(['risks'], () => void list.reload(true));

  return (
    <div className="space-y-6">
      <PageHeader
        title="Risk Acceptance"
        subtitle="Formal acceptance of residual risk. Approval is restricted to the CISO with segregation of duties; acceptances expire automatically."
        actions={
          <select className="input w-44" value={status} onChange={(e) => setStatus(e.target.value)} aria-label="Filter status">
            <option value="">All statuses</option>
            {Object.keys(STATUS_CLASS).map((s) => (
              <option key={s}>{s}</option>
            ))}
          </select>
        }
      />
      {list.error && <ErrorBox message={list.error} />}
      <Card bodyClass="p-0">
        {list.loading && !list.data ? (
          <Spinner />
        ) : !list.data?.items.length ? (
          <Empty>No acceptance requests.</Empty>
        ) : (
          <table className="table-base">
            <thead>
              <tr>
                <th>Risk</th>
                <th>Justification</th>
                <th>Requested</th>
                <th>Expires</th>
                <th>Status</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {list.data.items.map((a) => (
                <tr key={a.id}>
                  <td>
                    <div className="font-medium text-slate-100">{a.risk?.title}</div>
                    <div className="text-xs text-slate-500">
                      {a.risk?.category} · score {(a.risk?.likelihood ?? 0) * (a.risk?.impact ?? 0)}
                    </div>
                  </td>
                  <td className="max-w-md text-sm text-slate-300">
                    {a.justification}
                    {a.decisionNote && <div className="mt-1 text-xs text-slate-500">Decision: {a.decisionNote}</div>}
                  </td>
                  <td className="text-xs text-slate-400">
                    {a.requestedByName}
                    <br />
                    {fmtDate(a.requestedAt)}
                  </td>
                  <td className="text-xs text-slate-400">{fmtDate(a.expiresAt)}</td>
                  <td>
                    <Badge className={STATUS_CLASS[a.status]}>{a.status}</Badge>
                  </td>
                  <td className="whitespace-nowrap text-right">
                    {can('risk:acceptance:approve') && a.status === 'PENDING' && (
                      a.requestedById === me?.user.id ? (
                        <span className="text-xs text-slate-500" title="Segregation of duties">Own request</span>
                      ) : (
                        <div className="flex justify-end gap-2">
                          <button className="btn-secondary px-2 py-1 text-emerald-300" onClick={() => setAction({ item: a, kind: 'APPROVE' })}>
                            <Check className="h-4 w-4" /> Approve
                          </button>
                          <button className="btn-secondary px-2 py-1 text-rose-300" onClick={() => setAction({ item: a, kind: 'REJECT' })}>
                            <X className="h-4 w-4" /> Reject
                          </button>
                        </div>
                      )
                    )}
                    {can('risk:acceptance:approve') && a.status === 'APPROVED' && (
                      <button className="btn-secondary px-2 py-1" onClick={() => setAction({ item: a, kind: 'REVOKE' })}>
                        <Undo2 className="h-4 w-4" /> Revoke
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>
      {action && <DecisionModal {...action} onClose={() => setAction(null)} onDone={() => void list.reload(true)} />}
    </div>
  );
}

function DecisionModal({ item, kind, onClose, onDone }: { item: Acceptance; kind: 'APPROVE' | 'REJECT' | 'REVOKE'; onClose: () => void; onDone: () => void }) {
  const [note, setNote] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const submit = async () => {
    setBusy(true);
    setError(null);
    try {
      if (kind === 'REVOKE') await api(`/risk-acceptances/${item.id}/revoke`, { method: 'POST', body: { note } });
      else await api(`/risk-acceptances/${item.id}/decision`, { method: 'POST', body: { decision: kind, note } });
      onDone();
      onClose();
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setBusy(false);
    }
  };
  return (
    <Modal
      open
      title={`${kind === 'APPROVE' ? 'Approve' : kind === 'REJECT' ? 'Reject' : 'Revoke'} acceptance — ${item.risk?.title ?? ''}`}
      onClose={onClose}
      footer={
        <>
          <button className="btn-secondary" onClick={onClose}>
            Cancel
          </button>
          <button className={kind === 'APPROVE' ? 'btn-primary' : 'btn-danger'} disabled={busy || note.trim().length < 5} onClick={() => void submit()}>
            Confirm
          </button>
        </>
      }
    >
      <div className="space-y-4">
        {error && <Notice kind="error">{error}</Notice>}
        <Notice>This decision is recorded in the immutable audit log with your identity.</Notice>
        <Field label="Decision rationale">
          <textarea className="input min-h-24" maxLength={2000} value={note} onChange={(e) => setNote(e.target.value)} />
        </Field>
      </div>
    </Modal>
  );
}
