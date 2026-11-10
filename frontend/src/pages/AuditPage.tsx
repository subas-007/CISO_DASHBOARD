import { useEffect, useState } from 'react';
import { Download, Fingerprint, Loader2, ShieldCheck, ShieldX } from 'lucide-react';
import { api, download, errorMessage } from '../lib/api';
import { useApi } from '../hooks/useApi';
import { Badge, Card, Empty, ErrorBox, Modal, Notice, PageHeader, Spinner } from '../components/ui';
import { fmtDateTime } from '../lib/format';
import type { AuditEntry, ChainVerification } from '../lib/types';

const OUTCOME_CLASS = {
  SUCCESS: 'bg-emerald-500/15 text-emerald-300 ring-emerald-500/40',
  FAILURE: 'bg-amber-500/15 text-amber-200 ring-amber-500/40',
  DENIED: 'bg-rose-500/15 text-rose-300 ring-rose-500/40',
} as const;

export function AuditPage() {
  const [action, setAction] = useState('');
  const [actor, setActor] = useState('');
  const [outcome, setOutcome] = useState('');
  const [from, setFrom] = useState('');
  const [to, setTo] = useState('');
  const [rows, setRows] = useState<AuditEntry[]>([]);
  const [nextBeforeId, setNext] = useState<string | null>(null);
  const [selected, setSelected] = useState<AuditEntry | null>(null);
  const [verify, setVerify] = useState<ChainVerification | null>(null);
  const [verifying, setVerifying] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const query = {
    action: action || undefined,
    actor: actor || undefined,
    outcome: outcome || undefined,
    from: from ? new Date(from).toISOString() : undefined,
    to: to ? new Date(to).toISOString() : undefined,
  };
  const actions = useApi(() => api<{ items: { action: string; count: number }[] }>('/audit/actions'));
  const page = useApi(() => api<{ items: AuditEntry[]; nextBeforeId: string | null }>('/audit', { query: { ...query, limit: 100 } }), [action, actor, outcome, from, to]);

  useEffect(() => {
    if (page.data) {
      setRows(page.data.items);
      setNext(page.data.nextBeforeId);
    }
  }, [page.data]);

  const more = async () => {
    if (!nextBeforeId) return;
    const res = await api<{ items: AuditEntry[]; nextBeforeId: string | null }>('/audit', { query: { ...query, limit: 100, beforeId: nextBeforeId } });
    setRows((r) => [...r, ...res.items]);
    setNext(res.nextBeforeId);
  };

  const runVerify = async () => {
    setVerifying(true);
    setErr(null);
    try {
      setVerify(await api<ChainVerification>('/audit/verify'));
    } catch (e) {
      setErr(errorMessage(e));
    } finally {
      setVerifying(false);
    }
  };

  const exportCsv = async () => {
    try {
      await download('/audit/export', query, `audit-log-${new Date().toISOString().slice(0, 10)}.csv`);
    } catch (e) {
      setErr(errorMessage(e));
    }
  };

  return (
    <div className="space-y-6">
      <PageHeader
        title="Immutable Security Audit Log"
        subtitle="Append-only, HMAC hash-chained records (NIST SP 800-53 AU, PCI DSS v4.0.1 Req. 10). Viewing, verification and export are themselves audited."
        actions={
          <>
            <button className="btn-secondary" disabled={verifying} onClick={() => void runVerify()}>
              {verifying ? <Loader2 className="h-4 w-4 animate-spin" /> : <Fingerprint className="h-4 w-4" />} Verify integrity
            </button>
            <button className="btn-secondary" onClick={() => void exportCsv()}>
              <Download className="h-4 w-4" /> Export CSV
            </button>
          </>
        }
      />
      {err && <ErrorBox message={err} />}
      {verify && (
        <Notice kind={verify.valid ? 'success' : 'error'}>
          <span className="flex items-center gap-2">
            {verify.valid ? <ShieldCheck className="h-4 w-4" /> : <ShieldX className="h-4 w-4" />}
            {verify.valid
              ? `Hash chain intact — ${verify.checked} records verified at ${fmtDateTime(verify.verifiedAt)}.`
              : `INTEGRITY FAILURE at record #${verify.firstInvalidId}: ${verify.reason}. Escalate immediately.`}
          </span>
        </Notice>
      )}
      <Card bodyClass="grid grid-cols-1 gap-3 md:grid-cols-5">
        <select className="input" value={action} onChange={(e) => setAction(e.target.value)} aria-label="Action">
          <option value="">All actions</option>
          {actions.data?.items.map((a) => <option key={a.action} value={a.action}>{a.action} ({a.count})</option>)}
        </select>
        <input className="input" placeholder="Actor name" maxLength={120} value={actor} onChange={(e) => setActor(e.target.value)} />
        <select className="input" value={outcome} onChange={(e) => setOutcome(e.target.value)} aria-label="Outcome">
          <option value="">Any outcome</option>
          <option>SUCCESS</option>
          <option>FAILURE</option>
          <option>DENIED</option>
        </select>
        <input className="input" type="datetime-local" value={from} onChange={(e) => setFrom(e.target.value)} aria-label="From" />
        <input className="input" type="datetime-local" value={to} onChange={(e) => setTo(e.target.value)} aria-label="To" />
      </Card>
      {page.error && <ErrorBox message={page.error} />}
      <Card bodyClass="p-0">
        {page.loading && !page.data ? <Spinner /> : rows.length === 0 ? <Empty>No audit records.</Empty> : (
          <div className="overflow-x-auto">
            <table className="table-base">
              <thead>
                <tr>
                  <th>#</th>
                  <th>Timestamp (UTC)</th>
                  <th>Actor</th>
                  <th>Action</th>
                  <th>Target</th>
                  <th>Outcome</th>
                  <th>Source IP</th>
                  <th>Hash</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((r) => (
                  <tr key={r.id} className="cursor-pointer" onClick={() => setSelected(r)}>
                    <td className="font-mono text-xs text-slate-500">{r.id}</td>
                    <td className="whitespace-nowrap font-mono text-xs">{r.ts.replace('T', ' ').slice(0, 23)}</td>
                    <td className="text-xs">
                      <div className="text-slate-200">{r.actorName ?? 'system'}</div>
                      <div className="text-slate-500">{r.actorRoles.join(', ')}</div>
                    </td>
                    <td className="font-mono text-xs text-sky-300">{r.action}</td>
                    <td className="text-xs text-slate-400">{r.targetType}{r.targetId && <div className="max-w-40 truncate font-mono text-slate-500">{r.targetId}</div>}</td>
                    <td><Badge className={OUTCOME_CLASS[r.outcome]}>{r.outcome}</Badge></td>
                    <td className="font-mono text-xs text-slate-400">{r.ip ?? '—'}</td>
                    <td className="font-mono text-xs text-slate-500">{r.hash.slice(0, 12)}…</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        {nextBeforeId && (
          <div className="border-t border-surface-800 p-3 text-center">
            <button className="btn-secondary" onClick={() => void more()}>Load older records</button>
          </div>
        )}
      </Card>
      {selected && (
        <Modal open wide title={`Audit record #${selected.id}`} onClose={() => setSelected(null)}>
          <dl className="grid grid-cols-[10rem_1fr] gap-x-4 gap-y-2 text-sm">
            {(['ts', 'actorName', 'actorId', 'action', 'targetType', 'targetId', 'outcome', 'ip', 'userAgent', 'prevHash', 'hash'] as const).map((k) => (
              <div key={k} className="contents">
                <dt className="text-slate-500">{k}</dt>
                <dd className="break-all font-mono text-xs text-slate-200">{String(selected[k] ?? '—')}</dd>
              </div>
            ))}
            <dt className="text-slate-500">details</dt>
            <dd>
              <pre className="max-h-80 overflow-auto rounded bg-surface-950 p-3 font-mono text-xs text-slate-300">{JSON.stringify(selected.details, null, 2)}</pre>
            </dd>
          </dl>
        </Modal>
      )}
    </div>
  );
}
