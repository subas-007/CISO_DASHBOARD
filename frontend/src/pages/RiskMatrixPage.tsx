import { useState } from 'react';
import { ChevronRight, Plus, Server } from 'lucide-react';
import { api, errorMessage } from '../lib/api';
import { useApi } from '../hooks/useApi';
import { useLiveRefresh } from '../hooks/useEventStream';
import { Can } from '../auth/AuthContext';
import { RiskMatrix } from '../components/RiskMatrix';
import { Badge, Card, Empty, ErrorBox, Field, Modal, Notice, PageHeader, SeverityBadge, Spinner } from '../components/ui';
import { fmtDate, IMPACT_LABELS, LIKELIHOOD_LABELS, riskCellClass } from '../lib/format';
import type { Asset, MatrixCell, RiskDetail, RiskLevel } from '../lib/types';

const levelBadge: Record<RiskLevel, string> = {
  LOW: 'bg-emerald-500/15 text-emerald-300 ring-emerald-500/40',
  MEDIUM: 'bg-amber-500/15 text-amber-200 ring-amber-500/40',
  HIGH: 'bg-orange-500/15 text-orange-300 ring-orange-500/40',
  CRITICAL: 'bg-rose-500/15 text-rose-300 ring-rose-500/40',
};

export function RiskMatrixPage() {
  const matrix = useApi(() => api<{ cells: MatrixCell[]; appetite: number; total: number }>('/risks/matrix'));
  const [cell, setCell] = useState<MatrixCell | null>(null);
  const [riskId, setRiskId] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);
  useLiveRefresh(['risks'], () => void matrix.reload(true));

  // keep the selected cell in sync after live refreshes
  const selected = cell && matrix.data ? matrix.data.cells.find((c) => c.likelihood === cell.likelihood && c.impact === cell.impact) ?? null : null;

  return (
    <div className="space-y-6">
      <PageHeader
        title="ISO 31000 Risk Matrix"
        subtitle="5×5 likelihood × impact. Select a cell to drill into risks, linked assets and their open vulnerabilities."
        actions={
          <Can permission="risk:write">
            <button className="btn-primary" onClick={() => setCreating(true)}>
              <Plus className="h-4 w-4" /> Register risk
            </button>
          </Can>
        }
      />
      {matrix.error && <ErrorBox message={matrix.error} onRetry={() => void matrix.reload()} />}
      <div className="grid grid-cols-1 gap-6 xl:grid-cols-5">
        <Card className="xl:col-span-3" title={`Inherent risk heat map — ${matrix.data?.total ?? 0} open risks`}>
          {matrix.data ? (
            <>
              <RiskMatrix cells={matrix.data.cells} selected={selected} onSelect={setCell} />
              <div className="mt-4 flex flex-wrap items-center gap-3 text-xs text-slate-400">
                {(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'] as RiskLevel[]).map((l) => (
                  <span key={l} className="flex items-center gap-1.5">
                    <span className={`h-3 w-3 rounded-sm border ${riskCellClass[l]}`} /> {l}
                  </span>
                ))}
                <span className="flex items-center gap-1.5">
                  <span className="h-3 w-3 rounded-sm border border-dashed border-slate-300" /> above appetite (score &gt; {matrix.data.appetite})
                </span>
              </div>
            </>
          ) : (
            <Spinner />
          )}
        </Card>

        <Card className="xl:col-span-2" title={selected ? `L${selected.likelihood} × I${selected.impact} — ${LIKELIHOOD_LABELS[selected.likelihood]} / ${IMPACT_LABELS[selected.impact]}` : 'Risks in cell'} bodyClass="p-0">
          {!selected ? (
            <Empty>Select a matrix cell to list its risks.</Empty>
          ) : selected.risks.length === 0 ? (
            <Empty>No open risks in this cell.</Empty>
          ) : (
            <ul className="divide-y divide-surface-800">
              {selected.risks.map((r) => (
                <li key={r.id}>
                  <button className="flex w-full items-center justify-between gap-3 px-4 py-3 text-left hover:bg-surface-850" onClick={() => setRiskId(r.id)}>
                    <div>
                      <div className="text-sm font-medium text-slate-100">{r.title}</div>
                      <div className="mt-1 text-xs text-slate-500">
                        {r.category} · Owner: {r.ownerName} · {r.status}
                      </div>
                    </div>
                    <ChevronRight className="h-4 w-4 text-slate-500" />
                  </button>
                </li>
              ))}
            </ul>
          )}
        </Card>
      </div>

      {riskId && <RiskDrilldown id={riskId} onClose={() => setRiskId(null)} />}
      {creating && <CreateRiskModal onClose={() => setCreating(false)} onCreated={() => void matrix.reload(true)} />}
    </div>
  );
}

function RiskDrilldown({ id, onClose }: { id: string; onClose: () => void }) {
  const risk = useApi(() => api<RiskDetail>(`/risks/${id}`), [id]);
  const [requesting, setRequesting] = useState(false);
  useLiveRefresh(['risks', 'vulnerabilities'], () => void risk.reload(true));
  const r = risk.data;

  return (
    <Modal open title={r ? r.title : 'Risk detail'} onClose={onClose} wide>
      {risk.loading && !r && <Spinner />}
      {risk.error && <ErrorBox message={risk.error} />}
      {r && (
        <div className="space-y-5">
          <div className="flex flex-wrap items-center gap-2">
            <Badge className={levelBadge[r.level]}>
              {r.level} · score {r.score}
            </Badge>
            <Badge>L{r.likelihood} {LIKELIHOOD_LABELS[r.likelihood]}</Badge>
            <Badge>I{r.impact} {IMPACT_LABELS[r.impact]}</Badge>
            <Badge>{r.category}</Badge>
            <Badge>{r.status}</Badge>
            <span className="text-xs text-slate-400">Owner: {r.ownerName}</span>
          </div>
          <p className="whitespace-pre-wrap text-sm text-slate-300">{r.description}</p>
          {r.treatment && <Notice>Treatment: {r.treatment}</Notice>}

          <div>
            <h4 className="mb-2 flex items-center gap-2 text-sm font-semibold text-white">
              <Server className="h-4 w-4" /> Linked assets & open vulnerabilities ({r.assets.length})
            </h4>
            <div className="space-y-3">
              {r.assets.map((a: Asset) => (
                <details key={a.id} className="rounded-lg border border-surface-700 bg-surface-950/50" open={r.assets.length <= 2}>
                  <summary className="flex cursor-pointer items-center justify-between gap-3 px-3 py-2 text-sm">
                    <span className="font-mono text-slate-200">{a.hostname}</span>
                    <span className="flex items-center gap-2 text-xs text-slate-400">
                      {a.businessUnit} · crit {a.criticality}/5 ·{' '}
                      <span className={a.patchCompliant ? 'text-emerald-300' : 'text-rose-300'}>{a.patchCompliant ? 'patched' : `${a.missingPatches} patches missing`}</span>
                      · {a.vulnerabilities?.length ?? 0} open vulns
                    </span>
                  </summary>
                  {a.vulnerabilities && a.vulnerabilities.length > 0 ? (
                    <table className="table-base">
                      <thead>
                        <tr>
                          <th>Severity</th>
                          <th>Finding</th>
                          <th>Status</th>
                          <th>Due</th>
                        </tr>
                      </thead>
                      <tbody>
                        {a.vulnerabilities.map((v) => (
                          <tr key={v.id}>
                            <td>
                              <SeverityBadge severity={v.severity} />
                            </td>
                            <td>
                              <div className="text-slate-200">{v.title}</div>
                              <div className="font-mono text-xs text-slate-500">
                                {v.cveId ?? '—'} {v.cvss != null && `· CVSS ${v.cvss}`}
                              </div>
                            </td>
                            <td className="text-xs">{v.status}</td>
                            <td className={`text-xs ${v.dueAt && new Date(v.dueAt) < new Date() ? 'text-rose-300' : 'text-slate-400'}`}>{fmtDate(v.dueAt)}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  ) : (
                    <div className="px-3 pb-3 text-xs text-slate-500">No open vulnerabilities.</div>
                  )}
                </details>
              ))}
              {r.assets.length === 0 && <Empty>No assets linked.</Empty>}
            </div>
          </div>

          <div>
            <div className="mb-2 flex items-center justify-between">
              <h4 className="text-sm font-semibold text-white">Risk acceptance history</h4>
              <Can permission="risk:acceptance:request">
                {!r.acceptances.some((a) => a.status === 'PENDING' || a.status === 'APPROVED') && r.status !== 'CLOSED' && (
                  <button className="btn-secondary" onClick={() => setRequesting(true)}>
                    Request acceptance
                  </button>
                )}
              </Can>
            </div>
            {r.acceptances.length === 0 ? (
              <p className="text-sm text-slate-500">No acceptance requests.</p>
            ) : (
              <ul className="space-y-2">
                {r.acceptances.map((a) => (
                  <li key={a.id} className="rounded-lg border border-surface-700 px-3 py-2 text-sm">
                    <div className="flex items-center justify-between">
                      <span className="font-medium">{a.status}</span>
                      <span className="text-xs text-slate-500">expires {fmtDate(a.expiresAt)}</span>
                    </div>
                    <p className="mt-1 text-slate-300">{a.justification}</p>
                    <p className="mt-1 text-xs text-slate-500">
                      Requested by {a.requestedByName} on {fmtDate(a.requestedAt)}
                      {a.decidedByName && ` · decided by ${a.decidedByName}: ${a.decisionNote ?? ''}`}
                    </p>
                  </li>
                ))}
              </ul>
            )}
          </div>
        </div>
      )}
      {requesting && r && <RequestAcceptanceModal riskId={r.id} onClose={() => setRequesting(false)} onDone={() => void risk.reload(true)} />}
    </Modal>
  );
}

export function RequestAcceptanceModal({ riskId, onClose, onDone }: { riskId: string; onClose: () => void; onDone: () => void }) {
  const [justification, setJustification] = useState('');
  const [days, setDays] = useState(90);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const submit = async () => {
    setBusy(true);
    setError(null);
    try {
      await api(`/risks/${riskId}/acceptances`, { method: 'POST', body: { justification, expiresInDays: days } });
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
      title="Request risk acceptance"
      onClose={onClose}
      footer={
        <>
          <button className="btn-secondary" onClick={onClose}>
            Cancel
          </button>
          <button className="btn-primary" disabled={busy || justification.trim().length < 20} onClick={() => void submit()}>
            Submit for CISO approval
          </button>
        </>
      }
    >
      <div className="space-y-4">
        {error && <Notice kind="error">{error}</Notice>}
        <Field label="Business justification & compensating controls" hint="Minimum 20 characters. Stored encrypted (AES-256-GCM).">
          <textarea className="input min-h-32" maxLength={4000} value={justification} onChange={(e) => setJustification(e.target.value)} />
        </Field>
        <Field label="Validity (days)" hint="Acceptance expires automatically and the risk re-opens.">
          <input className="input" type="number" min={1} max={365} value={days} onChange={(e) => setDays(Number(e.target.value))} />
        </Field>
      </div>
    </Modal>
  );
}

function CreateRiskModal({ onClose, onCreated }: { onClose: () => void; onCreated: () => void }) {
  const [form, setForm] = useState({ title: '', description: '', category: 'Cyber', likelihood: 3, impact: 3, ownerName: '', treatment: '' });
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const set = <K extends keyof typeof form>(k: K, v: (typeof form)[K]) => setForm((f) => ({ ...f, [k]: v }));
  const submit = async () => {
    setBusy(true);
    setError(null);
    try {
      await api('/risks', { method: 'POST', body: { ...form, treatment: form.treatment || undefined, assetIds: [] } });
      onCreated();
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
      title="Register risk"
      onClose={onClose}
      footer={
        <>
          <button className="btn-secondary" onClick={onClose}>
            Cancel
          </button>
          <button className="btn-primary" disabled={busy} onClick={() => void submit()}>
            Save risk
          </button>
        </>
      }
    >
      <div className="grid grid-cols-2 gap-4">
        {error && (
          <div className="col-span-2">
            <Notice kind="error">{error}</Notice>
          </div>
        )}
        <div className="col-span-2">
          <Field label="Title">
            <input className="input" maxLength={200} value={form.title} onChange={(e) => set('title', e.target.value)} />
          </Field>
        </div>
        <div className="col-span-2">
          <Field label="Description">
            <textarea className="input min-h-24" maxLength={4000} value={form.description} onChange={(e) => set('description', e.target.value)} />
          </Field>
        </div>
        <Field label="Category">
          <input className="input" maxLength={80} value={form.category} onChange={(e) => set('category', e.target.value)} />
        </Field>
        <Field label="Risk owner">
          <input className="input" maxLength={120} value={form.ownerName} onChange={(e) => set('ownerName', e.target.value)} />
        </Field>
        <Field label="Likelihood (1-5)">
          <select className="input" value={form.likelihood} onChange={(e) => set('likelihood', Number(e.target.value))}>
            {[1, 2, 3, 4, 5].map((n) => (
              <option key={n} value={n}>
                {n} — {LIKELIHOOD_LABELS[n]}
              </option>
            ))}
          </select>
        </Field>
        <Field label="Impact (1-5)">
          <select className="input" value={form.impact} onChange={(e) => set('impact', Number(e.target.value))}>
            {[1, 2, 3, 4, 5].map((n) => (
              <option key={n} value={n}>
                {n} — {IMPACT_LABELS[n]}
              </option>
            ))}
          </select>
        </Field>
        <div className="col-span-2">
          <Field label="Treatment plan (optional)">
            <textarea className="input" maxLength={2000} value={form.treatment} onChange={(e) => set('treatment', e.target.value)} />
          </Field>
        </div>
      </div>
    </Modal>
  );
}
