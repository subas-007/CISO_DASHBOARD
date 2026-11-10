import { Printer, ShieldCheck, ShieldX } from 'lucide-react';
import { api } from '../lib/api';
import { useApi } from '../hooks/useApi';
import { Badge, Card, ErrorBox, Notice, PageHeader, Spinner } from '../components/ui';
import { fmtDateTime, fmtNumber } from '../lib/format';

interface Report {
  generatedAt: string;
  auditChain: { valid: boolean; checked: number; firstInvalidId: string | null; reason: string | null };
  controls: { framework: string; id: string; title: string; status: 'IMPLEMENTED' | 'PARTIAL' | 'FAILED'; evidence: string }[];
  posture: { patchCompliancePct: number | null; openCriticalFindings: number; overdueFindings: number; mttdHours: number | null; mttrHours: number | null };
  riskAcceptances: Record<string, number>;
}

const STATUS = {
  IMPLEMENTED: 'bg-emerald-500/15 text-emerald-300 ring-emerald-500/40',
  PARTIAL: 'bg-amber-500/15 text-amber-200 ring-amber-500/40',
  FAILED: 'bg-rose-500/15 text-rose-300 ring-rose-500/40',
} as const;

export function CompliancePage() {
  const report = useApi(() => api<Report>('/compliance/report'));
  if (report.loading && !report.data) return <Spinner label="Generating report and verifying audit chain…" />;
  if (report.error || !report.data) return <ErrorBox message={report.error ?? 'Unavailable'} onRetry={() => void report.reload()} />;
  const r = report.data;
  const frameworks = [...new Set(r.controls.map((c) => c.framework))];

  return (
    <div className="space-y-6">
      <PageHeader
        title="Compliance Evidence Report"
        subtitle={`Generated ${fmtDateTime(r.generatedAt)} · read-only evidence for auditors`}
        actions={<button className="btn-secondary" onClick={() => window.print()}><Printer className="h-4 w-4" /> Print / PDF</button>}
      />
      <Notice kind={r.auditChain.valid ? 'success' : 'error'}>
        <span className="flex items-center gap-2">
          {r.auditChain.valid ? <ShieldCheck className="h-4 w-4" /> : <ShieldX className="h-4 w-4" />}
          Audit log integrity: {r.auditChain.valid ? `verified (${r.auditChain.checked} records)` : `FAILED at #${r.auditChain.firstInvalidId} — ${r.auditChain.reason}`}
        </span>
      </Notice>
      <div className="grid grid-cols-2 gap-4 md:grid-cols-5">
        {[
          ['Patch compliance', `${fmtNumber(r.posture.patchCompliancePct)}%`],
          ['Open critical', r.posture.openCriticalFindings],
          ['Past-SLA findings', r.posture.overdueFindings],
          ['MTTD', `${fmtNumber(r.posture.mttdHours)} h`],
          ['MTTR', `${fmtNumber(r.posture.mttrHours)} h`],
        ].map(([label, value]) => (
          <div key={label} className="card p-4">
            <div className="text-xs uppercase tracking-wide text-slate-400">{label}</div>
            <div className="mt-1 text-2xl font-semibold text-white">{value}</div>
          </div>
        ))}
      </div>
      {frameworks.map((fw) => (
        <Card key={fw} title={fw} bodyClass="p-0">
          <table className="table-base">
            <thead>
              <tr>
                <th className="w-24">Control</th>
                <th className="w-64">Title</th>
                <th className="w-32">Status</th>
                <th>Evidence</th>
              </tr>
            </thead>
            <tbody>
              {r.controls.filter((c) => c.framework === fw).map((c) => (
                <tr key={c.id}>
                  <td className="font-mono text-xs">{c.id}</td>
                  <td>{c.title}</td>
                  <td><Badge className={STATUS[c.status]}>{c.status}</Badge></td>
                  <td className="text-sm text-slate-400">{c.evidence}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </Card>
      ))}
      <Card title="Risk acceptance register summary">
        <div className="flex flex-wrap gap-3">
          {Object.entries(r.riskAcceptances).map(([k, v]) => <Badge key={k}>{k}: {v}</Badge>)}
          {Object.keys(r.riskAcceptances).length === 0 && <span className="text-sm text-slate-500">No acceptances recorded.</span>}
        </div>
      </Card>
    </div>
  );
}
