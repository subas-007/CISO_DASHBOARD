import { Link } from 'react-router-dom';
import { Activity, AlertOctagon, Clock, Gauge, Radar, ShieldAlert, Timer, TrendingUp, Wrench } from 'lucide-react';
import { api } from '../lib/api';
import { useApi } from '../hooks/useApi';
import { useLiveRefresh } from '../hooks/useEventStream';
import { KpiCard } from '../components/KpiCard';
import { TrendChart } from '../components/TrendChart';
import { RiskMatrix } from '../components/RiskMatrix';
import { Badge, Card, ErrorBox, PageHeader, RagBadge, SeverityBadge, Spinner } from '../components/ui';
import { fmtDateTime, fmtNumber, timeAgo } from '../lib/format';
import type { KpiSummary, MatrixCell, ThreatItem, TrendResponse } from '../lib/types';

export function DashboardPage() {
  const summary = useApi(() => api<KpiSummary>('/kpi/summary'));
  const trends = useApi(() =>
    api<TrendResponse>('/kpi/trends', {
      query: { metrics: 'mttdHours,mttrHours,patchCompliancePct,openCriticalFindings,remediationVelocityPerWeek,overdueCriticalFindings', days: 90 },
    }),
  );
  const matrix = useApi(() => api<{ cells: MatrixCell[]; appetite: number; total: number }>('/risks/matrix'));
  const threats = useApi(() => api<{ items: ThreatItem[] }>('/threats', { query: { limit: 6, severity: 'CRITICAL,HIGH' } }));

  useLiveRefresh(['kpi', 'kri', 'incidents', 'vulnerabilities', 'connectors'], () => void summary.reload(true));
  useLiveRefresh(['kpi'], () => void trends.reload(true));
  useLiveRefresh(['risks'], () => void matrix.reload(true));
  useLiveRefresh(['threats'], () => void threats.reload(true));

  if (summary.loading && !summary.data) return <Spinner />;
  if (summary.error || !summary.data) return <ErrorBox message={summary.error ?? 'Unable to load'} onRetry={() => void summary.reload()} />;

  const { kpis, deltas, kris } = summary.data;
  const red = kris.filter((k) => k.status === 'RED').length;
  const amber = kris.filter((k) => k.status === 'AMBER').length;
  const points = trends.data?.points ?? [];

  return (
    <div className="space-y-6">
      <PageHeader
        title="Executive Security Overview"
        subtitle={`Rolling ${summary.data.windowDays}-day window · updated ${fmtDateTime(summary.data.generatedAt)}`}
        actions={
          <div className="flex items-center gap-2 text-sm">
            <Badge className="bg-rose-500/15 text-rose-300 ring-rose-500/40">{red} KRI red</Badge>
            <Badge className="bg-amber-500/15 text-amber-200 ring-amber-500/40">{amber} KRI amber</Badge>
            <Badge>{kpis.totalAssets} assets</Badge>
          </div>
        }
      />

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-5">
        <KpiCard label="Mean time to detect" value={kpis.mttdHours} unit="h" delta={deltas.mttdHours} lowerIsBetter icon={Timer} />
        <KpiCard label="Mean time to respond" value={kpis.mttrHours} unit="h" delta={deltas.mttrHours} lowerIsBetter icon={Clock} accent="text-violet-400" />
        <KpiCard label="Patch compliance" value={kpis.patchCompliancePct} unit="%" delta={deltas.patchCompliancePct} icon={Wrench} accent="text-emerald-400" />
        <KpiCard
          label="Remediation velocity"
          value={kpis.remediationVelocityPerWeek}
          unit="/wk"
          delta={deltas.remediationVelocityPerWeek}
          icon={TrendingUp}
          accent="text-cyan-400"
          hint={kpis.meanDaysToRemediate != null ? `${fmtNumber(kpis.meanDaysToRemediate)}d avg fix` : undefined}
        />
        <KpiCard
          label="Open critical findings"
          value={kpis.openCriticalFindings}
          delta={deltas.openCriticalFindings}
          lowerIsBetter
          icon={AlertOctagon}
          accent="text-rose-400"
          hint={`${kpis.overdueCriticalFindings} past SLA`}
        />
      </div>

      <div className="grid grid-cols-1 gap-6 xl:grid-cols-3">
        <Card
          className="xl:col-span-2"
          title="Key Risk Indicators — risk appetite thresholds"
          actions={
            <Link to="/parameters" className="text-xs text-sky-400 hover:underline">
              Manage thresholds
            </Link>
          }
          bodyClass="p-0"
        >
          <table className="table-base">
            <thead>
              <tr>
                <th>Indicator</th>
                <th className="text-right">Current</th>
                <th className="text-right">Amber</th>
                <th className="text-right">Red</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {kris.map((k) => (
                <tr key={k.key}>
                  <td>
                    <div className="font-medium text-slate-100">{k.name}</div>
                    <div className="text-xs text-slate-500">{k.description}</div>
                  </td>
                  <td className="text-right font-semibold tabular-nums text-white">
                    {fmtNumber(k.value)} <span className="text-xs font-normal text-slate-500">{k.unit}</span>
                  </td>
                  <td className="text-right tabular-nums text-amber-200/80">
                    {k.direction === 'LOWER_IS_WORSE' ? '≤' : '≥'} {k.amberThreshold}
                  </td>
                  <td className="text-right tabular-nums text-rose-300/80">
                    {k.direction === 'LOWER_IS_WORSE' ? '≤' : '≥'} {k.redThreshold}
                  </td>
                  <td>
                    <RagBadge status={k.status} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </Card>

        <Card
          title={`Risk heat map (${matrix.data?.total ?? 0} open)`}
          actions={
            <Link to="/risk" className="text-xs text-sky-400 hover:underline">
              Drill down
            </Link>
          }
        >
          {matrix.data ? <RiskMatrix cells={matrix.data.cells} compact /> : <Spinner />}
          <div className="mt-3 flex items-center justify-between text-xs text-slate-400">
            <span>Risk appetite: score ≤ {summary.data.riskAppetiteScore}</span>
            <span className="text-rose-300">{kpis.risksAboveAppetite} above appetite</span>
          </div>
        </Card>
      </div>

      <div className="grid grid-cols-1 gap-6 xl:grid-cols-2">
        <Card title="Detection & response trend (90 days)">
          {points.length ? (
            <TrendChart
              data={points}
              unit="h"
              series={[
                { key: 'mttdHours', label: 'MTTD', color: '#38bdf8' },
                { key: 'mttrHours', label: 'MTTR', color: '#a78bfa' },
              ]}
            />
          ) : (
            <Spinner />
          )}
        </Card>
        <Card title="Patch compliance trend (90 days)">
          {points.length ? (
            <TrendChart
              data={points}
              unit="%"
              series={[{ key: 'patchCompliancePct', label: 'Patch compliance', color: '#34d399' }]}
              threshold={kris.find((k) => k.key === 'patch_compliance') ? { value: kris.find((k) => k.key === 'patch_compliance')!.amberThreshold, label: 'Amber', color: '#fbbf24' } : undefined}
            />
          ) : (
            <Spinner />
          )}
        </Card>
        <Card title="Critical exposure & remediation velocity (90 days)">
          {points.length ? (
            <TrendChart
              data={points}
              series={[
                { key: 'openCriticalFindings', label: 'Open critical', color: '#fb7185' },
                { key: 'overdueCriticalFindings', label: 'Critical past SLA', color: '#f97316' },
                { key: 'remediationVelocityPerWeek', label: 'Remediated / week', color: '#22d3ee' },
              ]}
            />
          ) : (
            <Spinner />
          )}
        </Card>
        <Card
          title="Priority threat intelligence"
          actions={
            <Link to="/threats" className="text-xs text-sky-400 hover:underline">
              Open stream
            </Link>
          }
          bodyClass="p-0"
        >
          <ul className="divide-y divide-surface-800">
            {(threats.data?.items ?? []).map((t) => (
              <li key={t.id} className="flex items-start gap-3 px-4 py-3">
                <Radar className="mt-0.5 h-4 w-4 shrink-0 text-sky-400" />
                <div className="min-w-0 flex-1">
                  <div className="truncate text-sm font-medium text-slate-100">{t.title}</div>
                  <div className="mt-1 flex flex-wrap items-center gap-2 text-xs text-slate-500">
                    <SeverityBadge severity={t.severity} />
                    <span>{t.source}</span>
                    <span>· {timeAgo(t.publishedAt)}</span>
                    {t.impactedAssetCount > 0 && <span className="text-rose-300">· {t.impactedAssetCount} assets impacted</span>}
                  </div>
                </div>
              </li>
            ))}
            {threats.data && threats.data.items.length === 0 && <li className="px-4 py-6 text-center text-sm text-slate-500">No high-severity intelligence</li>}
          </ul>
        </Card>
      </div>

      <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
        <MiniStat icon={ShieldAlert} label="Active incidents" value={kpis.activeIncidents} />
        <MiniStat icon={Activity} label="Open high findings" value={kpis.openHighFindings} />
        <MiniStat icon={Gauge} label="Pending risk acceptances" value={kpis.pendingAcceptances} />
        <MiniStat icon={Radar} label="Failed security feeds" value={kpis.failedConnectors} danger={kpis.failedConnectors > 0} />
      </div>
    </div>
  );
}

function MiniStat({ icon: Icon, label, value, danger }: { icon: typeof Activity; label: string; value: number; danger?: boolean }) {
  return (
    <div className="card flex items-center gap-3 p-4">
      <Icon className={danger ? 'h-5 w-5 text-rose-400' : 'h-5 w-5 text-slate-400'} />
      <div>
        <div className="text-xl font-semibold tabular-nums text-white">{value}</div>
        <div className="text-xs text-slate-400">{label}</div>
      </div>
    </div>
  );
}
