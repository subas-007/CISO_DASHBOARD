import { useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { CheckCircle2, CloudCog, Download, FlaskConical, Loader2, Play, RefreshCw, ShieldCheck, TriangleAlert, Users } from 'lucide-react';
import { api, errorMessage } from '../lib/api';
import { useApi } from '../hooks/useApi';
import { useAuth } from '../auth/AuthContext';
import { Card, ErrorBox, Field, Modal, Notice, PageHeader, Spinner } from '../components/ui';
import { APPLY_LABEL, ApplyBadge, SettingForm } from '../components/SettingForm';
import { fmtDateTime, timeAgo } from '../lib/format';
import type { ApplyMode, SettingItem } from '../lib/types';

interface ConfigStatus {
  deployment: {
    running: Record<string, unknown>;
    desired: Record<string, unknown>;
    redeployRequired: boolean;
    differences: { field: string; running: unknown; desired: unknown }[];
  };
  identity: { configured: boolean; lastAttemptAt: string | null; lastSuccessAt: string | null; ok: boolean | null; message: string };
  egress: { allowedHosts: string[]; deniedHosts: string[]; blockPrivateNetworks: boolean; timeoutMs: number; maxRetries: number };
  demo: { demoMode: boolean; liveSimulation: boolean; intervalSec: number; ticks: number; lastTickAt: string | null; lastCounts: Record<string, number> | null };
}

const show = (v: unknown) => (Array.isArray(v) ? v.join(', ') || '—' : v === null || v === undefined || v === '' ? '—' : String(v));

export function ConfigurationPage() {
  const { can } = useAuth();
  const settings = useApi(() => api<{ items: SettingItem[] }>('/admin/settings'));
  const status = useApi(() => api<ConfigStatus>('/admin/config/status'));
  const items = useMemo(() => (settings.data?.items ?? []).filter((s) => s.readPermission === 'config:read' || s.category !== 'risk'), [settings.data]);
  const categories = useMemo(() => {
    const seen = new Map<string, string>();
    for (const s of items) if (!seen.has(s.category)) seen.set(s.category, s.categoryLabel);
    return [...seen.entries()];
  }, [items]);
  const [active, setActive] = useState<string>('access');
  const current = categories.some(([c]) => c === active) ? active : categories[0]?.[0];
  const manage = can('system:manage');

  const reloadAll = () => {
    void settings.reload(true);
    void status.reload(true);
  };

  return (
    <div className="space-y-6">
      <PageHeader
        title="System Configuration"
        subtitle="Every platform parameter in one place: network access, rate limits, sessions, identity & MFA enrolment, integrations, demo data, deployment and host OS. All changes are validated, audited with before/after values, and applied according to their mode."
      />

      <div className="flex flex-wrap gap-2 text-xs text-slate-400">
        {(Object.keys(APPLY_LABEL) as ApplyMode[]).map((m) => (
          <span key={m} className="flex items-center gap-1.5">
            <ApplyBadge mode={m} /> {APPLY_LABEL[m].help}
          </span>
        ))}
      </div>

      {status.error && <ErrorBox message={status.error} />}
      {status.data && <StatusStrip s={status.data} manage={manage} onChanged={reloadAll} />}

      {settings.error && <ErrorBox message={settings.error} />}
      {!settings.data ? (
        <Spinner />
      ) : (
        <div className="grid grid-cols-1 gap-6 lg:grid-cols-[14rem_1fr]">
          <nav className="flex gap-1 overflow-x-auto lg:flex-col" aria-label="Configuration categories" role="tablist">
            {categories.map(([cat, label]) => (
              <button
                key={cat}
                role="tab"
                aria-selected={cat === current}
                onClick={() => setActive(cat)}
                className={`whitespace-nowrap rounded-lg px-3 py-2 text-left text-sm transition ${cat === current ? 'bg-sky-500/15 text-sky-200' : 'text-slate-400 hover:bg-surface-800 hover:text-slate-200'}`}
              >
                {label}
              </button>
            ))}
          </nav>
          <div className="min-w-0 space-y-6" role="tabpanel">
            {current === 'deployment' && status.data && <DeploymentPanel s={status.data} manage={manage} />}
            {current === 'host' && <HostPanel manage={manage} />}
            {current === 'identity' && <IdentityPanel s={status.data} manage={manage} onChanged={reloadAll} />}
            {current === 'demo' && status.data && <DemoPanel s={status.data} manage={manage} onChanged={reloadAll} />}
            {items
              .filter((s) => s.category === current)
              .map((s) => (
                <SettingForm key={s.key} item={s} onSaved={reloadAll} />
              ))}
          </div>
        </div>
      )}
    </div>
  );
}

function StatusStrip({ s, manage, onChanged }: { s: ConfigStatus; manage: boolean; onChanged: () => void }) {
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<string | null>(null);
  const resync = async () => {
    setBusy(true);
    setMsg(null);
    try {
      const r = await api<{ ok: boolean; message: string }>('/admin/identity/sync', { method: 'POST' });
      setMsg(r.message);
    } catch (e) {
      setMsg(errorMessage(e));
    } finally {
      setBusy(false);
      onChanged();
    }
  };
  return (
    <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
      <Card title={<span className="flex items-center gap-2"><CloudCog className="h-4 w-4" /> Deployment</span>}>
        {s.deployment.redeployRequired ? (
          <div className="flex items-start gap-2 text-sm text-amber-200"><TriangleAlert className="mt-0.5 h-4 w-4 shrink-0" /> Saved deployment parameters differ from the running stack ({s.deployment.differences.map((d) => d.field).join(', ')}). Apply them on the Docker host.</div>
        ) : (
          <div className="flex items-center gap-2 text-sm text-emerald-300"><CheckCircle2 className="h-4 w-4" /> Running stack matches the deployment profile</div>
        )}
        <div className="mt-2 text-xs text-slate-500">Public URL: <span className="font-mono text-slate-300">{show(s.deployment.running.publicBaseUrl)}</span></div>
      </Card>
      <Card title={<span className="flex items-center gap-2"><ShieldCheck className="h-4 w-4" /> Identity provider</span>}>
        {!s.identity.configured ? (
          <div className="text-sm text-slate-400">External IdP — apply identity policy in the IdP.</div>
        ) : (
          <>
            <div className={`text-sm ${s.identity.ok ? 'text-emerald-300' : 'text-amber-200'}`}>{s.identity.message}</div>
            <div className="mt-2 flex items-center justify-between gap-2 text-xs text-slate-500">
              <span>Last sync {timeAgo(s.identity.lastSuccessAt)}</span>
              {manage && <button className="btn-secondary px-2 py-1 text-xs" disabled={busy} onClick={() => void resync()}>{busy ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <RefreshCw className="h-3.5 w-3.5" />} Re-sync</button>}
            </div>
            {msg && <div className="mt-2 text-xs text-slate-300">{msg}</div>}
          </>
        )}
      </Card>
      <Card title={<span className="flex items-center gap-2"><FlaskConical className="h-4 w-4" /> Demo data</span>}>
        {!s.demo.demoMode ? (
          <div className="text-sm text-slate-400">Production profile — demo generator disabled.</div>
        ) : (
          <div className="text-sm text-slate-300">
            Live simulation <span className={s.demo.liveSimulation ? 'text-emerald-300' : 'text-slate-400'}>{s.demo.liveSimulation ? `on (every ${s.demo.intervalSec}s)` : 'off'}</span>
            <div className="mt-2 text-xs text-slate-500">{s.demo.ticks} ticks since start · last {timeAgo(s.demo.lastTickAt)}</div>
          </div>
        )}
      </Card>
    </div>
  );
}

function DeploymentPanel({ s, manage }: { s: ConfigStatus; manage: boolean }) {
  return (
    <Card title="Apply deployment changes on the Docker host">
      <div className="space-y-3 text-sm text-slate-300">
        <p>Use this when the dashboard is hosted on a server (IP address or DNS name) instead of the local machine. Save the profile below, then on the Docker host:</p>
        <pre className="overflow-x-auto rounded-lg bg-surface-950 p-3 font-mono text-xs text-slate-300">{`# copy deployment.env to the installation directory, then
scripts/apply-deployment.sh deployment.env --dry-run   # review
scripts/apply-deployment.sh deployment.env             # back up .env, re-issue TLS names, redeploy`}</pre>
        <p className="text-xs text-slate-500">The identity provider's redirect URIs follow the new public URL automatically on redeploy. Users reaching the gateway through an alternative name or IP are redirected to the public URL.</p>
        {s.deployment.differences.length > 0 && (
          <table className="table-base">
            <thead><tr><th>Parameter</th><th>Running</th><th>Saved</th></tr></thead>
            <tbody>
              {s.deployment.differences.map((d) => (
                <tr key={d.field}><td className="font-mono text-xs">{d.field}</td><td className="font-mono text-xs">{show(d.running)}</td><td className="font-mono text-xs text-amber-200">{show(d.desired)}</td></tr>
              ))}
            </tbody>
          </table>
        )}
        {manage ? (
          <a className="btn-primary inline-flex" href="/api/admin/config/bundle/deployment" download>
            <Download className="h-4 w-4" /> Download deployment.env
          </a>
        ) : (
          <Notice>Downloading the profile requires system:manage.</Notice>
        )}
      </div>
    </Card>
  );
}

function HostPanel({ manage }: { manage: boolean }) {
  return (
    <Card title="Host operating-system baseline">
      <div className="space-y-3 text-sm text-slate-300">
        <p>
          OS-level settings (time & NTP, DNS, syslog forwarding to your SIEM, edge firewall for the published ports, SSH restriction, automatic security updates, kernel hardening, auditd, Docker log rotation) are rendered into an idempotent script. The web application never changes the host itself — an operator reviews and runs the script.
        </p>
        <pre className="overflow-x-auto rounded-lg bg-surface-950 p-3 font-mono text-xs text-slate-300">{`sudo bash ciso-host-baseline-ubuntu.sh --dry-run --app-dir /opt/ciso-dashboard
sudo bash ciso-host-baseline-ubuntu.sh --app-dir /opt/ciso-dashboard`}</pre>
        {manage ? (
          <div className="flex flex-wrap gap-2">
            <a className="btn-primary" href="/api/admin/config/bundle/host?os=ubuntu" download>
              <Download className="h-4 w-4" /> Ubuntu script
            </a>
            <a className="btn-secondary" href="/api/admin/config/bundle/host?os=rhel" download>
              <Download className="h-4 w-4" /> RHEL / Rocky / Alma script
            </a>
          </div>
        ) : (
          <Notice>Downloading host scripts requires system:manage.</Notice>
        )}
      </div>
    </Card>
  );
}

function IdentityPanel({ s, manage, onChanged }: { s: ConfigStatus | null; manage: boolean; onChanged: () => void }) {
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<string | null>(null);
  const enforce = async () => {
    if (!window.confirm('Require every user without an authenticator app to enrol one at their next sign-in?')) return;
    setBusy(true);
    try {
      const r = await api<{ checked: number; flagged: number }>('/admin/identity/enforce-mfa', { method: 'POST' });
      setMsg(`${r.flagged} of ${r.checked} users must enrol an authenticator at next sign-in.`);
      onChanged();
    } catch (e) {
      setMsg(errorMessage(e));
    } finally {
      setBusy(false);
    }
  };
  return (
    <Card title="Enrolment">
      <div className="space-y-3 text-sm text-slate-300">
        <p>
          New users are enrolled from <Link className="text-sky-300 underline" to="/admin">System &amp; Users</Link> with a one-time password; at first sign-in they set their own password and register an authenticator app (Google Authenticator, Microsoft Authenticator, Authy, FreeOTP…) according to the policy below.
        </p>
        {s && !s.identity.configured && <Notice>The identity provider is external; enrolment and MFA policy are managed there.</Notice>}
        {manage && s?.identity.configured && (
          <button className="btn-secondary" disabled={busy} onClick={() => void enforce()}>
            {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <Users className="h-4 w-4" />} Enforce MFA for existing users
          </button>
        )}
        {msg && <Notice kind="success">{msg}</Notice>}
      </div>
    </Card>
  );
}

function DemoPanel({ s, manage, onChanged }: { s: ConfigStatus; manage: boolean; onChanged: () => void }) {
  const [busy, setBusy] = useState<string | null>(null);
  const [msg, setMsg] = useState<string | null>(null);
  const [confirmOpen, setConfirmOpen] = useState(false);
  const [confirmText, setConfirmText] = useState('');

  const tick = async () => {
    setBusy('tick');
    setMsg(null);
    try {
      const r = await api<{ counts: Record<string, number> | null }>('/admin/config/demo/tick', { method: 'POST' });
      setMsg(r.counts ? Object.entries(r.counts).map(([k, v]) => `${k}: ${v}`).join(' · ') : 'Another replica is running a tick — try again.');
      onChanged();
    } catch (e) {
      setMsg(errorMessage(e));
    } finally {
      setBusy(null);
    }
  };
  const regenerate = async () => {
    setBusy('regen');
    setMsg(null);
    try {
      const r = await api<{ assets: number; vulnerabilities: number; incidents: number; historyDays: number; ms: number }>('/admin/config/demo/regenerate', { method: 'POST', body: { confirm: confirmText } });
      setMsg(`Dataset regenerated: ${r.assets} assets, ${r.vulnerabilities} findings, ${r.incidents} incidents, ${r.historyDays} days of KPI history (${Math.round(r.ms / 100) / 10}s).`);
      setConfirmOpen(false);
      setConfirmText('');
      onChanged();
    } catch (e) {
      setMsg(errorMessage(e));
    } finally {
      setBusy(null);
    }
  };

  if (!s.demo.demoMode) return <Notice>Demo data tools are available only when the stack runs with SEED_DEMO_DATA=true.</Notice>;
  return (
    <Card title="Demo data tools">
      <div className="space-y-3 text-sm text-slate-300">
        <p>Use moving demo data to verify KPIs, KRIs, trends, the threat stream and live notifications. Every action is audited.</p>
        {s.demo.lastCounts && <div className="text-xs text-slate-500">Last tick {fmtDateTime(s.demo.lastTickAt)}: {Object.entries(s.demo.lastCounts).map(([k, v]) => `${k} ${v}`).join(' · ')}</div>}
        {manage && (
          <div className="flex flex-wrap gap-2">
            <button className="btn-secondary" disabled={!!busy} onClick={() => void tick()}>{busy === 'tick' ? <Loader2 className="h-4 w-4 animate-spin" /> : <Play className="h-4 w-4" />} Run simulation tick now</button>
            <button className="btn-secondary text-amber-200" disabled={!!busy} onClick={() => setConfirmOpen(true)}><RefreshCw className="h-4 w-4" /> Regenerate demo dataset</button>
          </div>
        )}
        {msg && <Notice kind="success">{msg}</Notice>}
      </div>
      <Modal
        open={confirmOpen}
        title="Regenerate demo dataset"
        onClose={() => setConfirmOpen(false)}
        footer={
          <>
            <button className="btn-secondary" onClick={() => setConfirmOpen(false)}>Cancel</button>
            <button className="btn-primary" disabled={confirmText !== 'REGENERATE' || busy === 'regen'} onClick={() => void regenerate()}>{busy === 'regen' && <Loader2 className="h-4 w-4 animate-spin" />} Regenerate</button>
          </>
        }
      >
        <div className="space-y-3">
          <Notice kind="error">Deletes all assets, findings, incidents, threat items, risks, acceptances and KPI history, then generates a new dataset with the sizes configured below. Audit records, users, connectors and parameters are kept.</Notice>
          <Field label="Type REGENERATE to confirm">
            <input className="input font-mono" value={confirmText} onChange={(e) => setConfirmText(e.target.value)} />
          </Field>
        </div>
      </Modal>
    </Card>
  );
}
