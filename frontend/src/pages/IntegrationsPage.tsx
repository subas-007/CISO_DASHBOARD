import { useMemo, useState } from 'react';
import clsx from 'clsx';
import { CheckCircle2, KeyRound, Loader2, Pencil, Play, Plug, Plus, RefreshCw, ShieldCheck, Trash2, XCircle } from 'lucide-react';
import { api, errorMessage } from '../lib/api';
import { useApi } from '../hooks/useApi';
import { useLiveRefresh } from '../hooks/useEventStream';
import { Can, useAuth } from '../auth/AuthContext';
import { Badge, Card, Empty, ErrorBox, Field, Modal, Notice, PageHeader, Spinner, Toggle } from '../components/ui';
import { humanize, timeAgo } from '../lib/format';
import type { AuthMode, CatalogItem, Connector, ConnectorCategory } from '../lib/types';

const CATEGORY_LABEL: Record<ConnectorCategory, string> = {
  SIEM: 'SIEM',
  VULNERABILITY: 'Vulnerability Management',
  PATCH: 'Patch Management',
  CHANGE: 'Change Management',
  THREAT_INTEL: 'Threat Intelligence',
};

const STATUS_CLASS: Record<Connector['status'], string> = {
  HEALTHY: 'bg-emerald-500/15 text-emerald-300 ring-emerald-500/40',
  FAILED: 'bg-rose-500/15 text-rose-300 ring-rose-500/40',
  UNTESTED: 'bg-amber-500/15 text-amber-200 ring-amber-500/40',
  DISABLED: 'bg-slate-500/15 text-slate-300 ring-slate-500/40',
};

const AUTH_LABEL: Record<AuthMode, string> = {
  NONE: 'None (public feed)',
  API_KEY: 'API key / token',
  BASIC: 'Basic (username + password)',
  OAUTH2: 'OAuth 2.0 client credentials',
  MTLS: 'Mutual TLS (client certificate)',
};

type CredField = { key: string; label: string; type?: 'password' | 'textarea' | 'text'; placeholder?: string; required?: boolean };
const CRED_FIELDS: Record<AuthMode, CredField[]> = {
  NONE: [],
  API_KEY: [
    { key: 'apiKey', label: 'API key / access key', type: 'password', required: true },
    { key: 'apiSecret', label: 'API secret (if vendor uses key pairs, e.g. Tenable)', type: 'password' },
    { key: 'apiKeyHeader', label: 'Header name', type: 'text', placeholder: 'Authorization' },
    { key: 'apiKeyPrefix', label: 'Value prefix', type: 'text', placeholder: 'Bearer ' },
  ],
  BASIC: [
    { key: 'username', label: 'Username', type: 'text', required: true },
    { key: 'password', label: 'Password / API token', type: 'password', required: true },
  ],
  OAUTH2: [
    { key: 'tokenUrl', label: 'Token endpoint URL', type: 'text', placeholder: 'https://idp.example.com/oauth2/token', required: true },
    { key: 'clientId', label: 'Client ID', type: 'text', required: true },
    { key: 'clientSecret', label: 'Client secret', type: 'password', required: true },
    { key: 'scope', label: 'Scope', type: 'text' },
  ],
  MTLS: [
    { key: 'clientCert', label: 'Client certificate (PEM)', type: 'textarea', required: true, placeholder: '-----BEGIN CERTIFICATE-----' },
    { key: 'clientKey', label: 'Client private key (PEM)', type: 'textarea', required: true, placeholder: '-----BEGIN PRIVATE KEY-----' },
    { key: 'passphrase', label: 'Key passphrase', type: 'password' },
    { key: 'apiKey', label: 'Additional API key (optional)', type: 'password' },
    { key: 'apiKeyHeader', label: 'API key header', type: 'text', placeholder: 'Authorization' },
  ],
};

interface Catalog {
  items: CatalogItem[];
  egressPolicy: { httpsOnly: boolean; allowlist: string[]; privateNetworksBlocked: boolean };
}

export function IntegrationsPage() {
  const catalog = useApi(() => api<Catalog>('/integrations/catalog'));
  const list = useApi(() => api<{ items: Connector[] }>('/integrations'));
  const [editing, setEditing] = useState<Connector | 'new' | null>(null);
  const [creds, setCreds] = useState<Connector | null>(null);
  useLiveRefresh(['connectors'], () => void list.reload(true), 300);

  const grouped = useMemo(() => {
    const g = new Map<ConnectorCategory, Connector[]>();
    for (const c of list.data?.items ?? []) g.set(c.category, [...(g.get(c.category) ?? []), c]);
    return g;
  }, [list.data]);

  return (
    <div className="space-y-6">
      <PageHeader
        title="Integration Layer"
        subtitle="Parameterised connectors for SIEM, vulnerability, patch, change and threat-intel feeds. Credentials are write-only and encrypted with AES-256-GCM."
        actions={
          <Can permission="integration:manage">
            <button className="btn-primary" onClick={() => setEditing('new')}>
              <Plus className="h-4 w-4" /> Add connector
            </button>
          </Can>
        }
      />
      {catalog.data && (
        <Notice>
          <span className="inline-flex items-center gap-2">
            <ShieldCheck className="h-4 w-4" /> Egress policy: {catalog.data.egressPolicy.httpsOnly ? 'HTTPS only' : 'HTTP allowed (dev)'} · metadata & loopback blocked
            {catalog.data.egressPolicy.privateNetworksBlocked && ' · private networks blocked'}
            {catalog.data.egressPolicy.allowlist.length > 0 && ` · allowlist: ${catalog.data.egressPolicy.allowlist.join(', ')}`}
          </span>
        </Notice>
      )}
      {list.error && <ErrorBox message={list.error} onRetry={() => void list.reload()} />}
      {list.loading && !list.data ? (
        <Spinner />
      ) : !list.data?.items.length ? (
        <Card><Empty>No connectors configured.</Empty></Card>
      ) : (
        (Object.keys(CATEGORY_LABEL) as ConnectorCategory[]).map((cat) =>
          grouped.get(cat)?.length ? (
            <section key={cat}>
              <h2 className="mb-2 text-xs font-semibold uppercase tracking-wider text-slate-400">{CATEGORY_LABEL[cat]}</h2>
              <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
                {grouped.get(cat)!.map((c) => (
                  <ConnectorCard key={c.id} c={c} vendor={catalog.data?.items.find((v) => v.vendor === c.vendor)} onEdit={() => setEditing(c)} onCreds={() => setCreds(c)} onChanged={() => void list.reload(true)} />
                ))}
              </div>
            </section>
          ) : null,
        )
      )}
      {editing && catalog.data && <ConnectorModal catalog={catalog.data.items} existing={editing === 'new' ? null : editing} onClose={() => setEditing(null)} onSaved={() => void list.reload(true)} />}
      {creds && <CredentialsModal connector={creds} onClose={() => setCreds(null)} onSaved={() => void list.reload(true)} />}
    </div>
  );
}

function ConnectorCard({ c, vendor, onEdit, onCreds, onChanged }: { c: Connector; vendor?: CatalogItem; onEdit: () => void; onCreds: () => void; onChanged: () => void }) {
  const { can } = useAuth();
  const manage = can('integration:manage');
  const [busy, setBusy] = useState<'test' | 'sync' | 'toggle' | 'delete' | null>(null);
  const [result, setResult] = useState<{ ok: boolean; message: string } | null>(null);

  const run = async (kind: 'test' | 'sync') => {
    setBusy(kind);
    setResult(null);
    try {
      setResult(await api<{ ok: boolean; message: string }>(`/integrations/${c.id}/${kind}`, { method: 'POST' }));
      onChanged();
    } catch (e) {
      setResult({ ok: false, message: errorMessage(e) });
    } finally {
      setBusy(null);
    }
  };
  const toggle = async (enabled: boolean) => {
    setBusy('toggle');
    try {
      await api(`/integrations/${c.id}`, { method: 'PATCH', body: { enabled } });
      onChanged();
    } catch (e) {
      setResult({ ok: false, message: errorMessage(e) });
    } finally {
      setBusy(null);
    }
  };
  const remove = async () => {
    if (!window.confirm(`Delete connector "${c.name}"? Stored credentials will be destroyed.`)) return;
    setBusy('delete');
    try {
      await api(`/integrations/${c.id}`, { method: 'DELETE' });
      onChanged();
    } catch (e) {
      setResult({ ok: false, message: errorMessage(e) });
      setBusy(null);
    }
  };

  return (
    <div className="card p-4">
      <div className="flex items-start justify-between gap-3">
        <div className="flex items-start gap-3">
          <Plug className="mt-0.5 h-5 w-5 text-sky-400" />
          <div>
            <div className="font-semibold text-white">{c.name}</div>
            <div className="text-xs text-slate-400">{vendor?.displayName ?? c.vendor}</div>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <Badge className={STATUS_CLASS[c.status]}>{c.status}</Badge>
          {manage && <Toggle label="Enabled" checked={c.enabled} disabled={busy !== null} onChange={(v) => void toggle(v)} />}
        </div>
      </div>
      <dl className="mt-3 grid grid-cols-2 gap-x-4 gap-y-1 text-xs">
        <dt className="text-slate-500">Endpoint</dt>
        <dd className="truncate font-mono text-slate-300" title={c.baseUrl}>{c.baseUrl}</dd>
        <dt className="text-slate-500">Authentication</dt>
        <dd className="text-slate-300">{AUTH_LABEL[c.authMode]}</dd>
        <dt className="text-slate-500">Credentials</dt>
        <dd className="text-slate-300">{c.authMode === 'NONE' ? 'n/a' : c.hasCredentials ? `stored (${c.credentialFields.join(', ')})` : <span className="text-amber-300">missing</span>}</dd>
        <dt className="text-slate-500">Polling</dt>
        <dd className="text-slate-300">every {Math.round(c.pollIntervalSec / 60)} min</dd>
        <dt className="text-slate-500">Last sync</dt>
        <dd className="text-slate-300">{timeAgo(c.lastSyncAt)}{c.lastRecordCount != null && ` · ${c.lastRecordCount} records`}</dd>
      </dl>
      {c.lastError && <div className="mt-2 rounded bg-rose-500/10 px-2 py-1 text-xs text-rose-300">Last error: {c.lastError}</div>}
      {result && (
        <div className={clsx('mt-2 flex items-center gap-1.5 rounded px-2 py-1 text-xs', result.ok ? 'bg-emerald-500/10 text-emerald-300' : 'bg-rose-500/10 text-rose-300')}>
          {result.ok ? <CheckCircle2 className="h-3.5 w-3.5" /> : <XCircle className="h-3.5 w-3.5" />} {result.message}
        </div>
      )}
      {manage && (
        <div className="mt-3 flex flex-wrap gap-2 border-t border-surface-800 pt-3">
          <button className="btn-secondary px-2 py-1 text-xs" disabled={busy !== null} onClick={() => void run('test')}>
            {busy === 'test' ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Play className="h-3.5 w-3.5" />} Test connection
          </button>
          <button className="btn-secondary px-2 py-1 text-xs" disabled={busy !== null} onClick={() => void run('sync')}>
            {busy === 'sync' ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <RefreshCw className="h-3.5 w-3.5" />} Sync now
          </button>
          <button className="btn-secondary px-2 py-1 text-xs" disabled={busy !== null} onClick={onEdit}>
            <Pencil className="h-3.5 w-3.5" /> Configure
          </button>
          {c.authMode !== 'NONE' && (
            <button className="btn-secondary px-2 py-1 text-xs" disabled={busy !== null} onClick={onCreds}>
              <KeyRound className="h-3.5 w-3.5" /> Rotate credentials
            </button>
          )}
          <button className="btn-ghost ml-auto px-2 py-1 text-xs text-rose-300" disabled={busy !== null} onClick={() => void remove()}>
            <Trash2 className="h-3.5 w-3.5" /> Delete
          </button>
        </div>
      )}
    </div>
  );
}

function CredentialInputs({ mode, value, onChange }: { mode: AuthMode; value: Record<string, string>; onChange: (v: Record<string, string>) => void }) {
  if (mode === 'NONE') return <p className="text-sm text-slate-500">No credentials required.</p>;
  return (
    <div className="space-y-3">
      {CRED_FIELDS[mode].map((f) => (
        <Field key={f.key} label={`${f.label}${f.required ? ' *' : ''}`}>
          {f.type === 'textarea' ? (
            <textarea className="input min-h-24 font-mono text-xs" autoComplete="off" spellCheck={false} placeholder={f.placeholder} value={value[f.key] ?? ''} onChange={(e) => onChange({ ...value, [f.key]: e.target.value })} />
          ) : (
            <input className="input" type={f.type === 'password' ? 'password' : 'text'} autoComplete="new-password" spellCheck={false} placeholder={f.placeholder} value={value[f.key] ?? ''} onChange={(e) => onChange({ ...value, [f.key]: e.target.value })} />
          )}
        </Field>
      ))}
      <Field label="Custom CA certificate (PEM, optional)">
        <textarea className="input min-h-20 font-mono text-xs" spellCheck={false} placeholder="-----BEGIN CERTIFICATE-----" value={value.caCert ?? ''} onChange={(e) => onChange({ ...value, caCert: e.target.value })} />
      </Field>
    </div>
  );
}

const compact = (o: Record<string, string>) => Object.fromEntries(Object.entries(o).filter(([, v]) => v.trim() !== ''));

function ConnectorModal({ catalog, existing, onClose, onSaved }: { catalog: CatalogItem[]; existing: Connector | null; onClose: () => void; onSaved: () => void }) {
  const [vendor, setVendor] = useState(existing?.vendor ?? catalog[0]!.vendor);
  const spec = catalog.find((c) => c.vendor === vendor)!;
  const [name, setName] = useState(existing?.name ?? '');
  const [baseUrl, setBaseUrl] = useState(existing?.baseUrl ?? spec.defaultBaseUrl ?? '');
  const [authMode, setAuthMode] = useState<AuthMode>(existing?.authMode ?? spec.supportedAuth[0]!);
  const [pollMin, setPollMin] = useState(Math.round((existing?.pollIntervalSec ?? spec.defaultPollSec) / 60));
  const [enabled, setEnabled] = useState(existing?.enabled ?? false);
  const [settings, setSettings] = useState<Record<string, string | number | boolean>>(existing?.settings ?? {});
  const [creds, setCreds] = useState<Record<string, string>>({});
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const pickVendor = (v: string) => {
    const s = catalog.find((c) => c.vendor === v)!;
    setVendor(v);
    setAuthMode(s.supportedAuth[0]!);
    setBaseUrl(s.defaultBaseUrl ?? '');
    setPollMin(Math.round(s.defaultPollSec / 60));
    setSettings({});
    setCreds({});
  };

  const cleanSettings = () =>
    Object.fromEntries(
      Object.entries(settings)
        .filter(([, v]) => v !== '' && v !== undefined)
        .map(([k, v]) => [k, spec.settingsFields.find((f) => f.key === k)?.type === 'number' ? Number(v) : v]),
    );

  const save = async () => {
    setBusy(true);
    setError(null);
    try {
      if (existing) {
        await api(`/integrations/${existing.id}`, { method: 'PATCH', body: { baseUrl, authMode, pollIntervalSec: pollMin * 60, enabled, settings: cleanSettings() } });
        if (Object.keys(compact(creds)).length) await api(`/integrations/${existing.id}/credentials`, { method: 'PUT', body: { credentials: compact(creds) } });
      } else {
        await api('/integrations', { method: 'POST', body: { name, vendor, baseUrl, authMode, pollIntervalSec: pollMin * 60, enabled, settings: cleanSettings(), credentials: compact(creds) } });
      }
      setCreds({});
      onSaved();
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
      wide
      title={existing ? `Configure ${existing.name}` : 'Add connector'}
      onClose={onClose}
      footer={
        <>
          <button className="btn-secondary" onClick={onClose}>Cancel</button>
          <button className="btn-primary" disabled={busy} onClick={() => void save()}>{busy && <Loader2 className="h-4 w-4 animate-spin" />} Save</button>
        </>
      }
    >
      <div className="grid grid-cols-1 gap-6 md:grid-cols-2">
        <div className="space-y-4">
          {error && <Notice kind="error">{error}</Notice>}
          <Field label="Connector type">
            <select className="input" value={vendor} disabled={!!existing} onChange={(e) => pickVendor(e.target.value)}>
              {(Object.keys(CATEGORY_LABEL) as ConnectorCategory[]).map((cat) => (
                <optgroup key={cat} label={CATEGORY_LABEL[cat]}>
                  {catalog.filter((c) => c.category === cat).map((c) => (
                    <option key={c.vendor} value={c.vendor}>{c.displayName}</option>
                  ))}
                </optgroup>
              ))}
            </select>
          </Field>
          <p className="text-xs text-slate-400">{spec.description}</p>
          <Field label="Display name">
            <input className="input" maxLength={80} disabled={!!existing} value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. Splunk ES Production" />
          </Field>
          <Field label="API endpoint (base URL)" hint="HTTPS only. Validated against the egress policy.">
            <input className="input font-mono" maxLength={500} value={baseUrl} onChange={(e) => setBaseUrl(e.target.value)} placeholder="https://siem.corp.example:8089" />
          </Field>
          <div className="grid grid-cols-2 gap-4">
            <Field label="Polling interval (minutes)">
              <input className="input" type="number" min={1} max={1440} value={pollMin} onChange={(e) => setPollMin(Number(e.target.value))} />
            </Field>
            <Field label="Enabled">
              <div className="pt-2"><Toggle label="Enabled" checked={enabled} onChange={setEnabled} /></div>
            </Field>
          </div>
          {spec.settingsFields.length > 0 && (
            <div className="space-y-3 rounded-lg border border-surface-700 p-3">
              <div className="text-xs font-semibold uppercase tracking-wide text-slate-400">{humanize(spec.vendor)} parameters</div>
              {spec.settingsFields.map((f) => (
                <Field key={f.key} label={`${f.label}${f.required ? ' *' : ''}`} hint={f.help}>
                  {f.type === 'textarea' ? (
                    <textarea className="input font-mono text-xs" placeholder={f.placeholder} value={String(settings[f.key] ?? '')} onChange={(e) => setSettings({ ...settings, [f.key]: e.target.value })} />
                  ) : (
                    <input className="input" type={f.type === 'number' ? 'number' : 'text'} placeholder={f.placeholder} value={String(settings[f.key] ?? '')} onChange={(e) => setSettings({ ...settings, [f.key]: e.target.value })} />
                  )}
                </Field>
              ))}
            </div>
          )}
        </div>
        <div className="space-y-4">
          <Field label="Authentication mode">
            <select className="input" value={authMode} onChange={(e) => { setAuthMode(e.target.value as AuthMode); setCreds({}); }}>
              {spec.supportedAuth.map((m) => <option key={m} value={m}>{AUTH_LABEL[m]}</option>)}
            </select>
          </Field>
          {existing?.hasCredentials && (
            <Notice>Credentials are stored encrypted and never displayed. Leave blank to keep them; enter values to replace them.</Notice>
          )}
          <CredentialInputs mode={authMode} value={creds} onChange={setCreds} />
        </div>
      </div>
    </Modal>
  );
}

function CredentialsModal({ connector, onClose, onSaved }: { connector: Connector; onClose: () => void; onSaved: () => void }) {
  const [creds, setCreds] = useState<Record<string, string>>({});
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const save = async () => {
    setBusy(true);
    setError(null);
    try {
      await api(`/integrations/${connector.id}/credentials`, { method: 'PUT', body: { credentials: compact(creds) } });
      setCreds({});
      onSaved();
      onClose();
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setBusy(false);
    }
  };
  return (
    <Modal open title={`Rotate credentials — ${connector.name}`} onClose={onClose} footer={<><button className="btn-secondary" onClick={onClose}>Cancel</button><button className="btn-primary" disabled={busy} onClick={() => void save()}>Replace credentials</button></>}>
      <div className="space-y-4">
        {error && <Notice kind="error">{error}</Notice>}
        <Notice>New credentials replace the stored set entirely. The action is audited; values are never logged.</Notice>
        <CredentialInputs mode={connector.authMode} value={creds} onChange={setCreds} />
      </div>
    </Modal>
  );
}
