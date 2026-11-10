import { Ban, CheckCircle2, Database, KeyRound, LogOut, Server, Users } from 'lucide-react';
import { api, errorMessage } from '../lib/api';
import { useApi } from '../hooks/useApi';
import { Can, useAuth } from '../auth/AuthContext';
import { Badge, Card, ErrorBox, PageHeader, Spinner } from '../components/ui';
import { fmtDateTime, ROLE_LABELS, timeAgo } from '../lib/format';
import type { Role } from '../lib/types';

interface UserRow {
  id: string;
  displayName: string;
  roles: Role[];
  active: boolean;
  lastLoginAt: string | null;
  activeSessions: number;
}

interface SystemInfo {
  version: string;
  nodeVersion: string;
  uptimeSec: number;
  memoryMb: number;
  database: { ok: boolean; latencyMs: number; readReplicas: number };
  scheduler: Record<string, string | boolean | null>;
  connectors: Record<string, number>;
  sessions: { active: number };
  audit: { records: number; lastEventAt: string | null };
  security: Record<string, string | number | boolean>;
}

export function AdminPage() {
  const { me, can } = useAuth();
  const users = useApi(() => api<{ items: UserRow[] }>('/admin/users'));
  const system = useApi(() => (can('system:manage') ? api<SystemInfo>('/admin/system') : Promise.resolve(null)), [can]);

  const setActive = async (u: UserRow, active: boolean) => {
    if (!active && !window.confirm(`Deactivate ${u.displayName}? All of their sessions will be revoked immediately.`)) return;
    try {
      await api(`/admin/users/${u.id}`, { method: 'PATCH', body: { active } });
      void users.reload(true);
    } catch (e) {
      alert(errorMessage(e));
    }
  };
  const revoke = async (u: UserRow) => {
    try {
      await api(`/admin/users/${u.id}/revoke-sessions`, { method: 'POST' });
      void users.reload(true);
    } catch (e) {
      alert(errorMessage(e));
    }
  };

  const s = system.data;
  return (
    <div className="space-y-6">
      <PageHeader title="System Management & Users" subtitle="Identities and roles are mastered in the OIDC identity provider; this console provides local kill-switches and health visibility." />

      <Can permission="system:manage">
        {system.error && <ErrorBox message={system.error} />}
        {s ? (
          <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-4">
            <Card title={<span className="flex items-center gap-2"><Server className="h-4 w-4" /> Application</span>}>
              <dl className="space-y-1 text-sm">
                <Row k="Version" v={s.version} />
                <Row k="Runtime" v={s.nodeVersion} />
                <Row k="Uptime" v={`${Math.round(s.uptimeSec / 3600)} h`} />
                <Row k="Memory" v={`${s.memoryMb} MB`} />
              </dl>
            </Card>
            <Card title={<span className="flex items-center gap-2"><Database className="h-4 w-4" /> Database</span>}>
              <dl className="space-y-1 text-sm">
                <Row k="Primary" v={s.database.ok ? 'healthy' : 'down'} />
                <Row k="Latency" v={`${s.database.latencyMs} ms`} />
                <Row k="Read replicas" v={String(s.database.readReplicas)} />
                <Row k="Audit records" v={String(s.audit.records)} />
              </dl>
            </Card>
            <Card title={<span className="flex items-center gap-2"><KeyRound className="h-4 w-4" /> Security posture</span>}>
              <dl className="space-y-1 text-sm">
                {Object.entries(s.security).map(([k, v]) => <Row key={k} k={k} v={String(v)} />)}
              </dl>
            </Card>
            <Card title="Scheduler & feeds">
              <dl className="space-y-1 text-sm">
                <Row k="Enabled" v={String(s.scheduler.enabled)} />
                <Row k="Connector tick" v={timeAgo(s.scheduler.lastConnectorTick as string | null)} />
                <Row k="KPI snapshot" v={timeAgo(s.scheduler.lastSnapshot as string | null)} />
                <Row k="KRI evaluation" v={timeAgo(s.scheduler.lastKriEvaluation as string | null)} />
                {Object.entries(s.connectors).map(([k, v]) => <Row key={k} k={`Connectors ${k.toLowerCase()}`} v={String(v)} />)}
                <Row k="Active sessions" v={String(s.sessions.active)} />
              </dl>
            </Card>
          </div>
        ) : (
          system.loading && <Spinner />
        )}
      </Can>

      <Card title={<span className="flex items-center gap-2"><Users className="h-4 w-4" /> Users (provisioned on first SSO login)</span>} bodyClass="p-0">
        {users.error && <ErrorBox message={users.error} />}
        {!users.data ? <Spinner /> : (
          <table className="table-base">
            <thead>
              <tr>
                <th>User</th>
                <th>Roles (from IdP)</th>
                <th>Last login</th>
                <th>Sessions</th>
                <th>Status</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {users.data.items.map((u) => (
                <tr key={u.id}>
                  <td className="font-medium text-slate-100">{u.displayName}{u.id === me?.user.id && <span className="ml-2 text-xs text-slate-500">(you)</span>}</td>
                  <td><div className="flex flex-wrap gap-1">{u.roles.map((r) => <Badge key={r}>{ROLE_LABELS[r]}</Badge>)}</div></td>
                  <td className="text-xs text-slate-400">{fmtDateTime(u.lastLoginAt)}</td>
                  <td className="tabular-nums">{u.activeSessions}</td>
                  <td>{u.active ? <Badge className="bg-emerald-500/15 text-emerald-300 ring-emerald-500/40">Active</Badge> : <Badge className="bg-rose-500/15 text-rose-300 ring-rose-500/40">Disabled</Badge>}</td>
                  <td className="whitespace-nowrap text-right">
                    <Can permission="users:manage">
                      {u.id !== me?.user.id && (
                        <div className="flex justify-end gap-2">
                          <button className="btn-secondary px-2 py-1 text-xs" disabled={!u.activeSessions} onClick={() => void revoke(u)}><LogOut className="h-3.5 w-3.5" /> Revoke sessions</button>
                          {u.active ? (
                            <button className="btn-secondary px-2 py-1 text-xs text-rose-300" onClick={() => void setActive(u, false)}><Ban className="h-3.5 w-3.5" /> Disable</button>
                          ) : (
                            <button className="btn-secondary px-2 py-1 text-xs text-emerald-300" onClick={() => void setActive(u, true)}><CheckCircle2 className="h-3.5 w-3.5" /> Enable</button>
                          )}
                        </div>
                      )}
                    </Can>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>
    </div>
  );
}

function Row({ k, v }: { k: string; v: string }) {
  return (
    <div className="flex justify-between gap-3">
      <dt className="text-slate-500">{k}</dt>
      <dd className="truncate text-right text-slate-200">{v}</dd>
    </div>
  );
}
