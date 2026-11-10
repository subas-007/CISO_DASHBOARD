/**
 * Identity & enrolment: users in the identity provider, enrolment with a one-time
 * password, role changes, password / MFA reset, enable / disable, delete.
 */
import { useState } from 'react';
import { Ban, CheckCircle2, Copy, KeyRound, Loader2, Search, ShieldOff, Trash2, UserCog, UserPlus } from 'lucide-react';
import { api, ApiError, errorMessage } from '../lib/api';
import { useApi } from '../hooks/useApi';
import { useAuth } from '../auth/AuthContext';
import { fmtDateTime, ROLE_LABELS } from '../lib/format';
import type { IdentityUser, Role } from '../lib/types';
import { Badge, Card, ErrorBox, Field, Modal, Notice, Spinner } from './ui';

const ALL_ROLES: Role[] = ['ADMIN', 'CISO', 'SECOPS', 'PATCH_ADMIN', 'AUDITOR'];

function RolePicker({ value, onChange }: { value: Role[]; onChange: (r: Role[]) => void }) {
  return (
    <div className="grid grid-cols-2 gap-2">
      {ALL_ROLES.map((r) => (
        <label key={r} className="flex items-center gap-2 rounded-lg border border-surface-700 px-3 py-2 text-sm">
          <input type="checkbox" checked={value.includes(r)} onChange={(e) => onChange(e.target.checked ? [...value, r] : value.filter((x) => x !== r))} />
          {ROLE_LABELS[r]}
        </label>
      ))}
    </div>
  );
}

function OneTimePassword({ username, password, onClose }: { username: string; password: string; onClose: () => void }) {
  const [copied, setCopied] = useState(false);
  return (
    <Modal open title="One-time password" onClose={onClose} footer={<button className="btn-primary" onClick={onClose}>Done</button>}>
      <div className="space-y-3">
        <Notice kind="success">Share this password with <strong>{username}</strong> over a separate, secure channel. It is shown only once, is never stored by the dashboard, and must be changed at first sign-in, followed by authenticator-app enrolment.</Notice>
        <div className="flex items-center gap-2">
          <code className="flex-1 rounded-lg bg-surface-950 px-3 py-2 font-mono text-base text-white" data-testid="one-time-password">{password}</code>
          <button
            className="btn-secondary"
            onClick={() => {
              void navigator.clipboard?.writeText(password).then(() => setCopied(true));
            }}
          >
            <Copy className="h-4 w-4" /> {copied ? 'Copied' : 'Copy'}
          </button>
        </div>
      </div>
    </Modal>
  );
}

export function IdentityUsers() {
  const { can } = useAuth();
  const manage = can('users:manage');
  const [search, setSearch] = useState('');
  const [query, setQuery] = useState('');
  const users = useApi(() => api<{ items: IdentityUser[]; hasMore: boolean }>('/admin/identity/users', { query: { search: query || undefined } }), [query]);
  const [enrolOpen, setEnrolOpen] = useState(false);
  const [editing, setEditing] = useState<IdentityUser | null>(null);
  const [otp, setOtp] = useState<{ username: string; password: string } | null>(null);
  const [flash, setFlash] = useState<{ kind: 'success' | 'error'; text: string } | null>(null);

  const act = async (fn: () => Promise<unknown>, ok: string) => {
    setFlash(null);
    try {
      await fn();
      setFlash({ kind: 'success', text: ok });
      void users.reload(true);
    } catch (e) {
      setFlash({ kind: 'error', text: errorMessage(e) });
    }
  };

  const notConfigured = users.error && /not configured/i.test(users.error);

  return (
    <Card
      title={<span className="flex items-center gap-2"><UserCog className="h-4 w-4" /> Identity &amp; enrolment (identity provider)</span>}
      actions={
        manage && !notConfigured ? (
          <button className="btn-primary px-3 py-1.5 text-xs" onClick={() => setEnrolOpen(true)}>
            <UserPlus className="h-3.5 w-3.5" /> Enrol user
          </button>
        ) : undefined
      }
      bodyClass="p-0"
    >
      <div className="flex flex-wrap items-center gap-2 border-b border-surface-700/60 px-4 py-3">
        <form
          className="flex items-center gap-2"
          onSubmit={(e) => {
            e.preventDefault();
            setQuery(search.trim());
          }}
        >
          <input className="input w-64 py-1.5" placeholder="Search username, name or email" aria-label="Search identities" value={search} onChange={(e) => setSearch(e.target.value)} />
          <button className="btn-secondary px-2 py-1.5" aria-label="Search"><Search className="h-4 w-4" /></button>
        </form>
        {flash && <div className="min-w-0 flex-1"><Notice kind={flash.kind}>{flash.text}</Notice></div>}
      </div>
      {notConfigured ? (
        <div className="p-4"><Notice>Users are managed in your external identity provider.</Notice></div>
      ) : users.error ? (
        <div className="p-4"><ErrorBox message={users.error} /></div>
      ) : !users.data ? (
        <Spinner />
      ) : (
        <div className="overflow-x-auto">
          <table className="table-base">
            <thead>
              <tr>
                <th>User</th>
                <th>Roles</th>
                <th>MFA</th>
                <th>Status</th>
                <th>Last dashboard login</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {users.data.items.map((u) => (
                <tr key={u.id}>
                  <td>
                    <div className="font-medium text-slate-100">{u.username}</div>
                    <div className="text-xs text-slate-500">{[u.firstName, u.lastName].filter(Boolean).join(' ')}{u.email ? ` · ${u.email}` : ''}</div>
                  </td>
                  <td><div className="flex flex-wrap gap-1">{u.roles.length ? u.roles.map((r) => <Badge key={r}>{ROLE_LABELS[r]}</Badge>) : <span className="text-xs text-slate-500">no dashboard role</span>}</div></td>
                  <td>
                    {u.mfaConfigured ? (
                      <Badge className="bg-emerald-500/15 text-emerald-300 ring-emerald-500/40">Authenticator</Badge>
                    ) : u.requiredActions.includes('CONFIGURE_TOTP') ? (
                      <Badge className="bg-amber-500/15 text-amber-300 ring-amber-500/40">Enrol at next sign-in</Badge>
                    ) : (
                      <Badge className="bg-rose-500/15 text-rose-300 ring-rose-500/40">None</Badge>
                    )}
                  </td>
                  <td>{u.enabled ? <Badge className="bg-emerald-500/15 text-emerald-300 ring-emerald-500/40">Enabled</Badge> : <Badge className="bg-rose-500/15 text-rose-300 ring-rose-500/40">Disabled</Badge>}</td>
                  <td className="text-xs text-slate-400">{fmtDateTime(u.lastLoginAt)}</td>
                  <td className="whitespace-nowrap text-right">
                    {manage && (
                      <div className="flex justify-end gap-1">
                        <button className="btn-ghost p-1.5" title="Edit roles" aria-label={`Edit roles of ${u.username}`} onClick={() => setEditing(u)}><UserCog className="h-4 w-4" /></button>
                        <button
                          className="btn-ghost p-1.5"
                          title="Reset password"
                          aria-label={`Reset password of ${u.username}`}
                          onClick={() => {
                            if (!window.confirm(`Issue a new one-time password for ${u.username}? Their sessions end immediately.`)) return;
                            void act(async () => {
                              const r = await api<{ temporaryPassword: string }>(`/admin/identity/users/${u.id}/reset-password`, { method: 'POST' });
                              setOtp({ username: u.username, password: r.temporaryPassword });
                            }, `Password reset for ${u.username}`);
                          }}
                        >
                          <KeyRound className="h-4 w-4" />
                        </button>
                        <button
                          className="btn-ghost p-1.5"
                          title="Reset MFA"
                          aria-label={`Reset MFA of ${u.username}`}
                          onClick={() => {
                            if (!window.confirm(`Remove ${u.username}'s authenticator? They must enrol a new one at next sign-in.`)) return;
                            void act(() => api(`/admin/identity/users/${u.id}/reset-mfa`, { method: 'POST' }), `MFA reset for ${u.username}`);
                          }}
                        >
                          <ShieldOff className="h-4 w-4" />
                        </button>
                        {u.enabled ? (
                          <button className="btn-ghost p-1.5 text-rose-300" title="Disable" aria-label={`Disable ${u.username}`} onClick={() => void act(() => api(`/admin/identity/users/${u.id}`, { method: 'PATCH', body: { enabled: false } }), `${u.username} disabled`)}><Ban className="h-4 w-4" /></button>
                        ) : (
                          <button className="btn-ghost p-1.5 text-emerald-300" title="Enable" aria-label={`Enable ${u.username}`} onClick={() => void act(() => api(`/admin/identity/users/${u.id}`, { method: 'PATCH', body: { enabled: true } }), `${u.username} enabled`)}><CheckCircle2 className="h-4 w-4" /></button>
                        )}
                        <button
                          className="btn-ghost p-1.5 text-rose-300"
                          title="Delete"
                          aria-label={`Delete ${u.username}`}
                          onClick={() => {
                            if (!window.confirm(`Permanently delete ${u.username} from the identity provider?`)) return;
                            void act(() => api(`/admin/identity/users/${u.id}`, { method: 'DELETE' }), `${u.username} deleted`);
                          }}
                        >
                          <Trash2 className="h-4 w-4" />
                        </button>
                      </div>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {enrolOpen && (
        <EnrolModal
          onClose={() => setEnrolOpen(false)}
          onEnrolled={(username, password) => {
            setEnrolOpen(false);
            setOtp({ username, password });
            setFlash({ kind: 'success', text: `${username} enrolled` });
            void users.reload(true);
          }}
        />
      )}
      {editing && <RolesModal user={editing} onClose={() => setEditing(null)} onSaved={() => { setEditing(null); setFlash({ kind: 'success', text: `Roles updated for ${editing.username}` }); void users.reload(true); }} />}
      {otp && <OneTimePassword username={otp.username} password={otp.password} onClose={() => setOtp(null)} />}
    </Card>
  );
}

function EnrolModal({ onClose, onEnrolled }: { onClose: () => void; onEnrolled: (username: string, password: string) => void }) {
  const [form, setForm] = useState({ username: '', email: '', firstName: '', lastName: '' });
  const [roles, setRoles] = useState<Role[]>(['AUDITOR']);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const set = (k: keyof typeof form) => (e: React.ChangeEvent<HTMLInputElement>) => setForm({ ...form, [k]: e.target.value });
  const submit = async () => {
    setBusy(true);
    setError(null);
    try {
      const r = await api<{ username: string; temporaryPassword: string }>('/admin/identity/users', { method: 'POST', body: { ...form, roles } });
      onEnrolled(r.username, r.temporaryPassword);
    } catch (e) {
      setError(e instanceof ApiError && e.issues?.length ? e.issues.map((i) => `${i.path}: ${i.message}`).join('; ') : errorMessage(e));
    } finally {
      setBusy(false);
    }
  };
  return (
    <Modal open title="Enrol user" onClose={onClose} footer={<><button className="btn-secondary" onClick={onClose}>Cancel</button><button className="btn-primary" disabled={busy || roles.length === 0} onClick={() => void submit()}>{busy && <Loader2 className="h-4 w-4 animate-spin" />} Enrol</button></>}>
      <div className="space-y-4">
        {error && <Notice kind="error">{error}</Notice>}
        <div className="grid grid-cols-2 gap-4">
          <Field label="Username"><input className="input" value={form.username} onChange={set('username')} autoComplete="off" /></Field>
          <Field label="Email"><input className="input" type="email" value={form.email} onChange={set('email')} autoComplete="off" /></Field>
          <Field label="First name"><input className="input" value={form.firstName} onChange={set('firstName')} /></Field>
          <Field label="Last name"><input className="input" value={form.lastName} onChange={set('lastName')} /></Field>
        </div>
        <div>
          <div className="label">Dashboard roles</div>
          <RolePicker value={roles} onChange={setRoles} />
        </div>
        <p className="text-xs text-slate-500">A one-time password is generated. At first sign-in the user sets a new password and enrols an authenticator app, as required by the identity policy (Configuration → Identity &amp; enrolment).</p>
      </div>
    </Modal>
  );
}

function RolesModal({ user, onClose, onSaved }: { user: IdentityUser; onClose: () => void; onSaved: () => void }) {
  const [roles, setRoles] = useState<Role[]>(user.roles);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const save = async () => {
    setBusy(true);
    setError(null);
    try {
      await api(`/admin/identity/users/${user.id}`, { method: 'PATCH', body: { roles } });
      onSaved();
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setBusy(false);
    }
  };
  return (
    <Modal open title={`Roles — ${user.username}`} onClose={onClose} footer={<><button className="btn-secondary" onClick={onClose}>Cancel</button><button className="btn-primary" disabled={busy || roles.length === 0} onClick={() => void save()}>Save roles</button></>}>
      <div className="space-y-3">
        {error && <Notice kind="error">{error}</Notice>}
        <RolePicker value={roles} onChange={setRoles} />
        <p className="text-xs text-slate-500">Removing a role ends the user's current sessions. You cannot change your own roles, and at least one administrator must remain.</p>
      </div>
    </Modal>
  );
}
