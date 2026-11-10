import { NavLink, Outlet } from 'react-router-dom';
import clsx from 'clsx';
import {
  Activity,
  BadgeCheck,
  Bug,
  FileCheck2,
  Gauge,
  Grid3x3,
  LogOut,
  Plug,
  Radar,
  ScrollText,
  Server,
  ShieldCheck,
  SlidersHorizontal,
  Siren,
} from 'lucide-react';
import { useAuth } from '../auth/AuthContext';
import { useStreamStatus } from '../hooks/useEventStream';
import { ROLE_LABELS } from '../lib/format';

const NAV = [
  { section: 'Executive', items: [
    { to: '/', label: 'Overview', icon: Gauge, perm: 'dashboard:read' },
    { to: '/risk', label: 'Risk Matrix', icon: Grid3x3, perm: 'risk:read' },
    { to: '/acceptances', label: 'Risk Acceptance', icon: BadgeCheck, perm: 'risk:read' },
  ] },
  { section: 'Operations', items: [
    { to: '/threats', label: 'Threat Intel Stream', icon: Radar, perm: 'threat:read' },
    { to: '/incidents', label: 'Incidents', icon: Siren, perm: 'incident:read' },
    { to: '/remediation', label: 'Remediation', icon: Bug, perm: 'vuln:read' },
  ] },
  { section: 'Governance', items: [
    { to: '/parameters', label: 'KRI & Parameters', icon: SlidersHorizontal, perm: 'kri:read' },
    { to: '/compliance', label: 'Compliance Report', icon: FileCheck2, perm: 'compliance:read' },
    { to: '/audit', label: 'Audit Log', icon: ScrollText, perm: 'audit:read' },
  ] },
  { section: 'Administration', items: [
    { to: '/integrations', label: 'Integrations', icon: Plug, perm: 'integration:read' },
    { to: '/admin', label: 'System & Users', icon: Server, perm: 'users:read' },
  ] },
];

export function Layout() {
  const { me, can, logout } = useAuth();
  const live = useStreamStatus();

  return (
    <div className="flex h-full">
      <aside className="hidden w-64 shrink-0 flex-col border-r border-surface-800 bg-surface-900/60 lg:flex">
        <div className="flex items-center gap-2 px-5 py-5">
          <ShieldCheck className="h-7 w-7 text-sky-400" />
          <div>
            <div className="text-sm font-semibold text-white">CISO Command</div>
            <div className="text-[11px] uppercase tracking-wider text-slate-500">Executive Security Dashboard</div>
          </div>
        </div>
        <nav className="flex-1 space-y-5 overflow-y-auto px-3 pb-4" aria-label="Main">
          {NAV.map((group) => {
            const items = group.items.filter((i) => can(i.perm));
            if (!items.length) return null;
            return (
              <div key={group.section}>
                <div className="px-2 pb-1 text-[11px] font-semibold uppercase tracking-wider text-slate-500">{group.section}</div>
                {items.map(({ to, label, icon: Icon }) => (
                  <NavLink
                    key={to}
                    to={to}
                    end={to === '/'}
                    className={({ isActive }) =>
                      clsx(
                        'flex items-center gap-3 rounded-lg px-2 py-2 text-sm transition',
                        isActive ? 'bg-sky-500/15 text-sky-200' : 'text-slate-300 hover:bg-surface-800 hover:text-white',
                      )
                    }
                  >
                    <Icon className="h-4 w-4" /> {label}
                  </NavLink>
                ))}
              </div>
            );
          })}
        </nav>
        <div className="border-t border-surface-800 p-4 text-xs text-slate-500">Zero-trust session · TLS 1.3</div>
      </aside>

      <div className="flex min-w-0 flex-1 flex-col">
        <header className="flex items-center justify-between gap-4 border-b border-surface-800 bg-surface-900/40 px-6 py-3">
          <div className="flex items-center gap-2 text-xs">
            <span className={clsx('flex items-center gap-1.5 rounded-full px-2 py-1', live ? 'bg-emerald-500/10 text-emerald-300' : 'bg-slate-500/10 text-slate-400')}>
              <Activity className="h-3.5 w-3.5" /> {live ? 'Live' : 'Reconnecting…'}
            </span>
          </div>
          <div className="flex items-center gap-4">
            <div className="text-right">
              <div className="text-sm font-medium text-white">{me?.user.name}</div>
              <div className="text-xs text-slate-400">{me?.user.roles.map((r) => ROLE_LABELS[r] ?? r).join(' · ')}</div>
            </div>
            <button className="btn-secondary" onClick={() => void logout()}>
              <LogOut className="h-4 w-4" /> Sign out
            </button>
          </div>
        </header>
        <nav className="flex gap-1 overflow-x-auto border-b border-surface-800 px-3 py-2 lg:hidden" aria-label="Mobile">
          {NAV.flatMap((g) => g.items)
            .filter((i) => can(i.perm))
            .map(({ to, label }) => (
              <NavLink key={to} to={to} end={to === '/'} className={({ isActive }) => clsx('whitespace-nowrap rounded-md px-3 py-1.5 text-xs', isActive ? 'bg-sky-500/15 text-sky-200' : 'text-slate-400')}>
                {label}
              </NavLink>
            ))}
        </nav>
        <main className="flex-1 overflow-y-auto px-4 py-6 sm:px-6 lg:px-8">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
