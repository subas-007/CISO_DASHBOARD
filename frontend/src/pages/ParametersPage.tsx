import { useState } from 'react';
import { Check, Save } from 'lucide-react';
import { api, errorMessage } from '../lib/api';
import { useApi } from '../hooks/useApi';
import { useLiveRefresh } from '../hooks/useEventStream';
import { useAuth } from '../auth/AuthContext';
import { Card, Empty, ErrorBox, Notice, PageHeader, RagBadge, Spinner, Toggle } from '../components/ui';
import { fmtDateTime, fmtNumber } from '../lib/format';
import type { KriStatus, Rag, SettingItem } from '../lib/types';

interface Breach {
  id: string;
  kriKey: string;
  level: Rag;
  value: number;
  threshold: number;
  detectedAt: string;
  acknowledgedAt: string | null;
}

export function ParametersPage() {
  const kris = useApi(() => api<{ items: KriStatus[] }>('/kri'));
  const breaches = useApi(() => api<{ items: Breach[] }>('/kri/breaches'));
  const settings = useApi(() => api<{ items: SettingItem[] }>('/admin/settings'));
  const { can } = useAuth();
  useLiveRefresh(['kri', 'kpi'], () => {
    void kris.reload(true);
    void breaches.reload(true);
  });

  const ack = async (id: string) => {
    try {
      await api(`/kri/breaches/${id}/acknowledge`, { method: 'POST' });
      void breaches.reload(true);
    } catch (e) {
      alert(errorMessage(e));
    }
  };

  return (
    <div className="space-y-6">
      <PageHeader title="KRI Thresholds & Parameter Definitions" subtitle="Risk appetite thresholds drive Red / Amber / Green status. All changes are audited with before/after values." />

      <Card title="Key Risk Indicators" bodyClass="p-0">
        {kris.error && <ErrorBox message={kris.error} />}
        {!kris.data ? <Spinner /> : (
          <div className="overflow-x-auto">
            <table className="table-base">
              <thead>
                <tr>
                  <th>Indicator</th>
                  <th>Direction</th>
                  <th className="text-right">Current</th>
                  <th>Amber</th>
                  <th>Red</th>
                  <th>Enabled</th>
                  <th>Status</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {kris.data.items.map((k) => <KriRow key={k.key} kri={k} editable={can('parameters:manage')} onSaved={() => void kris.reload(true)} />)}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      <div className="grid grid-cols-1 gap-6 xl:grid-cols-2">
        <Card title="System parameters">
          {!settings.data ? <Spinner /> : (
            <div className="space-y-4">
              {settings.data.items.map((s) => <SettingRow key={s.key} item={s} onSaved={() => void settings.reload(true)} />)}
            </div>
          )}
        </Card>

        <Card title="KRI breach register" bodyClass="p-0">
          {!breaches.data ? <Spinner /> : breaches.data.items.length === 0 ? <Empty>No breaches recorded.</Empty> : (
            <table className="table-base">
              <thead>
                <tr>
                  <th>KRI</th>
                  <th>Level</th>
                  <th className="text-right">Value / threshold</th>
                  <th>Detected</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {breaches.data.items.slice(0, 50).map((b) => (
                  <tr key={b.id}>
                    <td className="font-mono text-xs">{b.kriKey}</td>
                    <td><RagBadge status={b.level} /></td>
                    <td className="text-right tabular-nums">{fmtNumber(b.value)} / {b.threshold}</td>
                    <td className="text-xs text-slate-400">{fmtDateTime(b.detectedAt)}</td>
                    <td className="text-right">
                      {b.acknowledgedAt ? (
                        <span className="text-xs text-slate-500">ack {fmtDateTime(b.acknowledgedAt)}</span>
                      ) : can('kri:acknowledge') ? (
                        <button className="btn-secondary px-2 py-1 text-xs" onClick={() => void ack(b.id)}><Check className="h-3.5 w-3.5" /> Acknowledge</button>
                      ) : null}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Card>
      </div>
    </div>
  );
}

function KriRow({ kri, editable, onSaved }: { kri: KriStatus; editable: boolean; onSaved: () => void }) {
  const [amber, setAmber] = useState(String(kri.amberThreshold));
  const [red, setRed] = useState(String(kri.redThreshold));
  const [enabled, setEnabled] = useState(kri.enabled);
  const [error, setError] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);
  const dirty = Number(amber) !== kri.amberThreshold || Number(red) !== kri.redThreshold || enabled !== kri.enabled;

  const save = async () => {
    setError(null);
    try {
      await api(`/kri/${kri.key}`, { method: 'PUT', body: { amberThreshold: Number(amber), redThreshold: Number(red), enabled } });
      setSaved(true);
      setTimeout(() => setSaved(false), 2000);
      onSaved();
    } catch (e) {
      setError(errorMessage(e));
    }
  };

  return (
    <>
      <tr>
        <td>
          <div className="font-medium text-slate-100">{kri.name}</div>
          <div className="text-xs text-slate-500">{kri.description}</div>
        </td>
        <td className="text-xs text-slate-400">{kri.direction === 'HIGHER_IS_WORSE' ? 'Higher is worse' : 'Lower is worse'}</td>
        <td className="text-right tabular-nums">{fmtNumber(kri.value)} <span className="text-xs text-slate-500">{kri.unit}</span></td>
        <td><input className="input w-24 py-1" type="number" step="any" disabled={!editable} value={amber} onChange={(e) => setAmber(e.target.value)} aria-label={`${kri.name} amber threshold`} /></td>
        <td><input className="input w-24 py-1" type="number" step="any" disabled={!editable} value={red} onChange={(e) => setRed(e.target.value)} aria-label={`${kri.name} red threshold`} /></td>
        <td><Toggle label="Enabled" checked={enabled} disabled={!editable} onChange={setEnabled} /></td>
        <td><RagBadge status={kri.status} /></td>
        <td>
          {editable && (
            <button className="btn-secondary px-2 py-1 text-xs" disabled={!dirty} onClick={() => void save()}>
              {saved ? <Check className="h-3.5 w-3.5 text-emerald-300" /> : <Save className="h-3.5 w-3.5" />} Save
            </button>
          )}
        </td>
      </tr>
      {error && (
        <tr>
          <td colSpan={8}><Notice kind="error">{error}</Notice></td>
        </tr>
      )}
    </>
  );
}

function SettingRow({ item, onSaved }: { item: SettingItem; onSaved: () => void }) {
  const [text, setText] = useState(typeof item.value === 'object' ? JSON.stringify(item.value) : String(item.value));
  const [error, setError] = useState<string | null>(null);
  const [ok, setOk] = useState(false);
  const save = async () => {
    setError(null);
    let value: unknown;
    try {
      value = typeof item.value === 'object' ? JSON.parse(text) : Number(text);
    } catch {
      setError('Invalid JSON');
      return;
    }
    try {
      await api(`/admin/settings/${item.key}`, { method: 'PUT', body: { value } });
      setOk(true);
      setTimeout(() => setOk(false), 2000);
      onSaved();
    } catch (e) {
      setError(errorMessage(e));
    }
  };
  return (
    <div>
      <div className="label">{item.label}</div>
      <div className="flex gap-2">
        <input className="input font-mono text-xs" disabled={!item.editable} value={text} onChange={(e) => setText(e.target.value)} aria-label={item.label} />
        {item.editable && (
          <button className="btn-secondary" onClick={() => void save()}>
            {ok ? <Check className="h-4 w-4 text-emerald-300" /> : <Save className="h-4 w-4" />}
          </button>
        )}
      </div>
      {!item.editable && <div className="mt-1 text-xs text-slate-500">Requires {item.permission}</div>}
      {error && <div className="mt-1 text-xs text-rose-300">{error}</div>}
    </div>
  );
}
