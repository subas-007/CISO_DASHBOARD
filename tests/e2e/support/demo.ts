import { spawnSync } from 'node:child_process';
import { ENV, ROOT } from './env';

/** Toggles the live demo-data simulator directly in the settings table (API cache ≤ 15 s). */
export function setLiveSimulation(on: boolean): void {
  const sql = `UPDATE system_settings SET value = jsonb_set(value::jsonb, '{liveSimulation}', '${on}'::jsonb) WHERE key = 'demoData';`;
  spawnSync('docker', ['compose', 'exec', '-T', '-e', `PGPASSWORD=${ENV.POSTGRES_PASSWORD}`, 'postgres', 'psql', '-h', '127.0.0.1', '-U', ENV.POSTGRES_USER ?? 'ciso_owner', '-d', ENV.POSTGRES_DB ?? 'ciso', '-tA', '-c', sql], { cwd: ROOT, encoding: 'utf8' });
}
