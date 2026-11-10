/**
 * Applies a saved configuration change to the running system according to its apply
 * mode, and re-applies live settings periodically so every API replica converges.
 */
import { logger } from '../../lib/logger.js';
import { refreshEgressPolicy } from '../../connectors/egress.js';
import { idpConfigured, syncIdentityPolicy } from '../../idp/identity.service.js';
import { getSetting, SETTINGS, type SettingKey } from '../settings/settings.service.js';

export interface ApplyResult {
  mode: (typeof SETTINGS)[SettingKey]['apply'];
  ok: boolean;
  message: string;
}

export async function applyLiveSettings(): Promise<void> {
  await refreshEgressPolicy();
  const { level } = await getSetting('logging');
  if (logger.level !== level) logger.level = level;
}

export async function applySettingChange(key: SettingKey): Promise<ApplyResult> {
  const mode = SETTINGS[key].apply;
  switch (key) {
    case 'connectorDefaults':
    case 'logging':
      await applyLiveSettings();
      return { mode, ok: true, message: 'Applied immediately' };
    case 'identity':
    case 'sessionPolicy': {
      if (!idpConfigured()) {
        return { mode, ok: key === 'sessionPolicy', message: key === 'sessionPolicy' ? 'Applied to dashboard sessions (no IdP administration configured)' : 'Saved — identity provider administration is not configured; apply this policy in your IdP' };
      }
      const r = await syncIdentityPolicy();
      return { mode, ok: r.ok, message: r.ok ? `Applied and synchronised to the identity provider. ${r.message}` : `Saved, but identity provider sync failed: ${r.message}` };
    }
    default:
      if (mode === 'redeploy') return { mode, ok: true, message: 'Saved — download the deployment profile and run scripts/apply-deployment.sh on the Docker host' };
      if (mode === 'host') return { mode, ok: true, message: 'Saved — download the host baseline script, review it and run it with sudo on the Docker host' };
      return { mode, ok: true, message: 'Applied immediately' };
  }
}
