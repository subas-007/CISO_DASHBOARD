/**
 * Executes connector test / sync operations with decrypted credentials that exist only
 * in memory for the duration of the call.
 */
import type { Connector } from '@prisma/client';
import { decryptJson } from '../lib/crypto.js';
import { publish } from '../lib/events.js';
import { logger } from '../lib/logger.js';
import { prisma } from '../lib/prisma.js';
import { EgressPolicyError } from './egress.js';
import { ConnectorError, ConnectorHttpClient } from './httpClient.js';
import { ingestBatch, type IngestCounts } from './ingest.js';
import { getAdapter } from './registry.js';
import { DEFAULT_REQUEST_OPTIONS, RequestOptionsSchema } from './requestOptions.js';
import type { Credentials, NormalizedBatch } from './types.js';

export const credentialAad = (connectorId: string) => `connector:${connectorId}:credentials`;

const INITIAL_LOOKBACK_MS = 30 * 86_400_000;
const OVERLAP_MS = 5 * 60_000;

/** Returns a safe, generic error message — never upstream payload contents. */
export function describeError(err: unknown): string {
  if (err instanceof ConnectorError || err instanceof EgressPolicyError) return err.message;
  const code = (err as { code?: string })?.code;
  if (code === 'EBLOCKED') return 'Destination blocked by egress policy';
  if (code === 'ENOTFOUND') return 'Host could not be resolved';
  if (code === 'ECONNREFUSED') return 'Connection refused';
  if (code && /CERT|SSL|TLS/i.test(code)) return `TLS verification failed (${code})`;
  if (code === 'UND_ERR_HEADERS_TIMEOUT' || code === 'UND_ERR_BODY_TIMEOUT' || code === 'UND_ERR_CONNECT_TIMEOUT') return 'Connection timed out';
  if ((err as Error)?.name === 'ZodError') return 'Connector settings are invalid';
  return 'Connector operation failed';
}

function buildClient(connector: Connector) {
  const adapter = getAdapter(connector.vendor);
  if (!adapter) throw new ConnectorError(`Unknown connector vendor "${connector.vendor}"`);
  const creds: Credentials = connector.secretEnc ? decryptJson<Credentials>(connector.secretEnc, credentialAad(connector.id)) : {};
  const baseUrl = new URL(connector.baseUrl);
  const opts = RequestOptionsSchema.safeParse(connector.requestOptions ?? {});
  const http = new ConnectorHttpClient(baseUrl, connector.authMode, creds, adapter.apiKeyHeaders, opts.success ? opts.data : DEFAULT_REQUEST_OPTIONS);
  return { adapter, http, baseUrl };
}

export async function testConnector(connector: Connector): Promise<{ ok: boolean; message: string }> {
  let http: ConnectorHttpClient | undefined;
  try {
    const built = buildClient(connector);
    http = built.http;
    const message = await built.adapter.test({ connectorId: connector.id, baseUrl: built.baseUrl, http, since: new Date() }, connector.settings);
    await prisma.connector.update({
      where: { id: connector.id },
      data: { lastTestAt: new Date(), status: connector.enabled ? 'HEALTHY' : 'DISABLED', lastError: null },
    });
    return { ok: true, message };
  } catch (err) {
    const message = describeError(err);
    await prisma.connector.update({ where: { id: connector.id }, data: { lastTestAt: new Date(), status: 'FAILED', lastError: message } });
    return { ok: false, message };
  } finally {
    await http?.close();
    publish({ type: 'connectors' });
  }
}

export async function syncConnector(connector: Connector): Promise<{ ok: boolean; message: string; counts?: IngestCounts }> {
  let http: ConnectorHttpClient | undefined;
  let batch: NormalizedBatch | null = null;
  const started = Date.now();
  try {
    const built = buildClient(connector);
    http = built.http;
    const since = connector.lastSuccessAt
      ? new Date(connector.lastSuccessAt.getTime() - OVERLAP_MS)
      : new Date(Date.now() - INITIAL_LOOKBACK_MS);
    batch = await built.adapter.sync({ connectorId: connector.id, baseUrl: built.baseUrl, http, since }, connector.settings);
    const counts = await ingestBatch(connector.name, batch);
    const total = Object.values(counts).reduce((a, b) => a + b, 0);
    await prisma.connector.update({
      where: { id: connector.id },
      // A manual sync of a disabled connector must not make it look enabled.
      data: { status: connector.enabled ? 'HEALTHY' : 'DISABLED', lastSyncAt: new Date(), lastSuccessAt: new Date(), lastError: null, lastRecordCount: total },
    });
    logger.info({ connector: connector.name, vendor: connector.vendor, counts, ms: Date.now() - started }, 'connector sync complete');
    if (counts.threats) publish({ type: 'threats', data: { count: counts.threats } });
    if (counts.incidents) publish({ type: 'incidents', data: { count: counts.incidents } });
    if (counts.vulnerabilities || counts.assets) publish({ type: 'vulnerabilities' });
    return { ok: true, message: `Synchronised ${total} records`, counts };
  } catch (err) {
    const message = describeError(err);
    logger.warn({ connector: connector.name, vendor: connector.vendor, error: message }, 'connector sync failed');
    await prisma.connector.update({ where: { id: connector.id }, data: { status: 'FAILED', lastSyncAt: new Date(), lastError: message } });
    return { ok: false, message };
  } finally {
    batch = null; // release normalised + transient data for GC
    await http?.close();
    publish({ type: 'connectors' });
  }
}
