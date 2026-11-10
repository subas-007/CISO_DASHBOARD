/**
 * In-process event hub for Server-Sent Events. Events are lightweight change
 * notifications (no sensitive payloads); clients re-fetch through authorised APIs.
 * For horizontally scaled deployments, swap for PostgreSQL LISTEN/NOTIFY or Redis pub/sub.
 */
import { EventEmitter } from 'node:events';

export type StreamEventType = 'kpi' | 'kri' | 'threats' | 'incidents' | 'connectors' | 'risks' | 'vulnerabilities';

export interface StreamEvent {
  type: StreamEventType;
  data?: Record<string, string | number | boolean | null>;
}

const hub = new EventEmitter();
hub.setMaxListeners(2000);

export function publish(event: StreamEvent): void {
  hub.emit('event', event);
}

export function subscribe(listener: (e: StreamEvent) => void): () => void {
  hub.on('event', listener);
  return () => hub.off('event', listener);
}
