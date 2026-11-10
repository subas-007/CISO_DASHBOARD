import { createContext, useCallback, useContext, useEffect, useRef, useState, type ReactNode } from 'react';
import { refreshSession } from '../lib/api';

type Listener = (type: string, data: unknown) => void;
const EVENT_TYPES = ['kpi', 'kri', 'threats', 'incidents', 'connectors', 'risks', 'vulnerabilities'];

interface StreamCtx {
  connected: boolean;
  subscribe: (fn: Listener) => () => void;
}

const Ctx = createContext<StreamCtx>({ connected: false, subscribe: () => () => undefined });

/** Single shared SSE connection; reconnects after the server closes it on token expiry. */
export function EventStreamProvider({ children }: { children: ReactNode }) {
  const [connected, setConnected] = useState(false);
  const listeners = useRef(new Set<Listener>());

  useEffect(() => {
    let es: EventSource | null = null;
    let retry: ReturnType<typeof setTimeout> | undefined;
    let closed = false;

    const connect = () => {
      es = new EventSource('/api/stream', { withCredentials: true });
      es.addEventListener('ready', () => setConnected(true));
      es.addEventListener('reauth', () => {
        es?.close();
        setConnected(false);
        void refreshSession().then(() => !closed && connect());
      });
      for (const t of EVENT_TYPES) {
        es.addEventListener(t, (e) => {
          let data: unknown = {};
          try {
            data = JSON.parse((e as MessageEvent<string>).data);
          } catch {
            /* ignore */
          }
          listeners.current.forEach((fn) => fn(t, data));
        });
      }
      es.onerror = () => {
        setConnected(false);
        es?.close();
        if (closed) return;
        retry = setTimeout(() => {
          void refreshSession().finally(() => !closed && connect());
        }, 5000);
      };
    };
    connect();
    return () => {
      closed = true;
      clearTimeout(retry);
      es?.close();
    };
  }, []);

  const subscribe = useCallback((fn: Listener) => {
    listeners.current.add(fn);
    return () => {
      listeners.current.delete(fn);
    };
  }, []);

  return <Ctx.Provider value={{ connected, subscribe }}>{children}</Ctx.Provider>;
}

/** Invoke `onEvent` when any of the given event types arrive (debounced). */
export function useLiveRefresh(types: string[], onEvent: () => void, debounceMs = 800) {
  const { subscribe } = useContext(Ctx);
  const cb = useRef(onEvent);
  cb.current = onEvent;
  const key = types.join(',');
  useEffect(() => {
    let t: ReturnType<typeof setTimeout> | undefined;
    const unsub = subscribe((type) => {
      if (!key.split(',').includes(type)) return;
      clearTimeout(t);
      t = setTimeout(() => cb.current(), debounceMs);
    });
    return () => {
      clearTimeout(t);
      unsub();
    };
  }, [key, subscribe, debounceMs]);
}

export const useStreamStatus = () => useContext(Ctx).connected;
