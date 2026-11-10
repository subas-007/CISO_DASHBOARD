import { createContext, useCallback, useContext, useEffect, useState, type ReactNode } from 'react';
import { api, refreshSession } from '../lib/api';
import type { Me } from '../lib/types';

interface AuthState {
  me: Me | null;
  loading: boolean;
  can: (permission: string) => boolean;
  login: () => void;
  logout: () => Promise<void>;
}

const AuthCtx = createContext<AuthState | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [me, setMe] = useState<Me | null>(null);
  const [loading, setLoading] = useState(true);

  const load = useCallback(async () => {
    try {
      setMe(await api<Me>('/auth/me'));
    } catch {
      if (await refreshSession()) {
        try {
          setMe(await api<Me>('/auth/me'));
          return;
        } catch {
          /* fall through */
        }
      }
      setMe(null);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
    const onExpired = () => setMe(null);
    window.addEventListener('auth:expired', onExpired);
    return () => window.removeEventListener('auth:expired', onExpired);
  }, [load]);

  const can = useCallback((p: string) => !!me?.user.permissions.includes(p), [me]);

  const login = () => {
    const returnTo = window.location.pathname.startsWith('/login') ? '/' : window.location.pathname;
    window.location.assign(`/api/auth/login?returnTo=${encodeURIComponent(returnTo)}`);
  };

  const logout = async () => {
    try {
      const { logoutUrl } = await api<{ logoutUrl: string }>('/auth/logout', { method: 'POST' });
      setMe(null);
      // Only follow same-origin / IdP URLs returned by our own API.
      window.location.assign(logoutUrl);
    } catch {
      setMe(null);
      window.location.assign('/login');
    }
  };

  return <AuthCtx.Provider value={{ me, loading, can, login, logout }}>{children}</AuthCtx.Provider>;
}

export function useAuth(): AuthState {
  const ctx = useContext(AuthCtx);
  if (!ctx) throw new Error('useAuth must be used within AuthProvider');
  return ctx;
}

/** Hides children unless the user holds the permission (presentation only — the API enforces). */
export function Can({ permission, children, fallback = null }: { permission: string; children: ReactNode; fallback?: ReactNode }) {
  const { can } = useAuth();
  return <>{can(permission) ? children : fallback}</>;
}
