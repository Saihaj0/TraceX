// Global UI state: theme, active investigation, notifications, toasts.
// Forensic data itself always comes from the API — this module only stores
// UI preferences and the selected investigation id.

import React, { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react';
import { api, ApiError } from './api';
import type { AuthUser, Investigation, Toast } from './types';

interface AppState {
  theme: 'dark' | 'light';
  toggleTheme: () => void;
  investigations: Investigation[];
  refreshInvestigations: () => Promise<void>;
  activeId: string | null;
  setActiveId: (id: string | null) => void;
  active: Investigation | null;
  reloadActive: () => Promise<void>;
  toasts: Toast[];
  pushToast: (kind: Toast['kind'], message: string) => void;
  dismissToast: (id: number) => void;
  actor: string;
  setActor: (value: string) => void;
  backend: { status: string; dialect: string; engine_version: string; ruleset_version: string } | null;
  // auth
  authReady: boolean;          // status probe finished
  authRequired: boolean;       // backend demands a session
  user: AuthUser | null;       // signed-in user (null = anonymous)
  signIn: (user: AuthUser) => void;
  signOut: () => Promise<void>;
}

const Ctx = createContext<AppState | null>(null);

export function useApp(): AppState {
  const ctx = useContext(Ctx);
  if (!ctx) throw new Error('useApp must be used inside AppProvider');
  return ctx;
}

let toastSeq = 1;

export const AppProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [theme, setTheme] = useState<'dark' | 'light'>(
    () => (localStorage.getItem('tracex.theme') as 'dark' | 'light') || 'dark',
  );
  const [investigations, setInvestigations] = useState<Investigation[]>([]);
  const [activeId, setActiveIdState] = useState<string | null>(
    () => localStorage.getItem('tracex.active') || null,
  );
  const [toasts, setToasts] = useState<Toast[]>([]);
  const [actor, setActorState] = useState<string>(
    () => localStorage.getItem('tracex.actor') || 'investigator',
  );
  const [backend, setBackend] = useState<AppState['backend']>(null);
  const [authReady, setAuthReady] = useState(false);
  const [authRequired, setAuthRequired] = useState(false);
  const [user, setUser] = useState<AuthUser | null>(null);

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem('tracex.theme', theme);
  }, [theme]);

  // Boot: ask the backend whether sign-in is required and who we already are
  // (the HttpOnly session cookie is attached by the browser automatically).
  useEffect(() => {
    let alive = true;
    api
      .authStatus()
      .then((status) => {
        if (!alive) return;
        setAuthRequired(status.user_auth_required);
        setUser(status.user);
        setAuthReady(true);
      })
      .catch(() => {
        // Backend unreachable — don't lock the UI out of the login screen.
        if (!alive) return;
        setAuthRequired(true);
        setUser(null);
        setAuthReady(true);
      });
    return () => {
      alive = false;
    };
  }, []);

  // Any401 from the api layer means the session is gone: drop the user so
  // the route guard flips back to the login screen.
  useEffect(() => {
    const onUnauthorized = () => setUser(null);
    window.addEventListener('tracex:unauthorized', onUnauthorized);
    return () => window.removeEventListener('tracex:unauthorized', onUnauthorized);
  }, []);

  const signIn = useCallback((nextUser: AuthUser) => {
    // The session cookie was set by the login/signup response; the UI only
    // needs the identity it already holds — nothing is stored in JS.
    setUser(nextUser);
    setAuthRequired(true);
  }, []);

  const signOut = useCallback(async () => {
    try {
      await api.authLogout(); // revoke server-side + delete the cookie
    } catch {
      /* session may already be invalid — clearing locally is enough */
    }
    setUser(null);
    setActiveIdState(null);
    localStorage.removeItem('tracex.active');
    setInvestigations([]);
  }, []);

  const pushToast = useCallback((kind: Toast['kind'], message: string) => {
    const id = toastSeq++;
    setToasts((prev) => [...prev, { id, kind, message }]);
    window.setTimeout(() => setToasts((prev) => prev.filter((t) => t.id !== id)), 6500);
  }, []);

  const dismissToast = useCallback((id: number) => {
    setToasts((prev) => prev.filter((t) => t.id !== id));
  }, []);

  const refreshInvestigations = useCallback(async () => {
    try {
      const data = await api.listInvestigations();
      setInvestigations(data.investigations);
      return data.investigations;
    } catch (error) {
      if (error instanceof ApiError) pushToast('error', `Failed to load investigations: ${error.message}`);
      throw error;
    }
  }, [pushToast]);

  const reloadActive = useCallback(async () => {
    if (!activeId) return;
    try {
      const detail = await api.getInvestigation(activeId);
      setInvestigations((prev) => prev.map((i) => (i.id === detail.id ? detail : i)));
    } catch {
      setActiveIdState(null);
      localStorage.removeItem('tracex.active');
    }
  }, [activeId]);

  // Health is a public endpoint: probe it immediately so the login screen can
  // distinguish “backend down” from “waiting for sign-in”.
  useEffect(() => {
    api.health().then(setBackend).catch(() => setBackend(null));
  }, []);

  // Case data waits for auth: never hammer guarded endpoints before login.
  useEffect(() => {
    if (!authReady) return;
    if (authRequired && !user) return;
    refreshInvestigations().catch(() => undefined);
  }, [authReady, authRequired, user, refreshInvestigations]);

  const setActiveId = useCallback((id: string | null) => {
    setActiveIdState(id);
    if (id) localStorage.setItem('tracex.active', id);
    else localStorage.removeItem('tracex.active');
  }, []);

  // Keep the active investigation object fresh (metrics change after imports).
  useEffect(() => {
    if (!activeId) return;
    if (!investigations.some((i) => i.id === activeId)) {
      reloadActive().catch(() => undefined);
    }
  }, [activeId, investigations, reloadActive]);

  const setActor = useCallback((value: string) => {
    setActorState(value);
    localStorage.setItem('tracex.actor', value);
  }, []);

  const value = useMemo<AppState>(
    () => ({
      theme,
      toggleTheme: () => setTheme((t) => (t === 'dark' ? 'light' : 'dark')),
      investigations,
      refreshInvestigations: async () => {
        await refreshInvestigations();
      },
      activeId,
      setActiveId,
      active: investigations.find((i) => i.id === activeId) || null,
      reloadActive,
      toasts,
      pushToast,
      dismissToast,
      actor,
      setActor,
      backend,
      authReady,
      authRequired,
      user,
      signIn,
      signOut,
    }),
    [theme, investigations, activeId, toasts, actor, backend, authReady, authRequired, user,
     signIn, signOut, refreshInvestigations, setActiveId, reloadActive, pushToast, dismissToast, setActor],
  );

  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
};

export function useAsync<T>(loader: () => Promise<T>, deps: any[]): {
  data: T | null;
  error: string | null;
  loading: boolean;
  reload: () => void;
} {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [tick, setTick] = useState(0);

  useEffect(() => {
    let alive = true;
    setLoading(true);
    setError(null);
    loader()
      .then((result) => {
        if (alive) setData(result);
      })
      .catch((err) => {
        if (alive) setError(err instanceof ApiError ? err.message : String(err));
      })
      .finally(() => {
        if (alive) setLoading(false);
      });
    return () => {
      alive = false;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, tick]);

  return { data, error, loading, reload: () => setTick((t) => t + 1) };
}