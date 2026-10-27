// Sign in / sign up screen. Rendered by the route guard whenever the backend
// reports TRACEX_USER_AUTH_ENABLED and no live session exists. The session
// credential is an HttpOnly cookie set by the response — this page (and any
// page JavaScript) never sees or stores a token.

import React, { useState } from 'react';
import { KeyRound, ShieldCheck, UserPlus } from 'lucide-react';
import { api, ApiError } from '../api';
import { useApp } from '../state';

type Mode = 'signin' | 'signup';

export const Login: React.FC = () => {
  const { signIn, pushToast, backend } = useApp();
  const [mode, setMode] = useState<Mode>('signin');
  const [username, setUsername] = useState('');
  const [displayName, setDisplayName] = useState('');
  const [password, setPassword] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    if (busy) return;
    setError(null);
    setBusy(true);
    try {
      if (mode === 'signin') {
        const session = await api.authLogin({ username, password });
        signIn(session.user);
        pushToast('success', `Welcome back, ${session.user.display_name || session.user.username}.`);
      } else {
        const session = await api.authSignup({
          username,
          password,
          ...(displayName.trim() ? { display_name: displayName.trim() } : {}),
        });
        signIn(session.user);
        pushToast('success', session.message || `Account created for ${session.user.username}.`);
      }
    } catch (err) {
      const message = err instanceof ApiError ? err.message : 'sign-in failed — is the backend running?';
      setError(message);
      if (err instanceof ApiError && err.code === 'too_many_attempts') {
        pushToast('warning', message);
      }
    } finally {
      setBusy(false);
    }
  };

  const switchMode = (next: Mode) => {
    setMode(next);
    setError(null);
  };

  return (
    <div className="auth-screen">
      <div className="auth-card">
        <div className="auth-brand">
          <div className="brand-logo" style={{ width: 40, height: 40, display: 'grid', placeItems: 'center' }}>
            <ShieldCheck size={20} />
          </div>
          <div>
            <div className="brand-name" style={{ fontSize: 18 }}>TRACE-X</div>
            <div className="brand-sub">Explainable Forensics Engine</div>
          </div>
        </div>

        <div className="auth-tabs" role="tablist" aria-label="Authentication mode">
          <button
            type="button"
            role="tab"
            aria-selected={mode === 'signin'}
            className={`auth-tab ${mode === 'signin' ? 'active' : ''}`}
            onClick={() => switchMode('signin')}
          >
            <KeyRound size={14} /> Sign in
          </button>
          <button
            type="button"
            role="tab"
            aria-selected={mode === 'signup'}
            className={`auth-tab ${mode === 'signup' ? 'active' : ''}`}
            onClick={() => switchMode('signup')}
          >
            <UserPlus size={14} /> Sign up
          </button>
        </div>

        <form onSubmit={submit} className="auth-form">
          <label className="field">
            <span>Username</span>
            <input
              className="input"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              autoComplete="username"
              placeholder="investigator"
              required
              autoFocus
            />
            {mode === 'signup' && (
              <small className="faint">3–32 characters: letters, digits, “.”, “_” or “-”.</small>
            )}
          </label>

          {mode === 'signup' && (
            <label className="field">
              <span>Display name <em className="faint">(optional)</em></span>
              <input
                className="input"
                value={displayName}
                onChange={(e) => setDisplayName(e.target.value)}
                autoComplete="name"
                placeholder="Ada Lovelace"
                maxLength={128}
              />
            </label>
          )}

          <label className="field">
            <span>Password</span>
            <input
              className="input"
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              autoComplete={mode === 'signin' ? 'current-password' : 'new-password'}
              placeholder={mode === 'signup' ? 'at least 8 characters' : '••••••••'}
              required
              minLength={mode === 'signup' ? 8 : 1}
            />
          </label>

          {error && (
            <div className="errorbox" role="alert">
              <span>{error}</span>
            </div>
          )}

          <button className="btn primary" type="submit" disabled={busy} style={{ width: '100%' }}>
            {busy ? 'Verifying…' : mode === 'signin' ? 'Sign in' : 'Create account'}
          </button>
        </form>

        <div className="auth-foot faint">
          Your username becomes the audit actor and the owner of the cases you create.
          {backend === null && ' · backend unreachable'}
        </div>
      </div>
    </div>
  );
};
