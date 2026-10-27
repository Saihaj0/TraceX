// Administration — registered users, their sign-in sessions and session
// revocation. Every value on this page comes from /api/admin/*; the backend
// never returns password hashes or raw session tokens.

import React, { useState } from 'react';
import { ChevronDown, ChevronRight, LogOut, RefreshCw, ShieldCheck, Users, XOctagon } from 'lucide-react';
import { api, fmtTs } from '../api';
import { useApp, useAsync } from '../state';
import { ErrorBox, InfoNote, Skeleton } from '../components/ui';
import type { AdminSession, AdminUser } from '../types';

const STATUS_CHIP: Record<AdminSession['status'], string> = {
  live: 'chip cyan',
  expired: 'chip',
  revoked: 'chip red',
};

const SessionTable: React.FC<{
  user: AdminUser;
  busy: string | null;
  onRevoke: (session: AdminSession) => void;
}> = ({ user, busy, onRevoke }) => {
  if (!user.sessions.length) {
    return <div className="faint" style={{ padding: '8px 0' }}>No sessions recorded for this account.</div>;
  }
  return (
    <table className="data" style={{ marginTop: 6 }}>
      <thead>
        <tr>
          <th>Device (user agent)</th>
          <th>Client IP</th>
          <th>Signed in</th>
          <th>Expires</th>
          <th>Status</th>
          <th style={{ textAlign: 'right' }}>Action</th>
        </tr>
      </thead>
      <tbody>
        {user.sessions.map((session) => (
          <tr key={session.id}>
            <td className="truncate" style={{ maxWidth: 320 }} title={session.user_agent || undefined}>
              {session.user_agent || <span className="faint">unknown device</span>}
              {session.is_current && <span className="chip amber" style={{ marginLeft: 6 }}>this session</span>}
            </td>
            <td className="hashes" title={session.client_ip || undefined}>
              {session.client_ip || <span className="faint">—</span>}
            </td>
            <td>{fmtTs(session.created_at)}</td>
            <td>{fmtTs(session.expires_at)}</td>
            <td><span className={STATUS_CHIP[session.status]}>{session.status}</span></td>
            <td style={{ textAlign: 'right' }}>
              {session.status === 'live' ? (
                <button
                  className="btn sm danger"
                  disabled={busy === session.id}
                  title={session.is_current
                    ? 'This is your own session — revoking signs you out on the next request'
                    : 'The session token is rejected from its next request onwards'}
                  onClick={() => onRevoke(session)}
                >
                  <XOctagon size={13} /> {busy === session.id ? 'Revoking…' : 'Revoke'}
                </button>
              ) : (
                <span className="faint">—</span>
              )}
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
};

export const AdminPage: React.FC = () => {
  const { user: me, pushToast } = useApp();
  const { data, error, loading, reload } = useAsync(() => api.adminUsers(), []);
  const [expanded, setExpanded] = useState<Record<string, boolean>>({});
  const [busy, setBusy] = useState<string | null>(null);

  const revokeOne = async (owner: AdminUser, session: AdminSession) => {
    setBusy(session.id);
    try {
      const result = await api.adminRevokeSession(session.id);
      pushToast(
        'success',
        session.is_current
          ? 'Session revoked — including your own; you will be asked to sign in again.'
          : `Session for @${owner.username} revoked.`,
      );
      reload();
      return result;
    } catch (err: any) {
      pushToast('error', `Revocation failed: ${err.message}`);
    } finally {
      setBusy(null);
    }
  };

  const revokeAll = async (target: AdminUser) => {
    setBusy(`${target.id}:all`);
    try {
      const result = await api.adminRevokeUserSessions(target.id);
      pushToast('success', `@${target.username}: ${result.revoked} session(s) revoked.`);
      reload();
    } catch (err: any) {
      pushToast('error', `Revocation failed: ${err.message}`);
    } finally {
      setBusy(null);
    }
  };

  const users = data?.users ?? [];

  return (
    <div>
      <div className="row" style={{ marginBottom: 14 }}>
        <div className="grow">
          <h2 style={{ margin: 0, fontSize: 18 }}>Administration</h2>
          <div className="faint">
            Registered accounts and their sign-in sessions — revocation takes effect on the
            session's next request
          </div>
        </div>
        <button className="btn ghost" onClick={reload} disabled={loading}>
          <RefreshCw size={14} style={loading ? { animation: 'spin 1s linear infinite' } : undefined} /> Refresh
        </button>
      </div>

      <InfoNote>
        Sessions authenticate through an HttpOnly cookie — tokens are never readable by page
        JavaScript, and only SHA-256 digests are stored server-side. Password hashes and raw
        tokens are never shown here. All revocations are recorded in the audit trail.
      </InfoNote>

      {error && <ErrorBox error={error} onRetry={reload} />}

      {loading && !data && <Skeleton height={44} count={4} />}

      {data && !users.length && (
        <div className="card" style={{ marginTop: 12 }}>
          <div className="empty">
            <Users size={26} />
            <h4>No accounts yet</h4>
            <p>User accounts appear here after the first sign-up on this instance.</p>
          </div>
        </div>
      )}

      {data && users.length > 0 && (
        <div className="card" style={{ marginTop: 12 }}>
          <div className="card-head">
            <Users size={15} color="var(--accent)" />
            <h3 className="grow">
              Registered users <span className="faint">({users.length})</span>
            </h3>
            {me?.is_admin && (
              <span className="chip cyan" title="You administer this instance">you are admin</span>
            )}
          </div>
          <table className="data">
            <thead>
              <tr>
                <th>User</th>
                <th>Role</th>
                <th>Registered</th>
                <th>Last sign-in</th>
                <th>Sessions</th>
                <th style={{ textAlign: 'right' }}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {users.map((account) => (
                <React.Fragment key={account.id}>
                  <tr>
                    <td>
                      <button
                        className="btn ghost sm"
                        aria-expanded={!!expanded[account.id]}
                        onClick={() => setExpanded((prev) => ({ ...prev, [account.id]: !prev[account.id] }))}
                        title="Show session history"
                      >
                        {expanded[account.id] ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
                        <strong>{account.display_name || account.username}</strong>
                        <span className="faint">@{account.username}</span>
                      </button>
                    </td>
                    <td>
                      {account.is_admin
                        ? <span className="chip cyan"><ShieldCheck size={11} /> admin</span>
                        : <span className="chip">investigator</span>}
                      {!account.is_active && <span className="chip red">deactivated</span>}
                    </td>
                    <td>{fmtTs(account.created_at)}</td>
                    <td>{account.last_login_at ? fmtTs(account.last_login_at) : <span className="faint">never</span>}</td>
                    <td>
                      <span className={account.active_sessions ? 'chip cyan' : 'chip'}>
                        {account.active_sessions} live
                      </span>{' '}
                      <span className="faint">of {account.total_sessions} total</span>
                    </td>
                    <td style={{ textAlign: 'right' }}>
                      <button
                        className="btn sm danger"
                        disabled={busy === `${account.id}:all` || account.active_sessions === 0}
                        title={account.active_sessions === 0
                          ? 'No live sessions to revoke'
                          : 'Revoke every live session for this account at once'}
                        onClick={() => revokeAll(account)}
                      >
                        <LogOut size={13} />{' '}
                        {busy === `${account.id}:all` ? 'Revoking…' : 'Revoke all sessions'}
                      </button>
                    </td>
                  </tr>
                  {expanded[account.id] && (
                    <tr>
                      <td colSpan={7} style={{ paddingTop: 0 }}>
                        <SessionTable
                          user={account}
                          busy={busy}
                          onRevoke={(session) => revokeOne(account, session)}
                        />
                      </td>
                    </tr>
                  )}
                </React.Fragment>
              ))}
            </tbody>
          </table>
          <div className="faint" style={{ marginTop: 8 }}>{data.note}</div>
        </div>
      )}
    </div>
  );
};
