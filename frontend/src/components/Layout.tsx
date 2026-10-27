// Persistent application shell: sidebar navigation, global search, active
// investigation selector, notifications area and profile/settings menu.

import React, { useEffect, useMemo, useRef, useState } from 'react';
import { NavLink, useNavigate } from 'react-router-dom';
import {
  Activity, AlertOctagon, Bell, Boxes, ChevronDown, FileBarChart2, FileSearch, GitFork,
  LayoutDashboard, LogOut, Moon, Network, PanelLeftClose, Search, Settings as SettingsIcon, Sun,
  User, Users as UsersIcon, Workflow,
} from 'lucide-react';
import { api, fmtTs } from '../api';
import { useApp } from '../state';

const NAV = [
  { to: '/', label: 'Overview', icon: LayoutDashboard, end: true },
  { to: '/investigations', label: 'Investigations', icon: Boxes },
  { to: '/timeline', label: 'Timeline', icon: Activity },
  { to: '/evidence', label: 'Evidence Explorer', icon: FileSearch },
  { to: '/anti-forensics', label: 'Anti-Forensics', icon: AlertOctagon },
  { to: '/chains', label: 'Suspicion Chains', icon: Workflow },
  { to: '/graph', label: 'Forensic Graph', icon: Network },
  { to: '/reports', label: 'Reports', icon: FileBarChart2 },
  { to: '/admin', label: 'Admin', icon: UsersIcon, adminOnly: true },
  { to: '/settings', label: 'Settings', icon: SettingsIcon },
];

export const Layout: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const { activeId, investigations, setActiveId, theme, toggleTheme, backend, pushToast,
    user, signOut } = useApp();
  const navigate = useNavigate();
  const [search, setSearch] = useState('');
  const [results, setResults] = useState<Record<string, any> | null>(null);
  const [showSearch, setShowSearch] = useState(false);
  const [showBell, setShowBell] = useState(false);
  const [showProfile, setShowProfile] = useState(false);
  const [showPicker, setShowPicker] = useState(false);
  const [notifications, setNotifications] = useState<Array<Record<string, any>>>([]);
  const searchRef = useRef<HTMLDivElement>(null);

  // Global search (debounced) across investigations, findings, chains and events.
  useEffect(() => {
    if (search.trim().length < 2) {
      setResults(null);
      return;
    }
    const handle = window.setTimeout(() => {
      api
        .search(search.trim())
        .then((data) => {
          setResults(data);
          setShowSearch(true);
        })
        .catch((error) => pushToast('error', `Search failed: ${error.message}`));
    }, 260);
    return () => window.clearTimeout(handle);
  }, [search, pushToast]);

  useEffect(() => {
    const onClick = (event: MouseEvent) => {
      if (searchRef.current && !searchRef.current.contains(event.target as Node)) setShowSearch(false);
    };
    document.addEventListener('mousedown', onClick);
    return () => document.removeEventListener('mousedown', onClick);
  }, []);

  // Notifications are derived from persisted findings/imports on the active case.
  useEffect(() => {
    if (!activeId) {
      setNotifications([]);
      return;
    }
    api
      .findings(activeId, { severity: 'critical', limit: 5 })
      .then((data) => {
        const items = data.findings.map((f) => ({
          id: f.id,
          text: `${f.rule_id}: ${f.title}`,
          at: f.occurred_at,
          kind: 'critical' as const,
          finding: f,
        }));
        setNotifications(items);
      })
      .catch(() => setNotifications([]));
  }, [activeId]);

  const activeInvestigation = useMemo(
    () => investigations.find((i) => i.id === activeId) || null,
    [investigations, activeId],
  );

  const go = (path: string) => {
    navigate(path);
    setShowSearch(false);
  };

  return (
    <div className="shell">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-logo">
            <Network size={18} />
          </div>
          <div>
            <div className="brand-name">TRACE-X</div>
            <div className="brand-sub">Forensics Engine</div>
          </div>
        </div>
        <nav className="nav" aria-label="Main navigation">
          {NAV.filter((item) => !(item as any).adminOnly || user?.is_admin).map((item) => {
            const Icon = item.icon;
            return (
              <NavLink
                key={item.to}
                to={item.to}
                end={(item as any).end}
                className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}
              >
                <Icon size={16} />
                <span className="label">{item.label}</span>
              </NavLink>
            );
          })}
        </nav>
        <div className="sidebar-foot">
          engine {backend?.engine_version || '—'} · ruleset {backend?.ruleset_version || '—'}
          <br />
          {backend ? `db: ${backend.dialect}` : 'backend unreachable'}
        </div>
      </aside>

      <div className="main">
        <header className="topbar">
          <div className="row tight" style={{ position: 'relative' }}>
            <button
              className="btn sm"
              onClick={() => setShowPicker((v) => !v)}
              aria-haspopup="listbox"
              aria-expanded={showPicker}
            >
              <span className="badge-dot" style={{ background: activeInvestigation ? 'var(--green)' : 'var(--text-faint)' }} />
              {activeInvestigation ? activeInvestigation.case_id : 'No investigation'}
              <ChevronDown size={14} />
            </button>
            {showPicker && (
              <div className="dropdown" style={{ left: 0, right: 'auto', maxHeight: 400, overflowY: 'auto' }} role="listbox">
                <div className="head">Active investigation</div>
                {investigations.length === 0 && <div className="item faint">No investigations yet</div>}
                {investigations.map((inv) => (
                  <div
                    key={inv.id}
                    className="item"
                    role="option"
                    aria-selected={inv.id === activeId}
                    onClick={() => {
                      setActiveId(inv.id);
                      setShowPicker(false);
                    }}
                  >
                    <span className="grow">
                      <div>{inv.case_id} · {inv.name}</div>
                      <div className="faint">
                        {inv.metrics.events} events · {inv.metrics.findings} findings
                        {inv.is_demo ? ' · SYNTHETIC' : ''}
                      </div>
                    </span>
                    {inv.id === activeId && <span className="chip cyan">active</span>}
                  </div>
                ))}
                <div className="item" onClick={() => { setShowPicker(false); navigate('/investigations'); }}>
                  <Search size={14} /> Manage investigations…
                </div>
              </div>
            )}
          </div>

          <div className="searchbox grow" ref={searchRef} style={{ maxWidth: 460 }}>
            <span className="icon">
              <Search size={14} />
            </span>
            <input
              className="input"
              placeholder="Global search — events, findings, files, users…"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              onFocus={() => results && setShowSearch(true)}
              aria-label="Global search"
            />
            {showSearch && results && (
              <div className="dropdown" style={{ left: 0, right: 0, maxHeight: 420, overflowY: 'auto' }}>
                <div className="head">
                  {results.total_hits} hit(s) for “{search}”
                </div>
                {(results.investigations || []).map((i: any) => (
                  <div key={`inv-${i.id}`} className="item" onClick={() => { setActiveId(i.id); go('/investigations'); }}>
                    <Boxes size={13} /> {i.case_id} — {i.name}
                  </div>
                ))}
                {(results.findings || []).map((f: any) => (
                  <div key={`f-${f.id}`} className="item" onClick={() => { setActiveId(f.investigation_id); go(`/anti-forensics?f=${f.id}`); }}>
                    <AlertOctagon size={13} /> <span className="truncate">{f.rule_id} · {f.title}</span>
                  </div>
                ))}
                {(results.chains || []).map((c: any) => (
                  <div key={`c-${c.id}`} className="item" onClick={() => { setActiveId(c.investigation_id); go(`/chains?c=${c.id}`); }}>
                    <Workflow size={13} /> <span className="truncate">{c.title}</span>
                  </div>
                ))}
                {(results.events || []).map((e: any) => (
                  <div key={`e-${e.id}`} className="item" onClick={() => { setActiveId(e.investigation_id); go(`/timeline?e=${e.id}`); }}>
                    <Activity size={13} /> <span className="truncate">{e.description}</span>
                  </div>
                ))}
                {!results.total_hits && <div className="item faint">Nothing matches that query.</div>}
              </div>
            )}
          </div>

          <div className="spacer" />

          <div style={{ position: 'relative' }}>
            <button className="btn ghost sm" onClick={() => setShowBell((v) => !v)} aria-label="Notifications">
              <Bell size={16} />
              {notifications.length > 0 && (
                <span className="chip red" style={{ padding: '0 6px' }}>{notifications.length}</span>
              )}
            </button>
            {showBell && (
              <div className="dropdown">
                <div className="head">High-priority findings on active case</div>
                {notifications.length === 0 && (
                  <div className="item faint">No critical findings — or no investigation selected.</div>
                )}
                {notifications.map((n) => (
                  <div key={n.id} className="item" onClick={() => { setShowBell(false); navigate('/anti-forensics'); }}>
                    <span className="badge-dot" style={{ background: 'var(--red)' }} />
                    <span className="truncate" title={n.text}>{n.text}</span>
                  </div>
                ))}
              </div>
            )}
          </div>

          <div style={{ position: 'relative' }}>
            <button className="btn ghost sm" onClick={toggleTheme} aria-label="Toggle theme">
              {theme === 'dark' ? <Sun size={16} /> : <Moon size={16} />}
            </button>
          </div>

          <div style={{ position: 'relative' }}>
            <button className="btn ghost sm" onClick={() => setShowProfile((v) => !v)} aria-label="Profile menu">
              <User size={16} />
              <ChevronDown size={13} />
            </button>
            {showProfile && (
              <div className="dropdown">
                <div className="head">Session</div>
                {user ? (
                  <>
                    <div className="item">
                      <User size={14} />
                      <span className="grow">
                        <div>{user.display_name || user.username}</div>
                        <div className="faint">@{user.username} · audit actor & case owner</div>
                      </span>
                    </div>
                    <div
                      className="item"
                      onClick={() => {
                        setShowProfile(false);
                        signOut().then(() => pushToast('info', 'Signed out.'));
                      }}
                    >
                      <LogOut size={14} /> Sign out
                    </div>
                  </>
                ) : (
                  <>
                    <div className="item">
                      <User size={14} />
                      <span className="grow">Actor recorded in the audit trail</span>
                    </div>
                    <div style={{ padding: '0 12px 10px' }}>
                      <input
                        className="input"
                        style={{ width: '100%' }}
                        defaultValue=""
                        placeholder="investigator"
                        aria-label="Actor name"
                        onKeyDown={(e) => {
                          if (e.key === 'Enter') {
                            const value = (e.target as HTMLInputElement).value.trim();
                            if (value) {
                              localStorage.setItem('tracex.actor', value);
                              window.location.reload();
                            }
                          }
                        }}
                      />
                      <div className="faint" style={{ marginTop: 4 }}>press Enter to apply</div>
                    </div>
                  </>
                )}
                <div className="item" onClick={() => { setShowProfile(false); navigate('/settings'); }}>
                  <SettingsIcon size={14} /> Settings & methodology
                </div>
              </div>
            )}
          </div>
        </header>

        <main className="content">{children}</main>
      </div>
    </div>
  );
};