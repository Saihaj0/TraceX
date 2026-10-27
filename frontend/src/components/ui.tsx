// Small presentational primitives shared by every page.
// All charts render values passed in from the API — nothing here invents data.

import React from 'react';
import { AlertTriangle, Info, Search, X } from 'lucide-react';
import type { Toast } from '../types';

export const Skeleton: React.FC<{ height?: number; width?: string | number; count?: number }> = ({
  height = 14,
  width = '100%',
  count = 1,
}) => (
  <>
    {Array.from({ length: count }).map((_, i) => (
      <div key={i} className="skeleton" style={{ height, width, marginBottom: 6 }} />
    ))}
  </>
);

export const EmptyState: React.FC<{
  icon?: React.ReactNode;
  title: string;
  message: string;
  action?: React.ReactNode;
}> = ({ icon, title, message, action }) => (
  <div className="empty">
    <div style={{ display: 'grid', placeItems: 'center', color: 'var(--accent)' }}>{icon}</div>
    <h4>{title}</h4>
    <p>{message}</p>
    {action}
  </div>
);

export const ErrorBox: React.FC<{ error: string; onRetry?: () => void }> = ({ error, onRetry }) => (
  <div className="errorbox">
    <div className="row">
      <AlertTriangle size={16} />
      <span className="grow">{error}</span>
      {onRetry && (
        <button className="btn sm" onClick={onRetry}>
          Retry
        </button>
      )}
    </div>
  </div>
);

export const StatCard: React.FC<{
  label: string;
  value: React.ReactNode;
  hint?: React.ReactNode;
  tone?: 'default' | 'accent' | 'warn' | 'danger';
  icon?: React.ReactNode;
}> = ({ label, value, hint, tone = 'default', icon }) => (
  <div className={`stat ${tone === 'default' ? '' : tone}`}>
    <div className="label">
      {icon}
      {label}
    </div>
    <div className="value">{value}</div>
    {hint && <div className="hint">{hint}</div>}
  </div>
);

export const Modal: React.FC<{
  title: string;
  onClose: () => void;
  children: React.ReactNode;
  footer?: React.ReactNode;
}> = ({ title, onClose, children, footer }) => (
  <div className="modal-backdrop" onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
    <div className="modal" role="dialog" aria-modal="true" aria-label={title}>
      <div className="row" style={{ marginBottom: 6 }}>
        <h3 className="grow">{title}</h3>
        <button className="btn ghost sm" onClick={onClose} aria-label="Close dialog">
          <X size={16} />
        </button>
      </div>
      {children}
      {footer && <div className="row" style={{ marginTop: 16, justifyContent: 'flex-end' }}>{footer}</div>}
    </div>
  </div>
);

export const Drawer: React.FC<{
  title: React.ReactNode;
  subtitle?: React.ReactNode;
  onClose: () => void;
  children: React.ReactNode;
}> = ({ title, subtitle, onClose, children }) => (
  <>
    <div className="drawer-backdrop" onMouseDown={onClose} />
    <aside className="drawer" aria-label="Detail panel">
      <div className="row" style={{ marginBottom: 4 }}>
        <div className="grow">
          <div style={{ fontWeight: 650, fontSize: 15 }}>{title}</div>
          {subtitle && <div className="faint">{subtitle}</div>}
        </div>
        <button className="btn ghost sm" onClick={onClose} aria-label="Close panel">
          <X size={16} />
        </button>
      </div>
      {children}
    </aside>
  </>
);

export const ToastStack: React.FC<{ toasts: Toast[]; onDismiss: (id: number) => void }> = ({
  toasts,
  onDismiss,
}) => (
  <div className="toast-stack">
    {toasts.map((toast) => (
      <div key={toast.id} className={`toast ${toast.kind}`} role="status">
        <span className="grow">{toast.message}</span>
        <button className="btn ghost sm" onClick={() => onDismiss(toast.id)} aria-label="Dismiss">
          <X size={13} />
        </button>
      </div>
    ))}
  </div>
);

/** Horizontal distribution bars computed from a count map. */
export const Distribution: React.FC<{
  data: Record<string, number>;
  tone?: 'cyan' | 'amber' | 'red';
  label?: (key: string) => string;
  max?: number;
}> = ({ data, tone = 'cyan', label, max }) => {
  const entries = Object.entries(data || {}).sort((a, b) => b[1] - a[1]);
  if (!entries.length) return <div className="faint">No data recorded yet.</div>;
  const ceiling = max || Math.max(...entries.map(([, v]) => v)) || 1;
  return (
    <div className="bars">
      {entries.map(([key, value]) => (
        <div className="bar-row" key={key}>
          <div className="truncate" title={key}>
            {label ? label(key) : key}
          </div>
          <div className="bar-track">
            <div className={`bar-fill ${tone === 'amber' ? 'amber' : tone === 'red' ? 'red' : ''}`} style={{ width: `${(value / ceiling) * 100}%` }} />
          </div>
          <div style={{ textAlign: 'right', fontVariantNumeric: 'tabular-nums' }}>{value}</div>
        </div>
      ))}
    </div>
  );
};

/** Lightweight SVG area chart for event activity over time (real bucket counts). */
export const ActivityChart: React.FC<{
  points: Array<{ bucket: string; count: number }>;
  height?: number;
}> = ({ points, height = 130 }) => {
  if (!points?.length) {
    return <div className="faint">No timestamped activity recorded yet.</div>;
  }
  const width = 720;
  const pad = { top: 10, right: 8, bottom: 20, left: 30 };
  const maxCount = Math.max(...points.map((p) => p.count), 1);
  const stepX = (width - pad.left - pad.right) / Math.max(points.length - 1, 1);
  const toY = (count: number) => pad.top + (height - pad.top - pad.bottom) * (1 - count / maxCount);
  const line = points
    .map((p, i) => `${i === 0 ? 'M' : 'L'}${(pad.left + i * stepX).toFixed(1)},${toY(p.count).toFixed(1)}`)
    .join(' ');
  const area = `${line} L${(pad.left + (points.length - 1) * stepX).toFixed(1)},${height - pad.bottom} L${pad.left},${height - pad.bottom} Z`;
  const first = points[0].bucket.slice(0, 16).replace('T', ' ');
  const last = points[points.length - 1].bucket.slice(0, 16).replace('T', ' ');
  return (
    <svg viewBox={`0 0 ${width} ${height}`} width="100%" height={height} role="img" aria-label="Event activity over time">
      <defs>
        <linearGradient id="activityFill" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor="var(--accent)" stopOpacity="0.35" />
          <stop offset="100%" stopColor="var(--accent)" stopOpacity="0.02" />
        </linearGradient>
      </defs>
      {[0.25, 0.5, 0.75].map((f) => (
        <line key={f} x1={pad.left} x2={width - pad.right} y1={pad.top + (height - pad.top - pad.bottom) * f} y2={pad.top + (height - pad.top - pad.bottom) * f} stroke="var(--border)" strokeWidth="1" />
      ))}
      <path d={area} fill="url(#activityFill)" />
      <path d={line} fill="none" stroke="var(--accent)" strokeWidth="2" />
      <text x={pad.left} y={height - 6} fontSize="10" fill="var(--text-faint)">{first}</text>
      <text x={width - pad.right} y={height - 6} fontSize="10" fill="var(--text-faint)" textAnchor="end">{last}</text>
      <text x={4} y={pad.top + 8} fontSize="10" fill="var(--text-faint)">{maxCount}</text>
    </svg>
  );
};

export const SearchInput: React.FC<{
  value: string;
  onChange: (value: string) => void;
  placeholder?: string;
  onSubmit?: () => void;
}> = ({ value, onChange, placeholder, onSubmit }) => (
  <div className="searchbox">
    <span className="icon">
      <Search size={14} />
    </span>
    <input
      className="input"
      value={value}
      placeholder={placeholder || 'Search…'}
      onChange={(e) => onChange(e.target.value)}
      onKeyDown={(e) => e.key === 'Enter' && onSubmit?.()}
      aria-label={placeholder || 'Search'}
    />
  </div>
);

export const InfoNote: React.FC<{ children: React.ReactNode; tone?: 'default' | 'warn' }> = ({
  children,
  tone = 'default',
}) => (
  <div className={`notice ${tone === 'warn' ? 'warn' : ''}`}>
    <div className="row tight">
      <Info size={14} style={{ flex: '0 0 auto' }} />
      <div>{children}</div>
    </div>
  </div>
);

export const SeverityBadge: React.FC<{ severity: string }> = ({ severity }) => (
  <span className={`chip ${severity === 'critical' || severity === 'high' ? 'red' : severity === 'medium' ? 'amber' : ''}`}>
    <span className={`sev ${severity}`}>{severity}</span>
  </span>
);

export const SupportBadge: React.FC<{ support: string }> = ({ support }) => (
  <span className={`chip support ${support}`} title="Qualitative evidence-strength classification — not a probability">
    {support} support
  </span>
);

export const Hash: React.FC<{ value?: string | null }> = ({ value }) =>
  value ? <span className="hashes" title={value}>{value.slice(0, 16)}…{value.slice(-6)}</span> : <span className="faint">—</span>;