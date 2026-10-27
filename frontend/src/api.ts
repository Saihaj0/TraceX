// Thin typed client for the TRACE-X API.
// All forensic data flows through these functions — the UI never fabricates values.

import type {
  AdminUsersResponse,
  AuthSession,
  AuthStatus,
  AuthUser,
  DashboardData,
  EvidenceSource,
  Finding,
  GraphPayload,
  Investigation,
  RuleInfo,
  ScenarioInfo,
  SuspicionChain,
  TimelineResponse,
} from './types';

export const API_BASE = '/api';

// --- session ---------------------------------------------------------------
// The session credential is an HttpOnly cookie set by /auth/login|signup:
// page JavaScript can never read it, and the browser attaches it to every
// same-origin request below automatically.

// One-time cleanup of the pre-cookie storage scheme.
try {
  localStorage.removeItem('tracex.token');
} catch {
  /* storage unavailable — nothing to clean */
}

export class ApiError extends Error {
  code: string;
  status: number;
  details: any;
  constructor(status: number, code: string, message: string, details?: any) {
    super(message);
    this.status = status;
    this.code = code;
    this.details = details;
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, {
    ...init,
    credentials: 'same-origin', // send the HttpOnly session cookie
  });
  const text = await response.text();
  let payload: any = null;
  try {
    payload = text ? JSON.parse(text) : null;
  } catch {
    payload = null;
  }
  if (!response.ok) {
    const detail = payload?.detail ?? payload?.error ?? {};
    const message =
      typeof detail === 'string'
        ? detail
        : detail.message || `request failed (${response.status})`;
    const code = typeof detail === 'object' ? detail.code || 'error' : 'error';
    // Session rejected server-side: tell the app to show the login screen
    // (unless this response *is* the login attempt).
    if (response.status === 401 && code !== 'invalid_credentials') {
      window.dispatchEvent(new CustomEvent('tracex:unauthorized'));
    }
    throw new ApiError(response.status, code, message, typeof detail === 'object' ? detail.details : undefined);
  }
  return payload as T;
}

function qs(params: Record<string, any>): string {
  const search = new URLSearchParams();
  Object.entries(params || {}).forEach(([key, value]) => {
    if (value === undefined || value === null || value === '') return;
    if (Array.isArray(value)) {
      if (value.length) search.set(key, value.join(','));
    } else {
      search.set(key, String(value));
    }
  });
  const out = search.toString();
  return out ? `?${out}` : '';
}

export const api = {
  health: () => request<{ status: string; dialect: string; engine_version: string; ruleset_version: string }>('/health'),
  version: () => request<Record<string, any>>('/version'),
  rules: () => request<{ rules: RuleInfo[]; ruleset_version: string; engine_version: string; defaults: Record<string, number>; severity_rationale: Record<string, string> }>('/rules'),
  parsers: () => request<{ parsers: Array<Record<string, any>>; note: string }>('/parsers'),
  uncertainty: () => request<Record<string, any>>('/uncertainty'),
  demoInfo: () => request<{ scenarios: ScenarioInfo[]; demo_investigations: number; available_scenarios: string[]; labeling: string }>('/demo'),

  dashboard: (investigationId?: string | null) =>
    request<DashboardData>(`/dashboard${qs({ investigation_id: investigationId })}`),

  search: (q: string) => request<Record<string, any>>(`/search${qs({ q })}`),

  listInvestigations: () => request<{ investigations: Investigation[]; count: number }>('/investigations'),
  getInvestigation: (id: string) => request<Investigation>(`/investigations/${id}`),
  createInvestigation: (body: { name: string; case_id: string; description?: string; notes?: string }) =>
    request<Investigation>('/investigations', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
    }),
  updateInvestigation: (id: string, body: Record<string, any>) =>
    request<Investigation>(`/investigations/${id}`, {
      method: 'PATCH',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
    }),
  deleteInvestigation: (id: string, confirm: boolean) =>
    request<{ deleted: boolean; was_demo: boolean }>(`/investigations/${id}${confirm ? '?confirm=true' : ''}`, {
      method: 'DELETE',
    }),
  updateConfig: (id: string, body: Record<string, number>) =>
    request<Record<string, any>>(`/investigations/${id}/config`, {
      method: 'PUT',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
    }),
  audit: (id: string) => request<{ entries: Array<Record<string, any>>; count: number }>(`/investigations/${id}/audit`),

  evidence: (id: string) => request<{ evidence: EvidenceSource[]; count: number }>(`/investigations/${id}/evidence`),
  evidenceErrors: (id: string, sourceId: string) =>
    request<Record<string, any>>(`/investigations/${id}/evidence/${sourceId}/errors`),
  evidenceEvents: (id: string, sourceId: string) =>
    request<{ events: any[]; total: number }>(`/investigations/${id}/evidence/${sourceId}/events`),
  previewEvidence: async (id: string, file: File) => {
    const form = new FormData();
    form.append('file', file);
    return request<{ preview: Record<string, any>; persisted: boolean }>(`/investigations/${id}/evidence/preview`, {
      method: 'POST',
      body: form,
    });
  },
  importEvidence: async (id: string, file: File) => {
    const form = new FormData();
    form.append('file', file);
    return request<Record<string, any>>(`/investigations/${id}/evidence`, { method: 'POST', body: form });
  },
  importEvidenceBatch: async (id: string, files: File[]) => {
    const form = new FormData();
    files.forEach((f) => form.append('files', f));
    return request<{
      imported: Array<Record<string, any>>;
      errors: Array<{ filename: string; code: string; message: string }>;
      files_imported: number;
      files_failed: number;
      events_accepted: number;
      records_rejected: number;
      message: string;
    }>(`/investigations/${id}/evidence/batch`, { method: 'POST', body: form });
  },
  verifyEvidence: (id: string, sourceId: string) =>
    request<{
      evidence_source_id: string; filename: string; stored_file_available: boolean;
      verified: boolean; recorded_sha256?: string; current_sha256?: string; note: string;
      limitation?: string;
    }>(`/investigations/${id}/evidence/${sourceId}/verify`, { method: 'POST' }),
  authVerify: () =>
    request<{ authenticated: boolean; actor: string; auth_mode: string; key_presented: boolean | null; note: string }>('/auth/verify'),

  authStatus: () => request<AuthStatus>('/auth/status'),
  authSignup: (body: { username: string; password: string; display_name?: string }) =>
    request<AuthSession>('/auth/signup', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
    }),
  authLogin: (body: { username: string; password: string }) =>
    request<AuthSession>('/auth/login', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
    }),
  authLogout: () => request<{ revoked: boolean; message: string }>('/auth/logout', { method: 'POST' }),
  authMe: () => request<{ user: AuthUser }>('/auth/me'),

  adminUsers: () => request<AdminUsersResponse>('/admin/users'),
  adminRevokeSession: (sessionId: string) =>
    request<{ revoked: boolean; session_id: string; message: string }>(
      `/admin/sessions/${sessionId}`, { method: 'DELETE' }),
  adminRevokeUserSessions: (userId: string) =>
    request<{ revoked: number; user_id: string; message: string }>(
      `/admin/users/${userId}/revoke-sessions`, { method: 'POST' }),

  events: (id: string, params: Record<string, any>) =>
    request<TimelineResponse>(`/investigations/${id}/events${qs(params)}`),
  eventDetail: (id: string, eventId: string) =>
    request<Record<string, any>>(`/investigations/${id}/events/${eventId}`),
  facets: (id: string, params: Record<string, any> = {}) =>
    request<Record<string, any>>(`/investigations/${id}/timeline/facets${qs(params)}`),
  timelineExportUrl: (id: string, params: Record<string, any>, format: 'csv' | 'json') =>
    `${API_BASE}/investigations/${id}/timeline/export${qs({ ...params, format })}`,

  runAnalysis: (id: string) =>
    request<Record<string, any>>(`/investigations/${id}/analysis/run`, { method: 'POST' }),
  analysisRuns: (id: string) => request<Record<string, any>>(`/investigations/${id}/analysis/runs`),

  findings: (id: string, params: Record<string, any> = {}) =>
    request<{ findings: Finding[]; total: number; summary: Record<string, any> }>(`/investigations/${id}/findings${qs(params)}`),
  finding: (id: string, findingId: string) => request<Finding>(`/investigations/${id}/findings/${findingId}`),

  chains: (id: string, params: Record<string, any> = {}) =>
    request<{ chains: SuspicionChain[]; count: number; complete: number; partial: number; note: string }>(
      `/investigations/${id}/chains${qs(params)}`),
  chain: (id: string, chainId: string) => request<SuspicionChain>(`/investigations/${id}/chains/${chainId}`),
  updateChain: (id: string, chainId: string, body: { status: string; note?: string }) =>
    request<SuspicionChain>(`/investigations/${id}/chains/${chainId}`, {
      method: 'PATCH',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
    }),

  graph: (id: string, params: Record<string, any> = {}) =>
    request<GraphPayload>(`/investigations/${id}/graph${qs(params)}`),
  graphActions: (id: string) => request<Record<string, any>>(`/investigations/${id}/graph/actions`),
  graphPath: (id: string, source_id: string, target_id: string) =>
    request<Record<string, any>>(`/investigations/${id}/graph/path`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ source_id, target_id }),
    }),
  isolateChain: (id: string, chainId: string) =>
    request<Record<string, any>>(`/investigations/${id}/graph/isolate${qs({ chain_id: chainId })}`),

  reportHtmlUrl: (id: string) => `${API_BASE}/investigations/${id}/report.html`,
  reportJsonUrl: (id: string) => `${API_BASE}/investigations/${id}/report.json?download=true`,
  reportPdfUrl: (id: string) => `${API_BASE}/investigations/${id}/report.pdf`,
  findingsCsvUrl: (id: string) => `${API_BASE}/investigations/${id}/export/findings.csv`,
  eventsJsonUrl: (id: string) => `${API_BASE}/investigations/${id}/export/events.json`,
  bodyfileCsvUrl: (id: string) => `${API_BASE}/investigations/${id}/export/bodyfile.csv`,
  supertimelineCsvUrl: (id: string) => `${API_BASE}/investigations/${id}/export/supertimeline.csv`,
  report: (id: string) => request<Record<string, any>>(`/investigations/${id}/report.json`),
  manifest: (id: string) => request<Record<string, any>>(`/investigations/${id}/report/manifest`),

  generateDemo: (scenarios: string[]) =>
    request<Record<string, any>>('/demo/generate', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(scenarios.length ? { scenarios } : {}),
    }),
  runEvaluation: (configurations: string[] = ['A', 'B', 'C']) =>
    request<Record<string, any>>('/evaluation/run', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ configurations }),
    }),
};

export function fmtTs(value?: string | null, opts: { date?: boolean } = {}): string {
  if (!value) return 'time unknown';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return String(value);
  const iso = date.toISOString();
  return opts.date ? iso.slice(0, 10) : `${iso.slice(0, 10)} ${iso.slice(11, 19)} UTC`;
}

export function fmtBytes(bytes?: number | null): string {
  if (bytes === undefined || bytes === null) return '—';
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KiB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MiB`;
}

export function titleCase(value?: string | null): string {
  if (!value) return '—';
  return String(value)
    .replace(/[_-]+/g, ' ')
    .replace(/\b\w/g, (c) => c.toUpperCase());
}

/** Trigger a client-side download of an in-memory JSON payload. */
export function downloadJson(filename: string, payload: unknown): void {
  const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
  saveBlob(filename, blob);
}

/** Trigger a client-side download of an in-memory CSV payload (already-formatted rows). */
export function downloadCsv(filename: string, csv: string): void {
  const blob = new Blob([csv], { type: 'text/csv;charset=utf-8' });
  saveBlob(filename, blob);
}

function saveBlob(filename: string, blob: Blob): void {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}
