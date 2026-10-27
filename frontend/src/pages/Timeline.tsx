// Timeline — the interactive forensic timeline.
// Chronological ordering (asc/desc), date-range + facet filters, free-text search,
// multi-select, suspicious-sequence highlighting, uncertainty display and export.
// Every value here comes from the API; nothing is fabricated client-side.

import React, { useEffect, useMemo, useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import {
  Activity, AlertTriangle, ArrowDownWideNarrow, ArrowUpWideNarrow, Download, FileJson,
  Filter, GitFork, RotateCcw, Search,
} from 'lucide-react';
import { api, downloadCsv, downloadJson, fmtTs, titleCase } from '../api';
import { useApp } from '../state';
import type { TimelineEvent, TimelineResponse } from '../types';
import { Distribution, Drawer, EmptyState, ErrorBox, Hash, Skeleton } from '../components/ui';

const PAGE_SIZE = 50;
type FacetApiResponse = {
  event_types?: string[]; users?: string[]; processes?: string[]; files?: string[];
  devices?: string[]; hosts?: string[]; source_types?: string[];
  sources?: Array<{ id: string; filename: string; file_type: string; origin: string }>;
};

// Filter field -> key used by GET /timeline/facets.
const FACET_KEYS = ['event_type', 'source_file', 'user', 'process_name', 'file_path', 'device_id', 'host'] as const;
const FIELD_LABELS: Record<string, string> = {
  event_type: 'Event type', source_file: 'Source file', user: 'User', process_name: 'Process',
  file_path: 'File path', device_id: 'Device', host: 'Host',
};
const API_FACET_KEY: Record<string, keyof FacetApiResponse> = {
  event_type: 'event_types', source_file: 'sources', user: 'users', process_name: 'processes',
  file_path: 'files', device_id: 'devices', host: 'hosts',
};

/** Distinct values for one facet as plain strings (values come from the API only). */
function facetValues(facets: FacetApiResponse | null, field: string): string[] {
  if (!facets) return [];
  const raw = facets[API_FACET_KEY[field]];
  if (!raw) return [];
  if (field === 'source_file') return (raw as FacetApiResponse['sources'])!.map((s) => s.filename);
  return raw as string[];
}

interface Filters {
  q: string; start: string; end: string; sort: 'asc' | 'desc'; include_undated: boolean;
  event_type: string; source_file: string; user: string; process_name: string;
  file_path: string; device_id: string; host: string;
}
const EMPTY_FILTERS: Filters = {
  q: '', start: '', end: '', sort: 'asc', include_undated: true,
  event_type: '', source_file: '', user: '', process_name: '', file_path: '', device_id: '', host: '',
};

export const TimelinePage: React.FC = () => {
  const { active, pushToast, reloadActive } = useApp();
  const navigate = useNavigate();
  const [params, setParams] = useSearchParams();
  const [filters, setFilters] = useState<Filters>(EMPTY_FILTERS);
  const [page, setPage] = useState(1);
  const [data, setData] = useState<TimelineResponse | null>(null);
  const [facets, setFacets] = useState<FacetApiResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [detail, setDetail] = useState<TimelineEvent | null>(null);
  const [showFilters, setShowFilters] = useState(true);
  const [busy, setBusy] = useState(false);

  const invId = active?.id ?? null;
  const focusId = params.get('e');

  const activeCount = useMemo(
    () => FACET_KEYS.filter((k) => filters[k]).length + (filters.q ? 1 : 0) + (filters.start ? 1 : 0) + (filters.end ? 1 : 0),
    [filters],
  );

  // Map UI filter fields to the plural query parameters used by the API
  // (GET /investigations/{id}/events). Sending invented names would silently
  // no-op the filter, so every key here is verified against the backend.
  const query = useMemo(() => {
    const base: Record<string, any> = {
      limit: PAGE_SIZE, offset: (page - 1) * PAGE_SIZE,
      sort: filters.sort, include_undated: filters.include_undated,
    };
    if (filters.q) base.search = filters.q;
    if (filters.start) base.start = filters.start;
    // A date-only "end" must cover the whole day, not cut off at midnight.
    if (filters.end) base.end = `${filters.end}T23:59:59`;
    if (filters.event_type) base.event_types = filters.event_type;
    if (filters.user) base.users = filters.user;
    if (filters.process_name) base.processes = filters.process_name;
    if (filters.file_path) base.files = filters.file_path;
    if (filters.device_id) base.devices = filters.device_id;
    if (filters.host) base.hosts = filters.host;
    if (filters.source_file) {
      const ids = (facets?.sources || [])
        .filter((s) => s.filename === filters.source_file)
        .map((s) => s.id);
      if (ids.length) base.source_ids = ids.join(',');
    }
    return base;
  }, [filters, page, facets]);

  const load = async () => {
    if (!invId) { setData(null); return; }
    setLoading(true); setError(null);
    try {
      const [timeline, facetData] = await Promise.all([api.events(invId, query), api.facets(invId, {})]);
      setData(timeline);
      setFacets((facetData as unknown as FacetApiResponse) || null);
    } catch (e: any) {
      setError(e?.message || 'Failed to load timeline');
      setData(null);
    } finally {
      setLoading(false);
    }
  };

  // Key the reload on the SERIALIZED query: `query` gets a fresh identity
  // whenever a facets object is replaced, which previously re-triggered load()
  // in an unbounded loop (skeletons never resolved, API hammered).
  const queryKey = JSON.stringify(query);
  useEffect(() => { load(); /* eslint-disable-next-line */ }, [invId, queryKey]);

  useEffect(() => {
    if (!focusId || !data) return;
    const hit = data.events.find((e) => e.id === focusId);
    if (hit) setDetail(hit);
  }, [focusId, data]);

  const setFilter = (patch: Partial<Filters>) => { setFilters((f) => ({ ...f, ...patch })); setPage(1); setSelected(new Set()); };
  const reset = () => { setFilters(EMPTY_FILTERS); setPage(1); setSelected(new Set()); };

  const runAnalysis = async () => {
    if (!invId) return;
    setBusy(true);
    try {
      await api.runAnalysis(invId);
      pushToast('success', 'Analysis complete — findings and suspicion chains refreshed.');
      await reloadActive();
      load();
    } catch (e: any) {
      pushToast('error', `Analysis failed: ${e?.message || e}`);
    } finally {
      setBusy(false);
    }
  };

  const toggle = (id: string) => setSelected((s) => { const n = new Set(s); if (n.has(id)) n.delete(id); else n.add(id); return n; });
  const allSelected = !!data && data.events.length > 0 && data.events.every((e) => selected.has(e.id));
  const toggleAll = () => { if (!data) return; setSelected(allSelected ? new Set() : new Set(data.events.map((e) => e.id))); };

  const exportTimeline = (format: 'json' | 'csv') => {
    if (!invId || !active || !data) return;
    // Selection export works from the rows already loaded; with no selection
    // the backend exports the FULL filtered result set (not just this page).
    if (selected.size) {
      const rows = data.events.filter((e) => selected.has(e.id));
      if (format === 'json') {
        downloadJson(`timeline-${active.case_id}-selection.json`, {
          exported_at: new Date().toISOString(),
          investigation: { id: active.id, case_id: active.case_id, name: active.name },
          filters, count: rows.length, events: rows,
        });
      } else {
        const cols = ['id', 'timestamp', 'timestamp_precision', 'timestamp_confidence', 'event_type', 'source_type', 'source_file', 'source_record_id', 'host', 'user', 'process_id', 'process_name', 'file_path', 'device_id', 'description', 'ingestion_status', 'origin'];
        const esc = (v: any) => { const s = v === null || v === undefined ? '' : String(v); return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s; };
        const lines = [cols.join(',')];
        rows.forEach((r: any) => lines.push(cols.map((c) => esc(r[c])).join(',')));
        downloadCsv(`timeline-${active.case_id}-selection.csv`, lines.join('\n'));
      }
      pushToast('success', `Exported ${rows.length} selected event(s).`);
      return;
    }
    const url = api.timelineExportUrl(invId, { ...query, limit: undefined, offset: 0 }, format);
    const a = document.createElement('a');
    a.href = url;
    a.setAttribute('download', '');
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    pushToast('success', `Exported ${data.total} filtered event(s) from the server.`);
  };

  const exportSelected = (format: 'json' | 'csv') => {
    if (!data) return;
    const rows = selected.size ? data.events.filter((e) => selected.has(e.id)) : data.events;
    if (!rows.length) { pushToast('warning', 'No events to export.'); return; }
    if (format === 'json') {
      downloadJson(`timeline-${active?.case_id || 'export'}.json`, {
        exported_at: new Date().toISOString(),
        investigation: active ? { id: active.id, case_id: active.case_id, name: active.name } : null,
        filters, total_matching: data.total, exported_count: rows.length, events: rows,
      });
    } else {
      const cols = ['id', 'timestamp', 'timestamp_precision', 'timestamp_confidence', 'event_type', 'source_type', 'source_file', 'source_record_id', 'host', 'user', 'process_id', 'process_name', 'file_path', 'device_id', 'description', 'ingestion_status', 'origin'];
      const esc = (v: any) => { const s = v === null || v === undefined ? '' : String(v); return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s; };
      const lines = [cols.join(',')];
      rows.forEach((r: any) => lines.push(cols.map((c) => esc(r[c])).join(',')));
      downloadCsv(`timeline-${active?.case_id || 'export'}.csv`, lines.join('\n'));
    }
    pushToast('success', `Exported ${rows.length} event(s) as ${format.toUpperCase()}.`);
  };

  if (!active) {
    return (
      <EmptyState
        icon={<Activity size={40} />} title="No active investigation"
        message="Create or select an investigation to reconstruct its timeline."
        action={<button className="btn" onClick={() => navigate('/investigations')}>Go to Investigations</button>}
      />
    );
  }

  const events = data?.events ?? [];
  const totalPages = data ? Math.max(1, Math.ceil(data.total / PAGE_SIZE)) : 1;
  const typeCounts: Record<string, number> = {};
  events.forEach((ev) => { typeCounts[ev.event_type] = (typeCounts[ev.event_type] || 0) + 1; });

  return (
    <div>
      <div className="row" style={{ marginBottom: 14 }}>
        <div className="grow">
          <h2 style={{ margin: 0, fontSize: 18 }}>Timeline</h2>
          <div className="faint">Reconstructed chronology for {active.case_id} — {active.name}</div>
        </div>
        <button className="btn ghost" onClick={() => setShowFilters((v) => !v)}>
          <Filter size={14} /> Filters{activeCount ? ` (${activeCount})` : ''}
        </button>
        <button className="btn ghost" onClick={() => exportTimeline('csv')} disabled={!events.length}><Download size={14} /> CSV{selected.size ? ' (selected)' : ''}</button>
        <button className="btn ghost" onClick={() => exportTimeline('json')} disabled={!events.length}><FileJson size={14} /> JSON{selected.size ? ' (selected)' : ''}</button>
        <button className="btn primary" onClick={runAnalysis} disabled={busy}>
          <RotateCcw size={14} style={busy ? { animation: 'spin 1s linear infinite' } : undefined} /> {busy ? 'Running…' : 'Run analysis'}
        </button>
      </div>

      {showFilters && (
        <div className="card">
          <div className="grid cols-4">
            <label className="field" style={{ gridColumn: 'span 2' }}>
              <label>Search</label>
              <div className="searchbox" style={{ minWidth: 0 }}>
                <span className="icon"><Search size={14} /></span>
                <input className="input" value={filters.q} placeholder="description, path, identifier…"
                  onChange={(e) => setFilter({ q: e.target.value })} aria-label="Search events" />
              </div>
            </label>
            <label className="field"><label>From</label>
              <input type="date" className="input" value={filters.start} onChange={(e) => setFilter({ start: e.target.value })} />
            </label>
            <label className="field"><label>To</label>
              <input type="date" className="input" value={filters.end} onChange={(e) => setFilter({ end: e.target.value })} />
            </label>
            {FACET_KEYS.map((k) => (
              <label className="field" key={k}>
                <label>{FIELD_LABELS[k]}</label>
                <select className="input" value={filters[k]} onChange={(e) => setFilter({ [k]: e.target.value } as any)}>
                  <option value="">All</option>
                  {facetValues(facets, k).slice(0, 200).map((v) => (
                    <option key={v} value={v}>{k === 'event_type' ? titleCase(v) : v}</option>
                  ))}
                </select>
              </label>
            ))}
            <div className="field"><label>Order</label>
              <div className="row tight">
                <button className={`btn sm ${filters.sort === 'asc' ? 'primary' : 'ghost'}`} onClick={() => setFilter({ sort: 'asc' })} title="Oldest first">
                  <ArrowUpWideNarrow size={14} /> Asc
                </button>
                <button className={`btn sm ${filters.sort === 'desc' ? 'primary' : 'ghost'}`} onClick={() => setFilter({ sort: 'desc' })} title="Newest first">
                  <ArrowDownWideNarrow size={14} /> Desc
                </button>
              </div>
            </div>
            <div className="field"><label>Undated</label>
              <label className="checkbox">
                <input type="checkbox" checked={filters.include_undated} onChange={(e) => setFilter({ include_undated: e.target.checked })} />
                include events without timestamps
              </label>
            </div>
          </div>
          <div className="row tight" style={{ marginTop: 4 }}>
            <button className="btn ghost sm" onClick={reset}>Reset</button>
            {selected.size > 0 && <span className="chip cyan">{selected.size} selected</span>}
            <div className="grow" />
            {data && (
              <span className="faint">
                {data.total} matching · {data.undated_in_page} undated in page{data.flagged_count ? ` · ${data.flagged_count} tied to findings` : ''}
              </span>
            )}
          </div>
        </div>
      )}

      {error && <div style={{ marginTop: 14 }}><ErrorBox error={error} onRetry={load} /></div>}

      <div className="card">
        {loading ? (
          <div>{Array.from({ length: 8 }).map((_, i) => <Skeleton key={i} height={26} />)}</div>
        ) : events.length === 0 ? (
          <EmptyState icon={<Search size={34} />} title="No events" message="No timeline events matched the current filters." />
        ) : (
          <>
            <div className="table-wrap">
              <table className="data">
                <thead>
                  <tr>
                    <th style={{ width: 34 }}><input type="checkbox" checked={allSelected} onChange={toggleAll} aria-label="Select all" /></th>
                    <th>Timestamp</th><th>Type</th><th>Description</th><th>User</th><th>Host</th><th>Source</th><th>Flags</th>
                  </tr>
                </thead>
                <tbody>
                  {events.map((ev) => {
                    const uncertain = ev.timestamp_confidence !== 'confirmed';
                    const cls = [selected.has(ev.id) ? 'selected' : '', ev.flagged ? 'flagged' : ''].filter(Boolean).join(' ');
                    return (
                      <tr key={ev.id} className={cls} onClick={() => setDetail(ev)}>
                        <td onClick={(e) => e.stopPropagation()}><input type="checkbox" checked={selected.has(ev.id)} onChange={() => toggle(ev.id)} aria-label="Select event" /></td>
                        <td className="mono" style={{ whiteSpace: 'nowrap' }}>
                          {fmtTs(ev.timestamp)}
                          {ev.order_uncertain && <span title="Order uncertain" style={{ color: 'var(--amber)' }}> ~</span>}
                        </td>
                        <td><span className="chip cyan">{titleCase(ev.event_type)}</span></td>
                        <td className="truncate" title={ev.description || ''}>{ev.description || '—'}</td>
                        <td className="cell-dim">{ev.user || '—'}</td>
                        <td className="cell-dim">{ev.host || '—'}</td>
                        <td className="cell-faint truncate" title={ev.source_file || ''}>{ev.source_file || '—'}</td>
                        <td style={{ whiteSpace: 'nowrap' }}>
                          {ev.flagged && <span className="chip amber" title="Part of a suspicion chain"><GitFork size={11} /></span>}{' '}
                          {uncertain && <span className="chip amber" title={`Timestamp ${ev.timestamp_confidence}`}>?</span>}{' '}
                          {ev.origin === 'demo' && <span className="chip">demo</span>}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
            {totalPages > 1 && (
              <div className="pager">
                <button className="btn ghost sm" disabled={page <= 1} onClick={() => setPage((p) => p - 1)}>Prev</button>
                <span>Page {page} / {totalPages}</span>
                <button className="btn ghost sm" disabled={page >= totalPages} onClick={() => setPage((p) => p + 1)}>Next</button>
              </div>
            )}
          </>
        )}
      </div>

      {facets && events.length > 0 && (
        <div className="card">
          <div className="card-head"><h3>Event distribution in view</h3></div>
          <Distribution data={typeCounts} tone="amber" label={titleCase} />
          <div className="faint" style={{ marginTop: 6 }}>
            Counts across the {events.length} event row(s) currently in view.
          </div>
        </div>
      )}

      {detail && (
        <Drawer
          title={`${titleCase(detail.event_type)}`}
          subtitle={fmtTs(detail.timestamp)}
          onClose={() => { setDetail(null); if (focusId) { const next = new URLSearchParams(params); next.delete('e'); setParams(next, { replace: true }); } }}
        >
          <p className="faint" style={{ marginTop: 0 }}>{detail.description || 'No description recorded.'}</p>

          {detail.warnings?.length > 0 && (
            <div className="notice warn" style={{ marginBottom: 12 }}>
              {detail.warnings.map((w, i) => <div key={i} className="row tight"><AlertTriangle size={12} style={{ flex: '0 0 auto' }} /> {w}</div>)}
            </div>
          )}

          <div className="section-title">Normalized record</div>
          <dl className="kv">
            <dt>event_id</dt><dd className="mono">{detail.id}</dd>
            <dt>timestamp</dt><dd className="mono">{detail.timestamp || '—'}</dd>
            <dt>precision</dt><dd>{detail.timestamp_precision}</dd>
            <dt>confidence</dt><dd>{detail.timestamp_confidence}</dd>
            {detail.timezone_note && (<><dt>timezone</dt><dd>{detail.timezone_note}</dd></>)}
            {detail.host && (<><dt>host</dt><dd>{detail.host}</dd></>)}
            {detail.user && (<><dt>user</dt><dd>{detail.user}</dd></>)}
            {detail.process_name && (<><dt>process</dt><dd className="mono">{detail.process_name}{detail.process_id ? ` (${detail.process_id})` : ''}</dd></>)}
            {detail.file_path && (<><dt>file_path</dt><dd className="mono">{detail.file_path}</dd></>)}
            {detail.device_id && (<><dt>device_id</dt><dd className="mono">{detail.device_id}</dd></>)}
          </dl>

          <div className="section-title">Provenance</div>
          <dl className="kv">
            <dt>source_type</dt><dd>{detail.source_type}</dd>
            <dt>source_file</dt><dd className="mono">{detail.source_file || '—'}</dd>
            <dt>source_record_id</dt><dd className="mono">{detail.source_record_id || '—'}</dd>
            <dt>parser</dt><dd className="mono">{detail.parser_name} v{detail.parser_version}</dd>
            <dt>raw_record_ref</dt><dd className="mono">{detail.raw_record_reference || '—'}</dd>
            <dt>ingestion_status</dt><dd>{detail.ingestion_status}</dd>
            <dt>origin</dt><dd>{detail.origin}</dd>
            <dt>integrity_hash</dt><dd><Hash value={detail.integrity_hash} /></dd>
          </dl>

          {detail.flagged && (
            <div className="notice" style={{ marginTop: 14 }}>
              <span className="row tight"><GitFork size={13} /> This event participates in a suspicion chain or finding. See Suspicion Chains.</span>
            </div>
          )}
        </Drawer>
      )}
    </div>
  );
};

export default TimelinePage;
