// Evidence Explorer — import artifacts (EVTX, filesystem/NTFS exports, browser
// history, JSON/CSV), inspect per-source parsing results, rejected records and
// the events each source contributed. Rejected rows are never hidden.

import React, { useEffect, useRef, useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import {
  AlertTriangle, Boxes, CheckCircle2, Eye, FileSearch, FileText, RefreshCw, ShieldCheck, Trash2,
  UploadCloud,
} from 'lucide-react';
import { api, fmtBytes, fmtTs, titleCase } from '../api';
import { useApp, useAsync } from '../state';
import type { EvidenceSource, TimelineEvent } from '../types';
import {
  Distribution, Drawer, EmptyState, ErrorBox, Hash, Modal, Skeleton, StatCard,
} from '../components/ui';

interface PreviewPayload {
  filename: string;
  file_type: string;
  record_count: number;
  accepted: number;
  rejected: number;
  status: string;
  preview: Array<Record<string, any>>;
  errors: Array<Record<string, any>>;
  warnings: string[];
  metadata: Record<string, any>;
  timezone_note: string | null;
  parser: { name: string; version: string; note?: string } | null;
}

type PickFn = (file: File) => void;

/* -------------------------------------------------------------------------- */
/* Upload card                                                                  */
/* -------------------------------------------------------------------------- */

const UploadCard: React.FC<{ investigationId: string; onImported: () => void }> = ({
  investigationId, onImported,
}) => {
  const { pushToast } = useApp();
  const inputRef = useRef<HTMLInputElement>(null);
  const batchRef = useRef<HTMLInputElement>(null);
  const [dragOver, setDragOver] = useState(false);
  const [pending, setPending] = useState<File | null>(null);
  const [preview, setPreview] = useState<PreviewPayload | null>(null);
  const [loading, setLoading] = useState(false);
  const [importing, setImporting] = useState(false);
  const [batching, setBatching] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handlePick: PickFn = async (file) => {
    setPending(file);
    setPreview(null);
    setError(null);
    setLoading(true);
    try {
      const res = await api.previewEvidence(investigationId, file);
      setPreview(res.preview as unknown as PreviewPayload);
    } catch (e: any) {
      setError(e?.message || 'Preview failed');
      setPreview(null);
    } finally {
      setLoading(false);
    }
  };

  const confirmImport = async () => {
    if (!pending) return;
    setImporting(true);
    setError(null);
    try {
      await api.importEvidence(investigationId, pending);
      pushToast('success', `${pending.name} imported — re-run analysis to refresh findings.`);
      setPending(null);
      setPreview(null);
      onImported();
      if (inputRef.current) inputRef.current.value = '';
    } catch (e: any) {
      setError(e?.message || 'Import failed');
    } finally {
      setImporting(false);
    }
  };

  const importBatch = async (files: FileList | File[]) => {
    const list = Array.from(files);
    if (!list.length) return;
    setBatching(true);
    setError(null);
    try {
      const res = await api.importEvidenceBatch(investigationId, list);
      pushToast('success', res.message);
      if (res.errors.length) {
        pushToast('warning',
          `${res.errors.length} file(s) not imported: ${res.errors.map((e) => e.filename).join(', ')}`);
      }
      onImported();
      if (batchRef.current) batchRef.current.value = '';
    } catch (e: any) {
      setError(e?.message || 'Batch import failed');
    } finally {
      setBatching(false);
    }
  };

  return (
    <div className="card">
      <div className="card-head">
        <UploadCloud size={15} color="var(--accent)" />
        <h3 className="grow">Import evidence</h3>
        <span className="sub">EVTX · filesystem/NTFS exports · Chromium history · JSON · CSV</span>
      </div>

      <div
        onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
        onDragLeave={() => setDragOver(false)}
        onDrop={(e) => {
          e.preventDefault();
          setDragOver(false);
          const file = e.dataTransfer.files?.[0];
          if (file) handlePick(file);
        }}
        style={{
          border: `1px dashed ${dragOver ? 'var(--accent)' : 'var(--border-strong)'}`,
          borderRadius: 'var(--radius)', padding: 26, textAlign: 'center',
          background: dragOver ? 'var(--accent-soft)' : 'var(--surface-2)',
        }}
      >
        <FileSearch size={26} color="var(--accent)" />
        <div style={{ marginTop: 8 }}>
          Drop a file here or{' '}
          <button className="btn sm" onClick={() => inputRef.current?.click()}>choose file</button>
          {' · '}
          <button className="btn sm ghost" onClick={() => batchRef.current?.click()}>
            import multiple files
          </button>
        </div>
        <div className="faint" style={{ marginTop: 6 }}>
          Parsed locally first — you review the preview before anything is persisted.
          Multi-file import skips the per-file preview and reports each file's result.
        </div>
        <input
          ref={inputRef} type="file" style={{ display: 'none' }}
          onChange={(e) => { const f = e.target.files?.[0]; if (f) handlePick(f); }}
          aria-label="Choose evidence file"
        />
        <input
          ref={batchRef} type="file" multiple style={{ display: 'none' }}
          onChange={(e) => { if (e.target.files?.length) importBatch(e.target.files); }}
          aria-label="Choose evidence files (multiple)"
        />
      </div>

      {loading && <div style={{ marginTop: 12 }}><Skeleton height={20} count={4} /></div>}
      {batching && <div className="faint" style={{ marginTop: 12 }}>Importing batch…</div>}
      {error && <div style={{ marginTop: 12 }}><ErrorBox error={error} /></div>}

      {preview && (
        <div style={{ marginTop: 14 }}>
          <div className="grid cols-4" style={{ marginBottom: 12 }}>
            <StatCard label="Records parsed" value={preview.record_count}
              hint={preview.parser ? `${preview.parser.name} v${preview.parser.version}` : 'auto-detected type'} />
            <StatCard label="Accepted" value={preview.accepted}
              tone={preview.accepted ? 'accent' : 'default'} hint="will be normalized on import" />
            <StatCard label="Rejected" value={preview.rejected}
              tone={preview.rejected ? 'warn' : 'default'}
              hint={preview.rejected ? 'inspected below, never discarded' : 'no invalid rows'} />
            <StatCard label="Detected type" value={titleCase(preview.file_type)}
              hint={preview.timezone_note || 'status ' + preview.status} />
          </div>

          {preview.warnings?.length > 0 && (
            <div className="notice warn" style={{ marginBottom: 12 }}>
              {preview.warnings.map((w, i) => <div key={i}>{w}</div>)}
            </div>
          )}

          {preview.preview.length > 0 && (
            <div className="table-wrap" style={{ maxHeight: 260, overflow: 'auto', marginBottom: 12 }}>
              <table className="data">
                <thead>
                  <tr><th>Timestamp</th><th>Type</th><th>Description</th><th>User</th></tr>
                </thead>
                <tbody>
                  {preview.preview.map((row, i) => (
                    <tr key={i}>
                      <td className="mono">{row.timestamp || '—'}</td>
                      <td><span className="chip cyan">{titleCase(row.event_type)}</span></td>
                      <td className="truncate" title={row.description}>{row.description}</td>
                      <td>{row.user || '—'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {preview.errors.length > 0 && (
            <div className="notice warn" style={{ marginBottom: 12 }}>
              <strong>{preview.errors.length} rejected row(s) — inspectable, retained with the source:</strong>
              <ul className="inline-list">
                {preview.errors.slice(0, 6).map((err, i) => (
                  <li key={i}>
                    row {String(err.row ?? err.row_index ?? i)}
                    {err.reason ? ` · ${err.reason}` : ''}
                    {err.detail ? ` · ${err.detail}` : ''}
                  </li>
                ))}
              </ul>
              {preview.errors.length > 6 && (
                <div className="faint">…and {preview.errors.length - 6} more; full list after import.</div>
              )}
            </div>
          )}

          <div className="row tight">
            <button className="btn primary" onClick={confirmImport} disabled={importing || preview.status === 'failed'}>
              {importing ? 'Importing…' : <><CheckCircle2 size={14} /> Import {preview.accepted} event(s)</>}
            </button>
            <button className="btn ghost" onClick={() => { setPreview(null); setPending(null); if (inputRef.current) inputRef.current.value = ''; }}>
              Cancel
            </button>
            {preview.status === 'failed' && (
              <span className="faint">Parser reported failure — nothing imported. See the errors above.</span>
            )}
          </div>
        </div>
      )}
    </div>
  );
};

/* -------------------------------------------------------------------------- */
/* Source detail drawer                                                         */
/* -------------------------------------------------------------------------- */

const SourceDetail: React.FC<{ investigationId: string; source: EvidenceSource; onClose: () => void }> = ({
  investigationId, source, onClose,
}) => {
  const { pushToast } = useApp();
  const [tab, setTab] = useState<'errors' | 'events' | 'meta'>('errors');
  const [verifying, setVerifying] = useState(false);
  const [verifyResult, setVerifyResult] = useState<Record<string, any> | null>(null);
  const errors = useAsync(
    () => api.evidenceErrors(investigationId, source.id),
    [investigationId, source.id],
  );
  const events = useAsync(
    () => api.evidenceEvents(investigationId, source.id),
    [investigationId, source.id],
  );

  const verify = async () => {
    setVerifying(true);
    try {
      const res = await api.verifyEvidence(investigationId, source.id);
      setVerifyResult(res as any);
      pushToast(res.verified ? 'success' : 'error',
        res.verified
          ? `${source.filename}: stored copy matches the import-time hash.`
          : `${source.filename}: HASH MISMATCH — stored copy differs from import time.`);
    } catch (e: any) {
      pushToast('error', e?.message || 'Verification failed');
    } finally {
      setVerifying(false);
    }
  };

  useEffect(() => {
    if (source.rejected_count === 0 && source.record_count > 0) setTab('events');
  }, [source.id]); // eslint-disable-line react-hooks/exhaustive-deps

  return (
    <Drawer
      title={source.filename}
      subtitle={`${source.file_type} · imported ${fmtTs(source.imported_at)} · ${fmtBytes(source.size_bytes)}`}
      onClose={onClose}
    >
      <div className="row tight" style={{ marginBottom: 12 }}>
        <span className={`chip ${source.status === 'processed' ? 'green' : source.status === 'failed' ? 'red' : 'amber'}`}>
          {source.status}
        </span>
        <span className="chip">{source.record_count} records</span>
        <span className="chip green">{source.accepted_count} accepted</span>
        <span className="chip amber">{source.rejected_count} rejected</span>
        <span className="chip purple">{source.origin}</span>
        <button className="btn sm ghost" onClick={verify} disabled={verifying}>
          <ShieldCheck size={13} /> {verifying ? 'Verifying…' : 'Verify integrity'}
        </button>
      </div>

      {verifyResult && (
        <div className={verifyResult.verified ? 'notice' : 'notice warn'} style={{ marginBottom: 12 }}>
          <strong>{verifyResult.verified ? 'Integrity OK' : 'MISMATCH'}</strong> — {verifyResult.note}
          {verifyResult.limitation && <div className="faint" style={{ marginTop: 4 }}>{verifyResult.limitation}</div>}
        </div>
      )}

      <dl className="kv" style={{ marginBottom: 14 }}>
        <dt>parser</dt><dd className="mono">{source.parser.name} v{source.parser.version}</dd>
        <dt>source_type</dt><dd>{titleCase(source.source_type)}</dd>
        <dt>sha256</dt><dd><Hash value={source.sha256} /></dd>
        <dt>timezone</dt><dd>{source.timezone_note || '—'}</dd>
        <dt>integrity</dt><dd>{source.integrity_note}</dd>
      </dl>

      <div className="tabs">
        <button className={`tab ${tab === 'errors' ? 'active' : ''}`} onClick={() => setTab('errors')}>
          Rejected records ({source.rejected_count})
        </button>
        <button className={`tab ${tab === 'events' ? 'active' : ''}`} onClick={() => setTab('events')}>
          Imported events ({source.accepted_count})
        </button>
        <button className={`tab ${tab === 'meta' ? 'active' : ''}`} onClick={() => setTab('meta')}>
          Metadata
        </button>
      </div>

      {tab === 'errors' && (
        errors.loading ? <Skeleton height={20} count={4} /> : errors.error ? <ErrorBox error={errors.error} /> : (
          <>
            <div className="notice" style={{ marginBottom: 10 }}>
              {errors.data?.policy || 'Rejected records are retained and never silently discarded.'}
            </div>
            {(errors.data?.errors || []).length === 0 ? (
              <div className="faint">No rejected records — every row normalized.</div>
            ) : (
              <div className="table-wrap">
                <table className="data">
                  <thead><tr><th>Row</th><th>Reason</th><th>Detail</th></tr></thead>
                  <tbody>
                    {(errors.data!.errors as any[]).map((err, i) => (
                      <tr key={i}>
                        <td className="mono">{String(err.row ?? err.row_index ?? i)}</td>
                        <td><span className="chip amber">{err.reason || 'invalid'}</span></td>
                        <td>
                          {err.detail || '—'}
                          {err.raw_excerpt && <pre className="raw">{err.raw_excerpt}</pre>}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </>
        )
      )}

      {tab === 'events' && (
        events.loading ? <Skeleton height={20} count={6} /> : events.error ? <ErrorBox error={events.error} /> : (
          <>
            <div className="faint" style={{ marginBottom: 8 }}>
              {events.data?.total} event(s) normalized from this artifact.
            </div>
            <div className="table-wrap" style={{ maxHeight: 420, overflow: 'auto' }}>
              <table className="data">
                <thead><tr><th>Timestamp</th><th>Type</th><th>Description</th></tr></thead>
                <tbody>
                  {(events.data?.events || []).map((ev: TimelineEvent) => (
                    <tr key={ev.id}>
                      <td className="mono" style={{ whiteSpace: 'nowrap' }}>{fmtTs(ev.timestamp)}</td>
                      <td><span className="chip cyan">{titleCase(ev.event_type)}</span></td>
                      <td className="truncate" title={ev.description || ''}>{ev.description || '—'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </>
        )
      )}

      {tab === 'meta' && (
        <pre className="raw">{JSON.stringify(source.metadata, null, 2)}</pre>
      )}
    </Drawer>
  );
};

/* -------------------------------------------------------------------------- */
/* Page                                                                         */
/* -------------------------------------------------------------------------- */

export const EvidenceExplorer: React.FC = () => {
  const { active, refreshInvestigations, pushToast, reloadActive } = useApp();
  const navigate = useNavigate();
  const [params] = useSearchParams();
  const [detailId, setDetailId] = useState<string | null>(params.get('source'));
  const { data, loading, error, reload } = useAsync(
    () => (active ? api.evidence(active.id) : Promise.resolve(null)),
    [active?.id],
  );

  if (!active) {
    return (
      <EmptyState
        icon={<Boxes size={38} />} title="No active investigation"
        message="Select or create an investigation before importing evidence."
        action={<button className="btn primary" onClick={() => navigate('/investigations')}>Go to Investigations</button>}
      />
    );
  }

  const sources = data?.evidence ?? [];
  const detail = sources.find((s) => s.id === detailId) || null;
  const totalAccepted = sources.reduce((n, s) => n + s.accepted_count, 0);
  const totalRejected = sources.reduce((n, s) => n + s.rejected_count, 0);

  const refreshed = async () => {
    reload();
    await refreshInvestigations();
    await reloadActive();
  };

  const sourceDistribution = sources.reduce<Record<string, number>>((acc, s) => {
    acc[s.source_type] = (acc[s.source_type] || 0) + s.accepted_count;
    return acc;
  }, {});

  return (
    <div>
      <div className="row" style={{ marginBottom: 14 }}>
        <div className="grow">
          <h2 style={{ margin: 0, fontSize: 18 }}>Evidence Explorer</h2>
          <div className="faint">{active.case_id} · {active.name} — SHA-256 hashed at import, errors always inspectable</div>
        </div>
        <button className="btn ghost" onClick={refreshed}><RefreshCw size={14} /> Refresh</button>
        <button className="btn" onClick={() => navigate('/timeline')}><FileText size={14} /> View timeline</button>
      </div>

      <UploadCard investigationId={active.id} onImported={refreshed} />

      <div className="grid cols-3" style={{ marginTop: 14 }}>
        <StatCard label="Evidence sources" value={sources.length} hint="each with persisted parse metadata" />
        <StatCard label="Accepted records" value={totalAccepted} tone="accent" hint="normalized events" />
        <StatCard label="Rejected records" value={totalRejected} tone={totalRejected ? 'warn' : 'default'}
          hint="retained with inspection details" />
      </div>

      <div className="card" style={{ marginTop: 14 }}>
        <div className="card-head">
          <Boxes size={15} />
          <h3 className="grow">Imported sources</h3>
          <span className="sub">file · type · import time · counts · status</span>
        </div>

        {loading && <Skeleton height={30} count={5} />}
        {error && <ErrorBox error={error} onRetry={reload} />}

        {!loading && !error && sources.length === 0 && (
          <EmptyState
            icon={<UploadCloud size={34} />} title="No evidence imported yet"
            message="Upload an EVTX file, filesystem/NTFS export, Chromium history DB, or a normalized JSON/CSV event file. You will see a parse preview with accepted and rejected rows before anything is persisted."
          />
        )}

        {sources.length > 0 && (
          <div className="table-wrap">
            <table className="data">
              <thead>
                <tr>
                  <th>File</th><th>Type</th><th>Imported</th><th>Records</th>
                  <th>Accepted</th><th>Rejected</th><th>Status</th><th></th>
                </tr>
              </thead>
              <tbody>
                {sources.map((s) => (
                  <tr key={s.id} onClick={() => setDetailId(s.id)}>
                    <td>
                      <div className="truncate" title={s.filename}>{s.filename}</div>
                      <div className="cell-faint">{s.parser.name} v{s.parser.version} · origin {s.origin}</div>
                    </td>
                    <td><span className="chip cyan">{titleCase(s.source_type)}</span></td>
                    <td className="mono cell-dim">{fmtTs(s.imported_at)}</td>
                    <td>{s.record_count}</td>
                    <td style={{ color: 'var(--green)' }}>{s.accepted_count}</td>
                    <td style={{ color: s.rejected_count ? 'var(--amber)' : 'inherit' }}>{s.rejected_count}</td>
                    <td>
                      <span className={`chip ${s.status === 'processed' ? 'green' : s.status === 'failed' ? 'red' : 'amber'}`}>
                        {s.status}
                      </span>
                    </td>
                    <td>
                      <button className="btn sm ghost" onClick={(e) => { e.stopPropagation(); setDetailId(s.id); }}>
                        <Eye size={13} /> Inspect
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {sources.length > 0 && (
        <div className="card" style={{ marginTop: 14 }}>
          <div className="card-head"><h3>Accepted events by source type</h3></div>
          <Distribution data={sourceDistribution} />
        </div>
      )}

      <div className="notice" style={{ marginTop: 14 }}>
        <span className="row tight">
          <AlertTriangle size={13} />
          Imported evidence is confined to this investigation — no other case can read or modify these rows.
          Re-run the detection engine after each import to refresh findings.
        </span>
      </div>

      {detail && (
        <SourceDetail investigationId={active.id} source={detail} onClose={() => setDetailId(null)} />
      )}
    </div>
  );
};

export default EvidenceExplorer;