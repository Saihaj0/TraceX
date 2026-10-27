// Reports — reproducible investigation export. The HTML report is rendered by
// the backend and previewed in an iframe; JSON/CSV downloads carry the same
// content. The manifest pins evidence hashes, engine/ruleset versions and the
// analysis-run config so any report can be regenerated and verified.

import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Database, FileBarChart2, FileDown, FileJson, FileText, Fingerprint, History, Layers, RefreshCw,
} from 'lucide-react';
import { api, fmtTs, titleCase } from '../api';
import { useApp, useAsync } from '../state';
import { EmptyState, ErrorBox, Hash, Skeleton, StatCard } from '../components/ui';

export const ReportsPage: React.FC = () => {
  const { active, pushToast } = useApp();
  const navigate = useNavigate();
  const [previewing, setPreviewing] = useState(true);

  const report = useAsync(() => (active ? api.report(active.id) : Promise.resolve(null as any)), [active?.id]);
  const manifest = useAsync(() => (active ? api.manifest(active.id) : Promise.resolve(null as any)), [active?.id]);

  if (!active) {
    return (
      <EmptyState
        icon={<FileBarChart2 size={38} />} title="No active investigation"
        message="Reports are generated per investigation from its persisted evidence and analysis runs."
        action={<button className="btn primary" onClick={() => navigate('/investigations')}>Go to Investigations</button>}
      />
    );
  }

  const scope = report.data?.scope || {};
  const version = report.data?.version || {};

  return (
    <div>
      <div className="row" style={{ marginBottom: 14 }}>
        <div className="grow">
          <h2 style={{ margin: 0, fontSize: 18 }}>Reports &amp; Export</h2>
          <div className="faint">{active.case_id} · {active.name} — generated from persisted rows only</div>
        </div>
        <a className="btn ghost" href={api.reportHtmlUrl(active.id)} target="_blank" rel="noreferrer">
          <FileBarChart2 size={14} /> Open HTML report
        </a>
        <a className="btn" href={api.reportJsonUrl(active.id)} download>
          <FileJson size={14} /> Report JSON
        </a>
        <a className="btn" href={api.findingsCsvUrl(active.id)} download>
          <FileDown size={14} /> Findings CSV
        </a>
        <a className="btn" href={api.eventsJsonUrl(active.id)} download>
          <Database size={14} /> Events JSON
        </a>
        <a className="btn" href={api.bodyfileCsvUrl(active.id)} download
          title="TSK bodyfile (mactime) — import into plaso/mactime directly">
          <FileDown size={14} /> Bodyfile CSV
        </a>
        <a className="btn" href={api.supertimelineCsvUrl(active.id)} download
          title="Plaso-style super-timeline CSV — feed to psort.py or a timeline explorer">
          <FileDown size={14} /> Super-timeline CSV
        </a>
        <a className="btn" href={api.reportPdfUrl(active.id)} download
          title="Self-contained PDF rendering of the investigation report">
          <FileText size={14} /> Report PDF
        </a>
        <button className="btn ghost" onClick={() => { report.reload(); manifest.reload(); }}>
          <RefreshCw size={14} /> Refresh
        </button>
      </div>

      {report.loading && <Skeleton height={86} count={2} />}
      {report.error && <ErrorBox error={report.error} onRetry={report.reload} />}

      {report.data && (
        <>
          <div className="grid cols-4" style={{ marginBottom: 14 }}>
            <StatCard label="Events in scope" value={scope.events ?? 0} hint="normalized timeline rows" />
            <StatCard label="Evidence sources" value={scope.evidence_sources ?? 0} hint="hashed artifacts backing the report" />
            <StatCard label="Analysis runs" value={scope.analysis_runs ?? 0} tone="accent"
              hint="each with config + engine snapshot" />
            <StatCard label="Generated" value={fmtTs(report.data.generated_at)}
              hint={`engine ${version.engine || '—'} · ruleset ${version.ruleset || '—'}`} />
          </div>

          <div className="card">
            <div className="card-head">
              <Layers size={15} />
              <h3 className="grow">Report preview</h3>
              <button className="btn sm ghost" onClick={() => setPreviewing((p) => !p)}>
                {previewing ? 'Hide' : 'Show'} preview
              </button>
            </div>
            {previewing && (
              <div className="report-preview">
                <iframe
                  title="Investigation report preview"
                  src={api.reportHtmlUrl(active.id)}
                />
              </div>
            )}
            <div className="faint" style={{ marginTop: 8 }}>
              The HTML report contains: case summary, methodology (evidence / correlation / hypothesis layers),
              timeline, findings with explanations and alternative explanations, suspicion chains, uncertainty
              notes, evidence-provenance and full audit trail.
            </div>
          </div>

          <div className="grid cols-2" style={{ marginTop: 14 }}>
            <div className="card">
              <div className="card-head"><Fingerprint size={15} color="var(--accent)" /><h3>Reproducibility manifest</h3></div>
              {manifest.loading && <Skeleton height={18} count={5} />}
              {manifest.error && <ErrorBox error={manifest.error} onRetry={manifest.reload} />}
              {manifest.data && (
                <>
                  <dl className="kv">
                    <dt>engine</dt><dd className="mono">{manifest.data.engine_version}</dd>
                    <dt>ruleset</dt><dd className="mono">{manifest.data.ruleset_version}</dd>
                    <dt>analysis runs</dt>
                    <dd className="mono" style={{ fontSize: 11 }}>
                      {(manifest.data.analysis_runs || []).join(', ') || 'none'}
                    </dd>
                    <dt>config</dt>
                    <dd>
                      <pre className="raw" style={{ margin: 0 }}>{JSON.stringify(manifest.data.config || {}, null, 2)}</pre>
                    </dd>
                  </dl>

                  <div className="section-title">Evidence SHA-256 hashes</div>
                  <table className="data">
                    <thead><tr><th>Artifact</th><th>sha256</th></tr></thead>
                    <tbody>
                      {Object.entries(manifest.data.evidence_sha256 || {}).map(([file, hash]) => (
                        <tr key={file}>
                          <td className="truncate" title={file}>{file}</td>
                          <td><Hash value={hash as string} /></td>
                        </tr>
                      ))}
                      {!Object.keys(manifest.data.evidence_sha256 || {}).length && (
                        <tr><td colSpan={2} className="faint">No evidence imported yet.</td></tr>
                      )}
                    </tbody>
                  </table>

                  <div className="notice" style={{ marginTop: 12 }}>{manifest.data.reproduce}</div>
                </>
              )}
            </div>

            <div className="card">
              <div className="card-head"><History size={15} color="var(--accent)" /><h3>Report contents</h3></div>
              {report.loading && <Skeleton height={18} count={8} />}
              {report.data && (
                <table className="data">
                  <thead><tr><th>Section</th><th>Source</th></tr></thead>
                  <tbody>
                    <tr><td>Case summary</td><td className="cell-faint">{titleCase(report.data.case?.status || active.status)} case, origin {report.data.case?.origin || active.origin}</td></tr>
                    <tr><td>Scope &amp; configuration</td><td className="cell-faint">{JSON.stringify(scope.configuration || {}) || '—'}</td></tr>
                    <tr><td>Findings &amp; explanations</td><td className="cell-faint">every finding with evidence, correlation, hypothesis, limitations, alternatives</td></tr>
                    <tr><td>Suspicion chains</td><td className="cell-faint">step-by-step with missing-step disclosure</td></tr>
                    <tr><td>Uncertain timestamps</td><td className="cell-faint">confidence + precision flags per event</td></tr>
                    <tr><td>Audit trail</td><td className="cell-faint">imports, analysis runs, status changes with actor</td></tr>
                    <tr><td>Provenance</td><td className="cell-faint">SHA-256 + parser version per artifact</td></tr>
                  </tbody>
                </table>
              )}
            </div>
          </div>

          <div className="notice" style={{ marginTop: 14 }}>
            Reports state evidence, correlation and hypothesis as separate layers. Findings are presented as
            testable hypotheses with alternative explanations — never as proof of malicious intent.
          </div>
        </>
      )}
    </div>
  );
};

export default ReportsPage;