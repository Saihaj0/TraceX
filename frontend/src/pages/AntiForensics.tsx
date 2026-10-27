// Anti-Forensics — rule catalogue plus persisted findings. Every finding shows
// the three analytical layers (evidence → correlation → hypothesis), what the
// rule does NOT establish, alternative explanations and score components.

import React, { useEffect, useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import {
  AlertOctagon, Info, PlayCircle, Radar, ShieldAlert, Target,
} from 'lucide-react';
import { api, fmtTs, titleCase } from '../api';
import { useApp, useAsync } from '../state';
import type { Finding, RuleInfo } from '../types';
import {
  EmptyState, ErrorBox, Hash, Modal, SeverityBadge, Skeleton, StatCard, SupportBadge,
} from '../components/ui';

/* -------------------------------------------------------------------------- */
/* Finding detail                                                               */
/* -------------------------------------------------------------------------- */

const FindingDetail: React.FC<{ finding: Finding; onClose: () => void }> = ({ finding, onClose }) => {
  const ex = finding.explanation;
  return (
    <div className="modal-backdrop" onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <div className="modal" style={{ width: 'min(880px, 96vw)' }} role="dialog" aria-modal="true">
        <div className="row" style={{ marginBottom: 8 }}>
          <div className="grow">
            <div className="row tight">
              <span className="chip cyan">{finding.rule_id}</span>
              <SeverityBadge severity={finding.severity} />
              <SupportBadge support={finding.support} />
              <span className="faint">{fmtTs(finding.occurred_at)}</span>
            </div>
            <h3 style={{ margin: '8px 0 4px' }}>{finding.title}</h3>
            <div className="faint">{finding.rule_name} · rule v{finding.rule_version}</div>
          </div>
          <button className="btn ghost sm" onClick={onClose} aria-label="Close">✕</button>
        </div>

        <div className="tabs" style={{ marginTop: 12 }}>
          <span className="faint" style={{ padding: '8px 0' }}>
            {finding.severity_note}
          </span>
        </div>

        <div className="grid cols-2" style={{ gap: 16 }}>
          <div>
            <div className="section-title">Evidence — what artifacts directly record</div>
            <ul className="inline-list">
              {(ex?.observed_evidence || []).map((line, i) => <li key={i}>{line}</li>)}
              {!(ex?.observed_evidence || []).length && <li className="faint">none recorded</li>}
            </ul>

            <div className="section-title">Correlation — how observations relate</div>
            <ul className="inline-list">
              {(ex?.correlation || []).map((line, i) => <li key={i}>{line}</li>)}
              {!(ex?.correlation || []).length && <li className="faint">no cross-artifact relationships used</li>}
            </ul>

            <div className="section-title">Hypothesis — what the sequence might indicate</div>
            <p style={{ margin: 0, fontSize: 13 }}>{ex?.hypothesis || '—'}</p>
          </div>

          <div>
            <div className="section-title">This does NOT establish</div>
            <ul className="inline-list">
              {(ex?.does_not_establish || []).map((line, i) => <li key={i}>{line}</li>)}
            </ul>

            <div className="section-title">Alternative explanations</div>
            <ul className="inline-list">
              {(ex?.alternative_explanations || []).map((alt, i) => (
                <li key={i}>
                  {alt.explanation}
                  {alt.why_relevant && <span className="faint"> — {alt.why_relevant}</span>}
                </li>
              ))}
              {!(ex?.alternative_explanations || []).length && <li className="faint">none recorded</li>}
            </ul>

            <div className="section-title">Missing evidence</div>
            <ul className="inline-list">
              {(ex?.missing_evidence || []).map((line, i) => <li key={i}>{line}</li>)}
              {!(ex?.missing_evidence || []).length && <li className="faint">none noted</li>}
            </ul>

            <div className="section-title">Recommended next checks</div>
            <ul className="inline-list">
              {(ex?.recommended_next_checks || []).map((line, i) => <li key={i}>{line}</li>)}
              {!ex?.recommended_next_checks?.length && <li className="faint">—</li>}
            </ul>
          </div>
        </div>

        {finding.heuristic_score !== null && finding.score_components?.length > 0 && (
          <>
            <div className="section-title">
              Heuristic score {finding.heuristic_score.toFixed(2)} — weighted components (not a probability)
            </div>
            <div className="table-wrap">
              <table className="data">
                <thead><tr><th>Component</th><th>Value</th><th>Weight</th><th>Contribution</th></tr></thead>
                <tbody>
                  {finding.score_components.map((c, i) => (
                    <tr key={i}>
                      <td>{c.name}</td>
                      <td className="mono">{Number(c.value).toFixed(2)}</td>
                      <td className="mono">{Number(c.weight).toFixed(2)}</td>
                      <td className="mono">{(Number(c.value) * Number(c.weight)).toFixed(3)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </>
        )}

        <div className="section-title">Supporting events ({finding.event_ids.length})</div>
        <div className="table-wrap" style={{ maxHeight: 260, overflow: 'auto' }}>
          <table className="data">
            <thead><tr><th>Timestamp</th><th>Type</th><th>Description</th><th>Source</th></tr></thead>
            <tbody>
              {(finding.events || []).map((ev) => (
                <tr key={ev.id}>
                  <td className="mono" style={{ whiteSpace: 'nowrap' }}>{fmtTs(ev.timestamp)}</td>
                  <td><span className="chip cyan">{titleCase(ev.event_type)}</span></td>
                  <td className="truncate" title={ev.description || ''}>{ev.description || '—'}</td>
                  <td className="cell-faint truncate">{ev.source_file || '—'}</td>
                </tr>
              ))}
              {!(finding.events || []).length && (
                <tr><td colSpan={4} className="faint">Event details unavailable (events may have been re-imported).</td></tr>
              )}
            </tbody>
          </table>
        </div>

        {ex?.temporal_relationships?.length ? (
          <>
            <div className="section-title">Temporal relationships</div>
            <ul className="inline-list">
              {ex.temporal_relationships.map((rel, i) => <li key={i}>{JSON.stringify(rel)}</li>)}
            </ul>
          </>
        ) : null}

        {ex?.limitations?.length ? (
          <div className="notice warn" style={{ marginTop: 12 }}>
            <strong>Rule limitations:</strong>
            <ul className="inline-list">{ex.limitations.map((l, i) => <li key={i}>{l}</li>)}</ul>
          </div>
        ) : null}
      </div>
    </div>
  );
};

/* -------------------------------------------------------------------------- */
/* Page                                                                         */
/* -------------------------------------------------------------------------- */

export const AntiForensics: React.FC = () => {
  const { active, pushToast, reloadActive } = useApp();
  const navigate = useNavigate();
  const [params] = useSearchParams();
  const focusFindingId = params.get('f');
  const [severityFilter, setSeverityFilter] = useState('');
  const [selected, setSelected] = useState<Finding | null>(null);
  const [running, setRunning] = useState(false);

  const rules = useAsync(() => api.rules(), []);
  const findings = useAsync(
    () => (active
      ? api.findings(active.id, severityFilter ? { severity: severityFilter } : {})
      : Promise.resolve(null)),
    [active?.id, severityFilter],
  );
  const runs = useAsync(
    () => (active ? api.analysisRuns(active.id) : Promise.resolve(null)),
    [active?.id],
  );

  // Deep link from global search: ?f=<finding id>
  useEffect(() => {
    if (!focusFindingId || !findings.data) return;
    const hit = findings.data.findings.find((f) => f.id === focusFindingId);
    if (hit) setSelected(hit);
  }, [focusFindingId, findings.data]); // eslint-disable-line react-hooks/exhaustive-deps

  if (!active) {
    return (
      <EmptyState
        icon={<Radar size={38} />} title="No active investigation"
        message="Signals from the detection engine are computed per investigation — select one first."
        action={<button className="btn primary" onClick={() => navigate('/investigations')}>Go to Investigations</button>}
      />
    );
  }

  const runDetection = async () => {
    setRunning(true);
    try {
      const result = await api.runAnalysis(active.id);
      await findings.reload();
      await runs.reload();
      await reloadActive();
      pushToast('success',
        result.message || `Analysis complete — ${result.analysis?.findings ?? 0} findings, ` +
          `${result.analysis?.chains ?? 0} suspicion chains.`);
    } catch (e: any) {
      pushToast('error', `Analysis failed: ${e?.message || e}`);
    } finally {
      setRunning(false);
    }
  };

  const summary = findings.data?.summary || {};
  const list = findings.data?.findings || [];

  return (
    <div>
      <div className="row" style={{ marginBottom: 14 }}>
        <div className="grow">
          <h2 style={{ margin: 0, fontSize: 18 }}>Anti-Forensics Detection</h2>
          <div className="faint">
            {active.case_id} · explainable rules AF-001…AF-008 — findings are hypotheses, not verdicts
          </div>
        </div>
        <select className="input" value={severityFilter} onChange={(e) => setSeverityFilter(e.target.value)} aria-label="Severity filter">
          <option value="">All severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
          <option value="info">Info</option>
        </select>
        <button className="btn primary" onClick={runDetection} disabled={running}>
          <PlayCircle size={15} /> {running ? 'Running…' : 'Run detection engine'}
        </button>
      </div>

      <div className="grid cols-4" style={{ marginBottom: 14 }}>
        <StatCard label="Indicators found" value={findings.data?.total ?? '—'}
          icon={<ShieldAlert size={13} />} hint="persisted findings for this case" />
        <StatCard label="Critical + high" value={summary.high_or_critical ?? 0}
          tone={(summary.high_or_critical ?? 0) ? 'danger' : 'default'}
          icon={<AlertOctagon size={13} />} hint="priority review queue" />
        <StatCard label="Rule coverage" value={`${Object.keys(summary.by_rule || {}).length}/${rules.data?.rules.length ?? 8}`}
          icon={<Target size={13} />} hint="distinct rules that fired" />
        <StatCard label="Last run"
          value={runs.data?.runs?.[0] ? fmtTs(runs.data.runs[0].started_at) : 'never'}
          icon={<Info size={13} />}
          hint={runs.data?.runs?.[0] ? `engine ${runs.data.runs[0].engine_version || '—'} · ${runs.data.runs[0].duration_ms ?? '—'} ms` : 'run detection to record a run'} />
      </div>

      <div className="split">
        <div>
          <div className="card">
            <div className="card-head">
              <ShieldAlert size={15} color="var(--amber)" />
              <h3 className="grow">Findings</h3>
              <span className="sub">{findings.data?.total ?? 0} matching</span>
            </div>

            {findings.loading && <Skeleton height={46} count={5} />}
            {findings.error && <ErrorBox error={findings.error} onRetry={findings.reload} />}

            {!findings.loading && !findings.error && list.length === 0 && (
              <EmptyState
                icon={<Radar size={32} />} title="No findings"
                message={active.metrics.events === 0
                  ? 'Import evidence first, then run the detection engine.'
                  : 'The ruleset produced no findings for this evidence — that is a valid result, not a failure.'}
                action={<button className="btn" onClick={runDetection} disabled={running}>Run detection</button>}
              />
            )}

            {list.map((f) => (
              <div
                key={f.id}
                className="row"
                style={{ padding: '10px 0', borderBottom: '1px solid var(--border)', cursor: 'pointer' }}
                onClick={() => setSelected(f)}
              >
                <span className="chip cyan">{f.rule_id}</span>
                <SeverityBadge severity={f.severity} />
                <SupportBadge support={f.support} />
                <span className="grow truncate" title={f.title}>{f.title}</span>
                <span className="faint" style={{ whiteSpace: 'nowrap' }}>{fmtTs(f.occurred_at)}</span>
              </div>
            ))}
          </div>

          <div className="card" style={{ marginTop: 14 }}>
            <div className="card-head"><Radar size={15} /><h3>Indicator distribution by rule</h3></div>
            <div className="bars">
              {Object.entries(summary.by_rule || {}).map(([rule, count]) => (
                <div className="bar-row" key={rule}>
                  <div className="truncate" title={rule}>{rule}</div>
                  <div className="bar-track">
                    <div className="bar-fill amber" style={{ width: `${Math.min(100, (Number(count) / Math.max(1, findings.data?.total || 1)) * 100)}%` }} />
                  </div>
                  <div style={{ textAlign: 'right' }}>{Number(count)}</div>
                </div>
              ))}
              {!Object.keys(summary.by_rule || {}).length && <div className="faint">No indicators recorded yet.</div>}
            </div>
          </div>
        </div>

        <div className="card">
          <div className="card-head"><Info size={15} /><h3>Rule catalogue</h3></div>
          {rules.loading && <Skeleton height={70} count={4} />}
          {rules.error && <ErrorBox error={rules.error} />}
          {(rules.data?.rules || []).map((r: RuleInfo) => (
            <div key={r.id} style={{ padding: '10px 0', borderBottom: '1px solid var(--border)' }}>
              <div className="row tight">
                <span className="chip cyan">{r.id}</span>
                <SeverityBadge severity={r.severity} />
                <span className="grow" style={{ fontWeight: 600, fontSize: 13 }}>{r.name}</span>
              </div>
              <div className="faint" style={{ marginTop: 4 }}>{r.description}</div>
              <div className="faint" style={{ marginTop: 4 }}>
                <strong>Requires:</strong> {r.required_evidence.join(', ')}
              </div>
              <details style={{ marginTop: 4 }}>
                <summary className="faint" style={{ cursor: 'pointer' }}>Detection conditions & exclusions</summary>
                <ul className="inline-list">
                  {r.detection_conditions.map((c, i) => <li key={`d${i}`}>{c}</li>)}
                  {r.exclusions.map((c, i) => <li key={`e${i}`}>excluded: {c}</li>)}
                </ul>
              </details>
            </div>
          ))}
          {rules.data && (
            <div className="faint" style={{ marginTop: 8 }}>
              ruleset {rules.data.ruleset_version} · engine {rules.data.engine_version}
            </div>
          )}
        </div>
      </div>

      <div className="notice" style={{ marginTop: 14 }}>
        Detection results are hypotheses about anti-forensic activity: they describe what the evidence
        supports, what it cannot establish, and which benign explanations remain open. Severity reflects
        investigative priority, never proven malicious intent.
      </div>

      {selected && <FindingDetail finding={selected} onClose={() => setSelected(null)} />}
    </div>
  );
};

export default AntiForensics;