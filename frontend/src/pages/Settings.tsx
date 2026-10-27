// Settings & methodology — appearance, actor (audit attribution), analysis
// configuration, demo-data generation, parser catalogue, uncertainty
// framework, audit trail and the A/B/C evaluation harness. All content comes
// from the API; the evaluation table shows measured numbers only.

import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Activity, BookOpen, FlaskConical, Moon, ScrollText, Settings as SettingsIcon, Sparkles, Sun,
} from 'lucide-react';
import { api, fmtTs, titleCase } from '../api';
import { useApp, useAsync } from '../state';
import { EmptyState, ErrorBox, InfoNote, Skeleton, StatCard } from '../components/ui';

const pct = (v: number | null | undefined) =>
  v === null || v === undefined ? 'n/a' : `${(v * 100).toFixed(1)}%`;

/* -------------------------------------------------------------------------- */
/* Evaluation harness                                                           */
/* -------------------------------------------------------------------------- */

const EvaluationCard: React.FC = () => {
  const { pushToast } = useApp();
  const [running, setRunning] = useState(false);
  const [result, setResult] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);

  const run = async (configs: string[]) => {
    setRunning(true);
    setError(null);
    try {
      const res = await api.runEvaluation(configs);
      setResult(res);
      if (res.errors?.length) {
        pushToast('warning', `Evaluation finished with ${res.errors.length} scenario error(s) — see table.`);
      } else {
        pushToast('success', `Evaluation complete — ${res.total_ms} ms total.`);
      }
    } catch (e: any) {
      setError(e?.message || 'Evaluation failed');
    } finally {
      setRunning(false);
    }
  };

  return (
    <div className="card">
      <div className="card-head">
        <FlaskConical size={15} color="var(--accent)" />
        <h3 className="grow">Evaluation harness (A / B / C)</h3>
        <span className="sub">same synthetic scenarios + ground truth for every configuration</span>
      </div>

      <div className="row tight" style={{ marginBottom: 12 }}>
        <button className="btn sm" onClick={() => run(['A'])} disabled={running}>A: Timeline only</button>
        <button className="btn sm" onClick={() => run(['B'])} disabled={running}>B: + detection rules</button>
        <button className="btn sm" onClick={() => run(['C'])} disabled={running}>C: + graph correlation</button>
        <button className="btn primary sm" onClick={() => run(['A', 'B', 'C'])} disabled={running}>
          {running ? 'Running…' : 'Compare A vs B vs C'}
        </button>
        {result && <span className="faint">generated {fmtTs(result.generated_at)} · {result.total_ms} ms</span>}
      </div>

      {running && <Skeleton height={26} count={5} />}
      {error && <ErrorBox error={error} />}

      {result && !running && (
        <>
          <div className="table-wrap">
            <table className="data">
              <thead>
                <tr>
                  <th>Config</th><th>Label</th><th>Rules P / R / FPR</th><th>Chains P / R / FPR</th>
                  <th>Order acc.</th><th>Rel. acc.</th><th>Explain cov.</th><th>Analysis ms (mean)</th>
                </tr>
              </thead>
              <tbody>
                {(result.aggregate || []).map((row: any) => (
                  <tr key={row.configuration}>
                    <td><span className="chip cyan">{row.configuration}</span></td>
                    <td>{row.label}</td>
                    <td className="mono">
                      {pct(row.rule_decisions.precision)} / {pct(row.rule_decisions.recall)} / {pct(row.rule_decisions.false_positive_rate)}
                    </td>
                    <td className="mono">
                      {row.chain_decisions
                        ? `${pct(row.chain_decisions.precision)} / ${pct(row.chain_decisions.recall)} / ${pct(row.chain_decisions.false_positive_rate)}`
                        : 'n/a'}
                    </td>
                    <td className="mono">{pct(row.event_order_accuracy)}</td>
                    <td className="mono">{pct(row.relationship_accuracy)}</td>
                    <td className="mono">{pct(row.explainability_coverage)}</td>
                    <td className="mono">{row.processing_time_ms?.mean_analysis ?? 'n/a'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <div className="faint" style={{ marginTop: 6 }}>
            Confusion totals per config:{' '}
            {(result.aggregate || []).map((row: any) =>
              `${row.configuration}: tp ${row.rule_decisions.tp} fp ${row.rule_decisions.fp} fn ${row.rule_decisions.fn} tn ${row.rule_decisions.tn}`,
            ).join(' · ')}
          </div>

          {result.errors?.length > 0 && (
            <div className="notice warn" style={{ marginTop: 10 }}>
              <strong>{result.errors.length} scenario error(s) — shown, not hidden:</strong>
              <ul className="inline-list">
                {result.errors.map((err: any, i: number) => (
                  <li key={i}>{err.configuration} / {err.scenario}: {err.error}</li>
                ))}
              </ul>
            </div>
          )}

          <div className="section-title">Methodology</div>
          <ul className="inline-list">
            {(result.methodology || []).map((m: string, i: number) => <li key={i}>{m}</li>)}
          </ul>

          <div className="section-title">Limitations</div>
          <ul className="inline-list">
            {(result.limitations || []).map((m: string, i: number) => <li key={i}>{m}</li>)}
          </ul>
        </>
      )}

      {!result && !running && (
        <div className="faint">
          No evaluation run yet in this session. Running one executes all selected scenarios against fresh
          databases and reports measured precision, recall, false-positive rate, event-order accuracy,
          relationship accuracy and processing time — nulls are shown as n/a, never invented.
        </div>
      )}
    </div>
  );
};

/* -------------------------------------------------------------------------- */
/* Page                                                                         */
/* -------------------------------------------------------------------------- */

export const SettingsPage: React.FC = () => {
  const {
    theme, toggleTheme, actor, setActor, backend, active, pushToast,
    refreshInvestigations, setActiveId,
  } = useApp();
  const navigate = useNavigate();
  const [actorDraft, setActorDraft] = useState(actor);
  const [configDraft, setConfigDraft] = useState<Record<string, number> | null>(null);
  const [saving, setSaving] = useState(false);
  const [generating, setGenerating] = useState(false);
  const [selectedScenarios, setSelectedScenarios] = useState<string[]>([]);

  const version = useAsync(() => api.version(), []);
  const parsers = useAsync(() => api.parsers(), []);
  const uncertainty = useAsync(() => api.uncertainty(), []);
  const demoInfo = useAsync(() => api.demoInfo(), []);
  const audit = useAsync(
    () => (active ? api.audit(active.id) : Promise.resolve({ entries: [], count: 0 })),
    [active?.id],
  );

  const config = (configDraft ?? (active?.analysis_config as Record<string, number>) ?? {});
  const isNumberConfig = (v: unknown) => typeof v === 'number';

  const saveConfig = async () => {
    if (!active) return;
    setSaving(true);
    try {
      await api.updateConfig(active.id, config);
      setConfigDraft(null);
      await refreshInvestigations();
      pushToast('success', 'Analysis configuration saved — re-run detection to apply it.');
    } catch (e: any) {
      pushToast('error', `Config save failed: ${e?.message || e}`);
    } finally {
      setSaving(false);
    }
  };

  const generateDemo = async () => {
    setGenerating(true);
    try {
      const result = await api.generateDemo(selectedScenarios);
      await refreshInvestigations();
      if (result.created?.length) {
        setActiveId(result.created[0].id);
        pushToast('success', `Generated ${result.created.length} labelled synthetic investigation(s).`);
        audit.reload();
      }
    } catch (e: any) {
      pushToast('error', `Demo generation failed: ${e?.message || e}`);
    } finally {
      setGenerating(false);
    }
  };

  return (
    <div>
      <div className="row" style={{ marginBottom: 14 }}>
        <div className="grow">
          <h2 style={{ margin: 0, fontSize: 18 }}>Settings &amp; Methodology</h2>
          <div className="faint">appearance, audit attribution, analysis configuration, engine metadata</div>
        </div>
      </div>

      <div className="grid cols-2">
        <div className="card">
          <div className="card-head">
            {theme === 'dark' ? <Sun size={15} color="var(--accent)" /> : <Moon size={15} color="var(--accent)" />}
            <h3 className="grow">Appearance</h3>
          </div>
          <div className="row tight">
            <span className="faint">Theme: <strong>{titleCase(theme)}</strong></span>
            <button className="btn sm" onClick={toggleTheme}>
              Switch to {theme === 'dark' ? 'light' : 'dark'}
            </button>
          </div>

          <div className="section-title">Audit actor</div>
          <div className="row tight">
            <input
              className="input grow" value={actorDraft}
              onChange={(e) => setActorDraft(e.target.value)}
              placeholder="investigator" aria-label="Actor name"
            />
            <button className="btn sm" disabled={!actorDraft.trim() || actorDraft === actor}
              onClick={() => { setActor(actorDraft.trim()); pushToast('success', 'Actor updated for future audit entries.'); }}>
              Apply
            </button>
          </div>
          <div className="faint" style={{ marginTop: 6 }}>
            Current actor “{actor}” is recorded on imports, analysis runs and status changes in the audit trail.
          </div>

          <div className="section-title">Backend</div>
          <dl className="kv">
            <dt>status</dt><dd>{backend?.status || 'unreachable'}</dd>
            <dt>database</dt><dd>{backend?.dialect || '—'}</dd>
            <dt>engine</dt><dd className="mono">{version.data?.engine_version || backend?.engine_version || '—'}</dd>
            <dt>ruleset</dt><dd className="mono">{version.data?.ruleset_version || backend?.ruleset_version || '—'}</dd>
            <dt>Python</dt><dd className="mono">{version.data?.python || version.data?.runtime || '—'}</dd>
          </dl>
          {version.error && <ErrorBox error={version.error} onRetry={version.reload} />}
        </div>

        <div className="card">
          <div className="card-head"><SettingsIcon size={15} color="var(--accent)" /><h3>Analysis configuration</h3></div>
          {!active ? (
            <div className="faint">Select an investigation to edit its analysis configuration.</div>
          ) : (
            <>
              <div className="faint" style={{ marginBottom: 8 }}>
                {active.case_id} — parameters used by the detection engine (snapshotted on every run for reproducibility).
              </div>
              <table className="data">
                <thead><tr><th>Parameter</th><th>Value</th></tr></thead>
                <tbody>
                  {Object.entries(config).map(([key, value]) => (
                    <tr key={key}>
                      <td className="mono">{key}</td>
                      <td>
                        {isNumberConfig(value) ? (
                          <input
                            className="input" type="number" value={value}
                            onChange={(e) => setConfigDraft({
                              ...config, [key]: Number(e.target.value),
                            } as Record<string, number>)}
                            aria-label={key}
                          />
                        ) : (
                          <span className="mono">{String(value)}</span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
              <div className="row tight" style={{ marginTop: 10 }}>
                <button className="btn primary sm" onClick={saveConfig} disabled={saving || !configDraft}>
                  {saving ? 'Saving…' : 'Save configuration'}
                </button>
                {configDraft && (
                  <button className="btn ghost sm" onClick={() => setConfigDraft(null)}>Discard changes</button>
                )}
              </div>
            </>
          )}

          <div className="section-title">Synthetic demo data</div>
          <div className="faint" style={{ marginBottom: 6 }}>
            {demoInfo.data
              ? `${demoInfo.data.available_scenarios.length} labelled scenarios · ${demoInfo.data.demo_investigations} demo investigation(s) exist · ${demoInfo.data.labeling}`
              : 'Loading demo catalogue…'}
          </div>
          <div className="row tight" style={{ marginBottom: 8 }}>
            {(demoInfo.data?.available_scenarios || []).map((sid) => {
              const on = selectedScenarios.includes(sid);
              return (
                <button
                  key={sid} className={`chip ${on ? 'cyan' : ''}`} style={{ cursor: 'pointer' }}
                  onClick={() => setSelectedScenarios((prev) => on ? prev.filter((s) => s !== sid) : [...prev, sid])}
                  title="Toggle scenario"
                >
                  {sid}
                </button>
              );
            })}
          </div>
          <button className="btn sm" onClick={generateDemo} disabled={generating}>
            <Sparkles size={14} /> {generating ? 'Generating…' : 'Generate selected demo investigations'}
          </button>
        </div>
      </div>

      <div className="card" style={{ marginTop: 14 }}>
        <div className="card-head"><BookOpen size={15} color="var(--accent)" /><h3>Uncertainty &amp; support framework</h3></div>
        {uncertainty.loading && <Skeleton height={30} count={5} />}
        {uncertainty.error && <ErrorBox error={uncertainty.error} onRetry={uncertainty.reload} />}
        {uncertainty.data && (
          <>
            <div className="section-title">Support levels (qualitative, not probabilities)</div>
            <table className="data">
              <thead><tr><th>Level</th><th>Meaning</th></tr></thead>
              <tbody>
                {(uncertainty.data.support_levels || []).map((row: any) => (
                  <tr key={row.level}>
                    <td><span className={`chip support ${row.level}`}>{row.level}</span></td>
                    <td>{row.definition || row.description || row.meaning || JSON.stringify(row)}</td>
                  </tr>
                ))}
              </tbody>
            </table>

            <div className="section-title">Principles</div>
            <ul className="inline-list">
              {(uncertainty.data.principles || []).map((p: string, i: number) => <li key={i}>{p}</li>)}
            </ul>

            <div className="section-title">Benign-explanation catalogue</div>
            <ul className="inline-list">
              {(uncertainty.data.benign_explanations_catalog || []).map((item: any, i: number) => (
                <li key={i}>{typeof item === 'string' ? item : (item.name || JSON.stringify(item))}</li>
              ))}
            </ul>
          </>
        )}
      </div>

      <div className="card" style={{ marginTop: 14 }}>
        <div className="card-head"><Activity size={15} color="var(--accent)" /><h3>Parser catalogue</h3></div>
        {parsers.loading && <Skeleton height={26} count={4} />}
        {parsers.error && <ErrorBox error={parsers.error} onRetry={parsers.reload} />}
        {parsers.data && (
          <>
            <div className="table-wrap">
              <table className="data">
                <thead><tr><th>Parser</th><th>Version</th><th>File type</th><th>Source type</th></tr></thead>
                <tbody>
                  {(parsers.data.parsers || []).map((p: any) => (
                    <tr key={`${p.name}-${p.file_type}`}>
                      <td className="mono">{p.name}</td>
                      <td className="mono">{p.version}</td>
                      <td><span className="chip cyan">{p.file_type}</span></td>
                      <td>{titleCase(p.source_type)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <InfoNote>{parsers.data.note}</InfoNote>
          </>
        )}
      </div>

      <div className="card" style={{ marginTop: 14 }}>
        <div className="card-head"><ScrollText size={15} color="var(--accent)" />
          <h3 className="grow">Audit trail</h3>
          <span className="sub">{active ? active.case_id : 'select an investigation'}</span>
        </div>
        {audit.loading && <Skeleton height={24} count={5} />}
        {audit.error && <ErrorBox error={audit.error} onRetry={audit.reload} />}
        {!audit.loading && !audit.error && (audit.data?.entries || []).length === 0 && (
          <div className="faint">No audit entries for this investigation yet.</div>
        )}
        {(audit.data?.entries || []).slice(0, 50).map((entry: any) => (
          <div key={entry.id} className="row tight" style={{ padding: '7px 0', borderBottom: '1px solid var(--border)' }}>
            <span className="chip cyan">{entry.action}</span>
            <span className="faint">{fmtTs(entry.at)}</span>
            <span className="grow truncate" title={typeof entry.detail === 'string' ? entry.detail : JSON.stringify(entry.detail)}>
              {entry.entity_type} by <strong>{entry.actor}</strong>
            </span>
          </div>
        ))}
        <div className="faint" style={{ marginTop: 8 }}>
          Entries: {audit.data?.count ?? 0}. Full log exported with every report.
        </div>
      </div>

      <div style={{ marginTop: 14 }}><EvaluationCard /></div>

      <div className="notice" style={{ marginTop: 14 }}>
        TRACE-X records engine and ruleset versions, full configuration snapshots and evidence hashes so that
        every reported number can be regenerated. Evaluation metrics on this page are computed at runtime from
        declared ground truth — nothing here is a stored or illustrative figure.
      </div>

      {!active && (
        <div style={{ marginTop: 14 }}>
          <EmptyState
            icon={<SettingsIcon size={30} />} title="No active investigation"
            message="Configuration, audit trail and demo generation operate on the selected investigation."
            action={<button className="btn" onClick={() => navigate('/investigations')}>Go to Investigations</button>}
          />
        </div>
      )}
    </div>
  );
};

export default SettingsPage;