// Overview — investigation dashboard. Every number on this page comes from
// persisted rows via /api/dashboard; nothing is illustrative.

import React, { useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  AlertTriangle, Boxes, Database, FileClock, GitFork, PlayCircle, Radar, ShieldAlert,
  Sparkles, UploadCloud,
} from 'lucide-react';
import { api, fmtTs, titleCase } from '../api';
import { useApp, useAsync } from '../state';
import { ActivityChart, Distribution, EmptyState, ErrorBox, Skeleton, StatCard } from '../components/ui';

const GraphPreview: React.FC<{ investigationId: string; onOpen: () => void }> = ({ investigationId, onOpen }) => {
  const { data, loading, error } = useAsync(() => api.graph(investigationId, {}), [investigationId]);
  const [hover, setHover] = useState<string | null>(null);

  const layout = useMemo(() => {
    if (!data) return null;
    const nodes = data.nodes.slice(0, 26).map((n) => n.data);
    const ids = new Set(nodes.map((n) => n.id));
    const edges = data.edges.map((e) => e.data).filter((e) => ids.has(e.source) && ids.has(e.target)).slice(0, 40);
    const radius = 116;
    const cx = 150;
    const cy = 130;
    const positioned = new Map<string, { x: number; y: number }>();
    nodes.forEach((node, index) => {
      const angle = (index / Math.max(nodes.length, 1)) * Math.PI * 2 - Math.PI / 2;
      positioned.set(node.id, {
        x: cx + Math.cos(angle) * radius,
        y: cy + Math.sin(angle) * radius,
      });
    });
    return { nodes, edges, positioned };
  }, [data]);

  if (loading) return <Skeleton height={220} count={4} />;
  if (error) return <ErrorBox error={error} />;
  if (!data || !layout || !layout.nodes.length) {
    return (
      <div className="faint">
        {data?.empty_reason || 'Run the detection engine to build the forensic graph for this investigation.'}
      </div>
    );
  }
  const color = (type: string) =>
    type === 'finding' ? 'var(--red)'
      : type === 'hypothesis' ? 'var(--amber)'
        : type === 'evidence_source' ? 'var(--purple)'
          : type === 'event' ? 'var(--accent)'
            : 'var(--text-dim)';
  return (
    <div>
      <svg viewBox="0 0 300 260" width="100%" height={250} role="img" aria-label="Connected events preview">
        {layout.edges.map((edge) => {
          const a = layout.positioned.get(edge.source);
          const b = layout.positioned.get(edge.target);
          if (!a || !b) return null;
          return (
            <line
              key={edge.id}
              x1={a.x} y1={a.y} x2={b.x} y2={b.y}
              stroke={hover && (hover === edge.source || hover === edge.target) ? 'var(--accent)' : 'var(--border-strong)'}
              strokeWidth={edge.inferred ? 0.8 : 1.3}
              strokeDasharray={edge.inferred ? '3 3' : undefined}
            />
          );
        })}
        {layout.nodes.map((node) => {
          const p = layout.positioned.get(node.id)!;
          const size = node.node_type === 'event' ? 5 : 8;
          return (
            <circle
              key={node.id}
              cx={p.x} cy={p.y} r={size}
              fill={color(node.node_type)}
              opacity={hover && hover !== node.id ? 0.35 : 0.95}
              onMouseEnter={() => setHover(node.id)}
              onMouseLeave={() => setHover(null)}
              style={{ cursor: 'pointer' }}
            >
              <title>{`${node.node_type}: ${node.label}`}</title>
            </circle>
          );
        })}
      </svg>
      <div className="row tight" style={{ flexWrap: 'wrap', gap: 10 }}>
        {[['event', 'var(--accent)'], ['finding', 'var(--red)'], ['hypothesis', 'var(--amber)'], ['evidence_source', 'var(--purple)']].map(([label, colour]) => (
          <span className="legend-item" key={label as string}>
            <span className="legend-dot" style={{ background: colour as string }} />
            {titleCase(label as string)}
          </span>
        ))}
        <span className="legend-item"><span className="legend-line" />observed</span>
        <span className="legend-item"><span className="legend-line dashed" />inferred</span>
      </div>
      <div className="faint" style={{ marginTop: 6 }}>
        {data.counts.nodes} nodes · {data.counts.edges} relationships in the stored graph — open the
        Forensic Graph for the full interactive view.
      </div>
      <button className="btn sm" style={{ marginTop: 8 }} onClick={onOpen}>Open forensic graph</button>
    </div>
  );
};

export const Overview: React.FC = () => {
  const { activeId, active, investigations, setActiveId, refreshInvestigations, pushToast } = useApp();
  const navigate = useNavigate();
  const [generating, setGenerating] = useState(false);
  const { data, loading, error, reload } = useAsync(() => api.dashboard(activeId), [activeId]);

  const generateDemo = async () => {
    setGenerating(true);
    try {
      const result = await api.generateDemo([]);
      await refreshInvestigations();
      if (result.created?.length) {
        setActiveId(result.created[0].id);
        pushToast('success', `Generated ${result.created.length} labelled synthetic investigation(s).`);
      }
      reload();
    } catch (err: any) {
      pushToast('error', `Demo generation failed: ${err.message}`);
    } finally {
      setGenerating(false);
    }
  };

  if (!investigations.length && !loading) {
    return (
      <EmptyState
        icon={<Sparkles size={30} />}
        title="No investigations yet"
        message="Create an investigation and import evidence (EVTX, filesystem/NTFS exports, browser history, JSON/CSV), or generate the labelled synthetic datasets to explore TRACE-X end to end."
        action={
          <div className="row" style={{ justifyContent: 'center' }}>
            <button className="btn primary" onClick={() => navigate('/investigations')}>
              <UploadCloud size={15} /> Create investigation
            </button>
            <button className="btn" onClick={generateDemo} disabled={generating}>
              <Sparkles size={15} /> {generating ? 'Generating…' : 'Generate synthetic demo data'}
            </button>
          </div>
        }
      />
    );
  }

  return (
    <div>
      <div className="row" style={{ marginBottom: 14 }}>
        <div className="grow">
          <h2 style={{ margin: 0, fontSize: 18 }}>Investigation overview</h2>
          <div className="faint">
            {active ? `${active.case_id} · ${active.name}` : 'All investigations'}
            {active?.is_demo ? ' · SYNTHETIC DEMO DATA' : ''}
          </div>
        </div>
        <button className="btn sm" onClick={reload}>Refresh</button>
        <button className="btn sm" onClick={() => navigate('/evidence')}>
          <UploadCloud size={14} /> Import evidence
        </button>
      </div>

      {loading && <Skeleton height={92} count={3} />}
      {error && <ErrorBox error={error} onRetry={reload} />}

      {data && (
        <>
          <div className="grid cols-4" style={{ marginBottom: 14 }}>
            <StatCard label="Imported events" value={data.metrics.events} icon={<Database size={13} />}
              hint={`${data.metrics.events_by_origin?.demo || 0} synthetic · ${(data.metrics.events_by_origin?.imported || 0)} imported`} />
            <StatCard label="Evidence sources" value={data.metrics.evidence_sources} icon={<Boxes size={13} />}
              hint="each hashed with SHA-256 at import" />
            <StatCard label="Detected indicators" value={data.metrics.detected_indicators} icon={<ShieldAlert size={13} />}
              tone={data.metrics.detected_indicators ? 'warn' : 'default'}
              hint={`${data.metrics.high_priority_findings} high-priority`} />
            <StatCard label="Suspicion sequences" value={data.metrics.suspicious_sequences} icon={<GitFork size={13} />}
              tone={data.metrics.suspicious_sequences ? 'danger' : 'default'}
              hint="candidate multi-event chains" />
            <StatCard label="High-priority findings" value={data.metrics.high_priority_findings} icon={<AlertTriangle size={13} />}
              tone={data.metrics.high_priority_findings ? 'danger' : 'default'}
              hint="critical + high severity" />
            <StatCard label="Uncertain timestamps" value={data.metrics.uncertain_timestamps} icon={<FileClock size={13} />}
              tone={data.metrics.uncertain_timestamps ? 'warn' : 'default'}
              hint={`${data.metrics.undated_events} with no usable time`} />
            <StatCard label="Processing status" value={titleCase(data.processing_status)}
              icon={<PlayCircle size={13} />}
              hint={data.last_analysis ? `last analysis ${fmtTs(data.last_analysis.started_at)} · ${data.last_analysis.duration_ms} ms` : 'no analysis run yet'} />
            <StatCard label="Ruleset" value={data.last_analysis?.rules_version || '—'}
              hint={data.last_analysis ? `engine ${data.last_analysis.engine_version}` : 'run analysis to record a run'} />
          </div>

          <div className="grid cols-2">
            <div className="card">
              <div className="card-head">
                <Radar size={15} color="var(--accent)" />
                <h3 className="grow">Event activity timeline</h3>
                <span className="sub">hourly buckets from persisted events</span>
              </div>
              <ActivityChart points={data.activity_timeline} />
            </div>
            <div className="card">
              <div className="card-head">
                <GitFork size={15} color="var(--accent)" />
                <h3 className="grow">Connected events preview</h3>
              </div>
              {activeId ? (
                <GraphPreview investigationId={activeId} onOpen={() => navigate('/graph')} />
              ) : (
                <div className="faint">Select an investigation to preview its relationship graph.</div>
              )}
            </div>
          </div>

          <div className="grid cols-2" style={{ marginTop: 14 }}>
            <div className="card">
              <div className="card-head"><ShieldAlert size={15} color="var(--amber)" /><h3>Anti-forensic indicator distribution</h3></div>
              <Distribution data={data.metrics.indicator_distribution || {}} tone="amber"
                label={(key) => key} />
              <div className="faint" style={{ marginTop: 8 }}>
                Counts of findings per detection rule (AF-001…AF-008). Severity mix:{' '}
                {Object.entries(data.metrics.severity_distribution || {}).map(([k, v]) => `${k} ${v}`).join(' · ') || 'none'}
              </div>
            </div>
            <div className="card">
              <div className="card-head"><Database size={15} color="var(--accent)" /><h3>Evidence-source distribution</h3></div>
              <Distribution data={data.metrics.source_distribution || {}} />
              <div className="faint" style={{ marginTop: 8 }}>Events by normalized source type.</div>
            </div>
          </div>

          <div className="grid cols-2" style={{ marginTop: 14 }}>
            <div className="card">
              <div className="card-head"><Boxes size={15} /><h3 className="grow">Recent investigations</h3>
                <button className="btn sm" onClick={() => navigate('/investigations')}>Manage</button></div>
              {data.recent_investigations.map((inv) => (
                <div
                  key={inv.id}
                  className="row"
                  style={{ padding: '8px 0', borderBottom: '1px solid var(--border)', cursor: 'pointer' }}
                  onClick={() => { setActiveId(inv.id); navigate('/investigations'); }}
                >
                  <div className="grow">
                    <div>{inv.case_id} · {inv.name} {inv.is_demo && <span className="chip amber">synthetic</span>}</div>
                    <div className="faint">{inv.metrics.events} events · {inv.metrics.findings} findings · {inv.metrics.suspicion_chains} chains · {titleCase(inv.processing)}</div>
                  </div>
                </div>
              ))}
              {!data.recent_investigations.length && <div className="faint">Nothing yet.</div>}
            </div>
            <div className="card">
              <div className="card-head"><AlertTriangle size={15} /><h3 className="grow">Recent findings</h3>
                <button className="btn sm" onClick={() => navigate('/anti-forensics')}>All findings</button></div>
              {data.recent_findings.length === 0 && <div className="faint">No findings recorded — run the detection engine.</div>}
              {data.recent_findings.map((f: any) => (
                <div key={f.id} className="row" style={{ padding: '8px 0', borderBottom: '1px solid var(--border)', cursor: 'pointer' }}
                  onClick={() => navigate('/anti-forensics')}>
                  <span className={`chip ${f.severity === 'critical' || f.severity === 'high' ? 'red' : 'amber'}`}>
                    <span className={`sev ${f.severity}`}>{f.severity}</span>
                  </span>
                  <span className="grow truncate" title={f.title}>{f.rule_id} · {f.title}</span>
                  <span className="faint">{fmtTs(f.created_at)}</span>
                </div>
              ))}
            </div>
          </div>

          {data.recent_chains?.length > 0 && (
            <div className="card" style={{ marginTop: 14 }}>
              <div className="card-head"><GitFork size={15} /><h3 className="grow">Suspicion chains</h3>
                <button className="btn sm" onClick={() => navigate('/chains')}>Open chains</button></div>
              {data.recent_chains.map((c: any) => (
                <div key={c.id} className="row" style={{ padding: '8px 0', borderBottom: '1px solid var(--border)', cursor: 'pointer' }}
                  onClick={() => navigate('/chains')}>
                  <span className="chip cyan">pattern {c.pattern_id}</span>
                  <span className={`chip ${c.completeness === 'complete' ? 'amber' : ''}`}>{c.completeness}</span>
                  <span className="grow truncate">{c.title}</span>
                </div>
              ))}
            </div>
          )}

          <div className="notice" style={{ marginTop: 14 }}>
            {data.disclaimer} Synthetic demo records are labelled <strong>origin=demo</strong> on every row and
            are never merged into imported investigations.
          </div>
        </>
      )}
    </div>
  );
};