// Forensic Graph — interactive Cytoscape.js view of the persisted relationship
// graph (events, artifacts, users, processes, sources, findings, hypotheses).
// Observed relationships are solid; inferred ones are dashed and labelled as
// such — the graph visualises correlation, never asserted causation.

import React, { useEffect, useMemo, useRef, useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import cytoscape from 'cytoscape';
import dagre from 'cytoscape-dagre';

cytoscape.use(dagre);
import { Crosshair, GitFork, Network, PlayCircle, RefreshCw, Route, Search } from 'lucide-react';
import { api, titleCase } from '../api';
import { useApp, useAsync } from '../state';
import type { GraphPayload } from '../types';
import { EmptyState, ErrorBox, Skeleton, StatCard } from '../components/ui';

const NODE_COLORS: Record<string, string> = {
  event: '#22d3ee',
  file: '#38bdf8',
  user: '#a78bfa',
  process: '#34d399',
  device: '#94a7c0',
  evidence_source: '#a78bfa',
  finding: '#f43f5e',
  hypothesis: '#f59e0b',
};

const findLayout = (count: number): any =>
  count > 120
    ? ({ name: 'cose', animate: false, padding: 30, nodeRepulsion: 4200, idealEdgeLength: 90 } as any)
    : ({ name: 'dagre', rankDir: 'LR', animate: false, padding: 30, rankSep: 70, edgeSep: 20, nodeSep: 55 } as any);

export const ForensicGraph: React.FC = () => {
  const { active, pushToast, reloadActive } = useApp();
  const navigate = useNavigate();
  const [params] = useSearchParams();
  const containerRef = useRef<HTMLDivElement>(null);
  const cyRef = useRef<cytoscape.Core | null>(null);

  const [search, setSearch] = useState('');
  const [activeTypes, setActiveTypes] = useState<string[]>([]);
  const [activeRelations, setActiveRelations] = useState<string[]>([]);
  const [selectedNode, setSelectedNode] = useState<Record<string, any> | null>(null);
  const [highlight, setHighlight] = useState<string[] | null>(null); // node ids
  const [pathResult, setPathResult] = useState<Record<string, any> | null>(null);
  const [running, setRunning] = useState(false);

  const chains = useAsync(() => (active ? api.chains(active.id, {}) : Promise.resolve(null as any)), [active?.id]);
  const graphActions = useAsync(() => (active ? api.graphActions(active.id) : Promise.resolve(null as any)), [active?.id]);

  // Isolation intent coming from the chains page: ?isolate=<chain id>
  const isolateChainId = params.get('isolate');

  const query = useMemo(() => {
    const q: Record<string, any> = {};
    if (activeTypes.length) q.node_types = activeTypes.join(',');
    if (activeRelations.length) q.relations = activeRelations.join(',');
    if (search.trim()) q.q = search.trim();
    return q;
  }, [activeTypes, activeRelations, search]);

  const { data, loading, error, reload } = useAsync<GraphPayload>(
    () => (active ? api.graph(active.id, query) : Promise.resolve(null as any)),
    [active?.id, JSON.stringify(query)],
  );

  /* ----- isolate a chain on arrival from the chains page ------------------ */
  useEffect(() => {
    if (!active || !isolateChainId) return;
    api.isolateChain(active.id, isolateChainId)
      .then((res: any) => { if (res.found) setHighlight(res.nodes); })
      .catch((e: any) => pushToast('error', `Isolation failed: ${e?.message || e}`));
  }, [active?.id, isolateChainId]); // eslint-disable-line react-hooks/exhaustive-deps

  /* ----- render the graph ------------------------------------------------- */
  useEffect(() => {
    if (!containerRef.current || !data) return;
    if (cyRef.current) { cyRef.current.destroy(); cyRef.current = null; }

    if (!data.nodes.length) return;

    const cy = cytoscape({
      container: containerRef.current,
      elements: [...data.nodes.map((n: any) => ({ ...n, classes: n.classes || (n.data?.flagged ? ['flagged'] : []) })), ...data.edges],
      style: [
        {
          selector: 'node',
          style: {
            label: 'data(label)', 'font-size': 9.5, color: '#dbe6f3',
            'text-outline-width': 0, 'text-valign': 'bottom', 'text-margin-y': 5,
            width: 22, height: 22, 'background-color': '#94a7c0',
            'border-width': 1.5, 'border-color': '#1f2b40',
          } as any,
        },
        ...Object.entries(NODE_COLORS).map(([type, color]) => ({
          selector: `node[type = "${type}"]`,
          style: { 'background-color': color, 'border-color': color } as any,
        })),
        {
          selector: 'node.flagged',
          style: { 'border-width': 3, 'border-color': '#f59e0b' } as any,
        },
        {
          selector: 'edge',
          style: {
            width: 1.6, 'curve-style': 'bezier', 'target-arrow-shape': 'triangle',
            'target-arrow-color': '#64748f', 'line-color': '#64748f',
            label: 'data(relation)', 'font-size': 8, color: '#64748f',
            'text-rotation': 'autorotate', 'text-background-color': '#0a0e16',
            'text-background-opacity': 0.75, 'text-background-padding': 1,
          } as any,
        },
        {
          selector: 'edge[inferred = true]',
          style: { 'line-style': 'dashed', 'target-arrow-color': '#f59e0b', 'line-color': '#f59e0b' } as any,
        },
        { selector: ':selected', style: { 'border-width': 4, 'border-color': '#ffffff' } as any },
        { selector: '.dim', style: { opacity: 0.12 } as any },
        { selector: '.focus', style: { 'border-width': 4, 'border-color': '#f59e0b' } as any },
      ],
      layout: findLayout(data.nodes.length),
      wheelSensitivity: 0.25,
      minZoom: 0.15,
      maxZoom: 3,
    });

    cy.on('tap', 'node', (evt) => {
      const d = evt.target.data();
      setSelectedNode({ ...d, edges: evt.target.connectedEdges().map((e: any) => e.data()) });
    });
    cy.on('tap', (evt) => { if (evt.target === cy) setSelectedNode(null); });
    cyRef.current = cy;

    try {
      const layout = cy.layout(findLayout(data.nodes.length));
      layout.run();
    } catch (err) {
      try {
        cy.layout({ name: 'cose', animate: false, padding: 30, nodeRepulsion: 4200, idealEdgeLength: 90 } as any).run();
      } catch (err2) {
        // ignore
      }
    }

    return () => { cy.destroy(); cyRef.current = null; };
  }, [data]);

  /* ----- apply isolation highlight ---------------------------------------- */
  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;
    cy.elements().removeClass('dim focus');
    if (highlight && highlight.length) {
      const wanted = new Set(highlight);
      cy.nodes().forEach((n) => {
        if (wanted.has(n.id())) n.addClass('focus');
        else n.addClass('dim');
      });
      cy.edges().forEach((e) => {
        if (!(wanted.has(e.source().id()) && wanted.has(e.target().id()))) e.addClass('dim');
      });
      cy.fit(cy.elements('.focus'), 60);
    }
  }, [highlight, data]);

  if (!active) {
    return (
      <EmptyState
        icon={<Network size={38} />} title="No active investigation"
        message="The forensic graph is rebuilt per investigation when analysis runs."
        action={<button className="btn primary" onClick={() => navigate('/investigations')}>Go to Investigations</button>}
      />
    );
  }

  const runDetection = async () => {
    setRunning(true);
    try {
      const result = await api.runAnalysis(active.id);
      await reload();
      await reloadActive();
      pushToast('success', result.message || 'Analysis complete — graph rebuilt.');
    } catch (e: any) {
      pushToast('error', `Analysis failed: ${e?.message || e}`);
    } finally {
      setRunning(false);
    }
  };

  const findPath = async (sourceId: string, targetId: string) => {
    if (!sourceId || !targetId) return;
    try {
      const res = await api.graphPath(active.id, sourceId, targetId);
      setPathResult(res);
      if (res.found) setHighlight(res.path);
      else pushToast('warning', res.reason || 'No relationship path exists between these elements.');
    } catch (e: any) {
      pushToast('error', `Path search failed: ${e?.message || e}`);
    }
  };

  const chainForIsolate = (chainId: string) => {
    if (!chainId) return;
    api.isolateChain(active.id, chainId)
      .then((res: any) => { if (res.found) setHighlight(res.nodes); else pushToast('warning', res.reason); })
      .catch((e: any) => pushToast('error', `Isolation failed: ${e?.message || e}`));
  };

  const entities = graphActions.data?.entities || {};
  const pathOptions = Object.values(entities).flat() as Array<{ id: string; label: string }>;

  return (
    <div>
      <div className="row" style={{ marginBottom: 14 }}>
        <div className="grow">
          <h2 style={{ margin: 0, fontSize: 18 }}>Forensic Graph</h2>
          <div className="faint">{active.case_id} — entities connected through evidence, correlation and hypotheses</div>
        </div>
        <button className="btn ghost" onClick={() => { setHighlight(null); setPathResult(null); setSelectedNode(null); }}>
          <Crosshair size={14} /> Clear highlights
        </button>
        <button className="btn ghost" onClick={reload}><RefreshCw size={14} /> Reload</button>
        <button className="btn primary" onClick={runDetection} disabled={running}>
          <PlayCircle size={15} /> {running ? 'Running…' : 'Run detection engine'}
        </button>
      </div>

      <div className="grid cols-4" style={{ marginBottom: 12 }}>
        <StatCard label="Nodes" value={data?.counts.nodes ?? '—'} hint="entities in the stored graph" />
        <StatCard label="Relationships" value={data?.counts.edges ?? '—'} tone="accent"
          hint={`${data?.counts.by_relation ? Object.keys(data.counts.by_relation).length : 0} relation types`} />
        <StatCard label="Connected components" value={graphActions.data?.components ?? '—'}
          hint="islands of uncorrelated evidence" />
        <StatCard label="Density" value={graphActions.data?.density ?? '—'}
          hint="linked pairs / possible pairs" />
      </div>

      <div className="card" style={{ padding: 12 }}>
        <div className="row tight" style={{ marginBottom: 10 }}>
          <div className="searchbox grow" style={{ maxWidth: 320 }}>
            <span className="icon"><Search size={14} /></span>
            <input className="input" value={search} placeholder="Filter nodes by label…"
              onChange={(e) => setSearch(e.target.value)} aria-label="Filter graph nodes" />
          </div>
          <div className="grow" />
          <label className="faint">Isolate chain:</label>
          <select className="input" defaultValue="" onChange={(e) => chainForIsolate(e.target.value)} aria-label="Isolate chain">
            <option value="">—</option>
            {(chains.data?.chains || []).map((c: any) => <option key={c.id} value={c.id}>{c.pattern_id} · {c.title}</option>)}
          </select>
          <span className="faint">Path:</span>
          <select className="input" id="path-source" defaultValue="" aria-label="Path source">
            <option value="">from…</option>
            {pathOptions.map((n) => <option key={`s-${n.id}`} value={n.id}>{n.label}</option>)}
          </select>
          <select className="input" id="path-target" defaultValue="" aria-label="Path target">
            <option value="">to…</option>
            {pathOptions.map((n) => <option key={`t-${n.id}`} value={n.id}>{n.label}</option>)}
          </select>
          <button className="btn sm" onClick={() => {
            const s = (document.getElementById('path-source') as HTMLSelectElement).value;
            const t = (document.getElementById('path-target') as HTMLSelectElement).value;
            findPath(s, t);
          }}>
            <Route size={13} /> Find path
          </button>
        </div>

        <div className="row tight" style={{ marginBottom: 8 }}>
          {Object.entries(data?.counts.by_node_type || {}).map(([type, count]) => (
            <button
              key={type}
              className={`chip ${activeTypes.includes(type) ? 'cyan' : ''}`}
              style={{ cursor: 'pointer' }}
              onClick={() => setActiveTypes((prev) => prev.includes(type) ? prev.filter((t) => t !== type) : [...prev, type])}
              title="Toggle node type filter"
            >
              <span className="legend-dot" style={{ background: NODE_COLORS[type] || '#94a7c0' }} />
              {titleCase(type)} ({count})
            </button>
          ))}
          {Object.entries(data?.counts.by_relation || {}).map(([rel, count]) => (
            <button
              key={rel}
              className={`chip ${activeRelations.includes(rel) ? 'cyan' : ''}`}
              style={{ cursor: 'pointer' }}
              onClick={() => setActiveRelations((prev) => prev.includes(rel) ? prev.filter((r) => r !== rel) : [...prev, rel])}
              title={(data?.legend?.relations || []).find((r) => r.relation === rel)?.meaning || 'Toggle relation filter'}
            >
              {rel} ({count})
            </button>
          ))}
        </div>

        {loading && <Skeleton height={360} count={1} />}
        {error && <ErrorBox error={error} onRetry={reload} />}

        {!loading && !error && data && data.nodes.length === 0 && (
          <EmptyState icon={<Network size={34} />} title="Graph not built"
            message={data.empty_reason || 'No graph nodes yet — run the detection engine to correlate this investigation.'}
            action={<button className="btn" onClick={runDetection} disabled={running}>Run detection</button>} />
        )}

        {!loading && data && data.nodes.length > 0 && (
          <>
            <div className="graph-canvas" ref={containerRef} role="application" aria-label="Forensic relationship graph" />
            <div className="row tight" style={{ marginTop: 8, flexWrap: 'wrap', gap: 10 }}>
              <span className="legend-item"><span className="legend-line" />observed relationship (from artifacts)</span>
              <span className="legend-item"><span className="legend-line dashed" />inferred relationship (requires human confirmation)</span>
              {(data.legend?.node_types || []).slice(0, 6).map((t) => (
                <span className="legend-item" key={t}>
                  <span className="legend-dot" style={{ background: NODE_COLORS[t] || '#94a7c0' }} />{titleCase(t)}
                </span>
              ))}
            </div>
          </>
        )}

        {pathResult && (
          <div className={`notice ${pathResult.found ? '' : 'warn'}`} style={{ marginTop: 10 }}>
            {pathResult.found
              ? <>
                  <strong>{pathResult.path.length} node path ({pathResult.inferred_hops} inferred hop(s)):</strong>{' '}
                  {pathResult.summary}
                  <div className="faint" style={{ marginTop: 4 }}>
                    Inferred hops are analyst-confirmable correlations — not proof of causation.
                  </div>
                </>
              : pathResult.reason}
          </div>
        )}
      </div>

      {selectedNode && (
        <div className="drawer" aria-label="Node details">
          <div className="row" style={{ marginBottom: 4 }}>
            <div className="grow">
              <div className="row tight">
                <span className="chip cyan">{titleCase(selectedNode.type || selectedNode.node_type)}</span>
                {selectedNode.flagged && <span className="chip amber">in finding/chain</span>}
              </div>
              <div style={{ fontWeight: 650, fontSize: 15, marginTop: 6 }}>{selectedNode.label}</div>
            </div>
            <button className="btn ghost sm" onClick={() => setSelectedNode(null)} aria-label="Close panel">✕</button>
          </div>

          <dl className="kv" style={{ marginTop: 10 }}>
            <dt>node id</dt><dd className="mono" style={{ fontSize: 11 }}>{selectedNode.id}</dd>
            {selectedNode.event_id && <><dt>event id</dt><dd className="mono" style={{ fontSize: 11 }}>{selectedNode.event_id}</dd></>}
            {selectedNode.description && <><dt>description</dt><dd>{selectedNode.description}</dd></>}
          </dl>

          <div className="section-title">Connected relationships ({(selectedNode.edges || []).length})</div>
          <div className="table-wrap" style={{ maxHeight: 320, overflow: 'auto' }}>
            <table className="data">
              <thead><tr><th>Relation</th><th>Target</th><th>Kind</th></tr></thead>
              <tbody>
                {(selectedNode.edges || []).map((e: any, i: number) => (
                  <tr key={i} title={e.explanation || ''}>
                    <td className="mono">{e.relation}</td>
                    <td className="truncate">{e.target === selectedNode.id ? e.source : e.target}</td>
                    <td>
                      <span className={`chip ${e.inferred ? 'amber' : 'green'}`}>{e.inferred ? 'inferred' : 'observed'}</span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {selectedNode.event_id && (
            <button className="btn sm" style={{ marginTop: 10 }}
              onClick={() => navigate(`/timeline?e=${selectedNode.event_id}`)}>
              <GitFork size={13} /> Open source event in timeline
            </button>
          )}
          <div className="faint" style={{ marginTop: 10 }}>
            Click any relationship row's explanation in the rules section; edges carry evidence_refs and a
            rule reference so every link is auditable.
          </div>
        </div>
      )}

      <div className="notice" style={{ marginTop: 14 }}>
        Node positions are a force layout and carry no meaning; only edges do. Solid edges are recorded in
        artifacts, dashed edges are inferred by the correlation engine and require analyst confirmation —
        the graph shows how evidence relates, not what it proves.
      </div>
    </div>
  );
};

export default ForensicGraph;