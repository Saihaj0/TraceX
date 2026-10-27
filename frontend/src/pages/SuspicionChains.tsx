// Suspicion Chains — multi-step correlation patterns. Each chain shows its
// ordered steps (matched and missing), the relationships that link them, the
// rules that contributed, and legitimate alternative explanations. Status can
// be triaged by the analyst; nothing here asserts intent.

import React, { useEffect, useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { Eye, Network, PlayCircle, Workflow } from 'lucide-react';
import { api, fmtTs, titleCase } from '../api';
import { useApp, useAsync } from '../state';
import type { SuspicionChain } from '../types';
import {
  EmptyState, ErrorBox, SeverityBadge, Skeleton, StatCard, SupportBadge,
} from '../components/ui';

const STATUS_OPTIONS = ['open', 'in_review', 'confirmed', 'dismissed'];

/* -------------------------------------------------------------------------- */
/* Chain detail panel                                                           */
/* -------------------------------------------------------------------------- */

const ChainDetail: React.FC<{
  chain: SuspicionChain;
  investigationId: string;
  onChanged: () => void;
  onClose: () => void;
}> = ({ chain, investigationId, onChanged, onClose }) => {
  const { pushToast } = useApp();
  const navigate = useNavigate();
  const [status, setStatus] = useState(chain.status);
  const [saving, setSaving] = useState(false);

  const save = async (next: string) => {
    setSaving(true);
    try {
      await api.updateChain(investigationId, chain.id, { status: next });
      setStatus(next);
      pushToast('success', `Chain marked ${next} (recorded in the audit trail).`);
      onChanged();
    } catch (e: any) {
      pushToast('error', `Update failed: ${e?.message || e}`);
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="modal-backdrop" onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <div className="modal" style={{ width: 'min(900px, 96vw)' }} role="dialog" aria-modal="true">
        <div className="row">
          <div className="grow">
            <div className="row tight">
              <span className="chip cyan">{chain.pattern_id}</span>
              <SeverityBadge severity={chain.severity} />
              <SupportBadge support={chain.support} />
              <span className={`chip ${chain.completeness === 'complete' ? 'amber' : ''}`}>
                {chain.completeness}{chain.missing_steps?.length ? ` · ${chain.missing_steps.length} missing step(s)` : ''}
              </span>
            </div>
            <h3 style={{ margin: '8px 0 4px' }}>{chain.title}</h3>
            <div className="faint">{chain.note}</div>
          </div>
          <button className="btn ghost sm" onClick={onClose} aria-label="Close">✕</button>
        </div>

        <div className="section-title">Sequence</div>
        <ol className="steps">
          {chain.steps.map((step) => (
            <li key={step.position} className={`step ${step.matched ? '' : 'missing'}`}>
              <span className="pos">{step.position}</span>
              <div className="grow">
                <div className="row tight">
                  <span style={{ fontWeight: 600, fontSize: 13 }}>{step.label}</span>
                  {step.is_anchor && <span className="chip cyan">anchor</span>}
                  {!step.matched && <span className="chip amber">missing</span>}
                  <span className="faint">{fmtTs(step.timestamp)}</span>
                </div>
                {step.description && <div className="faint">{step.description}</div>}
                {step.missing_reason && <div className="faint">reason: {step.missing_reason}</div>}
                {step.relationships?.length ? (
                  <div className="faint">linked by: {step.relationships.join(', ')}</div>
                ) : null}
                {(step.source_file || step.evidence_ref) && (
                  <div className="cell-faint mono">
                    {step.source_file || ''} {step.source_record_id ? `#${step.source_record_id}` : ''}
                    {step.evidence_ref ? ` · ${step.evidence_ref}` : ''}
                  </div>
                )}
              </div>
            </li>
          ))}
        </ol>

        {chain.missing_steps?.length > 0 && (
          <div className="notice warn" style={{ marginTop: 12 }}>
            <strong>Incomplete pattern — reported as a candidate, not a confirmed chain:</strong>
            <ul className="inline-list">
              {chain.missing_steps.map((m, i) => <li key={i}>{m.label}: {m.reason}</li>)}
            </ul>
          </div>
        )}

        <div className="grid cols-2" style={{ marginTop: 14, gap: 16 }}>
          <div>
            <div className="section-title">Relationship types used</div>
            <div className="row tight">
              {(chain.relationship_types || []).map((r) => <span key={r} className="chip">{r}</span>)}
              {!chain.relationship_types?.length && <span className="faint">temporal adjacency only</span>}
            </div>

            <div className="section-title">Triggered rules</div>
            <div className="row tight">
              {(chain.triggered_rules || []).map((r) => <span key={r} className="chip cyan">{r}</span>)}
              {!chain.triggered_rules?.length && <span className="faint">none</span>}
            </div>
          </div>
          <div>
            <div className="section-title">Alternative explanations</div>
            <ul className="inline-list">
              {(chain.alternative_explanations || []).map((alt, i) => (
                <li key={i}>
                  {alt.explanation}
                  {alt.why_relevant && <span className="faint"> — {alt.why_relevant}</span>}
                </li>
              ))}
              {!chain.alternative_explanations?.length && <li className="faint">none recorded</li>}
            </ul>
          </div>
        </div>

        <div className="section-title">Events in this chain ({chain.event_ids.length})</div>
        <div className="row tight" style={{ marginBottom: 8 }}>
          {(chain.events || []).map((ev) => (
            <span key={ev.id} className="chip" title={ev.description || ''}>
              {fmtTs(ev.timestamp)} · {titleCase(ev.event_type)}
            </span>
          ))}
          {!chain.events?.length && <span className="faint">events not loaded</span>}
        </div>

        <div className="row tight" style={{ marginTop: 12 }}>
          <select className="input" value={status} onChange={(e) => setStatus(e.target.value)} aria-label="Chain status">
            {STATUS_OPTIONS.map((s) => <option key={s} value={s}>{s}</option>)}
          </select>
          <button className="btn primary" disabled={saving || status === chain.status} onClick={() => save(status)}>
            {saving ? 'Saving…' : 'Save status'}
          </button>
          <div className="grow" />
          <button className="btn ghost" onClick={() => { onClose(); navigate('/graph'); }}>
            <Network size={14} /> View in forensic graph
          </button>
          <button className="btn ghost" onClick={() => { onClose(); navigate(`/timeline?e=${chain.event_ids[0] || ''}`); }}>
            <Eye size={14} /> Open first event in timeline
          </button>
        </div>
      </div>
    </div>
  );
};

/* -------------------------------------------------------------------------- */
/* Page                                                                         */
/* -------------------------------------------------------------------------- */

export const SuspicionChains: React.FC = () => {
  const { active, pushToast, reloadActive } = useApp();
  const navigate = useNavigate();
  const [params] = useSearchParams();
  const focusId = params.get('c');
  const [completeness, setCompleteness] = useState<'all' | 'complete' | 'partial'>('all');
  const [selected, setSelected] = useState<SuspicionChain | null>(null);
  const [running, setRunning] = useState(false);

  const chains = useAsync(
    () => (active
      ? api.chains(active.id, completeness === 'all' ? {} : { completeness })
      : Promise.resolve(null)),
    [active?.id, completeness],
  );

  useEffect(() => {
    if (!focusId || !chains.data) return;
    const hit = chains.data.chains.find((c) => c.id === focusId);
    if (hit) setSelected(hit);
  }, [focusId, chains.data]); // eslint-disable-line react-hooks/exhaustive-deps

  if (!active) {
    return (
      <EmptyState
        icon={<Workflow size={38} />} title="No active investigation"
        message="Suspicion chains are evaluated per investigation — select one first."
        action={<button className="btn primary" onClick={() => navigate('/investigations')}>Go to Investigations</button>}
      />
    );
  }

  const runDetection = async () => {
    setRunning(true);
    try {
      const result = await api.runAnalysis(active.id);
      await chains.reload();
      await reloadActive();
      pushToast('success',
        result.message || `Analysis complete — ${result.analysis?.chains ?? 0} suspicion chains.`);
    } catch (e: any) {
      pushToast('error', `Analysis failed: ${e?.message || e}`);
    } finally {
      setRunning(false);
    }
  };

  const list = chains.data?.chains || [];

  return (
    <div>
      <div className="row" style={{ marginBottom: 14 }}>
        <div className="grow">
          <h2 style={{ margin: 0, fontSize: 18 }}>Suspicion Chains</h2>
          <div className="faint">
            {active.case_id} · multi-step sequences with temporal + graph corroboration —
            incomplete patterns are reported as candidates, never as proof
          </div>
        </div>
        <div className="pill-group">
          {(['all', 'complete', 'partial'] as const).map((mode) => (
            <button key={mode} className={completeness === mode ? 'active' : ''} onClick={() => setCompleteness(mode)}>
              {titleCase(mode)}
            </button>
          ))}
        </div>
        <button className="btn primary" onClick={runDetection} disabled={running}>
          <PlayCircle size={15} /> {running ? 'Running…' : 'Run detection engine'}
        </button>
      </div>

      <div className="grid cols-4" style={{ marginBottom: 14 }}>
        <StatCard label="Total chains" value={chains.data?.count ?? '—'} hint="multi-step candidate sequences" />
        <StatCard label="Complete patterns" value={chains.data?.complete ?? 0} tone="warn"
          hint="every required step matched" />
        <StatCard label="Partial patterns" value={chains.data?.partial ?? 0}
          hint="reported with explicit missing steps" />
        <StatCard label="Events in chains"
          value={list.reduce((n, c) => n + c.event_ids.length, 0)} hint="distinct supporting events" />
      </div>

      {chains.loading && <Skeleton height={70} count={4} />}
      {chains.error && <ErrorBox error={chains.error} onRetry={chains.reload} />}

      {!chains.loading && !chains.error && list.length === 0 && (
        <EmptyState
          icon={<Workflow size={34} />} title="No suspicion chains"
          message={active.metrics.events === 0
            ? 'Import evidence and run the detection engine to evaluate pattern detectors (staging → tampering → cleanup, evidence transfer, etc.).'
            : 'No pattern currently has sufficient supporting evidence on this case. That is a legitimate outcome: chains require corroborated multi-step evidence, not proximity alone.'}
          action={<button className="btn" onClick={runDetection} disabled={running}>Run detection</button>}
        />
      )}

      {list.map((chain) => (
        <div key={chain.id} className="card" style={{ cursor: 'pointer' }} onClick={() => setSelected(chain)}>
          <div className="row tight">
            <span className="chip cyan">{chain.pattern_id}</span>
            <span style={{ fontWeight: 650 }} className="grow">{chain.title}</span>
            <SeverityBadge severity={chain.severity} />
            <SupportBadge support={chain.support} />
            <span className={`chip ${chain.completeness === 'complete' ? 'amber' : ''}`}>{chain.completeness}</span>
            <span className="chip">{chain.status}</span>
          </div>
          <div className="faint" style={{ marginTop: 6 }}>{chain.note}</div>
          <ol className="steps" style={{ marginTop: 10 }}>
            {chain.steps.map((step) => (
              <li key={step.position} className={`step ${step.matched ? '' : 'missing'}`}>
                <span className="pos">{step.position}</span>
                <div className="grow">
                  <div className="row tight">
                    <span style={{ fontSize: 12.6, fontWeight: 600 }}>{step.label}</span>
                    {!step.matched && <span className="chip amber">missing</span>}
                    <span className="faint">{fmtTs(step.timestamp)}</span>
                  </div>
                  {step.description && <div className="faint truncate">{step.description}</div>}
                </div>
              </li>
            ))}
          </ol>
          {chain.alternative_explanations?.length > 0 && (
            <div className="faint" style={{ marginTop: 8 }}>
              Also consistent with: {chain.alternative_explanations[0].explanation}
            </div>
          )}
        </div>
      ))}

      <div className="notice" style={{ marginTop: 14 }}>
        {chains.data?.note ||
          'Chains remain hypotheses until corroborated: temporal order plus artifact relationships raise support strength, but no chain establishes intent or guilt.'}
      </div>

      {selected && (
        <ChainDetail
          chain={selected} investigationId={active.id}
          onChanged={async () => { await chains.reload(); reloadActive(); }}
          onClose={() => setSelected(null)}
        />
      )}
    </div>
  );
};

export default SuspicionChains;