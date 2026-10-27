// Investigations — create, inspect, configure, analyse, export and delete.

import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Boxes, FileBarChart2, PlayCircle, Plus, Sparkles, Trash2, UploadCloud } from 'lucide-react';
import { api, fmtTs, titleCase } from '../api';
import { useApp, useAsync } from '../state';
import { EmptyState, ErrorBox, Modal, Skeleton, StatCard } from '../components/ui';
import type { Investigation } from '../types';

const CreateModal: React.FC<{ onClose: () => void; onCreated: (inv: Investigation) => void }> = ({ onClose, onCreated }) => {
  const { pushToast } = useApp();
  const [form, setForm] = useState({ name: '', case_id: '', description: '', notes: '' });
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const submit = async () => {
    setBusy(true);
    setError(null);
    try {
      const inv = await api.createInvestigation(form);
      pushToast('success', `Investigation ${inv.case_id} created.`);
      onCreated(inv);
      onClose();
    } catch (err: any) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Modal
      title="New investigation"
      onClose={onClose}
      footer={
        <>
          <button className="btn" onClick={onClose}>Cancel</button>
          <button className="btn primary" onClick={submit} disabled={busy || form.name.trim().length < 3 || form.case_id.trim().length < 2}>
            {busy ? 'Creating…' : 'Create investigation'}
          </button>
        </>
      }
    >
      {error && <ErrorBox error={error} />}
      <div className="field">
        <label htmlFor="inv-name">Name *</label>
        <input id="inv-name" className="input" value={form.name} placeholder="e.g. Suspected data exfiltration — HQ laptop"
          onChange={(e) => setForm({ ...form, name: e.target.value })} />
      </div>
      <div className="field">
        <label htmlFor="inv-case">Case identifier *</label>
        <input id="inv-case" className="input" value={form.case_id} placeholder="e.g. CASE-2026-014"
          onChange={(e) => setForm({ ...form, case_id: e.target.value })} />
        <div className="help">Must be unique — it prefixes every export.</div>
      </div>
      <div className="field">
        <label htmlFor="inv-desc">Description</label>
        <textarea id="inv-desc" className="input" rows={3} value={form.description}
          onChange={(e) => setForm({ ...form, description: e.target.value })} />
      </div>
      <div className="field">
        <label htmlFor="inv-notes">Investigator notes</label>
        <textarea id="inv-notes" className="input" rows={3} value={form.notes}
          onChange={(e) => setForm({ ...form, notes: e.target.value })} />
      </div>
    </Modal>
  );
};

export const InvestigationsPage: React.FC = () => {
  const { investigations, refreshInvestigations, activeId, setActiveId, pushToast, actor } = useApp();
  const navigate = useNavigate();
  const [showCreate, setShowCreate] = useState(false);
  const [busy, setBusy] = useState<string | null>(null);
  const [deleteTarget, setDeleteTarget] = useState<Investigation | null>(null);
  const [generating, setGenerating] = useState(false);
  const { data: demo, reload: reloadDemo } = useAsync(() => api.demoInfo(), []);
  const [showScenarios, setShowScenarios] = useState(false);
  const [picked, setPicked] = useState<string[]>([]);

  const runAnalysis = async (inv: Investigation) => {
    setBusy(inv.id);
    try {
      const result = await api.runAnalysis(inv.id);
      pushToast('success', result.message);
      await refreshInvestigations();
    } catch (err: any) {
      pushToast('error', `Analysis failed: ${err.message}`);
    } finally {
      setBusy(null);
    }
  };

  const generate = async (scenarios: string[]) => {
    setGenerating(true);
    try {
      const result = await api.generateDemo(scenarios);
      await refreshInvestigations();
      await reloadDemo();
      pushToast('success', `Generated ${result.created.length} synthetic investigation(s), fully labelled origin=demo.`);
      setShowScenarios(false);
      setPicked([]);
    } catch (err: any) {
      pushToast('error', `Generation failed: ${err.message}`);
    } finally {
      setGenerating(false);
    }
  };

  const remove = async () => {
    if (!deleteTarget) return;
    try {
      await api.deleteInvestigation(deleteTarget.id, true);
      pushToast('success', `Investigation ${deleteTarget.case_id} deleted with its evidence.`);
      if (activeId === deleteTarget.id) setActiveId(null);
      await refreshInvestigations();
      setDeleteTarget(null);
    } catch (err: any) {
      pushToast('error', `Delete failed: ${err.message}`);
    }
  };

  return (
    <div>
      <div className="row" style={{ marginBottom: 14 }}>
        <div className="grow">
          <h2 style={{ margin: 0, fontSize: 18 }}>Investigations</h2>
          <div className="faint">Every investigation keeps its own evidence, findings, graph and configuration.</div>
        </div>
        <button className="btn" onClick={() => setShowScenarios(true)}>
          <Sparkles size={15} /> Synthetic demo data
        </button>
        <button className="btn primary" onClick={() => setShowCreate(true)}>
          <Plus size={15} /> New investigation
        </button>
      </div>

      {!investigations.length && !generating && (
        <EmptyState
          icon={<Boxes size={28} />}
          title="No investigations"
          message="Create your first investigation, or generate the controlled synthetic datasets (10 scenarios with declared ground truth) to explore the whole pipeline."
          action={
            <div className="row" style={{ justifyContent: 'center' }}>
              <button className="btn primary" onClick={() => setShowCreate(true)}><Plus size={15} /> New investigation</button>
              <button className="btn" onClick={() => setShowScenarios(true)}><Sparkles size={15} /> Generate demo data</button>
            </div>
          }
        />
      )}

      {investigations.map((inv) => (
        <div key={inv.id} className="card" style={{ marginBottom: 12 }}>
          <div className="row">
            <div className="grow">
              <div className="row tight">
                <strong>{inv.case_id}</strong>
                <span>{inv.name}</span>
                {inv.is_demo && <span className="chip amber">synthetic · origin=demo</span>}
                {inv.id === activeId && <span className="chip cyan">active</span>}
                <span className="chip">{titleCase(inv.processing)}</span>
                <span className="chip">status: {inv.status}</span>
              </div>
              <div className="faint" style={{ marginTop: 4 }}>
                created {fmtTs(inv.created_at)} · updated {fmtTs(inv.updated_at)}
              </div>
              {inv.description && <div className="muted" style={{ marginTop: 6, whiteSpace: 'pre-wrap' }}>{inv.description}</div>}
            </div>
            <div className="row tight">
              <button className="btn sm" onClick={() => { setActiveId(inv.id); navigate('/evidence'); }}>
                <UploadCloud size={14} /> Evidence
              </button>
              <button className="btn sm" onClick={() => runAnalysis(inv)} disabled={busy === inv.id || inv.metrics.events === 0}
                title={inv.metrics.events === 0 ? 'Import evidence first' : 'Re-run detection engine'}>
                <PlayCircle size={14} /> {busy === inv.id ? 'Running…' : 'Run analysis'}
              </button>
              <button className="btn sm" onClick={() => { setActiveId(inv.id); navigate('/reports'); }}>
                <FileBarChart2 size={14} /> Report
              </button>
              <button className="btn sm danger" onClick={() => setDeleteTarget(inv)}>
                <Trash2 size={14} /> Delete
              </button>
            </div>
          </div>

          <div className="grid cols-4" style={{ marginTop: 12 }}>
            <StatCard label="Events" value={inv.metrics.events} hint={`${inv.metrics.evidence_sources} sources`} />
            <StatCard label="Findings" value={inv.metrics.findings} hint={`${inv.metrics.high_priority_findings} high priority`} />
            <StatCard label="Chains" value={inv.metrics.suspicion_chains} />
            <StatCard label="Rejected records" value={inv.metrics.rejected_records}
              hint={inv.metrics.rejected_records ? 'inspect parsing errors in Evidence Explorer' : 'no parsing errors'} />
          </div>

          {inv.notes && (
            <details style={{ marginTop: 10 }}>
              <summary className="faint" style={{ cursor: 'pointer' }}>Investigator notes / ground truth</summary>
              <pre className="raw">{inv.notes}</pre>
            </details>
          )}
        </div>
      ))}

      {showCreate && (
        <CreateModal
          onClose={() => setShowCreate(false)}
          onCreated={async (inv) => {
            await refreshInvestigations();
            setActiveId(inv.id);
            navigate('/evidence');
          }}
        />
      )}

      {deleteTarget && (
        <Modal
          title="Confirm deletion"
          onClose={() => setDeleteTarget(null)}
          footer={
            <>
              <button className="btn" onClick={() => setDeleteTarget(null)}>Cancel</button>
              <button className="btn danger" onClick={remove}>
                <Trash2 size={14} /> Delete {deleteTarget.case_id} permanently
              </button>
            </>
          }
        >
          <p style={{ marginTop: 0 }}>
            This removes <strong>{deleteTarget.case_id} — {deleteTarget.name}</strong> with{' '}
            {deleteTarget.metrics.events} events, {deleteTarget.metrics.evidence_sources} evidence source(s),
            {deleteTarget.metrics.findings} findings and its graph. Evidence files on disk are deleted too.
          </p>
          {deleteTarget.is_demo && (
            <div className="notice warn">This is a synthetic demo investigation; deleting it does not affect imported evidence.</div>
          )}
        </Modal>
      )}

      {showScenarios && (
        <Modal
          title="Generate synthetic demonstration data"
          onClose={() => setShowScenarios(false)}
          footer={
            <>
              <button className="btn" onClick={() => setShowScenarios(false)}>Cancel</button>
              <button className="btn" onClick={() => generate([])} disabled={generating}>
                {generating ? 'Generating…' : 'Generate all scenarios'}
              </button>
              <button className="btn primary" onClick={() => generate(picked)} disabled={generating || !picked.length}>
                {generating ? 'Generating…' : `Generate selected (${picked.length})`}
              </button>
            </>
          }
        >
          <div className="notice">
            {demo?.labeling || 'Every generated record carries origin=demo on the investigation, evidence source and event rows.'}
          </div>
          <div style={{ marginTop: 12 }}>
            {(demo?.scenarios || []).map((scenario) => (
              <label key={scenario.id} className="checkbox" style={{ padding: '6px 0', alignItems: 'flex-start' }}>
                <input
                  type="checkbox"
                  checked={picked.includes(scenario.id)}
                  onChange={(e) => setPicked(e.target.checked ? [...picked, scenario.id] : picked.filter((s) => s !== scenario.id))}
                  style={{ marginTop: 3 }}
                />
                <span>
                  <strong>{scenario.name}</strong> <span className="faint">({scenario.case_id})</span>
                  <div className="faint">{scenario.description}</div>
                  <div className="faint">
                    ground truth: expect {scenario.expected_rules.join(', ') || 'no rules'} ·
                    must not fire {scenario.expected_absent.join(', ')} · chains {scenario.expected_chains.join(', ') || 'none'}
                  </div>
                </span>
              </label>
            ))}
          </div>
        </Modal>
      )}
    </div>
  );
};