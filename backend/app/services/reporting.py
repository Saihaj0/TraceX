"""Investigation report generation.

Produces a reproducible HTML report plus structured JSON / CSV exports.

The report separates the three analytical layers explicitly:
  Evidence (observed records) → Correlation (relationships) → Hypothesis
and always prints limitations, contradictions and alternative explanations.

PDF: TRACE-X does not embed a PDF renderer in this environment. The HTML report
is print-optimised (browser "Print → Save as PDF" produces a paginated PDF with
identical content), and the JSON export is the reproducible machine-readable
form. This limitation is stated inside the report itself.
"""

from __future__ import annotations

import html
import json
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from ..config import ENGINE_VERSION, RULES_VERSION
from ..models import AnalysisRun, AuditLog, EvidenceSource, Event, Finding, Investigation, SuspicionChain
from ..normalization import dt_to_iso
from .evidence import source_integrity
from .graph import flagged_event_ids_for
from .timeline import TimelineFilter, query_events
from .uncertainty import SUPPORT_DEFINITIONS, SUPPORT_LEVELS


def _esc(value) -> str:
    if value is None:
        return ""
    return html.escape(str(value))


def _fmt_ts(value) -> str:
    if value is None:
        return "<span class='muted'>time unknown</span>"
    dt = value if isinstance(value, datetime) else None
    if dt is None:
        return _esc(value)
    if dt.tzinfo is None:
        # SQLite hands back naive datetimes that were stored as UTC; naive
        # astimezone() would reinterpret them in the server's local zone.
        dt = dt.replace(tzinfo=timezone.utc)
    dt = dt.astimezone(timezone.utc)
    return dt.strftime("%Y-%m-%d %H:%M:%S UTC")


def build_report_data(db: Session, investigation: Investigation) -> dict:
    sources = (
        db.query(EvidenceSource)
        .filter(EvidenceSource.investigation_id == investigation.id)
        .order_by(EvidenceSource.imported_at)
        .all()
    )
    findings = (
        db.query(Finding)
        .filter(Finding.investigation_id == investigation.id)
        .order_by(Finding.severity, Finding.rule_id)
        .all()
    )
    chains = (
        db.query(SuspicionChain)
        .filter(SuspicionChain.investigation_id == investigation.id)
        .all()
    )
    runs = (
        db.query(AnalysisRun)
        .filter(AnalysisRun.investigation_id == investigation.id)
        .order_by(AnalysisRun.started_at)
        .all()
    )
    audit_entries = (
        db.query(AuditLog)
        .filter(AuditLog.investigation_id == investigation.id)
        .order_by(AuditLog.created_at)
        .all()
    )
    timeline_filter = TimelineFilter(limit=10_000)
    events, _ = query_events(db, investigation.id, timeline_filter)
    flagged = flagged_event_ids_for(db, investigation.id)

    executions = sorted(
        [r for r in runs if r.status == "completed"],
        key=lambda r: r.started_at or r.created_at if hasattr(r, "created_at") else r.started_at,
    )
    latest = executions[-1] if executions else None

    def finding_dict(finding: Finding) -> dict:
        explanation = dict(finding.explanation or {})
        evidence_rows = explanation.get("evidence", [])
        event_times = [e.get("timestamp") for e in evidence_rows if e.get("timestamp")]
        return {
            "id": finding.id,
            "title": finding.title,
            "severity": finding.severity,
            "support": finding.support,
            "heuristic_score": finding.heuristic_score,
            "rule_id": finding.rule_id,
            "rule_name": finding.rule_name,
            "rule_version": finding.rule_version,
            "occurred_at": min(event_times) if event_times else None,
            "evidence": evidence_rows,
            "why_triggered": explanation.get("why_triggered"),
            "observed": explanation.get("observed_evidence", []),
            "correlation": explanation.get("correlation", []),
            "hypothesis": explanation.get("hypothesis"),
            "does_not_establish": explanation.get("does_not_establish", []),
            "missing": explanation.get("missing_evidence", []),
            "contradicting": explanation.get("contradicting_evidence", []),
            "limitations": explanation.get("limitations", []),
            "alternatives": explanation.get("alternative_explanations", []),
            "next_steps": explanation.get("recommended_next_checks", []),
            "temporal": explanation.get("temporal_relationships", []),
            "rule_metadata": explanation.get("rule_metadata", {}),
            "created_at": finding.created_at.isoformat() if finding.created_at else None,
        }

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "version": {"engine": ENGINE_VERSION, "ruleset": RULES_VERSION},
        "case": {
            "name": investigation.name,
            "case_id": investigation.case_id,
            "description": investigation.description,
            "notes": investigation.notes,
            "status": investigation.status,
            "origin": investigation.origin,
            "created_at": investigation.created_at.isoformat() if investigation.created_at else None,
            "investigation_id": investigation.id,
        },
        "scope": {
            "events": len(events),
            "evidence_sources": len(sources),
            "analysis_runs": len(executions),
            "configuration": (latest.config_snapshot if latest else investigation.analysis_config),
            "statement": (
                "This report covers only the evidence supplied to TRACE-X for this "
                "investigation. Absence of a record is not evidence that the underlying event "
                "did not occur."
            ),
        },
        "sources": [source_integrity(s) for s in sources],
        "methodology": {
            "parsers": sorted({f"{s.parser_name}@{s.parser_version}" for s in sources}),
            "engine_version": ENGINE_VERSION,
            "ruleset_version": RULES_VERSION,
            "analysis_runs": [
                {"run_id": r.id, "started_at": dt_to_iso(r.started_at),
                 "finished_at": dt_to_iso(r.finished_at), "duration_ms": r.duration_ms,
                 "trigger": r.trigger, "config": r.config_snapshot,
                 "rules": r.rules_run, "summary": r.summary}
                for r in executions
            ],
            "integrity": (
                "Evidence files are hashed with SHA-256 at import; each normalized event carries "
                "its own integrity hash over normalized + raw fields. Hashes detect later "
                "modification of the stored copy but do not by themselves prove authenticity or "
                "chain of custody."
            ),
            "timezone_policy": (
                "All normalized timestamps are UTC. Source strings are preserved in "
                "`timestamp_raw`; records without a usable timestamp are reported as unknown and "
                "never placed in the sequence."
            ),
        },
        "timeline": [
            {
                "timestamp": dt_to_iso(e.timestamp),
                "timestamp_raw": e.timestamp_raw,
                "precision": e.timestamp_precision,
                "confidence": e.timestamp_confidence,
                "event_type": e.event_type,
                "description": e.description,
                "host": e.host,
                "user": e.user,
                "file_path": e.file_path,
                "source_file": e.source_file,
                "source_record_id": e.source_record_id,
                "origin": e.origin,
                "flagged": e.id in flagged,
            }
            for e in events
        ],
        "findings": [finding_dict(f) for f in findings],
        "chains": [
            {
                "id": c.id, "pattern_id": c.pattern_id, "pattern_name": c.pattern_name,
                "title": c.title, "steps": c.steps, "severity": c.severity,
                "support": c.support, "completeness": c.completeness,
                "missing_steps": c.missing_steps, "alternatives": c.alternative_explanations,
                "triggered_rules": c.triggered_rules, "status": c.status,
                "relationships": c.relationship_types,
            }
            for c in chains
        ],
        "graph_summary": (latest.summary or {}).get("graph", {}) if latest else {},
        "confidence_methodology": {
            "levels": [
                {"level": level, **SUPPORT_DEFINITIONS[level]} for level in SUPPORT_LEVELS
            ],
            "remarks": [
                "Support levels are qualitative, not probabilities; TRACE-X does not display "
                "arbitrary percentages as if they were calibrated.",
                "Heuristic scores are labelled as such and their components are stored with "
                "each finding.",
                "Severity expresses investigative priority and is never treated as a "
                "probability or as proof of an event.",
                "Source reliability, timestamp confidence, relationship strength, hypothesis "
                "support and severity are tracked separately.",
            ],
        },
        "audit_trail": [
            {"at": dt_to_iso(a.created_at), "action": a.action, "actor": a.actor,
             "entity_type": a.entity_type, "entity_id": a.entity_id, "detail": a.detail}
            for a in audit_entries[-400:]
        ],
        "limitations": [
            "Only the evidence supplied to this investigation is represented.",
            "Correlations are not causal findings; hypotheses are explicitly marked.",
            "Timestamps taken from different clock domains may be misordered; such records are "
            "labelled order-uncertain.",
            "Missing records are reported as missing coverage, never as proof of deletion.",
            "PDF rendering is not embedded — use the browser print dialog on this HTML report.",
        ],
    }


def render_html(data: dict) -> str:
    case = data["case"]
    esc = _esc

    def section_header(number: str, title: str) -> str:
        return f"<section><h2><span class='num'>{number}</span>{esc(title)}</h2>"

    finding_rows = []
    for finding in data["findings"]:
        ev_rows = "".join(
            f"<li><code>{esc(e.get('timestamp') or 'time unknown')}</code> — "
            f"{esc(e.get('description'))} <span class='src'>[{esc(e.get('source_file'))} "
            f"#{esc(e.get('source_record_id'))}]</span></li>"
            for e in finding["evidence"]
        ) or "<li class='muted'>no evidence rows attached</li>"
        obs = "".join(f"<li>{esc(item)}</li>" for item in finding["observed"])
        corr = "".join(f"<li>{esc(item)}</li>" for item in finding["correlation"])
        missing = "".join(f"<li>{esc(item)}</li>" for item in finding["missing"])
        contra = "".join(
            f"<li><strong>{esc(item.get('what'))}</strong> {esc(item.get('impact'))}</li>"
            for item in finding["contradicting"]
            if isinstance(item, dict)
        )
        alt = "".join(
            f"<li>{esc(item.get('explanation'))}</li>" for item in finding["alternatives"]
            if isinstance(item, dict)
        )
        nexts = "".join(f"<li>{esc(item)}</li>" for item in finding["next_steps"])
        limits = "".join(f"<li>{esc(item)}</li>" for item in finding["limitations"])
        notestab = "".join(f"<li>{esc(item)}</li>" for item in finding["does_not_establish"])
        finding_rows.append(f"""
<div class="finding sev-{esc(finding['severity'])}">
  <h3><span class="badge sev-{esc(finding['severity'])}">{esc(finding['severity'])}</span>
      {esc(finding['title'])}</h3>
  <p class="meta">Rule <strong>{esc(finding['rule_id'])}</strong> — {esc(finding['rule_name'])}
     (v{esc(finding['rule_version'])}) · support: <strong>{esc(finding['support'])}</strong>
     {f"· heuristic score {esc(finding['heuristic_score'])}" if finding['heuristic_score'] is not None else ""}
     · occurred: {esc(finding['occurred_at'] or 'time unknown')}</p>
  <div class="cols">
    <div><h4>Observed evidence (facts)</h4><ul>{obs}</ul>
         <h4>Evidence records</h4><ul class="evidence">{ev_rows}</ul></div>
    <div><h4>Correlation</h4><ul>{corr}</ul>
         <h4>Hypothesis</h4><p>{esc(finding['hypothesis'])}</p></div>
  </div>
  <div class="cols">
    <div><h4>What this does NOT establish</h4><ul>{notestab}</ul>
         {f"<h4>Contradicting evidence</h4><ul>{contra}</ul>" if contra else ""}</div>
    <div><h4>Missing evidence</h4><ul>{missing or "<li class='muted'>none recorded</li>"}</ul>
         <h4>Limitations</h4><ul>{limits}</ul></div>
  </div>
  <div class="cols">
    <div><h4>Plausible benign explanations</h4><ul>{alt}</ul></div>
    <div><h4>Recommended next checks</h4><ul>{nexts}</ul></div>
  </div>
</div>""")

    chain_rows = []
    for chain in data["chains"]:
        steps = ""
        for step in chain["steps"]:
            cls = "step" if step.get("matched") else "step missing"
            steps += (f"<li class='{cls}'>"
                      f"<span class='pos'>{step['position']}</span> "
                      f"<strong>{esc(step['label'])}</strong> "
                      + (f"— {esc(step.get('description'))} <code>{esc(step.get('timestamp'))}</code>"
                         if step.get("matched") else
                         f"— <em>not evidenced</em>: {esc(step.get('missing_reason'))}")
                      + "</li>")
        alt = "".join(f"<li>{esc(a.get('explanation'))}</li>" for a in chain["alternatives"])
        chain_rows.append(f"""
<div class="finding sev-{esc(chain['severity'])}">
  <h3>{esc(chain['title'])}</h3>
  <p class="meta">Severity <strong>{esc(chain['severity'])}</strong> · support
     <strong>{esc(chain['support'])}</strong> · completeness <strong>{esc(chain['completeness'])}</strong>
     · status {esc(chain['status'])}</p>
  <ol class="steps">{steps}</ol>
  <p class="meta">Relationships asserted: {esc(', '.join(chain['relationships']) or 'none')} ·
     Rules triggered: {esc(', '.join(chain['triggered_rules']) or 'none')}</p>
  <div class="cols"><div><h4>Alternative explanations</h4><ul>{alt}</ul></div>
  <div><h4>Missing steps</h4><ul>{''.join(f"<li><strong>{esc(m['label'])}</strong>: {esc(m['reason'])}</li>" for m in chain['missing_steps']) or "<li class='muted'>none</li>"}</ul></div></div>
</div>""")

    source_rows = "".join(
        f"<tr><td>{esc(s['filename'])}</td><td>{esc(s['file_type'])}</td>"
        f"<td>{esc(s['source_type'])}</td><td>{esc(s['accepted'])}/{esc(s['rejected'])} rejected</td>"
        f"<td class='hash'>{esc(s['sha256'])}</td>"
        f"<td>{esc(s['parser'])} · {esc(s['origin'])}</td>"
        f"<td>{esc(s['timezone_note'])}</td></tr>"
        for s in data["sources"]
    ) or "<tr><td colspan='7' class='muted'>no evidence sources</td></tr>"

    timeline_rows = "".join(
        f"<tr class='{'flagged' if row['flagged'] else ''}'>"
        f"<td>{esc(row['timestamp'] or 'time unknown')}</td>"
        f"<td>{esc(row['event_type'])}</td><td>{esc(row['description'])}</td>"
        f"<td>{esc(row['host'])}</td><td>{esc(row['user'])}</td>"
        f"<td>{esc(row['file_path'])}</td>"
        f"<td>{esc(row['source_file'])} #{esc(row['source_record_id'])}</td>"
        f"<td>{'⚑' if row['flagged'] else ''}</td></tr>"
        for row in data["timeline"]
    ) or "<tr><td colspan='8' class='muted'>no events imported</td></tr>"

    audit_rows = "".join(
        f"<tr><td>{esc(a['at'])}</td><td>{esc(a['action'])}</td><td>{esc(a['actor'])}</td>"
        f"<td>{esc(a['entity_type'])} {esc(a['entity_id'])}</td><td>{esc(json.dumps(a['detail'])[:300])}</td></tr>"
        for a in data["audit_trail"]
    ) or "<tr><td colspan='5' class='muted'>no audit entries</td></tr>"

    runs_rows = "".join(
        f"<tr><td>{esc(r['run_id'])}</td><td>{esc(r['started_at'])}</td>"
        f"<td>{esc(r['duration_ms'])} ms</td><td>{esc(r['trigger'])}</td>"
        f"<td class='hash'>{esc(json.dumps(r['config']))}</td>"
        f"<td>{esc(json.dumps(r['rules'])[:600])}</td></tr>"
        for r in data["methodology"]["analysis_runs"]
    ) or "<tr><td colspan='6' class='muted'>no completed analysis runs</td></tr>"

    confidence_rows = "".join(
        f"<tr><td><strong>{esc(level['level'])}</strong></td><td>{esc(level['rule'])}</td>"
        f"<td>{esc('; '.join(level['requires']))}</td></tr>"
        for level in data["confidence_methodology"]["levels"]
    )

    graph = data.get("graph_summary") or {}
    graph_rows = "".join(
        f"<tr><td>{esc(k)}</td><td>{esc(v)}</td></tr>"
        for k, v in (graph or {}).items() if not isinstance(v, (dict, list))
    ) or "<tr><td colspan='2' class='muted'>graph not built yet — re-run analysis</td></tr>"

    limitations = "".join(f"<li>{esc(item)}</li>" for item in data["limitations"])
    method_remarks = "".join(
        f"<li>{esc(item)}</li>" for item in data["confidence_methodology"]["remarks"]
    )

    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>TRACE-X Investigation Report — {esc(case['case_id'])} {esc(case['name'])}</title>
<style>
:root {{ color-scheme: light; }}
* {{ box-sizing: border-box; }}
body {{ font-family: "Segoe UI", system-ui, -apple-system, sans-serif; margin: 0; background: #f6f7f9;
  color: #14181f; line-height: 1.5; }}
.wrap {{ max-width: 1100px; margin: 0 auto; padding: 32px 26px 80px; }}
header.case {{ background: #0b1220; color: #e8f4ff; padding: 26px 30px; border-radius: 12px; }}
header.case h1 {{ margin: 0 0 6px; font-size: 24px; letter-spacing: .3px; }}
header.case .sub {{ color: #88b7d9; font-size: 14px; }}
header.case .chips {{ margin-top: 14px; display: flex; flex-wrap: wrap; gap: 8px; }}
.chip {{ background: #16243a; border: 1px solid #25405f; border-radius: 999px; padding: 4px 11px;
  font-size: 12px; color: #cfe6fb; }}
section {{ background: #fff; border: 1px solid #e3e7ee; border-radius: 10px; padding: 20px 22px;
  margin-top: 20px; }}
section h2 {{ font-size: 17px; margin: 0 0 14px; border-bottom: 1px solid #e8ecf3; padding-bottom: 9px; }}
section h2 .num {{ display: inline-block; min-width: 34px; color: #0e8bc4; font-weight: 700; }}
h4 {{ margin: 14px 0 6px; font-size: 13px; text-transform: uppercase; letter-spacing: .06em; color: #4a5a72; }}
table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
th, td {{ text-align: left; padding: 7px 9px; border-bottom: 1px solid #eef1f6; vertical-align: top; }}
th {{ background: #f3f6fa; color: #3b4a61; font-weight: 600; }}
td.hash, code {{ font-family: ui-monospace, "Cascadia Mono", Menlo, monospace; font-size: 11.5px;
  word-break: break-all; }}
.muted {{ color: #8b93a4; font-style: italic; }}
.finding {{ border: 1px solid #e6eaf1; border-left: 4px solid #4a6078; border-radius: 8px;
  padding: 14px 16px; margin-bottom: 16px; background: #fcfdff; }}
.finding.sev-critical {{ border-left-color: #b4231f; }}
.finding.sev-high {{ border-left-color: #d97706; }}
.finding.sev-medium {{ border-left-color: #0e8bc4; }}
.finding.sev-low {{ border-left-color: #64748b; }}
.badge {{ font-size: 11px; text-transform: uppercase; letter-spacing: .05em; padding: 2px 8px;
  border-radius: 4px; background: #eef1f6; color: #334; margin-right: 6px; }}
.badge.sev-critical {{ background: #fee2e2; color: #991b1b; }}
.badge.sev-high {{ background: #ffedd5; color: #9a3412; }}
.badge.sev-medium {{ background: #e0f2fe; color: #075985; }}
.finding h3 {{ margin: 0 0 6px; font-size: 15.5px; }}
.meta {{ color: #5a6478; font-size: 12.5px; margin: 4px 0 10px; }}
.cols {{ display: grid; grid-template-columns: 1fr 1fr; gap: 18px; }}
ul {{ margin: 4px 0 0; padding-left: 18px; font-size: 13.3px; }}
li {{ margin-bottom: 4px; }}
.evidence code {{ color: #0f6c93; }}
.src {{ color: #8b93a4; font-size: 12px; }}
.steps {{ padding-left: 0; list-style: none; }}
.step {{ padding: 7px 10px; border-left: 3px solid #cbd5e1; margin-bottom: 6px; background: #f8fafc; }}
.step.missing {{ border-left-color: #f0b429; background: #fffdf5; }}
.pos {{ display: inline-block; width: 20px; height: 20px; line-height: 20px; text-align: center;
  background: #0e8bc4; color: #fff; border-radius: 50%; font-size: 11px; margin-right: 6px; }}
.flagged td {{ background: #fff7ed; }}
footer {{ margin-top: 24px; color: #7a828f; font-size: 12px; }}
@media print {{ body {{ background: #fff; }} section, .finding {{ break-inside: avoid; }}
  header.case {{ background: #0b1220 !important; -webkit-print-color-adjust: exact; }} }}
</style></head><body><div class="wrap">
<header class="case">
  <h1>TRACE-X Investigation Report</h1>
  <div class="sub">{esc(case['case_id'])} · {esc(case['name'])} · generated {esc(data['generated_at'])}</div>
  <div class="sub">{esc(case['description'] or '')}</div>
  <div class="chips">
    <span class="chip">engine {esc(data['version']['engine'])}</span>
    <span class="chip">ruleset {esc(data['version']['ruleset'])}</span>
    <span class="chip">{esc(data['scope']['events'])} events</span>
    <span class="chip">{esc(len(data['findings']))} findings</span>
    <span class="chip">{esc(len(data['chains']))} suspicion chains</span>
    <span class="chip">origin: {esc(case['origin'])}</span>
    <span class="chip">status: {esc(case['status'])}</span>
  </div>
</header>

{section_header('1', 'Case information')}
<p>{esc(case['description']) or '<span class="muted">no description</span>'}</p>
<p><strong>Investigator notes:</strong> {esc(case['notes']) or '<span class="muted">none</span>'}</p>
<p class="meta">Investigation ID {esc(case['investigation_id'])} · created {esc(case['created_at'])}</p>
</section>

{section_header('2', 'Investigation scope')}
<p>{esc(data['scope']['statement'])}</p>
<p class="meta">{esc(data['scope']['events'])} timeline events ·
 {esc(data['scope']['evidence_sources'])} evidence sources ·
 {esc(data['scope']['analysis_runs'])} analysis runs</p>
</section>

{section_header('3', 'Evidence sources and integrity hashes')}
<table><thead><tr><th>File</th><th>Type</th><th>Source</th><th>Accepted/rejected</th>
<th>SHA-256</th><th>Parser · origin</th><th>Timezone note</th></tr></thead>
<tbody>{source_rows}</tbody></table>
<p class="meta">{esc(data['methodology']['integrity'])}</p>
</section>

{section_header('4', 'Methodology and parser versions')}
<p class="meta">Parsers: {esc(', '.join(data['methodology']['parsers']) or 'n/a')} ·
 engine {esc(data['methodology']['engine_version'])} ·
 ruleset {esc(data['methodology']['ruleset_version'])}</p>
<p class="meta">{esc(data['methodology']['timezone_policy'])}</p>
<table><thead><tr><th>Run</th><th>Started</th><th>Duration</th><th>Trigger</th><th>Config</th>
<th>Rules evaluated</th></tr></thead><tbody>{runs_rows}</tbody></table>
</section>

{section_header('5', 'Reconstructed timeline')}
<p class="meta">Rows marked with ⚑ belong to a detected suspicion chain or finding. Records with
 <em>time unknown</em> are excluded from any asserted ordering.</p>
<div style="max-height: 520px; overflow: auto;">
<table><thead><tr><th>Time (UTC)</th><th>Type</th><th>Description</th><th>Host</th><th>User</th>
<th>File</th><th>Source record</th><th>⚑</th></tr></thead><tbody>{timeline_rows}</tbody></table></div>
</section>

{section_header('6', 'Anti-forensic findings')}
{''.join(finding_rows) or '<p class="muted">The detection engine produced no findings for this investigation.</p>'}
</section>

{section_header('7', 'Suspicion chains (hypotheses)')}
{''.join(chain_rows) or '<p class="muted">No suspicion chains were detected. This is not evidence that none exist — only that the acquired records did not match the configured patterns.</p>'}
</section>

{section_header('8', 'Graph relationship summary')}
<table><thead><tr><th>Metric</th><th>Value</th></tr></thead><tbody>{graph_rows}</tbody></table>
<p class="meta">Observed edges (record-backed) and inferred edges (rule-licensed) are stored with
separate explanations and rendered with distinct styles in the application.</p>
</section>

{section_header('9', 'Confidence methodology')}
<table><thead><tr><th>Level</th><th>Assignment rule</th><th>Requirements</th></tr></thead>
<tbody>{confidence_rows}</tbody></table>
<ul>{method_remarks}</ul>
</section>

{section_header('10', 'Audit trail')}
<table><thead><tr><th>Time</th><th>Action</th><th>Actor</th><th>Entity</th><th>Detail</th></tr></thead>
<tbody>{audit_rows}</tbody></table>
</section>

{section_header('11', 'Limitations')}
<ul>{limitations}</ul>
</section>

{section_header('12', 'Final investigative observations')}
<p>Findings above are rule-triggered observations with documented evidence. Correlations and
hypotheses are presented as such: this report does <strong>not</strong> assert malicious intent,
does <strong>not</strong> convert correlation into causation, and does <strong>not</strong> treat
missing records as proven deletion. Re-running analysis with the recorded configuration and
ruleset version reproduces sections 6–8 from the stored evidence.</p>
<p class="meta">Report generated by TRACE-X v{esc(data['version']['engine'])} at
{esc(data['generated_at'])}. PDF: use your browser's print dialog on this document (TRACE-X does
not embed a PDF renderer in this deployment).</p>
</section>

</div></body></html>"""


def render_report(db: Session, investigation: Investigation) -> tuple[str, str]:
    data = build_report_data(db, investigation)
    return "text/html; charset=utf-8", render_html(data)


def export_findings_csv(db: Session, investigation_id: str) -> tuple[str, str]:
    import csv
    import io

    findings = db.query(Finding).filter(Finding.investigation_id == investigation_id).all()
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["finding_id", "rule_id", "rule_name", "rule_version", "title", "severity",
                     "support", "heuristic_score", "occurred_at", "event_count",
                     "observed_evidence", "correlation", "hypothesis", "missing_evidence",
                     "limitations", "benign_explanations", "next_checks"])
    for finding in findings:
        explanation = finding.explanation or {}
        evidence = explanation.get("evidence", [])
        times = [e.get("timestamp") for e in evidence if e.get("timestamp")]
        writer.writerow([
            finding.id, finding.rule_id, finding.rule_name, finding.rule_version, finding.title,
            finding.severity, finding.support, finding.heuristic_score,
            min(times) if times else "", len(finding.event_ids or []),
            " | ".join(explanation.get("observed_evidence", [])),
            " | ".join(explanation.get("correlation", [])),
            explanation.get("hypothesis", ""),
            " | ".join(explanation.get("missing_evidence", [])),
            " | ".join(explanation.get("limitations", [])),
            " | ".join(a.get("explanation", "") for a in
                        explanation.get("alternative_explanations", []) if isinstance(a, dict)),
            " | ".join(explanation.get("recommended_next_checks", [])),
        ])
    return "text/csv", buffer.getvalue()


def export_bodyfile_csv(db: Session, investigation_id: str) -> tuple[str, str]:
    """TSK 'bodyfile' (mactime) CSV — the interchange format that
    plaso/mactime and other timeline tools consume directly.

    Column set follows The Sleuth Kit's bodyfile(5):
      MD5|name|inode|mode|UID|GID|size|atime|mtime|ctime|crtime
    Fields the source did not record are exported as `-` (TSK's unknown
    marker), never as zero — a fabricated 0 timestamp would corrupt any
    downstream timeline analysis.
    """
    import csv
    import io

    events = (
        db.query(Event)
        .filter(Event.investigation_id == investigation_id)
        .order_by(Event.timestamp.is_(None), Event.timestamp, Event.seq)
        .all()
    )
    buffer = io.StringIO()
    # bodyfile(5) is pipe-delimited, not comma-delimited.
    writer = csv.writer(buffer, delimiter="|", lineterminator="\n")
    for e in events:
        # Map each normalized event onto the MACB times TSK expects. We only
        # populate the slot the record actually evidences; the others stay '-'.
        ts = int(e.timestamp.timestamp()) if e.timestamp else "-"
        atime = mtime = ctime = crtime = "-"
        if e.event_type in ("file_access", "file_read", "handle_requested"):
            atime = ts
        elif e.event_type in ("file_modified", "file_written"):
            mtime = ts
        elif e.event_type in ("file_created",):
            crtime = ctime = ts
        elif e.event_type in ("file_deleted", "object_deleted", "file_deleted_archived"):
            mtime = ts
        else:
            # Non-file events: record the observation time as mtime so the
            # event still appears in a mactime rendering of the timeline.
            mtime = ts
        name = e.file_path or e.description or e.event_type
        writer.writerow([
            "-",  # MD5: TRACE-X does not re-hash file content at ingest
            name.replace("|", "_"),
            e.id, "r/rrwxrwxrwx", "0", "0",
            (e.raw_record or {}).get("size", "-") if isinstance(e.raw_record, dict) else "-",
            atime, mtime, ctime, crtime,
        ])
    return "text/csv", buffer.getvalue()


def export_supertimeline_csv(db: Session, investigation_id: str) -> tuple[str, str]:
    """Plaso-style super-timeline CSV (the format log2timeline emits).

    Columns: date,timezone,hostname,short,source,type,user,message,reference
    so the file can be fed straight into psort.py or opened in a timeline
    explorer. Timestamps are ISO-8601 UTC; undated events carry an empty date
    and are listed after dated ones with a note in the message field.
    """
    import csv
    import io

    events = (
        db.query(Event)
        .filter(Event.investigation_id == investigation_id)
        .order_by(Event.timestamp.is_(None), Event.timestamp, Event.seq)
        .all()
    )
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(["date", "timezone", "hostname", "short", "source", "type",
                     "user", "message", "reference"])
    for e in events:
        date = dt_to_iso(e.timestamp) or ""
        writer.writerow([
            date.replace("+00:00", "") if date else "",
            "UTC",
            e.host or "-",
            (e.source_type or "unknown")[:12],
            e.source_file or e.raw_record_reference or "-",
            e.event_type,
            e.user or "-",
            (e.description or "").replace("\n", " "),
            f"event:{e.id}",
        ])
    return "text/csv", buffer.getvalue()


def render_report_pdf(db: Session, investigation: Investigation) -> tuple[str, bytes]:
    """Self-contained PDF rendering of the investigation report.

    Written as a minimal PDF 1.4 document with the built-in Helvetica font —
    no third-party PDF library is required. Content mirrors the HTML report:
    case header, evidence inventory, findings, chains and limitations.
    Long text is wrapped; characters outside PDF-WinAnsi are replaced.
    """
    data = build_report_data(db, investigation)

    def clean(text) -> str:
        s = str(text or "")
        s = (s.replace("\u2018", "'").replace("\u2019", "'")
               .replace("\u201c", '"').replace("\u201d", '"')
               .replace("\u2013", "-").replace("\u2014", "-")
               .replace("\u2192", "->").replace("\u2026", "..."))
        return s.encode("cp1252", errors="replace").decode("cp1252")

    lines: list[tuple[int, str]] = []  # (size, text) — size doubles as weight

    def add(size: int, text: str) -> None:
        text = clean(text)
        width = max(40, int(96 - size * 0.55))
        while len(text) > width:
            cut = text.rfind(" ", 0, width)
            if cut < width // 2:
                cut = width
            lines.append((size, text[:cut]))
            text = text[cut:].lstrip()
        lines.append((size, text))

    inv = data["case"]
    version = data.get("version", {})
    add(18, f"TRACE-X Investigation Report — {inv['case_id']}")
    add(12, inv["name"])
    add(9, f"Generated: {data.get('generated_at', '')}")
    add(9, f"Engine {version.get('engine', '')} | Rules {version.get('ruleset', '')}")
    add(9, f"Status: {inv['status']} | Origin: {inv['origin']}")
    add(11, "Evidence inventory")
    for s in data.get("sources", []):
        add(9, f"- {s['filename']} [{s['file_type']}] sha256={s['sha256'][:16]}... "
               f"accepted={s['accepted']} rejected={s['rejected']}")
    add(11, "Findings")
    if not data.get("findings"):
        add(9, "No findings were produced by the detection engine.")
    for f in data.get("findings", []):
        add(10, f"[{f['severity'].upper()}] {f['title']} (rule {f['rule_id']}, "
                f"support: {f['support']})")
        for line in (f.get("explanation") or {}).get("observed_evidence", [])[:4]:
            add(8, f"  evidence: {line}")
        hypothesis = (f.get("explanation") or {}).get("hypothesis")
        if hypothesis:
            add(8, f"  hypothesis: {hypothesis}")
        for lim in (f.get("explanation") or {}).get("limitations", [])[:3]:
            add(8, f"  limitation: {lim}")
    add(11, "Suspicion chains")
    if not data.get("chains"):
        add(9, "No multi-step suspicion chains were identified.")
    for c in data.get("chains", []):
        add(10, f"[{c['severity'].upper()}] {c['title']} "
                f"(pattern {c['pattern_id']}, completeness: {c['completeness']})")
    add(11, "Limitations and alternative explanations")
    for note in data.get("limitations", [])[:8]:
        add(8, f"- {note}")
    add(8, "Correlation is never presented as causation; missing records are "
           "reported as missing coverage, not as proven deletion.")

    # --- build the PDF objects -------------------------------------------
    esc = lambda s: s.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
    pages: list[str] = []
    y = 770
    stream_parts: list[str] = []
    for size, text in lines:
        if y < 60:
            stream_parts.append("BT /F1 9 Tf ET")  # sentinel ends the page stream
            pages.append("\n".join(stream_parts))
            stream_parts, y = [], 770
        stream_parts.append(f"BT /F1 {size} Tf 50 {y} Td ({esc(text)}) Tj ET")
        y -= size + 5
    if stream_parts:
        pages.append("\n".join(stream_parts))

    objects = ["<< /Type /Catalog /Pages 2 0 R >>"]
    kids = " ".join(f"{3 + i * 2} 0 R" for i in range(len(pages)))
    objects.append(f"<< /Type /Pages /Kids [{kids}] /Count {len(pages)} >>")
    for i, stream in enumerate(pages):
        page_obj = (f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
                    f"/Resources << /Font << /F1 {3 + len(pages) * 2} 0 R >> >> "
                    f"/Contents {4 + i * 2} 0 R >>")
        content = f"<< /Length {len(stream.encode('cp1252'))} >>\nstream\n{stream}\nendstream"
        objects.append(page_obj)
        objects.append(content)
    objects.append("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>")

    out = bytearray(b"%PDF-1.4\n")
    offsets = [0]
    for i, obj in enumerate(objects, start=1):
        offsets.append(len(out))
        out += f"{i} 0 obj\n{obj}\nendobj\n".encode("cp1252")
    xref_at = len(out)
    out += f"xref\n0 {len(objects) + 1}\n".encode()
    out += b"0000000000 65535 f \n"
    for off in offsets[1:]:
        out += f"{off:010d} 00000 n \n".encode()
    out += (f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\n"
            f"startxref\n{xref_at}\n%%EOF\n").encode()
    return "application/pdf", bytes(out)


def report_manifest(db: Session, investigation: Investigation) -> dict:
    """Small reproducibility manifest: what was used to build the report."""
    runs = (
        db.query(AnalysisRun)
        .filter(AnalysisRun.investigation_id == investigation.id)
        .order_by(AnalysisRun.started_at)
        .all()
    )
    sources = db.query(EvidenceSource).filter(
        EvidenceSource.investigation_id == investigation.id).all()
    return {
        "investigation_id": investigation.id,
        "case_id": investigation.case_id,
        "engine_version": ENGINE_VERSION,
        "ruleset_version": RULES_VERSION,
        "evidence_sha256": {s.filename: s.sha256 for s in sources},
        "analysis_runs": [r.id for r in runs],
        "config": (runs[-1].config_snapshot if runs else (investigation.analysis_config or {})),
        "reproduce": (
            "Re-run `POST /api/investigations/{id}/analysis/run` with the recorded config and "
            "the same evidence hashes to reproduce findings, chains and graph edges."
        ),
    }