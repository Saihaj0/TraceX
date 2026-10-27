"""Anti-forensics detection engine.

A modular, rule-based, explainable engine:

  * every rule declares its metadata (id, required evidence, conditions,
    exclusions, severity, explanation template, limitations, version),
  * a rule only runs when the evidence types it requires exist in the
    investigation (availability is recorded, never assumed),
  * a missing record is *never* treated as proof of deletion or tampering -
    observed / inferred / absence-of-evidence are kept distinct,
  * every finding carries its evidence, correlations, hypothesis, missing
    evidence, contradictions, limitations and alternative explanations.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from ..config import DEFAULT_ANALYSIS_CONFIG, ENGINE_VERSION, RULES_VERSION
from ..models import (
    AnalysisRun,
    AuditLog,
    EvidenceSource,
    Event,
    Finding,
    GraphEdge,
    GraphNode,
    Investigation,
    SuspicionChain,
    new_id,
)
from .uncertainty import SupportAssessment, alternative_explanations, assess_support


@dataclass
class DetectionContext:
    investigation_id: str
    events: list[Event]                    # all events (timed sorted first)
    timed: list[Event]                     # events with a timestamp, chronologically sorted
    undated: list[Event]
    config: dict
    sources: list[EvidenceSource]
    source_types: set[str]
    evidence_type_counts: dict[str, int]
    generated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def by_type(self) -> dict[str, list[Event]]:
        if not hasattr(self, "_by_type"):
            self._by_type = {}
            for event in self.timed:
                self._by_type.setdefault(event.event_type, []).append(event)
        return self._by_type

    def has_evidence(self, evidence_type: str) -> bool:
        return self.evidence_type_counts.get(evidence_type, 0) > 0

    def hours_between(self, a: Event, b: Event) -> float | None:
        if a.timestamp is None or b.timestamp is None:
            return None
        return (b.timestamp - a.timestamp).total_seconds() / 3600.0

    def window(self, start: datetime, hours: float) -> list[Event]:
        from datetime import timedelta

        end = start + timedelta(hours=hours)
        return [e for e in self.timed if e.timestamp and start <= e.timestamp <= end]

    def until(self, start: datetime, hours: float) -> list[Event]:
        from datetime import timedelta

        end = start + timedelta(hours=hours)
        return [
            e for e in self.timed
            if e.timestamp and start < e.timestamp <= end
        ]


@dataclass
class RuleResult:
    rule_id: str
    status: str                     # ran | skipped
    skip_reason: str | None = None
    findings: list[dict] = field(default_factory=list)


class Rule:
    """Base detection rule with fully documented metadata."""

    id = "AF-000"
    name = "Base rule"
    description = ""
    category = "general"
    required_evidence: tuple[str, ...] = ()
    required_evidence_note = ""
    detection_conditions: tuple[str, ...] = ()
    exclusions: tuple[str, ...] = ()
    severity = "info"
    explanation_template = ""
    limitations: tuple[str, ...] = ()
    version = "0"
    anchor_event_types: tuple[str, ...] = ()
    #: "any" (defaults): the listed evidence types are alternatives and at
    #: least one must exist.  "all": every listed type must exist.
    required_evidence_mode = "any"

    def available(self, ctx: DetectionContext) -> tuple[bool, str]:
        missing = [e for e in self.required_evidence if not ctx.has_evidence(e)]
        satisfied = (bool(missing) is False) if self.required_evidence_mode == "all" else (
            len(missing) < len(self.required_evidence)
        )
        if not satisfied:
            note = self.required_evidence_note or "required inputs are absent"
            needed = ("all of" if self.required_evidence_mode == "all" else "at least one of")
            return False, (
                f"skipped: {note} — needs {needed} "
                f"({', '.join(self.required_evidence)}); missing: {', '.join(missing)}"
            )
        if self.anchor_event_types:
            present = any(t in ctx.by_type for t in self.anchor_event_types)
            if not present:
                return False, (
                    f"skipped: no records of type {', '.join(self.anchor_event_types)} "
                    "in this investigation"
                )
        return True, ""

    def evaluate(self, ctx: DetectionContext) -> list[dict]:  # pragma: no cover
        raise NotImplementedError

    def base_finding(self, ctx: DetectionContext, *, title: str, events: list[Event],
                     observed: list[str], correlation: list[str], hypothesis: str,
                     does_not_establish: list[str], limitations_extra: list[str] | None = None,
                     missing: list[str] | None = None, contradicting: list[dict] | None = None,
                     alternatives_context: str = "", alternatives_extra: list[str] | None = None,
                     next_steps: list[str] | None = None, support: SupportAssessment | None = None,
                     relationship_corroborated: bool = False, assumption_dependent: bool = False,
                     severity: str | None = None, dedupe_context: str = "",
                     related_findings: list[str] | None = None) -> dict:
        sources = {e.evidence_source_id for e in events if e.evidence_source_id}
        contradicting = contradicting or []
        support = support or assess_support(
            observed=len(events),
            sources=len(sources) or 1,
            relationship_corroborated=relationship_corroborated,
            missing_required=bool(missing),
            assumption_dependent=assumption_dependent,
            contradictions=len(contradicting),
        )
        from .evidence import describe_evidence_ref

        evidence_rows = [describe_evidence_ref(e) for e in events]
        return {
            "rule_id": self.id,
            "rule_name": self.name,
            "rule_version": self.version,
            "title": title,
            "severity": severity or self.severity,
            "support": support.to_dict(),
            "event_ids": [e.id for e in events],
            "explanation": {
                "why_triggered": self.explanation_template.format(
                    conditions="; ".join(self.detection_conditions)
                ),
                "observed_evidence": observed,
                "correlation": correlation,
                "hypothesis": hypothesis,
                "does_not_establish": does_not_establish,
                "missing_evidence": missing or [],
                "contradicting_evidence": contradicting,
                "temporal_relationships": _temporal_relationships(events),
                "limitations": list(self.limitations) + list(limitations_extra or []),
                "alternative_explanations": alternative_explanations(
                    alternatives_context or self.description, alternatives_extra
                ),
                "recommended_next_checks": next_steps or [],
                "rule_metadata": {
                    "required_evidence": list(self.required_evidence),
                    "detection_conditions": list(self.detection_conditions),
                    "exclusions": list(self.exclusions),
                    "severity_rationale": SEVERITY_RATIONALE.get(severity or self.severity, ""),
                    "version": self.version,
                    "ruleset_version": RULES_VERSION,
                },
                "evidence": evidence_rows,
                "related_findings": related_findings or [],
            },
            "dedupe_key": f"{self.id}:{dedupe_context or title}",
        }


SEVERITY_RATIONALE = {
    "critical": "Direct indicator of evidence-tampering tooling in immediate relation to other findings",
    "high": "Direct indicator of evidence loss or audit-trail removal",
    "medium": "Anomaly requiring corroboration; not evidence of tampering on its own",
    "low": "Worth tracking but has plausible routine explanations",
    "info": "Observational note with no adverse implication",
}


def _temporal_relationships(events: list[Event]) -> list[dict]:
    timed = [e for e in events if e.timestamp]
    out = []
    for a, b in zip(timed, timed[1:]):
        delta = (b.timestamp - a.timestamp).total_seconds()
        out.append({
            "from_event": a.id,
            "to_event": b.id,
            "delta_seconds": delta,
            "delta_human": humanize_seconds(delta),
            "order_quality": "precise" if a.timestamp_precision == "second"
            and b.timestamp_precision == "second" else "coarse",
        })
    return out


def humanize_seconds(seconds: float) -> str:
    seconds = abs(seconds)
    if seconds < 60:
        return f"{seconds:.0f}s"
    if seconds < 3600:
        return f"{seconds / 60:.1f} minutes"
    if seconds < 86400:
        return f"{seconds / 3600:.1f} hours"
    return f"{seconds / 86400:.1f} days"


def load_context(db: Session, investigation: Investigation) -> DetectionContext:
    config = {**DEFAULT_ANALYSIS_CONFIG, **(investigation.analysis_config or {})}
    events = (
        db.query(Event)
        .filter(Event.investigation_id == investigation.id)
        .order_by(Event.seq.asc())
        .all()
    )
    timed = sorted(
        [e for e in events if e.timestamp is not None],
        key=lambda e: (e.timestamp, e.seq),
    )
    undated = [e for e in events if e.timestamp is None]
    sources = (
        db.query(EvidenceSource)
        .filter(EvidenceSource.investigation_id == investigation.id)
        .all()
    )

    counts: dict[str, int] = {}
    for source in sources:
        counts[source.source_type] = counts.get(source.source_type, 0) + 1
        counts[f"file:{source.file_type}"] = counts.get(f"file:{source.file_type}", 0) + 1
        # Events carry their own source_type; count them too so structured
        # imports with windows/filesystem semantics still enable rules.
    for event in events:
        counts[event.source_type] = counts.get(event.source_type, 0) + 1
        counts[event.event_type] = counts.get(event.event_type, 0) + 1

    return DetectionContext(
        investigation_id=investigation.id,
        events=events,
        timed=timed,
        undated=undated,
        config=config,
        sources=sources,
        source_types={s.source_type for s in sources} | {e.source_type for e in events},
        evidence_type_counts=counts,
    )


def run_analysis(
    db: Session,
    investigation: Investigation,
    actor: str = "investigator",
    trigger: str = "manual",
    previous_runs: int | None = None,
    include_correlation: bool = True,
) -> dict:
    """Run detection rules, chain detection and graph rebuild. Traceable + audited.

    `include_correlation=False` evaluates only the rule layer (used by the A/B/C
    evaluation to compare configurations while keeping rules identical).
    """
    from .chains import detect_chains
    from .graph import rebuild_graph
    from .rules import ALL_RULES

    ctx = load_context(db, investigation)
    started = time.perf_counter()
    run = AnalysisRun(
        id=new_id(),
        investigation_id=investigation.id,
        engine_version=ENGINE_VERSION,
        rules_version=RULES_VERSION,
        trigger=trigger,
        config_snapshot=dict(ctx.config),
        status="running",
        rules_run=[],
    )
    db.add(run)
    db.flush()

    # Findings are regenerated per analysis run; earlier runs remain recorded in
    # analysis_runs so re-analysis stays traceable.
    db.query(Finding).filter(Finding.investigation_id == investigation.id).delete()
    db.query(Finding).filter(Finding.chain_id.isnot(None)).delete()

    results: list[RuleResult] = []
    created_findings: list[Finding] = []
    for rule in ALL_RULES:
        ok, reason = rule.available(ctx)
        if not ok:
            results.append(RuleResult(rule.id, "skipped", reason))
            continue
        try:
            outputs = rule.evaluate(ctx) or []
        except Exception as exc:  # a rule failure must not sink the run
            results.append(RuleResult(rule.id, "skipped", f"rule error: {exc}"))
            continue
        findings = []
        seen_keys = set()
        for output in outputs:
            finding = Finding(
                id=new_id(),
                investigation_id=investigation.id,
                analysis_run_id=run.id,
                rule_id=output["rule_id"],
                rule_name=output["rule_name"],
                rule_version=output["rule_version"],
                title=output["title"],
                severity=output["severity"],
                support=output["support"]["level"],
                heuristic_score=output["support"].get("heuristic_score"),
                score_components=output["support"].get("components", []),
                event_ids=output["event_ids"],
                explanation=output["explanation"],
                dedupe_key=output.get("dedupe_key"),
            )
            if finding.dedupe_key in seen_keys:
                continue
            seen_keys.add(finding.dedupe_key)
            db.add(finding)
            findings.append(finding)
            created_findings.append(finding)
        results.append(RuleResult(rule.id, "ran", None, findings))

    db.flush()

    if include_correlation:
        chains = detect_chains(db, investigation, ctx, created_findings, run.id)
        graph_summary = rebuild_graph(db, investigation, ctx, created_findings, chains, run.id)
    else:
        db.query(SuspicionChain).filter(
            SuspicionChain.investigation_id == investigation.id).delete()
        db.query(GraphNode).filter(GraphNode.investigation_id == investigation.id).delete()
        db.query(GraphEdge).filter(GraphEdge.investigation_id == investigation.id).delete()
        chains = []
        graph_summary = {"skipped": True,
                         "reason": "correlation layer disabled for this configuration"}

    duration_ms = int((time.perf_counter() - started) * 1000)
    rules_run = [
        {
            "rule_id": r.rule_id,
            "status": r.status,
            "reason": r.skip_reason,
            "findings": len(r.findings),
        }
        for r in results
    ]
    severity_counts: dict[str, int] = {}
    support_counts: dict[str, int] = {}
    for finding in created_findings:
        severity_counts[finding.severity] = severity_counts.get(finding.severity, 0) + 1
        support_counts[finding.support] = support_counts.get(finding.support, 0) + 1

    summary = {
        "findings": len(created_findings),
        "severity_counts": severity_counts,
        "support_counts": support_counts,
        "skipped_rules": [
            {"rule_id": r.rule_id, "reason": r.skip_reason} for r in results
            if r.status == "skipped"
        ],
        "rules_run": len([r for r in results if r.status == "ran"]),
        "chains": len(chains),
        "graph": graph_summary,
        "events_analysed": len(ctx.events),
        "undated_events_excluded_from_ordering": len(ctx.undated),
    }
    run.finished_at = datetime.now(timezone.utc)
    run.duration_ms = duration_ms
    run.summary = summary
    run.rules_run = rules_run
    run.status = "completed"

    db.add(AuditLog(
        investigation_id=investigation.id,
        action="analysis.run",
        entity_type="analysis_run",
        entity_id=run.id,
        actor=actor,
        detail={
            "trigger": trigger,
            "engine_version": ENGINE_VERSION,
            "rules_version": RULES_VERSION,
            "config": ctx.config,
            "findings": len(created_findings),
            "chains": len(chains),
            "duration_ms": duration_ms,
            "rules": rules_run,
        },
    ))
    db.commit()

    return {
        "run_id": run.id,
        "duration_ms": duration_ms,
        "engine_version": ENGINE_VERSION,
        "rules_version": RULES_VERSION,
        "summary": summary,
        "rules": rules_run,
        "findings": len(created_findings),
        "chains": len(chains),
    }