"""Analysis, findings, suspicion chains and forensic-graph endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from ..auth import current_actor
from ..db import get_db
from ..models import AnalysisRun, Event, Finding, Investigation, SuspicionChain
from ..schemas import ChainUpdate, PathRequest
from ..services import graph as graph_service
from ..services.chains import chain_to_dict
from ..services.detection import run_analysis
from ..services.ingest import audit
from ..services.timeline import annotate_ordering, event_to_dict
from .investigations import get_investigation

router = APIRouter(prefix="/investigations", tags=["analysis"])


def _get_finding(db: Session, investigation_id: str, finding_id: str) -> Finding:
    finding = db.query(Finding).filter(
        Finding.id == finding_id, Finding.investigation_id == investigation_id).first()
    if finding is None:
        raise HTTPException(status_code=404, detail={
            "code": "finding_not_found", "message": f"finding {finding_id} not found"})
    return finding


def finding_payload(db: Session, finding: Finding) -> dict:
    explanation = finding.explanation or {}
    related_events = (
        db.query(Event)
        .filter(
            Event.id.in_(finding.event_ids or ["__none__"]),
            Event.investigation_id == finding.investigation_id,
        ).all()
    )
    event_times = [
        e.get("timestamp") for e in explanation.get("evidence", []) if e.get("timestamp")
    ]
    return {
        "id": finding.id,
        "investigation_id": finding.investigation_id,
        "analysis_run_id": finding.analysis_run_id,
        "rule_id": finding.rule_id,
        "rule_name": finding.rule_name,
        "rule_version": finding.rule_version,
        "title": finding.title,
        "severity": finding.severity,
        "support": finding.support,
        "heuristic_score": finding.heuristic_score,
        "score_components": finding.score_components,
        "chain_id": finding.chain_id,
        "created_at": finding.created_at.isoformat() if finding.created_at else None,
        "occurred_at": min(event_times) if event_times else None,
        "event_ids": finding.event_ids,
        "events": [event_to_dict(e) for e in
                   sorted(related_events, key=lambda e: (e.timestamp is None, e.timestamp or e.seq))],
        "explanation": explanation,
        "severity_note": (
            "Severity expresses investigative priority only; it is not a probability and does "
            "not indicate how likely the hypothesis is to be true."
        ),
    }


# --- analysis -------------------------------------------------------------

@router.post("/{investigation_id}/analysis/run")
def trigger_analysis(investigation_id: str, db: Session = Depends(get_db),
                    trigger: str = Query("manual"),
                    actor: str = Depends(current_actor)):
    from .investigations import require_owner

    investigation = get_investigation(db, investigation_id)
    require_owner(investigation, actor)
    if db.query(Finding).filter(Finding.investigation_id == investigation.id).count() == 0 \
            and not investigation.evidence_sources:
        raise HTTPException(status_code=400, detail={
            "code": "no_evidence",
            "message": "import evidence before running the detection engine"})
    result = run_analysis(db, investigation, actor=actor, trigger=trigger or "manual")
    db.expire_all()
    return {"analysis": result,
            "message": (
                f"Analysis complete: {result['findings']} finding(s), "
                f"{result['chains']} suspicion chain(s), "
                f"{sum(r['findings'] for r in result['rules'])} rule hit(s) in "
                f"{result['duration_ms']} ms.")}


@router.get("/{investigation_id}/analysis/runs")
def list_runs(investigation_id: str, db: Session = Depends(get_db)):
    get_investigation(db, investigation_id)
    rows = (
        db.query(AnalysisRun)
        .filter(AnalysisRun.investigation_id == investigation_id)
        .order_by(AnalysisRun.started_at.desc())
        .all()
    )
    return {
        "runs": [
            {
                "id": r.id, "started_at": r.started_at.isoformat() if r.started_at else None,
                "finished_at": r.finished_at.isoformat() if r.finished_at else None,
                "duration_ms": r.duration_ms, "engine_version": r.engine_version,
                "rules_version": r.rules_version, "trigger": r.trigger, "status": r.status,
                "config_snapshot": r.config_snapshot, "summary": r.summary,
                "rules_run": r.rules_run,
            }
            for r in rows
        ],
        "count": len(rows),
        "traceability": (
            "Each run records engine version, ruleset version, the full configuration snapshot "
            "and per-rule outcomes, so a re-analysis can be reproduced and attributed."
        ),
    }


# --- findings --------------------------------------------------------------

@router.get("/{investigation_id}/findings")
def list_findings(investigation_id: str, db: Session = Depends(get_db),
                 severity: str | None = Query(None),
                 rule_id: str | None = Query(None),
                 support: str | None = Query(None),
                 q: str | None = Query(None),
                 limit: int = Query(200, ge=1, le=1000), offset: int = 0):
    get_investigation(db, investigation_id)
    query = db.query(Finding).filter(Finding.investigation_id == investigation_id)
    if severity:
        query = query.filter(Finding.severity == severity)
    if rule_id:
        query = query.filter(Finding.rule_id == rule_id)
    if support:
        query = query.filter(Finding.support == support)
    if q:
        query = query.filter(Finding.title.ilike(f"%{q}%"))
    total = query.count()
    rows = query.order_by(
        Finding.severity.desc(), Finding.rule_id).offset(offset).limit(limit).all()

    by_severity, by_support, by_rule = {}, {}, {}
    for f in db.query(Finding).filter(Finding.investigation_id == investigation_id).all():
        by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
        by_support[f.support] = by_support.get(f.support, 0) + 1
        by_rule[f.rule_id] = by_rule.get(f.rule_id, 0) + 1
    return {
        "findings": [finding_payload(db, f) for f in rows],
        "total": total, "offset": offset, "limit": limit,
        "summary": {"by_severity": by_severity, "by_support": by_support, "by_rule": by_rule},
    }


@router.get("/{investigation_id}/findings/{finding_id}")
def get_finding(investigation_id: str, finding_id: str, db: Session = Depends(get_db)):
    get_investigation(db, investigation_id)
    return finding_payload(db, _get_finding(db, investigation_id, finding_id))


# --- suspicion chains -------------------------------------------------------

@router.get("/{investigation_id}/chains")
def list_chains(investigation_id: str, db: Session = Depends(get_db),
               completeness: str | None = Query(None),
               severity: str | None = Query(None),
               status: str | None = Query(None)):
    get_investigation(db, investigation_id)
    query = db.query(SuspicionChain).filter(SuspicionChain.investigation_id == investigation_id)
    if completeness:
        query = query.filter(SuspicionChain.completeness == completeness)
    if severity:
        query = query.filter(SuspicionChain.severity == severity)
    if status:
        query = query.filter(SuspicionChain.status == status)
    rows = query.order_by(SuspicionChain.severity, SuspicionChain.pattern_id).all()

    events = {e.id: e for e in _chain_events(db, investigation_id)}
    payloads = []
    for row in rows:
        payload = chain_to_dict(row)
        payload["events"] = [
            event_to_dict(events[eid]) for eid in row.event_ids if eid in events
        ]
        payloads.append(payload)
    return {
        "chains": payloads,
        "count": len(payloads),
        "complete": sum(1 for p in payloads if p["completeness"] == "complete"),
        "partial": sum(1 for p in payloads if p["completeness"] == "partial"),
        "note": (
            "Patterns are candidate sequences, not verdicts. Incomplete patterns are listed with "
            "the evidence that is missing rather than hidden."
        ),
    }


def _chain_events(db: Session, investigation_id: str):
    from ..models import Event

    chains = db.query(SuspicionChain).filter(
        SuspicionChain.investigation_id == investigation_id).all()
    ids = {eid for c in chains for eid in (c.event_ids or [])}
    if not ids:
        return []
    return db.query(Event).filter(Event.id.in_(ids)).all()


@router.get("/{investigation_id}/chains/{chain_id}")
def get_chain(investigation_id: str, chain_id: str, db: Session = Depends(get_db)):
    get_investigation(db, investigation_id)
    row = db.query(SuspicionChain).filter(
        SuspicionChain.id == chain_id,
        SuspicionChain.investigation_id == investigation_id).first()
    if row is None:
        raise HTTPException(status_code=404, detail={
            "code": "chain_not_found", "message": f"chain {chain_id} not found"})
    events = {e.id: e for e in _chain_events(db, investigation_id)}
    payload = chain_to_dict(row)
    payload["events"] = [event_to_dict(events[eid]) for eid in row.event_ids if eid in events]
    payload["support_definition"] = "see uncertainty module: qualitative levels, not a probability"
    return payload


@router.patch("/{investigation_id}/chains/{chain_id}")
def update_chain(investigation_id: str, chain_id: str, body: ChainUpdate,
                db: Session = Depends(get_db),
                actor: str = Depends(current_actor)):
    from .investigations import get_investigation as _g  # noqa: F401
    from .investigations import require_owner

    investigation = get_investigation(db, investigation_id)
    require_owner(investigation, actor)
    row = db.query(SuspicionChain).filter(
        SuspicionChain.id == chain_id,
        SuspicionChain.investigation_id == investigation_id).first()
    if row is None:
        raise HTTPException(status_code=404, detail={
            "code": "chain_not_found", "message": f"chain {chain_id} not found"})
    previous = row.status
    row.status = body.status
    audit(db, "chain.status_changed", investigation_id, actor=actor,
          detail={"chain_id": chain_id, "from": previous, "to": body.status,
                  "note": body.note})
    db.commit()
    db.refresh(row)
    return chain_to_dict(row)


# --- forensic graph ---------------------------------------------------------

@router.get("/{investigation_id}/graph")
def get_graph(investigation_id: str, db: Session = Depends(get_db),
              node_types: str | None = Query(None, description="comma separated node types"),
              relations: str | None = Query(None, description="comma separated relations"),
              q: str | None = Query(None, description="search labels / properties")):
    get_investigation(db, investigation_id)
    flagged = graph_service.flagged_event_ids_for(db, investigation_id)
    payload = graph_service.graph_payload(
        db, investigation_id,
        node_types=[t.strip() for t in node_types.split(",") if t.strip()] if node_types else None,
        relation_types=[r.strip() for r in relations.split(",") if r.strip()] if relations else None,
        search=q, flagged_event_ids=flagged,
    )
    payload["empty_reason"] = None if payload["nodes"] else (
        "No graph has been built for this investigation yet — run the detection engine first.")
    return payload


@router.get("/{investigation_id}/graph/actions")
def get_graph_actions(investigation_id: str, db: Session = Depends(get_db)):
    get_investigation(db, investigation_id)
    return graph_service.graph_actions(db, investigation_id)


@router.post("/{investigation_id}/graph/path")
def get_graph_path(investigation_id: str, body: PathRequest, db: Session = Depends(get_db)):
    get_investigation(db, investigation_id)
    return graph_service.highlight_path(db, investigation_id, body.source_id, body.target_id)


@router.get("/{investigation_id}/graph/isolate")
def isolate_chain(investigation_id: str, chain_id: str = Query(...),
                  db: Session = Depends(get_db)):
    get_investigation(db, investigation_id)
    result = graph_service.isolate_chain(db, investigation_id, chain_id)
    if not result.get("found"):
        raise HTTPException(status_code=404, detail={
            "code": "chain_not_found", "message": result.get("reason", "chain not found")})
    return result