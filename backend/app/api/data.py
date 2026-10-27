"""Timeline, reporting, dashboard, meta, demo and evaluation endpoints."""

from __future__ import annotations

import json

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import HTMLResponse, Response
from sqlalchemy import func, or_, text
from sqlalchemy.orm import Session

from ..config import (
    DEFAULT_ANALYSIS_CONFIG,
    ENGINE_VERSION,
    PARSERS_VERSION,
    RULES_VERSION,
)
from ..db import get_db
from ..models import (
    AnalysisRun,
    AuditLog,
    EvidenceSource,
    Event,
    Finding,
    Investigation,
    SuspicionChain,
)
from ..parsers.base import parser_catalog
from ..schemas import DemoRequest, EvaluationRequest
from ..services.detection import run_analysis
from ..services.evidence import describe_evidence_ref
from ..services.graph import flagged_event_ids_for
from ..services.reporting import (
    build_report_data,
    export_bodyfile_csv,
    export_findings_csv,
    export_supertimeline_csv,
    render_report,
    render_report_pdf,
    report_manifest,
)
from ..services.rules import rule_catalog
from ..services.timeline import (
    TimelineFilter,
    annotate_ordering,
    event_to_dict,
    export_events,
    facets,
    parse_dt,
    timeline_payload,
    timeline_stats,
)
from ..services.uncertainty import BENIGN_EXPLANATIONS_CATALOG, SUPPORT_DEFINITIONS, SUPPORT_LEVELS
from .investigations import get_investigation, investigation_payload

router = APIRouter(tags=["data"])

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


def _download_filename(case_id: str, suffix: str) -> str:
    """Build a safe Content-Disposition filename suffix for a case id.

    ``case_id`` is user-supplied and (for rows created before validation
    tightened) may still contain quotes, CR/LF or path separators. Raw CR/LF
    in a header value enables response splitting and a bare ``"`` breaks
    filename parsing, so every character outside the safe set is replaced.
    """
    safe = "".join(
        "_" if (ord(ch) < 32 or ord(ch) == 127 or ch in '"\\/') else ch
        for ch in case_id
    ).strip()
    return f"{safe or 'case'}{suffix}"


# ---------------------------------------------------------------------------
# Meta / capabilities
# ---------------------------------------------------------------------------

@router.get("/health")
def health(db: Session = Depends(get_db)):
    try:
        db.execute(func.now() if db.bind.dialect.name != "sqlite" else func.now())
        database = "up"
    except Exception as exc:  # pragma: no cover
        database = f"error: {exc}"

    # Live database identity, read from the very connection the backend uses.
    # This is what makes a database switch independently verifiable.
    identity: dict = {}
    if db.bind.dialect.name == "postgresql":
        try:
            row = db.execute(
                text("SELECT current_database(), inet_server_port(), version()")
            ).one()
            identity = {
                "database_name": row[0],
                "server_port": row[1],
                "server_version": row[2],
            }
        except Exception as exc:  # pragma: no cover
            identity = {"error": str(exc)[:200]}
    else:
        identity = {"database_name": db.bind.url.database or "(sqlite)",
                    "server_port": None, "server_version": None}

    return {"status": "ok", "database": database, "engine_version": ENGINE_VERSION,
            "ruleset_version": RULES_VERSION, "parser_version": PARSERS_VERSION,
            "backend": "fastapi", "dialect": db.bind.dialect.name,
            "db_identity": identity}


@router.get("/version")
def version():
    return {
        "engine": ENGINE_VERSION, "ruleset": RULES_VERSION, "parsers": PARSERS_VERSION,
        "components": {"backend": "FastAPI", "orm": "SQLAlchemy", "graph": "NetworkX",
                       "visualization": "Cytoscape.js", "frontend": "React + TypeScript"},
    }


@router.get("/rules")
def get_rules():
    from ..config import DEFAULT_ANALYSIS_CONFIG as defaults

    return {
        "rules": rule_catalog(),
        "ruleset_version": RULES_VERSION,
        "engine_version": ENGINE_VERSION,
        "defaults": {
            "chain_window_hours": defaults["chain_window_hours"],
            "activity_window_hours": defaults["activity_window_hours"],
            "mass_deletion_threshold": defaults["mass_deletion_threshold"],
            "mass_deletion_window_hours": defaults["mass_deletion_window_hours"],
            "logging_gap_hours": defaults["logging_gap_hours"],
            "clock_drift_seconds": defaults["clock_drift_seconds"],
        },
        "severity_rationale": {
            "critical": "Anti-forensic tooling observed in relation to other findings",
            "high": "Direct indicator of evidence loss or audit-trail removal",
            "medium": "Anomaly requiring corroboration",
            "low": "Worth tracking; plausible routine explanations",
            "info": "Observational note",
        },
    }


@router.get("/parsers")
def get_parsers():
    return {"parsers": parser_catalog(),
            "note": "Parsers register under a file type; the EVTX parser is an adapter over "
                    "python-evtx and can be swapped without touching the rest of TRACE-X."}


@router.get("/uncertainty")
def get_uncertainty():
    return {
        "support_levels": [{"level": lv, **SUPPORT_DEFINITIONS[lv]} for lv in SUPPORT_LEVELS],
        "benign_explanations_catalog": BENIGN_EXPLANATIONS_CATALOG,
        "principles": [
            "Support levels are qualitative — TRACE-X does not display arbitrary percentages "
            "as if they were calibrated probabilities.",
            "Source reliability, timestamp confidence, relationship strength, hypothesis support "
            "and severity are recorded separately and never merged.",
            "Heuristic scores are labelled heuristic and ship with their inspectable components.",
            "Severity is investigative priority, not probability.",
            "Missing records are reported as missing coverage, never as proven deletion.",
            "Correlation is never presented as causation; hypotheses carry limitations and "
            "alternative explanations.",
        ],
        "counters": {
            "score_components": [
                {"name": "observed_records", "weight": 1.0, "cap": 3},
                {"name": "independent_sources", "weight": 1.5, "cap": 3},
                {"name": "relationship_corroboration", "weight": 1.5},
                {"name": "missing_required_input", "weight": -3.0},
                {"name": "single_source_only", "weight": -1.0},
                {"name": "assumption_dependent", "weight": -0.5},
                {"name": "contradiction_present", "weight": -2.0},
            ],
            "note": "Labeled heuristic; not validated against ground truth as a probability.",
        },
    }


# ---------------------------------------------------------------------------
# Dashboard (every value derived from persisted rows)
# ---------------------------------------------------------------------------

def _metrics(db: Session, investigation_id: str | None) -> dict:
    event_q = db.query(func.count(Event.id))
    source_q = db.query(func.count(EvidenceSource.id))
    finding_q = db.query(func.count(Finding.id))
    chain_q = db.query(func.count(SuspicionChain.id))
    if investigation_id:
        event_q = event_q.filter(Event.investigation_id == investigation_id)
        source_q = source_q.filter(EvidenceSource.investigation_id == investigation_id)
        finding_q = finding_q.filter(Finding.investigation_id == investigation_id)
        chain_q = chain_q.filter(SuspicionChain.investigation_id == investigation_id)

    total_events = event_q.scalar() or 0
    undated = event_q.filter(Event.timestamp.is_(None)).scalar() or 0
    uncertain = event_q.filter(
        or_(Event.timestamp_confidence.in_(("low", "none")),
            Event.timestamp_precision.in_(("minute", "hour", "day", "unknown")))
    ).scalar() or 0
    demo_events = event_q.filter(Event.origin == "demo").scalar() or 0
    high = finding_q.filter(Finding.severity.in_(("critical", "high"))).scalar() or 0

    indicators = dict(db.query(Finding.rule_id, func.count(Finding.id)).group_by(Finding.rule_id))
    if investigation_id:
        indicators = dict(
            db.query(Finding.rule_id, func.count(Finding.id))
            .filter(Finding.investigation_id == investigation_id)
            .group_by(Finding.rule_id).all())

    by_severity = dict(db.query(Finding.severity, func.count(Finding.id)).group_by(Finding.severity))
    if investigation_id:
        by_severity = dict(
            db.query(Finding.severity, func.count(Finding.id))
            .filter(Finding.investigation_id == investigation_id)
            .group_by(Finding.severity).all())

    by_source_type = dict(db.query(Event.source_type, func.count(Event.id)).group_by(Event.source_type))
    if investigation_id:
        by_source_type = dict(
            db.query(Event.source_type, func.count(Event.id))
            .filter(Event.investigation_id == investigation_id)
            .group_by(Event.source_type).all())

    by_origin = dict(db.query(Event.origin, func.count(Event.id)).group_by(Event.origin))
    if investigation_id:
        by_origin = dict(
            db.query(Event.origin, func.count(Event.id))
            .filter(Event.investigation_id == investigation_id)
            .group_by(Event.origin).all())

    return {
        "events": total_events,
        "evidence_sources": source_q.scalar() or 0,
        "detected_indicators": finding_q.scalar() or 0,
        "suspicious_sequences": chain_q.scalar() or 0,
        "high_priority_findings": high,
        "uncertain_timestamps": uncertain,
        "undated_events": undated,
        "demo_events": demo_events,
        "events_by_origin": by_origin,
        "indicator_distribution": indicators,
        "severity_distribution": by_severity,
        "source_distribution": by_source_type,
    }


def _activity_series(db: Session, investigation_id: str | None, buckets: int = 48) -> list[dict]:
    # Build the bucket expression ONCE and reuse that same object in the
    # SELECT, GROUP BY and ORDER BY clauses. Rebuilding it per clause makes
    # the compiler emit distinct bind parameters (date_trunc($1, ...) vs
    # date_trunc($3, ...)), which PostgreSQL rejects with GroupingError since
    # two Param nodes never compare equal in a grouping expression. SQLite
    # inlines literals, so the bug only surfaces on PostgreSQL.
    bucket_expr = (func.date_trunc("hour", Event.timestamp)
                   if db.bind.dialect.name == "postgresql"
                   else func.strftime("%Y-%m-%dT%H:00", Event.timestamp))
    query = db.query(bucket_expr, func.count(Event.id))
    if investigation_id:
        query = query.filter(Event.investigation_id == investigation_id)
    rows = query.filter(Event.timestamp.isnot(None)) \
        .group_by(bucket_expr) \
        .order_by(bucket_expr).limit(buckets * 4).all()
    return [{"bucket": str(bucket), "count": count} for bucket, count in rows]


@router.get("/dashboard")
def dashboard(db: Session = Depends(get_db),
              investigation_id: str | None = Query(None)):
    if investigation_id:
        get_investigation(db, investigation_id)

    metrics = _metrics(db, investigation_id)
    recent_investigations = [
        investigation_payload(db, i)
        for i in db.query(Investigation)
        .order_by(Investigation.updated_at.desc()).limit(6).all()
    ]
    finding_q = db.query(Finding)
    if investigation_id:
        finding_q = finding_q.filter(Finding.investigation_id == investigation_id)
    recent_findings = finding_q.order_by(Finding.created_at.desc()).limit(8).all()

    chain_q = db.query(SuspicionChain)
    if investigation_id:
        chain_q = chain_q.filter(SuspicionChain.investigation_id == investigation_id)
    recent_chains = chain_q.order_by(SuspicionChain.created_at.desc()).limit(5).all()

    last_run = db.query(AnalysisRun)
    if investigation_id:
        last_run = last_run.filter(AnalysisRun.investigation_id == investigation_id)
    last_run = last_run.order_by(AnalysisRun.started_at.desc()).first()

    investigating = (db.query(Investigation)
                     .filter(Investigation.id == investigation_id).first()
                     if investigation_id else None)
    if investigating is None:
        status = "no_investigation_selected"
    elif metrics["events"] == 0:
        status = "awaiting_evidence"
    elif last_run and last_run.status == "completed":
        status = "analysed"
    else:
        status = "ready_for_analysis"

    flagged_ids = flagged_event_ids_for(db, investigation_id) if investigation_id else set()
    preview_query = db.query(Event).filter(Event.timestamp.isnot(None))
    if investigation_id:
        preview_query = preview_query.filter(Event.investigation_id == investigation_id)
    preview_nodes = preview_query.order_by(Event.timestamp.desc()).limit(40).all()

    return {
        "investigation_id": investigation_id,
        "processing_status": status,
        "metrics": metrics,
        "activity_timeline": _activity_series(db, investigation_id),
        "recent_investigations": recent_investigations,
        "recent_findings": [
            {
                "id": f.id, "investigation_id": f.investigation_id, "title": f.title,
                "severity": f.severity, "support": f.support, "rule_id": f.rule_id,
                "rule_name": f.rule_name, "created_at": f.created_at.isoformat() if f.created_at else None,
            }
            for f in recent_findings
        ],
        "recent_chains": [
            {"id": c.id, "investigation_id": c.investigation_id, "title": c.title,
             "pattern_id": c.pattern_id, "severity": c.severity, "completeness": c.completeness,
             "support": c.support}
            for c in recent_chains
        ],
        "last_analysis": {
            "id": last_run.id, "duration_ms": last_run.duration_ms,
            "rules_version": last_run.rules_version, "engine_version": last_run.engine_version,
            "summary": last_run.summary,
            "started_at": last_run.started_at.isoformat() if last_run.started_at else None,
        } if last_run else None,
        "graph_preview_nodes": [
            {"id": e.id, "label": (e.description or e.event_type)[:80],
             "event_type": e.event_type, "timestamp": e.timestamp.isoformat() if e.timestamp else None,
             "host": e.host, "user": e.user, "file_path": e.file_path,
             "flagged": e.id in flagged_ids}
            for e in preview_nodes
        ],
        "disclaimer": "All values are computed from persisted rows; nothing on this page is "
                      "static sample data.",
    }


@router.get("/search")
def global_search(q: str = Query(..., min_length=2), db: Session = Depends(get_db)):
    needle = f"%{q.lower()}%"
    investigations = db.query(Investigation).filter(
        or_(Investigation.name.ilike(needle), Investigation.case_id.ilike(needle),
            Investigation.description.ilike(needle))).limit(10).all()
    findings = db.query(Finding).filter(
        or_(Finding.title.ilike(needle), Finding.rule_id.ilike(needle))).limit(10).all()
    chains = db.query(SuspicionChain).filter(
        SuspicionChain.title.ilike(needle)).limit(10).all()
    events = db.query(Event).filter(
        or_(Event.description.ilike(needle), Event.file_path.ilike(needle),
            Event.user.ilike(needle), Event.process_name.ilike(needle),
            Event.source_record_id.ilike(needle))).limit(25).all()
    return {
        "query": q,
        "investigations": [{"id": i.id, "name": i.name, "case_id": i.case_id} for i in investigations],
        "findings": [{"id": f.id, "investigation_id": f.investigation_id, "title": f.title,
                      "severity": f.severity, "rule_id": f.rule_id} for f in findings],
        "chains": [{"id": c.id, "investigation_id": c.investigation_id, "title": c.title}
                   for c in chains],
        "events": [{"id": e.id, "investigation_id": e.investigation_id,
                    "description": (e.description or "")[:140],
                    "event_type": e.event_type,
                    "timestamp": e.timestamp.isoformat() if e.timestamp else None}
                   for e in events],
        "total_hits": len(investigations) + len(findings) + len(chains) + len(events),
    }


# ---------------------------------------------------------------------------
# Timeline
# ---------------------------------------------------------------------------

def _filter_from_params(start=None, end=None, event_types=None, source_ids=None, users=None,
                        processes=None, files=None, devices=None, hosts=None, search=None,
                        sort="asc", limit=200, offset=0, include_undated=True) -> TimelineFilter:
    def split(value):
        if not value:
            return []
        return [v.strip() for v in value.split(",") if v.strip()]

    return TimelineFilter(
        start=parse_dt(start), end=parse_dt(end),
        event_types=split(event_types), source_ids=split(source_ids), users=split(users),
        processes=split(processes), files=split(files), devices=split(devices),
        hosts=split(hosts), search=search, sort=sort, limit=limit, offset=offset,
        include_undated=include_undated,
    )


@router.get("/investigations/{investigation_id}/events")
def get_events(investigation_id: str,
               start: str | None = None, end: str | None = None,
               event_types: str | None = None, source_ids: str | None = None,
               users: str | None = None, processes: str | None = None,
               files: str | None = None, devices: str | None = None,
               hosts: str | None = None, search: str | None = None,
               sort: str = Query("asc", pattern="^(asc|desc)$"),
               limit: int = Query(200, ge=1, le=5000), offset: int = 0,
               event_ids: str | None = None,
               include_undated: bool = True,
               db: Session = Depends(get_db)):
    get_investigation(db, investigation_id)
    flt = _filter_from_params(start, end, event_types, source_ids, users, processes, files,
                              devices, hosts, search, sort, limit, offset,
                              include_undated=include_undated)
    if event_ids:
        flt.event_ids = [e.strip() for e in event_ids.split(",") if e.strip()]
    flagged = flagged_event_ids_for(db, investigation_id)
    payload = timeline_payload(db, investigation_id, flt, flagged)
    payload["stats"] = timeline_stats(db, investigation_id)
    payload["flagged_count"] = sum(1 for e in payload["events"] if e["flagged"])
    return payload


@router.get("/investigations/{investigation_id}/timeline/facets")
def get_facets(investigation_id: str,
               start: str | None = None, end: str | None = None,
               event_types: str | None = None, search: str | None = None,
               db: Session = Depends(get_db)):
    get_investigation(db, investigation_id)
    flt = _filter_from_params(start, end, event_types, search=search)
    data = facets(db, investigation_id, flt)
    data["stats"] = timeline_stats(db, investigation_id)
    return data


@router.get("/investigations/{investigation_id}/events/{event_id}")
def get_event(investigation_id: str, event_id: str, db: Session = Depends(get_db)):
    get_investigation(db, investigation_id)
    event = db.query(Event).filter(Event.id == event_id,
                                  Event.investigation_id == investigation_id).first()
    if event is None:
        raise HTTPException(status_code=404, detail={
            "code": "event_not_found", "message": f"event {event_id} not found"})
    source = None
    if event.evidence_source_id:
        source = db.query(EvidenceSource).filter(
            EvidenceSource.id == event.evidence_source_id).first()
    related_findings = db.query(Finding).filter(
        Finding.investigation_id == investigation_id).all()
    in_findings = [
        {"id": f.id, "title": f.title, "rule_id": f.rule_id, "severity": f.severity}
        for f in related_findings if event.id in (f.event_ids or [])
    ]
    in_chains = [
        {"id": c.id, "title": c.title, "pattern_id": c.pattern_id, "severity": c.severity}
        for c in db.query(SuspicionChain).filter(
            SuspicionChain.investigation_id == investigation_id).all()
        if event.id in (c.event_ids or [])
    ]
    return {
        "event": event_to_dict(event, include_raw=True),
        "evidence_source": {
            "id": source.id, "filename": source.filename, "sha256": source.sha256,
            "file_type": source.file_type, "origin": source.origin,
            "imported_at": source.imported_at.isoformat() if source.imported_at else None,
            "parser": {"name": source.parser_name, "version": source.parser_version},
        } if source else None,
        "raw_record_reference": event.raw_record_reference,
        "raw_record": event.raw_record,
        "normalized_vs_source": {
            "normalized_timestamp": event_to_dict(event)["timestamp"],
            "source_timestamp": event.timestamp_raw,
            "timezone_note": event.timezone_note,
            "note": "The source value is preserved verbatim; normalization never overwrites it.",
        },
        "findings": in_findings,
        "chains": in_chains,
        "integrity": {
            "hash": event.integrity_hash,
            "note": "SHA-256 over normalized + raw fields detects later modification of the "
                    "stored record; it is not proof of authenticity on its own.",
        },
    }


@router.get("/investigations/{investigation_id}/timeline/export")
def export_timeline(investigation_id: str, format: str = Query("csv", pattern="^(csv|json)$"),
                   start: str | None = None, end: str | None = None,
                   event_types: str | None = None, source_ids: str | None = None,
                   users: str | None = None, processes: str | None = None,
                   files: str | None = None, devices: str | None = None,
                   hosts: str | None = None, search: str | None = None,
                   sort: str = Query("asc", pattern="^(asc|desc)$"),
                   include_undated: bool = True,
                   db: Session = Depends(get_db)):
    investigation = get_investigation(db, investigation_id)
    flt = _filter_from_params(start, end, event_types, source_ids, users, processes, files,
                              devices, hosts, search, sort, limit=100_000, offset=0,
                              include_undated=include_undated)
    media_type, body = export_events(db, investigation_id, flt, format)
    filename = _download_filename(investigation.case_id, f"_timeline.{format}")
    return Response(content=body, media_type=media_type, headers={
        "Content-Disposition": f'attachment; filename="{filename}"',
        "X-TRACE-X-note": "Filtered export reflects the active timeline filters.",
    })


# ---------------------------------------------------------------------------
# Reports and exports
# ---------------------------------------------------------------------------

@router.get("/investigations/{investigation_id}/report.html")
def html_report(investigation_id: str, db: Session = Depends(get_db)):
    investigation = get_investigation(db, investigation_id)
    media_type, body = render_report(db, investigation)
    return HTMLResponse(content=body, media_type=media_type, headers={
        "Content-Disposition": (
            f'inline; filename="{_download_filename(investigation.case_id, "_report.html")}"'),
        "Cache-Control": "no-store",
        # Defense in depth: the report is static, escaped markup with one
        # inline <style> block. Deny everything else so even a future
        # escaping regression cannot execute script or load external resources.
        "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'",
        "X-Content-Type-Options": "nosniff",
    })


@router.get("/investigations/{investigation_id}/report.json")
def json_report(investigation_id: str, download: bool = False,
                db: Session = Depends(get_db)):
    investigation = get_investigation(db, investigation_id)
    data = build_report_data(db, investigation)
    headers = {"Cache-Control": "no-store"}
    if download:
        headers["Content-Disposition"] = (
            f'attachment; filename="{_download_filename(investigation.case_id, "_report.json")}"')
    return Response(content=json.dumps(data, indent=2, default=str),
                    media_type="application/json", headers=headers)


@router.get("/investigations/{investigation_id}/report/manifest")
def get_manifest(investigation_id: str, db: Session = Depends(get_db)):
    investigation = get_investigation(db, investigation_id)
    return report_manifest(db, investigation)


@router.get("/investigations/{investigation_id}/export/findings.csv")
def findings_csv(investigation_id: str, db: Session = Depends(get_db)):
    investigation = get_investigation(db, investigation_id)
    _, body = export_findings_csv(db, investigation_id)
    return Response(content=body, media_type="text/csv", headers={
        "Content-Disposition": (
            f'attachment; filename="{_download_filename(investigation.case_id, "_findings.csv")}"')})


@router.get("/investigations/{investigation_id}/export/events.json")
def events_json(investigation_id: str, download: bool = True, db: Session = Depends(get_db)):
    investigation = get_investigation(db, investigation_id)
    _, body = export_events(db, investigation_id, TimelineFilter(limit=100_000), "json")
    headers = {}
    if download:
        headers["Content-Disposition"] = (
            f'attachment; filename="{_download_filename(investigation.case_id, "_events.json")}"')
    return Response(content=body, media_type="application/json", headers=headers)


@router.get("/investigations/{investigation_id}/export/bodyfile.csv")
def bodyfile_csv(investigation_id: str, db: Session = Depends(get_db)):
    """TSK bodyfile (mactime) CSV — import into plaso/mactime directly."""
    investigation = get_investigation(db, investigation_id)
    _, body = export_bodyfile_csv(db, investigation_id)
    return Response(content=body, media_type="text/csv", headers={
        "Content-Disposition": (
            f'attachment; filename="{_download_filename(investigation.case_id, "_bodyfile.csv")}"'),
        "X-TRACE-X-note": "TSK bodyfile columns; '-' marks fields the source did not record.",
    })


@router.get("/investigations/{investigation_id}/export/supertimeline.csv")
def supertimeline_csv(investigation_id: str, db: Session = Depends(get_db)):
    """Plaso-style super-timeline CSV — feed to psort.py or a timeline explorer."""
    investigation = get_investigation(db, investigation_id)
    _, body = export_supertimeline_csv(db, investigation_id)
    return Response(content=body, media_type="text/csv", headers={
        "Content-Disposition": (
            f'attachment; filename="{_download_filename(investigation.case_id, "_supertimeline.csv")}"'),
        "X-TRACE-X-note": "plaso super-timeline columns; timestamps are ISO-8601 UTC.",
    })


@router.get("/investigations/{investigation_id}/report.pdf")
def pdf_report(investigation_id: str, db: Session = Depends(get_db)):
    """Self-contained PDF rendering of the investigation report (no extra deps)."""
    investigation = get_investigation(db, investigation_id)
    media_type, body = render_report_pdf(db, investigation)
    return Response(content=body, media_type=media_type, headers={
        "Content-Disposition": (
            f'attachment; filename="{_download_filename(investigation.case_id, "_report.pdf")}"'),
        "Cache-Control": "no-store",
    })


# ---------------------------------------------------------------------------
# Demo data
# ---------------------------------------------------------------------------

@router.get("/demo")
def demo_info(db: Session = Depends(get_db)):
    from ..datasets import catalog
    from ..demo import demo_summary

    return {"scenarios": catalog(), **demo_summary(db)}


@router.post("/demo/generate", status_code=201)
def generate_demo(body: DemoRequest, db: Session = Depends(get_db)):
    from ..datasets import scenario_by_id
    from ..demo import create_demo_investigation

    requested = body.scenarios or []
    created, errors = [], []

    from ..datasets import SCENARIOS

    selected = requested or [s.id for s in SCENARIOS]
    for sid in selected:
        scenario = scenario_by_id(sid)
        if scenario is None:
            errors.append({"scenario": sid, "error": "unknown scenario id"})
            continue
        try:
            investigation = create_demo_investigation(db, scenario)
            from .investigations import investigation_payload
            created.append({**investigation_payload(db, investigation), "scenario": sid})
        except Exception as exc:  # surface per-scenario failures
            db.rollback()
            errors.append({"scenario": sid, "error": str(exc)})
    if not created and errors:
        raise HTTPException(status_code=422, detail={
            "code": "demo_generation_failed", "message": "no demo investigations created",
            "details": errors})
    return {
        "created": created, "errors": errors, "count": len(created),
        "labeling": "Every generated record carries origin='demo' (SYNTHETIC) on the "
                    "investigation, evidence source and event rows.",
        "generated_from": "controlled synthetic scenarios with declared ground truth",
    }


# ---------------------------------------------------------------------------
# Evaluation (metrics + A/B/C configuration comparison)
# ---------------------------------------------------------------------------

@router.post("/evaluation/run")
def evaluate(body: EvaluationRequest, db: Session = Depends(get_db)):
    from ..evaluation import run_evaluation

    result = run_evaluation(body.scenarios, body.configurations)
    if result.get("error"):
        raise HTTPException(status_code=422, detail={
            "code": "evaluation_failed", "message": result["error"]})
    return result


@router.get("/evaluation/run")
def evaluate_get(scenarios: str | None = None, configurations: str = "A,B,C",
                 db: Session = Depends(get_db)):
    from ..evaluation import run_evaluation

    scenario_ids = [s.strip() for s in scenarios.split(",")] if scenarios else None
    configs = [c.strip().upper() for c in configurations.split(",") if c.strip() in ("a", "b", "c", "A", "B", "C")]
    configs = [c or "A" for c in configs] or ["A", "B", "C"]
    result = run_evaluation(scenario_ids, configs)
    if result.get("error"):
        raise HTTPException(status_code=422, detail={
            "code": "evaluation_failed", "message": result["error"]})
    return result