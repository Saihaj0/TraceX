"""Investigation management, evidence ingestion and audit-trail endpoints."""

from __future__ import annotations

import io

from fastapi import APIRouter, Depends, File, HTTPException, Query, Request, UploadFile
from sqlalchemy.orm import Session

from ..auth import auth_on, current_actor
from ..config import DEFAULT_ANALYSIS_CONFIG, EVIDENCE_DIR
from ..db import get_db
from ..models import AnalysisRun, AuditLog, EvidenceSource, Event, Finding, Investigation, SuspicionChain, new_id
from ..schemas import AnalysisConfigUpdate, InvestigationCreate, InvestigationUpdate
from ..services.ingest import audit, ingest_file, preview_file
from ..services.timeline import event_to_dict

router = APIRouter(prefix="/investigations", tags=["investigations"])

MAX_UPLOAD_BYTES = 64 * 1024 * 1024


def get_investigation(db: Session, investigation_id: str) -> Investigation:
    investigation = db.query(Investigation).filter(
        Investigation.id == investigation_id
    ).first()
    if investigation is None:
        raise HTTPException(status_code=404, detail={
            "code": "investigation_not_found",
            "message": f"investigation {investigation_id} does not exist",
        })
    return investigation


def actor_from(headers) -> str:
    from ..config import DEFAULT_ACTOR

    return (headers.get("x-tracex-actor") or DEFAULT_ACTOR).strip()[:128] or DEFAULT_ACTOR


def require_owner(investigation: Investigation, actor: str) -> None:
    """Ownership gate: when auth is on, non-owners may not touch the case.

    Investigations with no owner (created before auth was enabled) stay
    open to every authenticated actor — nothing becomes inaccessible by
    turning auth on.
    """
    if auth_on() and investigation.owner and investigation.owner != actor:
        raise HTTPException(status_code=403, detail={
            "code": "not_owner",
            "message": f"investigation {investigation.case_id} is owned by "
                       f"another actor"})


def ownership_guard(request: Request, db: Session = Depends(get_db)) -> None:
    """Router-level read+write ownership gate for user-session mode.

    Attached to every investigation-scoped router so detail reads, evidence,
    events, exports, findings and analysis endpoints all honour ownership —
    previously only the list and explicit mutations did, letting anyone who
    knew an id fetch the case directly.  Scoped to USER_AUTH_ENABLED so the
    legacy API-key mode keeps its shipped semantics.
    """
    from .. import config

    if not config.USER_AUTH_ENABLED:
        return
    inv_id = (request.path_params.get("investigation_id")
              or request.query_params.get("investigation_id"))
    if not inv_id:
        return
    user = getattr(request.state, "user", None)  # set by the auth middleware
    if user is None:
        return
    investigation = db.get(Investigation, inv_id)
    if investigation is None:
        return  # let the endpoint produce its usual 404
    require_owner(investigation, user.username)


def investigation_payload(db: Session, investigation: Investigation) -> dict:
    event_count = db.query(Event).filter(Event.investigation_id == investigation.id).count()
    source_count = db.query(EvidenceSource).filter(
        EvidenceSource.investigation_id == investigation.id).count()
    rejected_rows = db.query(EvidenceSource).filter(
        EvidenceSource.investigation_id == investigation.id)
    rejected_total = sum(s.rejected_count for s in rejected_rows.all())
    finding_count = db.query(Finding).filter(
        Finding.investigation_id == investigation.id).count()
    chain_count = db.query(SuspicionChain).filter(
        SuspicionChain.investigation_id == investigation.id).count()
    last_run = (
        db.query(AnalysisRun)
        .filter(AnalysisRun.investigation_id == investigation.id)
        .order_by(AnalysisRun.started_at.desc())
        .first()
    )
    high = db.query(Finding).filter(
        Finding.investigation_id == investigation.id,
        Finding.severity.in_(("critical", "high"))).count()
    undated = db.query(Event).filter(
        Event.investigation_id == investigation.id, Event.timestamp.is_(None)).count()
    low_conf = db.query(Event).filter(
        Event.investigation_id == investigation.id,
        Event.timestamp_confidence.in_(("low", "none"))).count()

    if event_count == 0:
        processing = "awaiting_evidence"
    elif last_run and last_run.status == "completed":
        processing = "analysed"
    elif last_run:
        processing = "analysing"
    else:
        processing = "ready_for_analysis"

    return {
        "id": investigation.id,
        "name": investigation.name,
        "case_id": investigation.case_id,
        "description": investigation.description,
        "notes": investigation.notes,
        "status": investigation.status,
        "origin": investigation.origin,
        "owner": investigation.owner,
        "is_demo": investigation.origin == "demo",
        "created_at": investigation.created_at.isoformat() if investigation.created_at else None,
        "updated_at": investigation.updated_at.isoformat() if investigation.updated_at else None,
        "analysis_config": {**DEFAULT_ANALYSIS_CONFIG, **(investigation.analysis_config or {})},
        "metrics": {
            "events": event_count,
            "evidence_sources": source_count,
            "rejected_records": rejected_total,
            "findings": finding_count,
            "high_priority_findings": high,
            "suspicion_chains": chain_count,
            "undated_events": undated,
            "low_confidence_timestamps": low_conf,
        },
        "processing": processing,
        "last_run": {
            "id": last_run.id,
            "started_at": last_run.started_at.isoformat() if last_run.started_at else None,
            "finished_at": last_run.finished_at.isoformat() if last_run.finished_at else None,
            "duration_ms": last_run.duration_ms,
            "engine_version": last_run.engine_version,
            "rules_version": last_run.rules_version,
            "trigger": last_run.trigger,
            "summary": last_run.summary,
            "status": last_run.status,
        } if last_run else None,
    }


# --- CRUD ------------------------------------------------------------------

@router.get("")
def list_investigations(db: Session = Depends(get_db),
                        actor: str = Depends(current_actor),
                        origin: str | None = Query(None, description="filter by user|demo"),
                        q: str | None = Query(None, description="name/case search")):
    query = db.query(Investigation)
    if auth_on():
        # Each actor sees their own cases plus unowned/shared ones.
        query = query.filter((Investigation.owner.is_(None))
                             | (Investigation.owner == actor))
    if origin:
        query = query.filter(Investigation.origin == origin)
    if q:
        needle = f"%{q.lower()}%"
        query = query.filter(
            (Investigation.name.ilike(needle)) | (Investigation.case_id.ilike(needle))
            | (Investigation.description.ilike(needle)))
    rows = query.order_by(Investigation.updated_at.desc()).all()
    return {"investigations": [investigation_payload(db, i) for i in rows], "count": len(rows)}


@router.post("", status_code=201)
def create_investigation(body: InvestigationCreate, db: Session = Depends(get_db),
                        actor: str = Depends(current_actor)):
    duplicate = db.query(Investigation).filter(Investigation.case_id == body.case_id).first()
    if duplicate:
        raise HTTPException(status_code=409, detail={
            "code": "case_id_exists",
            "message": f"case id '{body.case_id}' is already used by another investigation",
        })
    investigation = Investigation(
        id=new_id(), name=body.name, case_id=body.case_id,
        description=body.description, notes=body.notes,
        status="open", origin="user", analysis_config={},
        owner=actor if auth_on() else None,
    )
    db.add(investigation)
    db.flush()
    audit(db, "investigation.created", investigation.id, actor=actor, detail={
        "name": investigation.name, "case_id": investigation.case_id})
    db.commit()
    db.refresh(investigation)
    return investigation_payload(db, investigation)


@router.get("/{investigation_id}")
def get_investigation_detail(investigation_id: str, db: Session = Depends(get_db)):
    return investigation_payload(db, get_investigation(db, investigation_id))


@router.patch("/{investigation_id}")
def update_investigation(investigation_id: str, body: InvestigationUpdate,
                        db: Session = Depends(get_db),
                        actor: str = Depends(current_actor)):
    investigation = get_investigation(db, investigation_id)
    require_owner(investigation, actor)
    changes = {}
    for field in ("name", "description", "notes", "status"):
        value = getattr(body, field)
        if value is not None and value != getattr(investigation, field):
            changes[field] = {"from": getattr(investigation, field), "to": value}
            setattr(investigation, field, value)
    if changes:
        audit(db, "investigation.updated", investigation.id, actor=actor,
              detail={"changes": changes})
        db.commit()
        db.refresh(investigation)
    return investigation_payload(db, investigation)


@router.delete("/{investigation_id}")
def delete_investigation(investigation_id: str, confirm: bool = Query(False),
                        db: Session = Depends(get_db),
                        actor: str = Depends(current_actor)):
    investigation = get_investigation(db, investigation_id)
    require_owner(investigation, actor)
    if investigation.origin == "demo" and not confirm:
        raise HTTPException(status_code=400, detail={
            "code": "confirmation_required",
            "message": "Deleting a demo investigation requires ?confirm=true",
        })
    summary = investigation_payload(db, investigation)
    audit(db, "investigation.deleted", investigation.id, actor=actor,
          detail={"case_id": investigation.case_id, "origin": investigation.origin,
                  "events": summary["metrics"]["events"]})
    db.delete(investigation)
    db.commit()

    # remove stored evidence files after the row is gone
    import shutil

    directory = EVIDENCE_DIR / investigation_id
    if directory.exists():
        shutil.rmtree(directory, ignore_errors=True)
    return {"deleted": True, "investigation_id": investigation_id,
            "was_demo": summary["is_demo"]}


@router.put("/{investigation_id}/config")
def update_analysis_config(investigation_id: str, body: AnalysisConfigUpdate,
                          db: Session = Depends(get_db),
                          actor: str = Depends(current_actor)):
    investigation = get_investigation(db, investigation_id)
    require_owner(investigation, actor)
    previous = {**DEFAULT_ANALYSIS_CONFIG, **(investigation.analysis_config or {})}
    updates = {k: v for k, v in body.model_dump().items() if v is not None}
    investigation.analysis_config = {**(investigation.analysis_config or {}), **updates}
    db.flush()
    audit(db, "analysis.config_updated", investigation.id, actor=actor, detail={
        "changed": updates, "previous": previous,
        "note": "re-run analysis to apply the new configuration"},
        entity_type="investigation", entity_id=investigation.id)
    db.commit()
    db.refresh(investigation)
    return {
        "analysis_config": {**DEFAULT_ANALYSIS_CONFIG, **investigation.analysis_config},
        "changed": updates,
        "requires_reanalysis": True,
    }


@router.get("/{investigation_id}/audit")
def get_audit(investigation_id: str, db: Session = Depends(get_db),
              limit: int = Query(200, ge=1, le=2000)):
    get_investigation(db, investigation_id)
    rows = (
        db.query(AuditLog)
        .filter(AuditLog.investigation_id == investigation_id)
        .order_by(AuditLog.created_at.desc())
        .limit(limit)
        .all()
    )
    return {
        "entries": [
            {
                "id": row.id, "at": row.created_at.isoformat() if row.created_at else None,
                "action": row.action, "actor": row.actor,
                "entity_type": row.entity_type, "entity_id": row.entity_id,
                "detail": row.detail,
            }
            for row in rows
        ],
        "count": len(rows),
    }


# --- evidence ---------------------------------------------------------------

@router.get("/{investigation_id}/evidence")
def list_evidence(investigation_id: str, db: Session = Depends(get_db)):
    get_investigation(db, investigation_id)
    rows = (
        db.query(EvidenceSource)
        .filter(EvidenceSource.investigation_id == investigation_id)
        .order_by(EvidenceSource.imported_at.desc())
        .all()
    )
    return {
        "evidence": [
            {
                "id": s.id, "filename": s.filename, "file_type": s.file_type,
                "source_type": s.source_type, "size_bytes": s.size_bytes,
                "sha256": s.sha256, "origin": s.origin,
                "imported_at": s.imported_at.isoformat() if s.imported_at else None,
                "record_count": s.record_count, "accepted_count": s.accepted_count,
                "rejected_count": s.rejected_count, "status": s.status,
                "parser": {"name": s.parser_name, "version": s.parser_version},
                "timezone_note": s.timezone_note,
                "metadata": s.metadata_json,
                "error_count": len(s.record_errors or []),
                "integrity_note": (
                    "SHA-256 supports integrity verification of the stored copy; a hash alone "
                    "does not prove authenticity or chain of custody."
                ),
            }
            for s in rows
        ],
        "count": len(rows),
    }


@router.get("/{investigation_id}/evidence/{source_id}/errors")
def evidence_errors(investigation_id: str, source_id: str, db: Session = Depends(get_db)):
    get_investigation(db, investigation_id)
    source = db.query(EvidenceSource).filter(
        EvidenceSource.id == source_id,
        EvidenceSource.investigation_id == investigation_id).first()
    if source is None:
        raise HTTPException(status_code=404, detail={
            "code": "evidence_not_found", "message": "evidence source not found"})
    return {
        "evidence_source_id": source.id,
        "filename": source.filename,
        "status": source.status,
        "record_count": source.record_count,
        "accepted_count": source.accepted_count,
        "rejected_count": source.rejected_count,
        "errors": source.record_errors or [],
        "metadata": source.metadata_json,
        "policy": "Rejected records are retained here and never silently discarded.",
    }


@router.get("/{investigation_id}/evidence/{source_id}/events")
def evidence_events(investigation_id: str, source_id: str, limit: int = Query(200, ge=1, le=5000),
                   offset: int = 0, db: Session = Depends(get_db)):
    get_investigation(db, investigation_id)
    query = db.query(Event).filter(
        Event.investigation_id == investigation_id,
        Event.evidence_source_id == source_id)
    total = query.count()
    rows = query.order_by(Event.seq).offset(offset).limit(limit).all()
    return {"events": [event_to_dict(e, include_raw=True) for e in rows],
            "total": total, "offset": offset, "limit": limit}


@router.post("/{investigation_id}/evidence/preview")
async def preview_evidence(investigation_id: str, file: UploadFile = File(...),
                           file_type: str | None = Query(None),
                           db: Session = Depends(get_db)):
    """Parse an artifact and show the result WITHOUT persisting anything."""
    get_investigation(db, investigation_id)
    content = await file.read()
    if len(content) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail={
            "code": "file_too_large",
            "message": f"file exceeds the {MAX_UPLOAD_BYTES // (1024 * 1024)} MiB limit"})
    if not content:
        raise HTTPException(status_code=400, detail={
            "code": "empty_file", "message": "uploaded file is empty"})
    try:
        result = preview_file(file.filename or "upload.bin", content=content, file_type=file_type)
    except Exception as exc:  # parser-level failure surfaced for inspection
        raise HTTPException(status_code=422, detail={
            "code": "parse_failed", "message": str(exc)})
    return {"preview": result, "persisted": False}


@router.post("/{investigation_id}/evidence", status_code=201)
async def import_evidence(investigation_id: str, file: UploadFile = File(...),
                         file_type: str | None = Query(None),
                         db: Session = Depends(get_db),
                         actor: str = Depends(current_actor)):
    investigation = get_investigation(db, investigation_id)
    require_owner(investigation, actor)
    content = await file.read()
    if len(content) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail={
            "code": "file_too_large",
            "message": f"file exceeds the {MAX_UPLOAD_BYTES // (1024 * 1024)} MiB limit"})
    if not content:
        raise HTTPException(status_code=400, detail={
            "code": "empty_file", "message": "uploaded file is empty"})

    try:
        report = ingest_file(
            db, investigation, filename=file.filename or "upload.bin",
            content=content, file_type=file_type, actor=actor, origin="imported",
        )
        db.commit()
    except Exception as exc:
        db.rollback()
        raise HTTPException(status_code=422, detail={
            "code": "ingest_failed", "message": str(exc)})

    return {
        **report.to_dict(),
        "message": (
            f"Imported {report.accepted} record(s); {report.rejected} rejected."
            if report.rejected else f"Imported {report.accepted} record(s)."
        ),
        "next": "run the detection engine to analyse this evidence",
    }


@router.post("/{investigation_id}/evidence/batch", status_code=201)
async def import_evidence_batch(investigation_id: str,
                                files: list[UploadFile] = File(...),
                                db: Session = Depends(get_db),
                                actor: str = Depends(current_actor)):
    """Import several artifacts in one request (e.g. a folder of CSV exports).

    Each file goes through the exact same hash → parse → normalize path as a
    single import; one failing file never aborts the batch, its error is
    reported per file and the other artifacts are still imported.
    """
    investigation = get_investigation(db, investigation_id)
    require_owner(investigation, actor)
    if not files:
        raise HTTPException(status_code=400, detail={
            "code": "empty_batch", "message": "no files supplied"})
    if len(files) > 50:
        raise HTTPException(status_code=413, detail={
            "code": "batch_too_large",
            "message": "a batch may contain at most 50 files; import the rest separately"})

    imported, errors = [], []
    for upload in files:
        filename = upload.filename or "upload.bin"
        try:
            content = await upload.read()
        except Exception as exc:
            errors.append({"filename": filename, "code": "read_failed", "message": str(exc)})
            continue
        if not content:
            errors.append({"filename": filename, "code": "empty_file",
                           "message": "uploaded file is empty"})
            continue
        if len(content) > MAX_UPLOAD_BYTES:
            errors.append({"filename": filename, "code": "file_too_large",
                           "message": f"exceeds the {MAX_UPLOAD_BYTES // (1024 * 1024)} MiB limit"})
            continue
        try:
            report = ingest_file(
                db, investigation, filename=filename, content=content,
                actor=actor, origin="imported")
            imported.append(report.to_dict())
        except Exception as exc:
            db.rollback()
            errors.append({"filename": filename, "code": "ingest_failed", "message": str(exc)})

    if not imported:
        raise HTTPException(status_code=422, detail={
            "code": "batch_failed", "message": "no artifact in the batch could be imported",
            "details": errors})
    db.commit()
    return {
        "imported": imported,
        "errors": errors,
        "files_imported": len(imported),
        "files_failed": len(errors),
        "events_accepted": sum(r["accepted"] for r in imported),
        "records_rejected": sum(r["rejected"] for r in imported),
        "message": (f"Imported {len(imported)} file(s) "
                    f"({sum(r['accepted'] for r in imported)} event(s)); "
                    f"{len(errors)} file(s) failed."),
        "next": "run the detection engine to analyse this evidence",
    }


@router.post("/{investigation_id}/evidence/{source_id}/verify")
def verify_evidence(investigation_id: str, source_id: str, db: Session = Depends(get_db),
                   actor: str = Depends(current_actor)):
    """Re-hash the stored artifact and compare with the recorded SHA-256.

    Detects later modification of the stored copy. The result is written to the
    audit trail because evidence integrity is a chain-of-custody concern, not a
    display-only metric. A matching hash does not prove authenticity.
    """
    from pathlib import Path

    from ..services.ingest import sha256_file

    investigation = get_investigation(db, investigation_id)
    require_owner(investigation, actor)
    source = db.query(EvidenceSource).filter(
        EvidenceSource.id == source_id,
        EvidenceSource.investigation_id == investigation_id).first()
    if source is None:
        raise HTTPException(status_code=404, detail={
            "code": "evidence_not_found", "message": "evidence source not found"})

    if not source.stored_path or not Path(source.stored_path).exists():
        result = {
            "evidence_source_id": source.id,
            "filename": source.filename,
            "stored_file_available": False,
            "verified": False,
            "note": "the stored artifact is not present on this host; the recorded "
                    "hash cannot be re-checked here",
        }
    else:
        current_hash = sha256_file(Path(source.stored_path))
        matches = current_hash == source.sha256
        result = {
            "evidence_source_id": source.id,
            "filename": source.filename,
            "stored_file_available": True,
            "recorded_sha256": source.sha256,
            "current_sha256": current_hash,
            "size_bytes": source.size_bytes,
            "verified": matches,
            "note": (
                "stored copy matches the hash recorded at import time"
                if matches else
                "MISMATCH: the stored copy no longer matches the import-time hash; "
                "treat it as potentially altered and re-acquire the artifact"),
            "limitation": "A matching hash supports integrity of this copy; it does not "
                          "prove authenticity or chain of custody.",
        }
    audit(db, "evidence.verified", investigation.id, actor=actor,
          entity_type="evidence_source", entity_id=source.id,
          detail={"verified": result["verified"],
                  "stored_file_available": result["stored_file_available"],
                  "recorded_sha256": source.sha256})
    db.commit()
    return result


@router.post("/{investigation_id}/evidence/{source_id}/reparse", status_code=201)
def reparse_evidence(investigation_id: str, source_id: str, db: Session = Depends(get_db),
                    actor: str = Depends(current_actor)):
    """Re-run a source's parser after a parser upgrade (original file kept read-only)."""
    from ..services.ingest import run_parser

    investigation = get_investigation(db, investigation_id)
    require_owner(investigation, actor)
    source = db.query(EvidenceSource).filter(
        EvidenceSource.id == source_id,
        EvidenceSource.investigation_id == investigation_id).first()
    if source is None or not source.stored_path:
        raise HTTPException(status_code=404, detail={
            "code": "evidence_not_found", "message": "evidence source or stored file missing"})
    from pathlib import Path

    path = Path(source.stored_path)
    if not path.exists():
        raise HTTPException(status_code=410, detail={
            "code": "stored_file_missing",
            "message": "the stored artifact is no longer available on this host"})
    try:
        result = run_parser(source.file_type, path, source.filename)
    except Exception as exc:
        raise HTTPException(status_code=422, detail={
            "code": "parse_failed", "message": str(exc)})
    audit(db, "evidence.reparsed", investigation.id, actor=actor,
          detail={"source_id": source.id, "accepted": len(result.events),
                  "rejected": len(result.errors), "parser": source.parser_name})
    db.commit()
    return {"evidence_source_id": source.id, "accepted": len(result.events),
            "rejected": len(result.errors), "persisted": False,
            "note": "a re-parse reports parser output; existing normalized records are unchanged "
                    "until you re-import the artifact"}