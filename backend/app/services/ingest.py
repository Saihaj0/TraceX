"""Evidence ingestion service.

Responsibilities:
  * store the uploaded artifact **read-only** under a content-addressed path,
  * compute SHA-256 / size / import metadata (provenance),
  * run the right parser, persist the normalized events, keep rejection detail,
  * write an audit entry for every import.
"""

from __future__ import annotations

import hashlib
import json
import shutil
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy.orm import Session

from ..config import EVIDENCE_DIR, PARSERS_VERSION
from ..models import AnalysisRun, AuditLog, EvidenceSource, Event, Investigation, new_id
from ..parsers.base import ParseResult, ParserError, detect_file_type, get_parser, parser_catalog


@dataclass
class IngestReport:
    evidence_source_id: str
    filename: str
    file_type: str
    record_count: int
    accepted: int
    rejected: int
    status: str
    errors: list[dict]
    warnings: list[str]
    sha256: str
    metadata: dict
    size_bytes: int = 0

    def to_dict(self) -> dict:
        return {
            "evidence_source_id": self.evidence_source_id,
            "id": self.evidence_source_id,
            "filename": self.filename,
            "file_type": self.file_type,
            "record_count": self.record_count,
            "accepted": self.accepted,
            "rejected": self.rejected,
            "accepted_count": self.accepted,
            "rejected_count": self.rejected,
            "size_bytes": self.size_bytes,
            "integrity_note": (
                "SHA-256 of the exact imported bytes; re-hash the stored artifact "
                "and compare to detect any alteration."),
            "status": self.status,
            "errors": self.errors,
            "warnings": self.warnings,
            "sha256": self.sha256,
            "metadata": self.metadata,
        }


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _utc(dt: datetime) -> datetime:
    """Attach UTC to a naive timestamp (policy: absent offset means UTC).

    Calling astimezone() on a naive value instead would reinterpret it in the
    server's local zone and silently shift every undated-offset record.
    """
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def audit(db: Session, action: str, investigation_id: str | None = None, actor: str = "investigator",
          detail: dict | None = None, entity_type: str | None = None, entity_id: str | None = None) -> AuditLog:
    entry = AuditLog(
        investigation_id=investigation_id,
        action=action,
        entity_type=entity_type,
        entity_id=entity_id,
        actor=actor,
        detail=detail or {},
    )
    db.add(entry)
    return entry


def save_upload(investigation_id: str, filename: str, content: bytes | None = None,
                file_obj=None) -> tuple[Path, str, int]:
    """Persist an uploaded artifact content-addressed under data/evidence."""
    safe_name = Path(filename).name or "upload.bin"
    directory = EVIDENCE_DIR / investigation_id
    directory.mkdir(parents=True, exist_ok=True)
    staging = directory / f"upload_{new_id()}_{safe_name}"
    if content is not None:
        staging.write_bytes(content)
    elif file_obj is not None:
        with open(staging, "wb") as out:
            shutil.copyfileobj(file_obj, out)
    else:
        raise ValueError("no content supplied")

    digest = sha256_file(staging)
    final = directory / f"{digest[:24]}_{safe_name}"
    if final.exists():
        staging.unlink(missing_ok=True)
    else:
        staging.replace(final)
    return final, digest, final.stat().st_size


def run_parser(file_type: str, path: Path, filename: str) -> ParseResult:
    parser = get_parser(file_type)
    if parser is None:
        raise ParserError(
            f"no parser registered for file type '{file_type}'. Supported types: "
            + ", ".join(p["file_type"] for p in parser_catalog())
        )
    return parser.parse(path, original_name=filename)


def ingest_file(
    db: Session,
    investigation: Investigation,
    filename: str,
    file_obj=None,
    content: bytes | None = None,
    file_type: str | None = None,
    actor: str = "investigator",
    origin: str = "imported",
) -> IngestReport:
    path, digest, size = save_upload(investigation.id, filename, content=content, file_obj=file_obj)
    resolved_type = file_type or detect_file_type(path, filename)

    try:
        result = run_parser(resolved_type, path, filename)
        parser_error = None
    except ParserError as exc:
        result = ParseResult()
        parser_error = str(exc)

    parser = get_parser(resolved_type)
    status = "processed"
    if parser_error:
        status = "failed"
    elif result.errors and result.events:
        status = "partial"
    elif result.errors and not result.events:
        status = "failed"

    source = EvidenceSource(
        id=new_id(),
        investigation_id=investigation.id,
        filename=filename,
        file_type=resolved_type,
        source_type=parser.source_type if parser else "unknown",
        stored_path=str(path),
        size_bytes=size,
        sha256=digest,
        origin=origin,
        parser_name=parser.name if parser else "none",
        parser_version=parser.version if parser else "0",
        record_count=result.record_count + (1 if parser_error else 0),
        accepted_count=len(result.events),
        rejected_count=len(result.errors) + (1 if parser_error else 0),
        status=status,
        timezone_note=result.timezone_note,
        metadata_json={
            **result.metadata,
            "warnings": result.warnings,
            "parser_catalog_version": PARSERS_VERSION,
            "file_error": parser_error,
            "imported_by": actor,
        },
        record_errors=[e.to_dict() for e in result.errors]
        + ([{"row_index": None, "record_id": None, "reason": "file_parse_failed",
             "detail": parser_error, "raw_excerpt": None}] if parser_error else []),
    )
    db.add(source)

    seq_base = db.query(Event).filter(Event.investigation_id == investigation.id).count()
    for offset, item in enumerate(result.events):
        item.origin = origin
        db.add(
            Event(
                id=new_id(),
                investigation_id=investigation.id,
                evidence_source_id=source.id,
                timestamp=item.timestamp,
                timestamp_raw=item.timestamp_raw,
                timestamp_precision=item.timestamp_precision,
                timestamp_confidence=item.timestamp_confidence,
                timezone_note=item.timezone_note,
                event_type=item.event_type,
                source_type=item.source_type,
                source_file=item.source_file,
                source_record_id=item.source_record_id,
                host=item.host,
                user=item.user,
                process_id=item.process_id,
                process_name=item.process_name,
                file_path=item.file_path,
                device_id=item.device_id,
                description=item.description,
                raw_record_reference=item.raw_record_reference,
                raw_record=item.raw_record,
                parser_name=item.parser_name,
                parser_version=item.parser_version,
                integrity_hash=item.integrity_hash(),
                ingestion_status=(
                    "accepted_with_warnings" if item.warnings else item.ingestion_status
                ),
                origin=origin,
                seq=seq_base + offset + 1,
            )
        )

    audit(
        db, "evidence.imported", investigation.id, actor,
        detail={
            "filename": filename,
            "file_type": resolved_type,
            "sha256": digest,
            "size_bytes": size,
            "accepted": len(result.events),
            "rejected": len(result.errors),
            "origin": origin,
            "status": status,
        },
        entity_type="evidence_source",
        entity_id=source.id,
    )
    report = IngestReport(
        evidence_source_id=source.id,
        filename=filename,
        file_type=resolved_type,
        record_count=source.record_count,
        accepted=len(result.events),
        rejected=source.rejected_count,
        status=status,
        errors=[e.to_dict() for e in result.errors][:200],
        warnings=result.warnings + ([parser_error] if parser_error else []),
        sha256=digest,
        metadata=result.metadata,
        size_bytes=size,
    )
    return report


def preview_file(filename: str, content: bytes | None = None, file_obj=None,
                 file_type: str | None = None, preview_limit: int = 25) -> dict:
    """Parse an upload WITHOUT persisting it - used by the import preview step."""
    import tempfile

    suffix = Path(filename).suffix or ".bin"
    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
        if content is not None:
            tmp.write(content)
        else:
            shutil.copyfileobj(file_obj, tmp)
        tmp_path = Path(tmp.name)
    try:
        resolved = file_type or detect_file_type(tmp_path, filename)
        try:
            result = run_parser(resolved, tmp_path, filename)
            error = None
        except ParserError as exc:
            result = ParseResult()
            error = str(exc)
        events = [
            {
                "timestamp": e.timestamp.isoformat() if e.timestamp else None,
                "timestamp_raw": e.timestamp_raw,
                "timestamp_precision": e.timestamp_precision,
                "timestamp_confidence": e.timestamp_confidence,
                "event_type": e.event_type,
                "source_record_id": e.source_record_id,
                "host": e.host,
                "user": e.user,
                "process_name": e.process_name,
                "file_path": e.file_path,
                "description": e.description,
                "warnings": e.warnings,
            }
            for e in result.events[:preview_limit]
        ]
        return {
            "filename": filename,
            "file_type": resolved,
            "record_count": result.record_count + (1 if error else 0),
            "accepted": len(result.events),
            "rejected": len(result.errors),
            "status": "failed" if (error or (result.errors and not result.events))
            else ("partial" if result.errors else "processed"),
            "preview": events,
            "errors": [e.to_dict() for e in result.errors][:100],
            "warnings": result.warnings + ([error] if error else []),
            "metadata": result.metadata,
            "timezone_note": result.timezone_note,
            "parser": next(
                (p for p in parser_catalog() if p["file_type"] == resolved), None
            ),
        }
    finally:
        tmp_path.unlink(missing_ok=True)


# --- convenience for demo datasets -------------------------------------------

def serialize_event(event: Event) -> dict:
    from ..normalization import dt_to_iso

    return {
        "timestamp": dt_to_iso(event.timestamp),
        "timestamp_raw": event.timestamp_raw,
        "timestamp_precision": event.timestamp_precision,
        "timestamp_confidence": event.timestamp_confidence,
        "timezone_note": event.timezone_note,
        "event_type": event.event_type,
        "source_type": event.source_type,
        "source_file": event.source_file,
        "source_record_id": event.source_record_id,
        "host": event.host,
        "user": event.user,
        "process_id": event.process_id,
        "process_name": event.process_name,
        "file_path": event.file_path,
        "device_id": event.device_id,
        "description": event.description,
    }


def ingest_records(
    db: Session,
    investigation: Investigation,
    filename: str,
    records: list[dict],
    file_type: str,
    source_type: str,
    note: str,
    sha: str | None = None,
    origin: str = "demo",
    parser_name: str = "structured_events",
    errors: list[dict] | None = None,
    metadata: dict | None = None,
    actor: str = "system",
) -> EvidenceSource:
    """Persist an already-validated list of normalized records (demo datasets)."""
    payload = json.dumps(records, sort_keys=True, default=str).encode("utf-8")
    digest = sha or hashlib.sha256(payload).hexdigest()
    directory = EVIDENCE_DIR / investigation.id
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / f"{digest[:24]}_{Path(filename).name}"
    if not path.exists():
        path.write_bytes(payload)

    errors = errors or []
    source = EvidenceSource(
        id=new_id(),
        investigation_id=investigation.id,
        filename=filename,
        file_type=file_type,
        source_type=source_type,
        stored_path=str(path),
        size_bytes=len(payload),
        sha256=digest,
        origin=origin,
        parser_name=parser_name,
        parser_version=PARSERS_VERSION,
        record_count=len(records) + len(errors),
        accepted_count=len(records),
        rejected_count=len(errors),
        status="processed" if not errors else "partial",
        timezone_note=note,
        metadata_json={**(metadata or {}), "synthetic": origin == "demo", "note": note,
                       "imported_by": actor},
        record_errors=errors,
    )
    db.add(source)
    db.flush()

    seq_base = db.query(Event).filter(Event.investigation_id == investigation.id).count()
    for offset, rec in enumerate(records):
        db.add(
            Event(
                id=new_id(),
                investigation_id=investigation.id,
                evidence_source_id=source.id,
                timestamp=_utc(datetime.fromisoformat(rec["timestamp"]))
                if rec.get("timestamp") else None,
                timestamp_raw=rec.get("timestamp_raw"),
                timestamp_precision=rec.get("timestamp_precision", "second"),
                timestamp_confidence=rec.get("timestamp_confidence", "high"),
                timezone_note=rec.get("timezone_note", note),
                event_type=rec.get("event_type", "unknown"),
                source_type=rec.get("source_type", source_type),
                source_file=rec.get("source_file", filename),
                source_record_id=rec.get("source_record_id", str(offset + 1)),
                host=rec.get("host"),
                user=rec.get("user"),
                process_id=rec.get("process_id"),
                process_name=rec.get("process_name"),
                file_path=rec.get("file_path"),
                device_id=rec.get("device_id"),
                description=rec.get("description"),
                raw_record_reference=rec.get("raw_record_reference", f"{filename}#{offset + 1}"),
                raw_record=rec.get("raw_record"),
                parser_name=parser_name,
                parser_version=PARSERS_VERSION,
                integrity_hash=None,
                ingestion_status="accepted",
                origin=origin,
                seq=seq_base + offset + 1,
            )
        )

    audit(db, "evidence.generated", investigation.id, actor,
          detail={"filename": filename, "records": len(records), "origin": origin, "note": note},
          entity_type="evidence_source", entity_id=source.id)
    return source