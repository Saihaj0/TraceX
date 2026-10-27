"""Helpers for describing evidence references in explanations."""

from __future__ import annotations

from ..models import Event, EvidenceSource
from ..normalization import dt_to_iso


def describe_evidence_ref(event: Event) -> dict:
    """A single, inspectable evidence row used inside finding explanations."""
    return {
        "event_id": event.id,
        "timestamp": dt_to_iso(event.timestamp),
        "event_type": event.event_type,
        "description": event.description,
        "source_file": event.source_file,
        "source_record_id": event.source_record_id,
        "raw_record_reference": event.raw_record_reference,
        "evidence_source_id": event.evidence_source_id,
        "source_type": event.source_type,
        "host": event.host,
        "user": event.user,
        "file_path": event.file_path,
        "process_name": event.process_name,
        "parser": f"{event.parser_name}@{event.parser_version}",
        "integrity_hash": event.integrity_hash,
        "origin": event.origin,
        "timestamp_confidence": event.timestamp_confidence,
        "ingestion_status": event.ingestion_status,
    }


def source_integrity(source: EvidenceSource) -> dict:
    return {
        "evidence_source_id": source.id,
        "filename": source.filename,
        "file_type": source.file_type,
        "source_type": source.source_type,
        "sha256": source.sha256,
        "size_bytes": source.size_bytes,
        "imported_at": source.imported_at.isoformat() if source.imported_at else None,
        "accepted": source.accepted_count,
        "rejected": source.rejected_count,
        "status": source.status,
        "origin": source.origin,
        "parser": f"{source.parser_name}@{source.parser_version}",
        "timezone_note": source.timezone_note,
        "integrity_note": (
            "SHA-256 supports integrity verification of the stored copy. A hash "
            "alone does not prove authenticity or chain of custody."
        ),
    }