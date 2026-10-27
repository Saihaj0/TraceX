"""Timeline engine: filtering, ordering, uncertainty handling and export."""

from __future__ import annotations

import csv
import io
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone

from sqlalchemy import func, or_
from sqlalchemy.orm import Session

from ..models import Event, EvidenceSource, Investigation
from ..normalization import dt_to_iso


@dataclass
class TimelineFilter:
    start: datetime | None = None
    end: datetime | None = None
    event_types: list[str] = field(default_factory=list)
    source_ids: list[str] = field(default_factory=list)
    source_types: list[str] = field(default_factory=list)
    users: list[str] = field(default_factory=list)
    processes: list[str] = field(default_factory=list)
    files: list[str] = field(default_factory=list)
    devices: list[str] = field(default_factory=list)
    hosts: list[str] = field(default_factory=list)
    search: str | None = None
    sort: str = "asc"              # asc | desc
    include_undated: bool = True   # undated events are never dropped silently
    event_ids: list[str] = field(default_factory=list)
    limit: int = 200
    offset: int = 0

    @property
    def descending(self) -> str:
        return "desc"


def _apply_filters(query, investigation_id: str, f: TimelineFilter):
    query = query.filter(Event.investigation_id == investigation_id)
    if f.start:
        query = query.filter(Event.timestamp >= f.start)
    if f.end:
        query = query.filter(Event.timestamp <= f.end)
    if f.event_types:
        query = query.filter(Event.event_type.in_(f.event_types))
    if f.source_ids:
        query = query.filter(Event.evidence_source_id.in_(f.source_ids))
    if f.source_types:
        query = query.filter(Event.source_type.in_(f.source_types))
    if f.users:
        query = query.filter(Event.user.in_(f.users))
    if f.processes:
        query = query.filter(Event.process_name.in_(f.processes))
    if f.files:
        query = query.filter(Event.file_path.in_(f.files))
    if f.devices:
        query = query.filter(Event.device_id.in_(f.devices))
    if f.hosts:
        query = query.filter(Event.host.in_(f.hosts))
    if f.event_ids:
        query = query.filter(Event.id.in_(f.event_ids))
    if f.search:
        needle = f"%{f.search.lower()}%"
        query = query.filter(
            or_(
                func.lower(Event.description).like(needle),
                func.lower(func.coalesce(Event.file_path, "")).like(needle),
                func.lower(func.coalesce(Event.source_record_id, "")).like(needle),
                func.lower(func.coalesce(Event.event_type, "")).like(needle),
                func.lower(func.coalesce(Event.user, "")).like(needle),
                func.lower(func.coalesce(Event.process_name, "")).like(needle),
                func.lower(func.coalesce(Event.host, "")).like(needle),
            )
        )
    if not f.include_undated:
        query = query.filter(Event.timestamp.isnot(None))
    return query


def _order_clause(descending: bool):
    # NULL timestamps sort last in both directions so undated records are shown
    # as "time unknown" rather than buried or falsely sequenced.
    return (Event.timestamp.is_(None),) + ((Event.timestamp.desc(),) if descending else (Event.timestamp.asc(),))


def query_events(db: Session, investigation_id: str, f: TimelineFilter) -> tuple[list[Event], int]:
    query = _apply_filters(db.query(Event), investigation_id, f)
    total = query.count()
    query = query.order_by(*_order_clause(f.sort == "desc"), Event.seq.asc())
    query = query.offset(f.offset).limit(f.limit if f.limit > 0 else 500)
    return query.all(), total


def facets(db: Session, investigation_id: str, f: TimelineFilter) -> dict:
    """Distinct values for the timeline filter controls."""

    def distinct(column):
        rows = (
            _apply_filters(db.query(column), investigation_id, f)
            .filter(column.isnot(None))
            .distinct()
            .order_by(column)
            .limit(500)
            .all()
        )
        return [r[0] for r in rows]

    return {
        "event_types": distinct(Event.event_type),
        "users": distinct(Event.user),
        "processes": distinct(Event.process_name),
        "files": distinct(Event.file_path),
        "devices": distinct(Event.device_id),
        "hosts": distinct(Event.host),
        "source_types": distinct(Event.source_type),
        "sources": [
            {"id": s.id, "filename": s.filename, "file_type": s.file_type, "origin": s.origin}
            for s in db.query(EvidenceSource)
            .filter(EvidenceSource.investigation_id == investigation_id)
            .order_by(EvidenceSource.imported_at)
            .all()
        ],
    }


def event_to_dict(event: Event, include_raw: bool = False) -> dict:
    data = {
        "id": event.id,
        "investigation_id": event.investigation_id,
        "evidence_source_id": event.evidence_source_id,
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
        "raw_record_reference": event.raw_record_reference,
        "parser_name": event.parser_name,
        "parser_version": event.parser_version,
        "integrity_hash": event.integrity_hash,
        "ingestion_status": event.ingestion_status,
        "origin": event.origin,
        "warnings": _stored_warnings(event),
        "order_uncertain": False,
        "has_timestamp": event.timestamp is not None,
    }
    if include_raw:
        data["raw_record"] = event.raw_record
    return data


def _stored_warnings(event: Event) -> list[str]:
    meta = (event.raw_record or {}).get("declarative_notes") if isinstance(event.raw_record, dict) else None
    if isinstance(meta, list):
        return meta
    return []


def annotate_ordering(items: list[dict]) -> list[dict]:
    """Mark records whose relative order cannot be established precisely.

    Events sharing an identical timestamp (and events with precision coarser
    than a second) are shown as order-uncertain instead of implying a sequence
    the evidence cannot support.
    """
    for item in items:
        if item["timestamp_precision"] in ("minute", "hour", "day", "unknown") and item["has_timestamp"]:
            item["order_uncertain"] = True
    for i, item in enumerate(items):
        if not item["has_timestamp"]:
            item["order_uncertain"] = True
            continue
        prev_iso = items[i - 1]["timestamp"] if i > 0 and items[i - 1]["has_timestamp"] else None
        next_iso = items[i + 1]["timestamp"] if i + 1 < len(items) and items[i + 1]["has_timestamp"] else None
        if (prev_iso and prev_iso == item["timestamp"]) or (next_iso and next_iso == item["timestamp"]):
            item["order_uncertain"] = True
    return items


def timeline_payload(db: Session, investigation_id: str, f: TimelineFilter,
                     flagged_event_ids: set[str] | None = None) -> dict:
    flagged_event_ids = flagged_event_ids or set()
    items, total = query_events(db, investigation_id, f)
    payload = annotate_ordering([event_to_dict(e) for e in items])
    for item in payload:
        item["flagged"] = item["id"] in flagged_event_ids
    undated = sum(1 for i in payload if not i["has_timestamp"])
    return {
        "total": total,
        "offset": f.offset,
        "limit": f.limit,
        "returned": len(payload),
        "undated_in_page": undated,
        "sort": f.sort,
        "events": payload,
    }


EXPORT_FIELDS = [
    "event_id", "timestamp_utc", "timestamp_raw", "timestamp_precision",
    "timestamp_confidence", "timezone_note", "event_type", "source_type",
    "source_file", "source_record_id", "host", "user", "process_id",
    "process_name", "file_path", "device_id", "description", "origin",
    "parser_name", "parser_version", "integrity_hash", "ingestion_status",
]


def export_events(db: Session, investigation_id: str, f: TimelineFilter, fmt: str) -> tuple[str, str]:
    """Return (media_type, body) for the filtered event export."""
    if fmt == "json":
        _, total = query_events(db, investigation_id, f)
        f.limit = max(total, 1)
        f.offset = 0
        items, total = query_events(db, investigation_id, f)
        body = json.dumps(
            {
                "investigation_id": investigation_id,
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "filter": {k: v for k, v in f.__dict__.items()},
                "count": total,
                "note": "timestamps are ISO-8601 UTC; NULL timestamps are unknown, not zero",
                "events": [event_to_dict(e, include_raw=True) for e in items],
            },
            indent=2,
            default=str,
        )
        return "application/json", body

    _, _ = query_events(db, investigation_id, f)
    all_events, total = _full_query(db, investigation_id, f)
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=EXPORT_FIELDS, extrasaction="ignore")
    writer.writeheader()
    for event in all_events:
        row = event_to_dict(event)
        writer.writerow({
            "event_id": row["id"],
            "timestamp_utc": row["timestamp"] or "UNKNOWN",
            **{k: ("" if row.get(k) is None else row.get(k)) for k in EXPORT_FIELDS if k != "event_id"},
        })
    return "text/csv", buffer.getvalue()


def _full_query(db: Session, investigation_id: str, f: TimelineFilter):
    query = _apply_filters(db.query(Event), investigation_id, f)
    total = query.count()
    query = query.order_by(*_order_clause(f.sort == "desc"), Event.seq.asc()).limit(100_000)
    return query.all(), total


def timeline_stats(db: Session, investigation_id: str) -> dict:
    timed = (
        db.query(func.count(Event.id), func.min(Event.timestamp), func.max(Event.timestamp))
        .filter(Event.investigation_id == investigation_id, Event.timestamp.isnot(None))
        .one()
    )
    total = db.query(func.count(Event.id)).filter(
        Event.investigation_id == investigation_id
    ).scalar()
    undated = db.query(func.count(Event.id)).filter(
        Event.investigation_id == investigation_id, Event.timestamp.is_(None)
    ).scalar()
    low_conf = db.query(func.count(Event.id)).filter(
        Event.investigation_id == investigation_id,
        Event.timestamp_confidence.in_(("low", "none")),
    ).scalar()
    by_type = dict(
        db.query(Event.event_type, func.count(Event.id))
        .filter(Event.investigation_id == investigation_id)
        .group_by(Event.event_type)
        .all()
    )
    return {
        "total_events": total,
        "timed_events": timed[0] or 0,
        "undated_events": undated or 0,
        "low_confidence_timestamps": low_conf or 0,
        "first_event": dt_to_iso(timed[1]),
        "last_event": dt_to_iso(timed[2]),
        "event_type_counts": sorted(by_type.items(), key=lambda kv: kv[1], reverse=True),
    }


def parse_dt(value: str | None) -> datetime | None:
    if not value:
        return None
    text = value.strip()
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        from ..normalization import coerce_datetime

        return coerce_datetime(value)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)