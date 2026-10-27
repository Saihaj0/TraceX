"""Normalized forensic event model shared by every parser.

Parsers emit `NormalizedEvent` instances; the ingestion service validates them
and persists them.  Rules:
  * never fabricate a value the source does not provide - leave it None
  * keep the original timestamp string next to the normalized one
  * record precision + confidence for every timestamp that is derived
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass, field, replace
from datetime import datetime, timezone


TIMESTAMP_PRECISIONS = ("second", "minute", "hour", "day", "unknown")
TIMESTAMP_CONFIDENCE = ("high", "medium", "low", "none")
INGESTION_STATUSES = ("accepted", "accepted_with_warnings", "rejected")


@dataclass
class NormalizedEvent:
    timestamp: datetime | None
    timestamp_raw: str | None
    timestamp_precision: str = "second"
    timestamp_confidence: str = "high"
    timezone_note: str | None = None
    event_type: str = "unknown"
    source_type: str = "unknown"
    source_file: str | None = None
    source_record_id: str | None = None
    host: str | None = None
    user: str | None = None
    process_id: int | None = None
    process_name: str | None = None
    file_path: str | None = None
    device_id: str | None = None
    description: str | None = None
    raw_record: dict | None = None
    raw_record_reference: str | None = None
    parser_name: str = "unknown"
    parser_version: str = "0"
    ingestion_status: str = "accepted"
    origin: str = "imported"
    warnings: list[str] = field(default_factory=list)

    def integrity_hash(self) -> str:
        """Stable SHA-256 of the normalized record *plus* its raw source record.

        This detects later modification of the stored representation.  A hash
        alone does not prove authenticity or chain of custody.
        """
        payload = {
            "timestamp_raw": self.timestamp_raw,
            "source_record_id": self.source_record_id,
            "source_file": self.source_file,
            "event_type": self.event_type,
            "description": self.description,
            "raw_record": self.raw_record,
        }
        blob = json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
        return hashlib.sha256(blob).hexdigest()

    def to_dict(self) -> dict:
        data = asdict(self)
        data["warnings"] = list(self.warnings)
        return data


def coerce_datetime(value) -> datetime | None:
    """Return an aware UTC datetime for many input shapes, else None."""
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        dt = value
    elif isinstance(value, (int, float)):
        # Magnitude-based epoch detection (source does not say which epoch it
        # used, so we choose the only unit that lands in a plausible range):
        #   >=1e17 -> NTFS FILETIME (100ns since 1601)
        #   >=1e14 -> microseconds since 1970
        #   >=1e11 -> milliseconds since 1970
        #   >=1e9  -> seconds since 1970
        if value >= 1e17:
            try:
                dt = datetime.fromtimestamp((value - 116444736000000000) / 10_000_000, tz=timezone.utc)
            except (OverflowError, OSError, ValueError):
                return None
        elif value >= 1e14:  # microseconds since epoch
            dt = datetime.fromtimestamp(value / 1_000_000, tz=timezone.utc)
        elif value >= 1e11:  # milliseconds since epoch
            dt = datetime.fromtimestamp(value / 1000, tz=timezone.utc)
        elif value >= 1e9:  # seconds since epoch
            dt = datetime.fromtimestamp(value, tz=timezone.utc)
        else:
            return None
    else:
        text = str(value).strip()
        if not text:
            return None
        if text.endswith(("Z", "z")):
            text = text[:-1] + "+00:00"
        # Windows FileTime: 100-ns intervals since 1601-01-01
        if text.isdigit() and len(text) >= 17:
            try:
                seconds = (int(text) - 116444736000000000) / 10_000_000
                dt = datetime.fromtimestamp(seconds, tz=timezone.utc)
            except (OverflowError, OSError, ValueError):
                return None
        else:
            try:
                dt = datetime.fromisoformat(text)
            except ValueError:
                from dateutil import parser as _dateutil

                try:
                    dt = _dateutil.parse(text)
                except (ValueError, OverflowError, TypeError):
                    return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def dt_to_iso(dt: datetime | None) -> str | None:
    if dt is None:
        return None
    if dt.tzinfo is None:
        # SQLite returns naive datetimes that were stored as UTC. Python's
        # astimezone() reinterprets a naive value as *local* wall-clock time,
        # which would silently shift every SQLite-backed timestamp by the
        # server's UTC offset. Policy: an absent offset means UTC.
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


_TIME_ONLY_RE = re.compile(r"^\d{1,2}:\d{2}(:\d{2})?")


def infer_timestamp_precision(raw: str | None) -> str:
    """Derive how precise a raw timestamp string actually is.

    ``2026-02-01`` only tells you the DAY — reporting it as second-precise
    would invent certainty the source never had.
    """
    if not raw:
        return "unknown"
    text = str(raw).strip()
    if text.isdigit():  # epoch / filetime values carry full precision
        return "second"
    if _TIME_ONLY_RE.match(text):
        # HH:MM or HH:MM:SS without a date
        return "minute" if len(text) <= 5 else "second"
    date_part, sep, time_part = text.partition("T")
    if not sep:
        date_part, _, time_part = text.partition(" ")
    if not time_part:
        return "day"
    # ignore a trailing timezone designator / numeric offset
    core = time_part.split("+")[0].rstrip("Zz")
    # a date-like suffix (2026-01-05) means the "time" part is actually a date
    if not any(ch.isdigit() for ch in core) or core.count("-") >= 2:
        return "day"
    if core.count(":") >= 2:
        return "second"
    if core.count(":") == 1:
        return "minute"
    return "hour"


def normalize_timestamp(value, precision: str | None = None, confidence: str | None = None,
                       timezone_note: str | None = None):
    """Normalize a timestamp and derive precision/confidence when not given."""
    raw = None if value is None else str(value)
    dt = coerce_datetime(value)
    if dt is None:
        return None, raw, "unknown", "none", timezone_note
    if precision not in TIMESTAMP_PRECISIONS:
        precision = infer_timestamp_precision(raw)
    if confidence not in TIMESTAMP_CONFIDENCE:
        # Coarser precision means a less certain moment in time; never present
        # a date-only value as if it were second-precise.
        confidence = {"day": "low", "hour": "medium", "minute": "medium"}.get(
            precision, "high")
    if timezone_note is None:
        timezone_note = "assumed UTC (source provided no timezone offset)"
    return dt, raw, precision, confidence, timezone_note


def with_origin(event: NormalizedEvent, origin: str) -> NormalizedEvent:
    return replace(event, origin=origin)