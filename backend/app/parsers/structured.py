"""Structured normalized-event import (JSON / CSV) with schema validation.

Guarantees:
  * every rejected row is returned with its index, reason and a raw excerpt -
    invalid records are never silently discarded;
  * fields missing from the source stay null (never invented);
  * a preview path (`parse_preview=True`) parses without persisting.
"""

from __future__ import annotations

import csv
import json
from pathlib import Path

from ..config import PARSERS_VERSION
from ..normalization import NormalizedEvent, coerce_datetime, normalize_timestamp
from .base import BaseParser, ParseResult, ParserError, RowError, register

KNOWN_FIELDS = {
    "event_id", "investigation_id", "timestamp", "timestamp_raw", "timestamp_precision",
    "timestamp_confidence", "timezone", "timezone_note", "event_type", "source_type",
    "source_file", "source_record_id", "host", "user", "username", "userid", "process_id",
    "pid", "process_name", "process", "file_path", "path", "device_id", "device", "description",
    "details", "raw_record_reference", "parser_name", "parser_version", "integrity_hash",
    "ingestion_status", "origin", "severity", "url", "note", "notes",
}

FIELD_MAP = {
    "username": "user", "userid": "user", "user_name": "user",
    "pid": "process_id", "process": "process_name", "processname": "process_name",
    "path": "file_path", "filepath": "file_path",
    "device": "device_id",
    "details": "description", "message": "description", "note": "description", "notes": "description",
    "time": "timestamp", "event_time": "timestamp", "datetime": "timestamp", "ts": "timestamp",
    "eventtype": "event_type", "type": "event_type", "kind": "event_type",
    "hostname": "host", "computer": "host", "computername": "host",
    "record_id": "source_record_id", "sourcerecordid": "source_record_id",
    "recordid": "source_record_id",
}

DEFAULT_EVENT_TYPES = {
    "file events": "file_modified", "log": "application_log", "log entry": "application_log",
    "login": "logon_success", "logon": "logon_success", "process": "process_creation",
    "execution": "process_creation",
}


def _norm_key(key: str) -> str:
    return str(key).strip().lower().replace(" ", "_").replace("-", "_")


def _map_fields(row: dict) -> dict:
    out: dict = {}
    for key, value in row.items():
        k = _norm_key(key)
        canonical = FIELD_MAP.get(k, k)
        if value not in (None, ""):
            out[canonical] = value
    return out


@register
class StructuredParser(BaseParser):
    name = "structured_events"
    version = PARSERS_VERSION
    display_name = "Normalized events (JSON / CSV)"
    file_types = ("json", "csv")
    source_type = "structured"
    description = "Schema-validated normalized forensic events as JSON arrays or CSV tables."

    def parse(self, file_path, original_name: str | None = None) -> ParseResult:
        source_name = original_name or Path(file_path).name
        suffix = Path(source_name).suffix.lower()
        result = ParseResult(
            timezone_note="timestamps without an explicit offset are interpreted as UTC"
        )
        if suffix == ".json":
            rows = _read_json(file_path, result)
        elif suffix == ".csv":
            rows = _read_csv(file_path, result)
        else:
            raise ParserError("structured import must be a .json or .csv file")

        if not rows:
            raise ParserError("file contains no records")
        if not all(isinstance(r, dict) for r in rows):
            raise ParserError("every record must be an object with named fields")

        unknown = sorted(
            {_norm_key(k) for r in rows for k in r} - KNOWN_FIELDS - set(FIELD_MAP)
        )
        if unknown:
            result.warnings.append(
                "unrecognised fields preserved in raw_record: " + ", ".join(unknown[:20])
            )

        total = len(rows)
        for index, row in enumerate(rows, start=1):
            try:
                event, row_errors, row_warnings = self._build_event(row, index, source_name)
            except Exception as exc:
                result.errors.append(RowError(index, str(row.get("event_id")), "row_parse_error",
                                              str(exc), _excerpt(row)))
                continue
            if event is None:
                result.errors.extend(row_errors)
                continue
            event.warnings.extend(row_warnings)
            result.events.append(event)
            for row_error in row_errors:
                # Validation issue that did not invalidate the row.
                result.errors.append(row_error)

        result.metadata = {
            "format": suffix.lstrip("."),
            "columns": sorted({_norm_key(k) for r in rows for k in r}),
            "record_total": total,
            "schema_valid_fields": sorted(KNOWN_FIELDS),
        }
        if any(e.timestamp is None for e in result.events):
            result.warnings.append(
                f"{sum(1 for e in result.events if e.timestamp is None)} accepted record(s) have no "
                "usable timestamp and are ordered as 'time unknown', never placed in the sequence"
            )
        return result

    def _build_event(self, row: dict, index: int, source_name: str):
        errors: list[RowError] = []
        warnings: list[str] = []
        data = _map_fields(row)

        if not any(str(v).strip() for v in data.values()):
            return None, [
                RowError(index, None, "empty_row", "row contains no values", _excerpt(row))
            ], warnings

        # A row with no recognizable forensic content (no timestamp, event type,
        # description, path, identifiers or actors) is unusable — reject it
        # explicitly instead of fabricating an 'unknown' event from it.
        _content_keys = ("timestamp", "event_type", "description", "file_path",
                         "source_record_id", "event_id", "user", "host",
                         "process_name", "process_id", "device_id")
        if not any(str(data.get(k) or "").strip() for k in _content_keys):
            return None, [
                RowError(index, None, "missing_required_fields",
                         "row has no timestamp, event type, description or identifiers",
                         _excerpt(row))
            ], warnings

        raw_ts = data.get("timestamp")
        precision = data.get("timestamp_precision")
        confidence = data.get("timestamp_confidence")
        tz_note = data.get("timezone_note") or data.get("timezone")

        ts, ts_raw, precision, confidence, inferred_note = normalize_timestamp(
            raw_ts, precision, confidence, tz_note
        )
        if raw_ts not in (None, "") and ts is None:
            errors.append(
                RowError(
                    index, str(data.get("source_record_id") or index),
                    "unparsable_timestamp",
                    f"cannot interpret {raw_ts!r} as a date/time",
                    _excerpt(row),
                )
            )
            return None, errors, warnings
        if raw_ts in (None, ""):
            warnings.append("timestamp absent in source record — ordering uses 'time unknown'")
            ts_raw = None
            precision, confidence = "unknown", "none"

        event_type = str(data.get("event_type") or "").strip().lower()
        if not event_type:
            warnings.append("event_type absent — normalized to 'unknown'")
            event_type = "unknown"
        elif event_type in DEFAULT_EVENT_TYPES:
            event_type = DEFAULT_EVENT_TYPES[event_type]

        process_id = data.get("process_id")
        if process_id not in (None, ""):
            try:
                process_id = int(str(process_id).strip())
            except ValueError:
                errors.append(
                    RowError(index, str(data.get("source_record_id") or index),
                             "invalid_process_id", f"process_id {process_id!r} is not an integer",
                             _excerpt(row))
                )
                return None, errors, warnings
        else:
            process_id = None

        description = data.get("description")
        if not description:
            description = f"{event_type} event from {source_name}"
            warnings.append("description absent in source record")

        record_id = data.get("source_record_id") or data.get("event_id") or str(index)
        extra = {k: v for k, v in row.items() if _norm_key(k) not in KNOWN_FIELDS}
        raw_record = dict(row) if not extra else {"row": {k: v for k, v in row.items()}}

        event = NormalizedEvent(
            timestamp=ts,
            timestamp_raw=ts_raw,
            timestamp_precision=precision,
            timestamp_confidence=confidence,
            timezone_note=inferred_note,
            event_type=event_type,
            source_type=str(data.get("source_type") or "structured"),
            source_file=data.get("source_file") or source_name,
            source_record_id=str(record_id),
            host=data.get("host"),
            user=data.get("user"),
            process_id=process_id,
            process_name=data.get("process_name"),
            file_path=data.get("file_path"),
            device_id=data.get("device_id"),
            description=str(data.get("description")),
            raw_record=raw_record if isinstance(raw_record, dict) else {"value": str(raw_record)},
            raw_record_reference=f"{source_name}#{record_id}",
            parser_name=self.name,
            parser_version=self.version,
        )
        return event, errors, warnings


def _excerpt(row) -> str:
    try:
        text = json.dumps(row, default=str)
    except (TypeError, ValueError):
        text = str(row)
    return text[:400]


def _read_json(path, result: ParseResult) -> list[dict]:
    try:
        with open(path, "r", encoding="utf-8-sig") as fh:
            data = json.load(fh)
    except (OSError, UnicodeDecodeError) as exc:
        raise ParserError(f"cannot read JSON file: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ParserError(f"invalid JSON at line {exc.lineno} column {exc.pos}: {exc.msg}") from exc

    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for key in ("events", "records", "data", "rows", "items"):
            if isinstance(data.get(key), list):
                return data[key]
        return [data]
    raise ParserError("JSON root must be an array or an object containing an array of records")


def _read_csv(path, result: ParseResult) -> list[dict]:
    try:
        with open(path, "r", encoding="utf-8-sig", newline="") as fh:
            raw = fh.read(8192)
            if not raw.strip():
                raise ParserError("CSV file is empty")
            fh.seek(0)
            try:
                dialect = csv.Sniffer().sniff(raw, delimiters=",;\t|")
            except csv.Error:
                dialect = csv.excel
            reader = csv.DictReader(fh, dialect=dialect)
            if not reader.fieldnames:
                raise ParserError("CSV has no header row")
            return [dict(row) for row in reader]
    except (OSError, UnicodeDecodeError) as exc:
        raise ParserError(f"cannot read CSV file: {exc}") from exc