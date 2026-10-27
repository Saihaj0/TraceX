"""Filesystem artifact parser.

Accepts structured filesystem metadata imports (CSV or JSON), including exports
of NTFS-related artifacts such as $MFT listings and USN Journal records.

Copy semantics: a file copy is NEVER confirmed from timestamps alone.  When
timestamps look "copied" we emit a warning and the derived event type stays
`file_metadata_suspect` with an explicit `possible_copy_pattern` note — the
correlation layer decides whether corroborating evidence exists.
"""

from __future__ import annotations

import csv
import json
from pathlib import Path

from ..config import PARSERS_VERSION
from ..normalization import NormalizedEvent, coerce_datetime, normalize_timestamp
from .base import BaseParser, ParseResult, ParserError, RowError, register

ALIASES = {
    "file_path": ["file_path", "path", "full_path", "filepath", "filename", "name", "member_name", "target"],
    "filename": ["filename", "file_name", "name"],
    "size": ["size", "file_size", "size_bytes", "filesize", "length"],
    "created": ["created", "ctime", "crtime", "created_time", "creation_time", "birth_time", "$STABLE_CREATED"],
    "modified": ["modified", "mtime", "mod_time", "write_time", "last_modified", "$STABLE_MODIFIED", "s_modified"],
    "accessed": ["accessed", "atime", "access_time", "last_access", "$STABLE_ACCESSED", "s_accessed"],
    "changed": ["changed", "ctime_ntfs", "mtime_mft", "metadata_changed", "change_time"],
    "deleted": ["deleted", "is_deleted", "isdeleted", "is_dead", "deletion", "deletion_state"],
    "usn": ["usn", "usn_number", "usn_journal", "sequence_number", "seq"],
    "reason": ["reason", "usn_reason", "change_reason", "action", "operation"],
    "file_id": ["file_id", "fid", "reference", "mft_entry", "inode", "file_reference"],
    "record_type": ["record_type", "artifact", "artifact_type", "source_kind"],
    "record_id": ["record_id", "id", "entry_id"],
    "host": ["host", "computer", "hostname", "device"],
    "user": ["user", "owner", "account", "username"],
    "drive": ["drive", "volume", "device_id", "volume_id"],
}

FS_HEADERS = {key for key in ALIASES}


def _norm_key(key: str) -> str:
    return str(key).strip().lower().replace(" ", "_").replace("-", "_")


def _get(row: dict, field: str):
    for alias in ALIASES.get(field, [field]):
        if alias in row and row[alias] not in (None, ""):
            return row[alias]
    return None


def is_filesystem_row(row: dict) -> bool:
    keys = {_norm_key(k) for k in row}
    has_path = bool(keys & {"file_path", "path", "full_path", "filepath", "filename", "file_name", "name"})
    has_time = bool(keys & FS_HEADERS & keys)
    return has_path and has_time


def _timestamp_fields(row: dict) -> dict:
    """Normalize the four NTFS timestamps with explicit provenance."""
    labels = {
        "created": "created",
        "modified": "modified",
        "accessed": "accessed",
        "changed": "metadata_changed",
    }
    out = {}
    for field, label in labels.items():
        raw = _get(row, field)
        if raw in (None, ""):
            out[label] = None
            continue
        dt = coerce_datetime(raw)
        out[label] = {"value": dt, "raw": str(raw), "present": True}
    return out


def _derive_event_type(row: dict, timestamps: dict) -> tuple[str, list[str]]:
    warnings: list[str] = []
    reason = str(_get(row, "reason") or "").upper()
    record_type = str(_get(row, "record_type") or "").lower()
    deleted = str(_get(row, "deleted") or "").lower()

    if deleted in ("1", "true", "yes", "deleted", "dead", "y"):
        return "file_deleted", warnings
    if "FILE_DELETE" in reason or "DELETE" in reason:
        return "file_deleted", warnings
    if "FILE_CREATE" in reason or "FILE_CREATE" in record_type.upper():
        return "file_created", warnings
    if "RENAME" in reason:
        return "file_renamed", warnings
    if "DATA_OVERWRITE" in reason or "CLOSE" in reason or "EXTEND" in reason:
        return "file_modified", warnings

    # Timestamp-consistency screen on the raw metadata columns.
    created = (timestamps.get("created") or {}).get("value")
    modified = (timestamps.get("modified") or {}).get("value")
    accessed = (timestamps.get("accessed") or {}).get("value")
    if created and modified and modified < created:
        warnings.append(
            "modified timestamp precedes created timestamp in the source record "
            "(metadata inconsistency candidate — not evidence of tampering on its own)"
        )
        return "file_metadata_suspect", warnings
    if created and accessed and accessed < created:
        warnings.append("accessed timestamp precedes created timestamp")

    # Equal MACE values suggest an operation reset all timestamps (common for
    # copies/extractions), but they do not prove a copy occurred.
    present = [t["value"] for t in timestamps.values() if t and t.get("value")]
    if len(present) >= 3 and len({t for t in present}) == 1:
        warnings.append(
            "created/modified/accessed timestamps are identical in the source record "
            "— possible copy or archive extraction; needs corroboration, not proven"
        )
        warnings.append("possible_copy_pattern (hypothesis only, requires corroborating evidence)")
        return "file_timestamps_equal", warnings

    if "mft" in record_type or _get(row, "usn") not in (None, ""):
        return "usn_journal_record", warnings
    return "filesystem_record", warnings


def _describe(row: dict, event_type: str, path: str | None) -> str:
    size = _get(row, "size")
    record_type = _get(row, "record_type") or "filesystem artifact"
    bits = [f"{event_type.replace('_', ' ')}: {path or 'unknown path'}"]
    if size not in (None, ""):
        bits.append(f"size {size} bytes")
    reason = _get(row, "reason")
    if reason:
        bits.append(f"reason {reason}")
    bits.append(f"record source {record_type}")
    return " ".join(str(b) for b in bits)


class FilesystemParserMixin:
    def _build_event(self, row: dict, index: int, source_name: str) -> NormalizedEvent | None:
        clean = {_norm_key(k): v for k, v in row.items()}
        path = _get(clean, "file_path")
        record_id = _get(clean, "record_id")
        timestamps = _timestamp_fields(clean)

        if path is None and not any(t and t.get("value") for t in timestamps.values()):
            return None  # caller records the rejection

        event_type, warnings = _derive_event_type(clean, timestamps)
        primary_field = "modified" if event_type in ("file_modified", "file_metadata_suspect") else "created"
        primary = timestamps.get(primary_field) or {}
        ts = primary.get("value")
        ts_raw = primary.get("raw")
        precision, confidence, note = (
            ("second", "high", "NTFS/FILETIME or source timestamp interpreted as UTC")
            if ts
            else ("unknown", "none", "no usable timestamp in source record")
        )
        usn = _get(clean, "usn")
        description = _describe(clean, event_type, path)
        if warnings:
            description += " [" + "; ".join(warnings) + "]"

        raw_ref = f"{source_name}#{record_id or index}"
        return NormalizedEvent(
            timestamp=ts,
            timestamp_raw=ts_raw,
            timestamp_precision=precision,
            timestamp_confidence=confidence,
            timezone_note=note,
            event_type=event_type,
            source_type="filesystem_artifact",
            source_file=source_name,
            source_record_id=str(record_id) if record_id not in (None, "") else str(index),
            host=_get(clean, "host"),
            user=_get(clean, "user"),
            process_id=None,
            process_name=None,
            file_path=path,
            device_id=_get(clean, "drive"),
            description=description,
            raw_record={
                "row": {k: v for k, v in clean.items()},
                "timestamps": {
                    k: ({"raw": v.get("raw"),
                         "iso": v["value"].isoformat() if v.get("value") else None}
                        if (v and v.get("present")) else None)
                    for k, v in timestamps.items()
                },
                "usn": usn,
                "file_id": _get(clean, "file_id"),
                "record_type": _get(clean, "record_type"),
                "declarative_notes": warnings,
            },
            raw_record_reference=raw_ref,
            parser_name=self.name,
            parser_version=self.version,
            warnings=warnings,
        )


@register
class FilesystemParser(FilesystemParserMixin, BaseParser):
    name = "filesystem_artifacts"
    version = PARSERS_VERSION
    display_name = "Filesystem / NTFS artifacts (CSV/JSON)"
    file_types = ("fsat",)
    source_type = "filesystem_artifact"
    description = "File listings, $MFT extracts and USN Journal exports (CSV or JSON)."

    def parse(self, file_path, original_name: str | None = None) -> ParseResult:
        source_name = original_name or Path(file_path).name
        suffix = Path(source_name).suffix.lower()
        result = ParseResult(timezone_note="source timestamps interpreted as UTC unless an offset is given")

        if suffix == ".json":
            rows = _load_json_rows(file_path, result)
        elif suffix == ".csv":
            rows = _load_csv_rows(file_path, result)
        else:
            raise ParserError("filesystem artifacts must be a .csv or .json file")

        if not rows:
            raise ParserError("no records found in filesystem artifact file")

        headers = {_norm_key(k) for k in rows[0]}
        if not (headers & {"file_path", "path", "full_path", "filepath", "filename", "file_name", "name"}):
            raise ParserError(
                "no file path column found — expected one of: " + ", ".join(ALIASES["file_path"])
            )

        for index, row in enumerate(rows, start=1):
            if not isinstance(row, dict):
                result.errors.append(
                    RowError(index, None, "row_not_object", f"expected an object, got {type(row).__name__}")
                )
                continue
            try:
                event = self._build_event(row, index, source_name)
            except Exception as exc:
                result.errors.append(RowError(index, None, "row_parse_error", str(exc), json_excerpt(row)))
                continue
            if event is None:
                result.errors.append(
                    RowError(
                        index,
                        str(row.get("record_id") or row.get("id") or index),
                        "missing_required_fields",
                        "row has neither a file path nor any timestamp",
                        json_excerpt(row),
                    )
                )
                continue
            result.events.append(event)

        result.metadata = {
            "format": suffix.lstrip("."),
            "columns": sorted(headers),
            "record_total": len(rows),
            "declared_artifact_types": sorted(
                {str(r.get("record_type") or r.get("artifact") or "") for r in rows if isinstance(r, dict)}
                - {""}
            ),
        }
        result.warnings.append(
            "Filesystem timestamps alone cannot confirm a copy, move or deletion; "
            "such operations are reported as hypotheses unless corroborated."
        )
        return result


def json_excerpt(row) -> str | None:
    try:
        text = json.dumps(row, default=str)
    except (TypeError, ValueError):
        text = str(row)
    return text[:400]


def _load_json_rows(path, result: ParseResult) -> list:
    try:
        with open(path, "r", encoding="utf-8-sig") as fh:
            data = json.load(fh)
    except (OSError, UnicodeDecodeError) as exc:
        raise ParserError(f"cannot read JSON file: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ParserError(f"invalid JSON at line {exc.lineno}: {exc.msg}") from exc

    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for key in ("events", "records", "entries", "files", "rows", "items", "data"):
            if isinstance(data.get(key), list):
                return data[key]
        # Single object treated as a one-row record file.
        return [data]
    raise ParserError("JSON root must be an array or an object containing a record array")


def _load_csv_rows(path, result: ParseResult) -> list[dict]:
    try:
        with open(path, "r", encoding="utf-8-sig", newline="") as fh:
            sample = fh.read(4096)
            fh.seek(0)
            try:
                dialect = csv.Sniffer().sniff(sample, delimiters=",;\t|")
            except csv.Error:
                dialect = csv.excel
            return [dict(row) for row in csv.DictReader(fh, dialect=dialect)]
    except (OSError, UnicodeDecodeError) as exc:
        raise ParserError(f"cannot read CSV file: {exc}") from exc