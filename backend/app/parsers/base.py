"""Parser framework + registry.

Each parser declares `name`, `version`, the `source_type` it produces and the
evidence `file_type` it accepts, and exposes `parse(path) -> ParseResult`.

`ParseResult` carries accepted events *and* row-level errors: invalid records
are never silently discarded, the API surfaces them for inspection.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from ..normalization import NormalizedEvent


UNKNOWN_FIELD_NOTE = "field not present in source artifact (recorded as null, not inferred)"


@dataclass
class RowError:
    row_index: int | None
    record_id: str | None
    reason: str
    detail: str | None = None
    raw_excerpt: str | None = None

    def to_dict(self) -> dict:
        return {
            "row_index": self.row_index,
            "record_id": self.record_id,
            "reason": self.reason,
            "detail": self.detail,
            "raw_excerpt": self.raw_excerpt,
        }


@dataclass
class ParseResult:
    events: list[NormalizedEvent] = field(default_factory=list)
    errors: list[RowError] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)
    timezone_note: str | None = None

    @property
    def accepted(self) -> int:
        return len(self.events)

    @property
    def rejected(self) -> int:
        return len(self.errors)

    @property
    def record_count(self) -> int:
        return self.accepted + self.rejected


class ParserError(Exception):
    """Raised when a file cannot be parsed at all (format level)."""


class BaseParser:
    name = "base"
    version = "0"
    display_name = "Base parser"
    file_types: tuple[str, ...] = ()
    source_type = "unknown"
    description = ""

    def parse(self, file_path, original_name: str | None = None) -> ParseResult:  # pragma: no cover
        raise NotImplementedError

    def accepts(self, file_type: str) -> bool:
        return file_type in self.file_types


_REGISTRY: dict[str, BaseParser] = {}


def register(parser):
    """Register a parser class or instance under its primary file type."""
    instance = parser() if isinstance(parser, type) else parser
    # Register under EVERY advertised file type (e.g. structured handles json
    # and csv) so `run_parser("csv", ...)` never dead-ends.
    for file_type in instance.file_types:
        _REGISTRY[file_type] = instance
    return parser


def get_parser(file_type: str) -> BaseParser | None:
    _load()
    return _REGISTRY.get(file_type)


def detect_file_type(file_path, original_name: str) -> str:
    """Decide which parser should handle an uploaded artifact.

    Sniffs content where the extension is ambiguous (`History` databases have no
    extension, `.json` may be a filesystem export or normalized events).
    """
    import sqlite3

    _load()
    lower = original_name.lower()
    suffix = Path(original_name).suffix.lower().lstrip(".")
    header = b""
    try:
        with open(file_path, "rb") as fh:
            # 64 bytes: covers the evtx magic, SQLite magic and the 24+ byte
            # minimum size of a Recycle Bin $I record's fixed fields.
            header = fh.read(64)
    except OSError:
        pass

    if suffix == "evtx" or header[:4] in (b"ElfF", b"ElfB"):
        return "evtx"
    if header.startswith(b"SQLite format 3") or lower in ("history", "history.db"):
        from .browser import is_browser_db
        if is_browser_db(file_path):
            return "browser"
    # Recycle Bin $I entries: binary, named $I<random> inside $Recycle.Bin.
    if lower.startswith("$i") and len(header) >= 24:
        return "recyclebin"
    if suffix == "csv":
        import csv

        with open(file_path, "r", encoding="utf-8-sig", newline="") as fh:
            first = fh.read(4096)
        try:
            fieldnames = csv.Sniffer().sniff(first, delimiters=",;\t|").delimiter
        except csv.Error:
            fieldnames = ","
        header_row = first.splitlines()[0].lower() if first else ""
        columns = {c.strip().lower() for c in header_row.split(fieldnames)}
        # Tool-specific CSV exports take precedence over the generic sniffers.
        if "full path" in columns or "entry number" in columns:
            return "mft"
        if "process name" in columns and ("run count" in columns or "run times" in columns):
            return "prefetch"
        if "execution time" in columns or (
                "path" in columns and "modified" in columns
                and "entry" not in columns and "usn" not in columns
                and "mtime" not in columns):
            return "shimcache"
        if columns & {"file_path", "path", "filename", "file_name", "full_path", "usn", "mtime", "ctime"}:
            if columns & {"timestamp", "event_type", "eventid", "event_id", "description", "host"}:
                return "csv"
            return "fsat"
        return "csv"
    if suffix == "reg":
        return "userassist"
    if suffix == "json":
        try:
            with open(file_path, "r", encoding="utf-8-sig") as fh:
                head = fh.read(200_000)
        except (OSError, UnicodeDecodeError):
            return "json"
        lowered = head.lower()
        fs_hits = sum(1 for token in ('"mtime"', '"ctime"', '"usn"', '"file_path"', '"full_path"', '"deleted"') if token in lowered)
        if fs_hits >= 2 and '"event_type"' not in lowered:
            return "fsat"
        return "json"
    if suffix in ("db", "sqlite", "sqlite3"):
        return "browser"
    return suffix or "json"
    pass


def all_parsers() -> list[BaseParser]:
    _load()
    return list(_REGISTRY.values())


_loaded = False


def _load() -> None:
    global _loaded
    if _loaded:
        return
    _loaded = True
    from . import browser, evtx, filesystem, structured, windows  # noqa: F401


def parser_catalog() -> list[dict]:
    return [
        {
            "file_type": p.file_types[0],
            "name": p.name,
            "display_name": p.display_name,
            "version": p.version,
            "source_type": p.source_type,
            "description": p.description,
        }
        for p in sorted(all_parsers(), key=lambda p: p.name)
    ]