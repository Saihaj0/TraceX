"""Windows forensic artifact parsers (v1).

Two kinds of adapters, both honest about what they are:

* **Binary parser** that reads the artifact format directly:
  - Recycle Bin `$I` entries (WinVista+ layout: 8-byte version, 8-byte file
    size, 8-byte deletion FILETIME, 4-byte path length, unicode original path).

* **Export adapters** that consume CSV/text produced by established tools
  (MFTECmd for `$MFT`, WinPrefetchView for Prefetch, AppCompatCacheParser for
  ShimCache/UserAssist, `reg export` for UserAssist). Each adapter states the
  tool it expects in its description and records that provenance in metadata,
  because TRACE-X does not re-implement those tools' binary parsers — it
  normalises their output.

Every parser here follows the framework rules: never fabricate a value the
source does not provide; keep the raw timestamp string; record what is missing
as an error row rather than silently dropping it.
"""

from __future__ import annotations

import csv
import io
import re
from datetime import datetime, timezone
from pathlib import Path

from ..config import PARSERS_VERSION
from ..normalization import NormalizedEvent, coerce_datetime
from .base import BaseParser, ParseResult, ParserError, RowError, register

FILETIME_EPOCH_S = 11644473600  # 1601-01-01 -> 1970-01-01, in seconds


def filetime_to_datetime(value) -> datetime | None:
    """Windows FILETIME (100ns ticks since 1601-01-01 UTC) -> aware datetime."""
    if value in (None, "", 0, "0"):
        return None
    try:
        ticks = int(value)
    except (TypeError, ValueError):
        return None
    if ticks <= 0:
        return None
    try:
        return datetime.fromtimestamp(ticks / 10_000_000 - FILETIME_EPOCH_S,
                                      tz=timezone.utc)
    except (OverflowError, OSError, ValueError):
        return None


# ---------------------------------------------------------------------------
# Recycle Bin $I (binary)
# ---------------------------------------------------------------------------

@register
class RecycleBinIParser(BaseParser):
    name = "recycle_bin_i"
    version = PARSERS_VERSION
    display_name = "Recycle Bin $I entry (Windows Vista+)"
    file_types = ("recyclebin",)
    source_type = "recycle_bin"
    description = (
        "Binary $I metadata entries from $Recycle.Bin (version, original path, "
        "file size, deletion time). The companion $R file holds the content; "
        "$I alone does not prove what the file contained."
    )

    def parse(self, file_path, original_name: str | None = None) -> ParseResult:
        source_name = original_name or Path(file_path).name
        raw = Path(file_path).read_bytes()
        result = ParseResult(
            timezone_note="deletion time is a Windows FILETIME, converted to UTC"
        )
        if len(raw) < 24:
            raise ParserError(
                f"$I entry too short ({len(raw)} bytes; expected >= 24) — "
                "not a Vista+ $I record")

        version = int.from_bytes(raw[0:8], "little")
        if version not in (1, 2):
            result.warnings.append(
                f"unexpected $I version marker {version}; attempting parse anyway")

        file_size = int.from_bytes(raw[8:16], "little")
        deleted_ft = int.from_bytes(raw[16:24], "little")
        deleted_at = filetime_to_datetime(deleted_ft)
        path_len = int.from_bytes(raw[24:28], "little") if len(raw) >= 28 else 0

        original_path = None
        if path_len and len(raw) >= 28 + path_len * 2:
            original_path = raw[28:28 + path_len * 2].decode("utf-16-le", "replace").rstrip("\x00")
        elif len(raw) > 28:
            # Some tools strip the trailing nulls; decode what is present.
            original_path = raw[28:].decode("utf-16-le", "replace").rstrip("\x00")

        if deleted_at is None:
            result.errors.append(RowError(
                1, source_name, "missing_timestamp",
                f"FILETIME value {deleted_ft} does not resolve to a valid time"))
        if not original_path:
            result.errors.append(RowError(
                1, source_name, "missing_path",
                "no unicode original path present in the $I record"))

        result.events.append(NormalizedEvent(
            timestamp=deleted_at,
            timestamp_raw=str(deleted_ft),
            timestamp_precision="second",
            timestamp_confidence="high" if deleted_at else "none",
            timezone_note=result.timezone_note,
            event_type="recycle_bin_emptied" if not original_path else "file_deleted",
            source_type=self.source_type,
            source_file=source_name,
            source_record_id=source_name,
            file_path=original_path,
            description=(
                f"Recycle Bin entry: {original_path or '(path not recorded)'} "
                f"deleted at {deleted_at.isoformat() if deleted_at else 'unknown time'} "
                f"({file_size} bytes)"
            ),
            raw_record={
                "i_version": version,
                "file_size": file_size,
                "deletion_filetime": deleted_ft,
                "path_length_chars": path_len,
                "original_path": original_path,
            },
            raw_record_reference=f"{source_name}#$I",
            parser_name=self.name,
            parser_version=self.version,
        ))
        result.metadata["format"] = "recycle_bin_i_vista_plus"
        result.metadata["note"] = (
            "The $R companion file (content) is not parsed here; $I is metadata only."
        )
        return result


# ---------------------------------------------------------------------------
# $MFT via MFTECmd CSV export
# ---------------------------------------------------------------------------

def _pick(row: dict, *candidates: str) -> str | None:
    lowered = {k.lower().strip(): v for k, v in row.items() if k}
    for name in candidates:
        value = lowered.get(name.lower())
        if value not in (None, ""):
            return str(value).strip()
    return None


def _mft_time(value: str | None) -> datetime | None:
    """MFTECmd timestamps may be raw FILETIME ticks OR an ISO-like string
    with an offset — accept both, never invent one the source lacks."""
    if value in (None, ""):
        return None
    text = str(value).strip()
    if text.isdigit():
        return filetime_to_datetime(text)
    return coerce_datetime(text)


def _filetime_fields(row: dict) -> dict:
    """MFTECmd emits 'Created', 'Modified', 'Entry Modified', 'Accessed'."""
    return {
        "created": _mft_time(_pick(row, "Created", "Created10")),
        "modified": _mft_time(_pick(row, "Modified", "Modified10")),
        "entry_modified": _mft_time(_pick(row, "Entry Modified")),
        "accessed": _mft_time(_pick(row, "Accessed", "Accessed10")),
    }


@register
class MftCsvParser(BaseParser):
    name = "mft_mftecmd"
    version = PARSERS_VERSION
    display_name = "$MFT export (MFTECmd CSV)"
    file_types = ("mft",)
    source_type = "mft"
    description = (
        "CSV export of the NTFS Master File Table produced by MFTECmd "
        "(-csv). One event per MFT record with the standard MACB timestamps."
    )

    def parse(self, file_path, original_name: str | None = None) -> ParseResult:
        source_name = original_name or Path(file_path).name
        result = ParseResult(
            timezone_note="MFTECmd emits local timestamps with offset; values "
                          "are converted to UTC when an offset is present"
        )
        try:
            text = Path(file_path).read_text(encoding="utf-8-sig", errors="replace")
        except OSError as exc:
            raise ParserError(f"cannot read MFT export: {exc}") from exc

        reader = csv.DictReader(io.StringIO(text))
        if not reader.fieldnames:
            raise ParserError("MFT export has no CSV header row")

        for index, row in enumerate(reader, start=2):
            full_path = _pick(row, "Full Path", "Filename_2", "Path", "Filename")
            if not full_path:
                result.errors.append(RowError(
                    index, _pick(row, "Entry Number"), "missing_path",
                    "row has no Full Path / Filename value"))
                continue
            times = _filetime_fields(row)
            is_deleted = (_pick(row, "In Use", "Filename Significance") or "").lower() in ("false", "no")
            record_type = _pick(row, "Record Type") or "file"
            seq = _pick(row, "Entry Number", "Sequence Number")

            for slot, dt in times.items():
                if dt is None and _pick(row, {"created": "Created", "modified": "Modified",
                                              "entry_modified": "Entry Modified",
                                              "accessed": "Accessed"}[slot]):
                    result.errors.append(RowError(
                        index, seq, "unparseable_timestamp",
                        f"{slot} value could not be converted from FILETIME"))

            primary = times["entry_modified"] or times["modified"] or times["created"]
            flags = []
            if is_deleted:
                flags.append("deleted-in-mft")
            if record_type.lower() in ("directory", "folder"):
                flags.append("directory")

            result.events.append(NormalizedEvent(
                timestamp=primary,
                timestamp_raw=_pick(row, "Entry Modified", "Modified", "Created"),
                timestamp_precision="second",
                timestamp_confidence="high" if primary else "none",
                timezone_note=result.timezone_note,
                event_type="file_metadata_suspect" if is_deleted else "file_metadata",
                source_type=self.source_type,
                source_file=source_name,
                source_record_id=f"mft#{seq}" if seq else None,
                file_path=full_path,
                description=(
                    f"MFT record {seq or '?'} for {full_path}"
                    + (f" [{', '.join(flags)}]" if flags else "")
                ),
                raw_record={"full_path": full_path, "record_type": record_type,
                            "in_use": not is_deleted, "seq": seq,
                            "macb": {k: v.isoformat() if v else None
                                     for k, v in times.items()},
                            "raw_row": {k: v for k, v in row.items() if k}},
                raw_record_reference=f"{source_name}#mft.{seq}",
                parser_name=self.name,
                parser_version=self.version,
            ))
        result.metadata["source_tool"] = "MFTECmd CSV export"
        if not result.events and not result.errors:
            result.warnings.append("MFT export contained no data rows")
        return result


# ---------------------------------------------------------------------------
# Prefetch via WinPrefetchView CSV export
# ---------------------------------------------------------------------------

@register
class PrefetchCsvParser(BaseParser):
    name = "prefetch_winprefetchview"
    version = PARSERS_VERSION
    display_name = "Prefetch export (WinPrefetchView CSV)"
    file_types = ("prefetch",)
    source_type = "prefetch"
    description = (
        "CSV export from WinPrefetchView of .pf files: process name, run count "
        "and run times. Prefetch shows a program started, not who ran it."
    )

    def parse(self, file_path, original_name: str | None = None) -> ParseResult:
        source_name = original_name or Path(file_path).name
        result = ParseResult(
            timezone_note="run times converted to UTC; source times are local"
        )
        try:
            text = Path(file_path).read_text(encoding="utf-8-sig", errors="replace")
        except OSError as exc:
            raise ParserError(f"cannot read prefetch export: {exc}") from exc

        reader = csv.DictReader(io.StringIO(text))
        if not reader.fieldnames:
            raise ParserError("prefetch export has no CSV header row")

        for index, row in enumerate(reader, start=2):
            proc = _pick(row, "Process Name", "Executable Name", "Name")
            if not proc:
                result.errors.append(RowError(
                    index, None, "missing_process_name",
                    "row has no process name value"))
                continue
            run_count = _pick(row, "Run Count", "Run Count ")
            runs_raw = _pick(row, "Run Times", "Run Time")
            run_times: list[str] = []
            if runs_raw:
                # WinPrefetchView separates run times with ','
                for chunk in re.split(r"\s*,\s*", runs_raw):
                    dt = coerce_datetime(chunk) or filetime_to_datetime(chunk)
                    if dt is not None:
                        run_times.append(dt.isoformat())
            last_run = max(run_times) if run_times else None
            last_dt = coerce_datetime(last_run) if last_run else None

            result.events.append(NormalizedEvent(
                timestamp=last_dt,
                timestamp_raw=runs_raw,
                timestamp_precision="second",
                timestamp_confidence="high" if last_dt else "none",
                timezone_note=result.timezone_note,
                event_type="process_creation",
                source_type=self.source_type,
                source_file=source_name,
                source_record_id=f"pf#{proc}",
                process_name=proc,
                description=(
                    f"Prefetch records {int(run_count) if run_count and run_count.isdigit() else (run_count or 'unknown')} "
                    f"execution(s) of {proc}"
                    + (f"; last run {last_run}" if last_run else
                       "; no run times present in the export")
                ),
                raw_record={"process_name": proc, "run_count": run_count,
                            "run_times": run_times[:50],
                            "raw_row": {k: v for k, v in row.items() if k}},
                raw_record_reference=f"{source_name}#pf.{proc}",
                parser_name=self.name,
                parser_version=self.version,
            ))
        result.metadata["source_tool"] = "WinPrefetchView CSV export"
        if not result.events and not result.errors:
            result.warnings.append("prefetch export contained no data rows")
        return result


# ---------------------------------------------------------------------------
# ShimCache / UserAssist via AppCompatCacheParser or reg-export CSV
# ---------------------------------------------------------------------------

@register
class ShimCacheCsvParser(BaseParser):
    name = "shimcache_appcompat"
    version = PARSERS_VERSION
    display_name = "ShimCache/UserAssist export (AppCompatCacheParser CSV)"
    file_types = ("shimcache",)
    source_type = "registry_artifact"
    description = (
        "CSV export from AppCompatCacheParser (ShimCache) or UserAssistParser: "
        "execution path with last-modified/executed time. Registry execution "
        "artifacts record that an entry exists, not that the program ran."
    )

    def parse(self, file_path, original_name: str | None = None) -> ParseResult:
        source_name = original_name or Path(file_path).name
        result = ParseResult(
            timezone_note="artifact times converted to UTC"
        )
        try:
            text = Path(file_path).read_text(encoding="utf-8-sig", errors="replace")
        except OSError as exc:
            raise ParserError(f"cannot read shimcache export: {exc}") from exc

        reader = csv.DictReader(io.StringIO(text))
        if not reader.fieldnames:
            raise ParserError("shimcache export has no CSV header row")

        for index, row in enumerate(reader, start=2):
            path = _pick(row, "Path", "Entry", "Key", "Program")
            when = (_pick(row, "Modified", "Execution Time", "Last Modified",
                          "Last Run", "Timestamp")
                    or _pick(row, "Modified Time"))
            dt = coerce_datetime(when) or filetime_to_datetime(when)
            if not path:
                result.errors.append(RowError(
                    index, None, "missing_path", "row has no path/entry value"))
                continue
            if dt is None and when:
                result.errors.append(RowError(
                    index, path, "unparseable_timestamp",
                    f"timestamp value '{when}' could not be converted"))
            result.events.append(NormalizedEvent(
                timestamp=dt,
                timestamp_raw=when,
                timestamp_precision="second",
                timestamp_confidence="high" if dt else "none",
                timezone_note=result.timezone_note,
                event_type="process_creation",
                source_type=self.source_type,
                source_file=source_name,
                source_record_id=f"reg#{path}",
                file_path=path,
                process_name=Path(path.replace("\\", "/")).name or path,
                description=f"Registry execution artifact entry for {path}",
                raw_record={"path": path, "when": when,
                            "raw_row": {k: v for k, v in row.items() if k}},
                raw_record_reference=f"{source_name}#reg.{path}",
                parser_name=self.name,
                parser_version=self.version,
            ))
        result.metadata["source_tool"] = "AppCompatCacheParser / UserAssistParser CSV"
        if not result.events and not result.errors:
            result.warnings.append("shimcache export contained no data rows")
        return result


# ---------------------------------------------------------------------------
# UserAssist via `reg export` text
# ---------------------------------------------------------------------------

_ROT13 = str.maketrans(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "nopqrstuvwxyzabcdefghijklmNOPQRSTUVWXYZABCDEFGHIJKLM")


@register
class UserAssistRegParser(BaseParser):
    name = "userassist_reg"
    version = PARSERS_VERSION
    display_name = "UserAssist registry export (reg.exe export)"
    file_types = ("userassist",)
    source_type = "registry_artifact"
    description = (
        "Text output of `reg export HKCU\\...\\UserAssist`. Value names are "
        "ROT13-encoded paths; the binary blob carries a session count and a "
        "FILETIME last-run. Presence in UserAssist is not proof of manual "
        "execution — many entries are created by automatic shell activity."
    )

    def parse(self, file_path, original_name: str | None = None) -> ParseResult:
        source_name = original_name or Path(file_path).name
        result = ParseResult(
            timezone_note="last-run FILETIME converted to UTC"
        )
        try:
            raw = Path(file_path).read_bytes()
        except OSError as exc:
            raise ParserError(f"cannot read UserAssist export: {exc}") from exc
        # `reg export` writes UTF-16LE with a BOM, but hand-collected exports
        # are often plain UTF-8. Decode by BOM / null-byte sniffing — the
        # utf-16 codec raises on a BOM-less stream regardless of errors=.
        if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
            text = raw.decode("utf-16", errors="replace")
        elif b"\x00" in raw[:200]:
            text = raw.decode("utf-16-le", errors="replace")
        else:
            text = raw.decode("utf-8", errors="replace")

        # Value lines look like:  "ROT13name"=hex:xx,xx,...  (REG_BINARY)
        value_re = re.compile(r'^\s*"([^"]+)"\s*=\s*hex\s*:\s*(.*)$', re.IGNORECASE)
        for index, line in enumerate(text.splitlines(), start=1):
            match = value_re.match(line)
            if not match:
                continue
            encoded_name, hex_bytes = match.groups()
            decoded = encoded_name.translate(_ROT13)
            blob = bytes(int(b, 16) for b in re.findall(r"[0-9a-fA-F]{2}", hex_bytes))

            session_count = int.from_bytes(blob[4:8], "little") if len(blob) >= 8 else None
            # Win7+ layout: last-run FILETIME at offset 60; XP layout: offset 4+4.
            last_ft = None
            if len(blob) >= 68:
                last_ft = int.from_bytes(blob[60:68], "little")
            if (last_ft in (None, 0)) and len(blob) >= 12:
                last_ft = int.from_bytes(blob[4:12], "little")
            last_run = filetime_to_datetime(last_ft)

            if not decoded.strip():
                result.errors.append(RowError(
                    index, None, "missing_path",
                    "ROT13-decoded value name is empty"))
                continue
            result.events.append(NormalizedEvent(
                timestamp=last_run,
                timestamp_raw=str(last_ft) if last_ft else None,
                timestamp_precision="second",
                timestamp_confidence="high" if last_run else "none",
                timezone_note=result.timezone_note,
                event_type="process_creation",
                source_type=self.source_type,
                source_file=source_name,
                source_record_id=f"ua#{decoded}",
                file_path=decoded,
                process_name=Path(decoded.replace("\\", "/")).name or None,
                description=(
                    f"UserAssist entry for {decoded}"
                    + (f" (run {session_count} time(s))" if session_count is not None else "")
                    + ("" if last_run else " — no usable last-run time in the blob")
                ),
                raw_record={"rot13_name": encoded_name, "decoded_path": decoded,
                            "session_count": session_count,
                            "last_run_filetime": last_ft,
                            "blob_length": len(blob)},
                raw_record_reference=f"{source_name}#ua.{index}",
                parser_name=self.name,
                parser_version=self.version,
            ))
        result.metadata["source_tool"] = "reg.exe export (UserAssist key)"
        if not result.events and not result.errors:
            result.warnings.append(
                "no UserAssist value lines found — is this a reg export of the "
                "UserAssist key?")
        return result
