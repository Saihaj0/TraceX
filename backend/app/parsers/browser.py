"""Chromium-family browser history parser (history.dat / History SQLite DB).

Extracts url, visit time and visit count from `urls` + `visits`.  Record the
visit as evidence of recorded browser activity only - browser history is not
proof of who operated the machine or of intent.
"""

from __future__ import annotations

import shutil
import sqlite3
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from ..config import PARSERS_VERSION
from ..normalization import NormalizedEvent, coerce_datetime
from .base import BaseParser, ParseResult, ParserError, RowError, register

# Chromium stores WebKit/Chrome epoch time in µs since 1601-01-01 UTC.
CHROMIUM_EPOCH_OFFSET_S = 11644473600


def chromium_time_to_datetime(value) -> datetime | None:
    if value in (None, 0, ""):
        return None
    try:
        seconds = int(value) / 1_000_000 - CHROMIUM_EPOCH_OFFSET_S
    except (TypeError, ValueError):
        return None
    if seconds <= 0:
        return None
    try:
        return datetime.fromtimestamp(seconds, tz=timezone.utc)
    except (OverflowError, OSError, ValueError):
        return None


def is_browser_db(file_path) -> bool:
    """True when a SQLite file looks like a Chromium history database."""
    path = Path(file_path)
    if path.stat().st_size < 100:
        return False
    with open(path, "rb") as fh:
        header = fh.read(16)
    if not header.startswith(b"SQLite format 3"):
        return False
    try:
        con = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=3)
        try:
            rows = con.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name IN ('urls','visits')"
            ).fetchall()
        finally:
            con.close()
    except sqlite3.Error:
        return False
    return {name for name, in rows} >= {"urls", "visits"}


@register
class BrowserHistoryParser(BaseParser):
    name = "chromium_history"
    version = PARSERS_VERSION
    display_name = "Chromium browser history (SQLite)"
    file_types = ("browser",)
    source_type = "browser_history"
    description = "Chromium-compatible history databases (urls + visits tables)."

    def parse(self, file_path, original_name: str | None = None) -> ParseResult:
        source_name = original_name or Path(file_path).name
        result = ParseResult(
            timezone_note="Chromium epoch (µs since 1601-01-01 UTC) converted to UTC"
        )
        tmp_dir = tempfile.mkdtemp(prefix="tracex_browser_")
        working = Path(tmp_dir) / "history.db"
        try:
            shutil.copyfile(file_path, working)
            con = sqlite3.connect(f"file:{working}?mode=ro", uri=True)
        except (OSError, sqlite3.Error) as exc:
            raise ParserError(f"cannot open browser history database: {exc}") from exc

        try:
            tables = {
                name
                for name, in con.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                ).fetchall()
            }
            if "urls" not in tables:
                raise ParserError("SQLite database has no `urls` table (not a Chromium history file)")

            visit_columns = set()
            if "visits" in tables:
                visit_columns = {r[1] for r in con.execute("PRAGMA table_info(visits)").fetchall()}
            url_columns = {r[1] for r in con.execute("PRAGMA table_info(urls)").fetchall()}

            result.metadata["tables_present"] = sorted(tables & {"urls", "visits", "downloads"})
            result.metadata["profile_hint"] = source_name

            query = "SELECT id, url, title, visit_count, last_visit_time FROM urls"
            rows = con.execute(query).fetchall()
            for index, (url_id, url, title, visit_count, last_visit) in enumerate(rows, start=1):
                if not url:
                    result.errors.append(
                        RowError(index, f"urls#{url_id}", "missing_url", "row has no url value")
                    )
                    continue
                # Per-visit times are preferred over the aggregate last_visit_time.
                visit_times: list[int] = []
                if "visits" in tables and "visit_time" in visit_columns:
                    visit_times = [
                        vt
                        for (vt,) in con.execute(
                            "SELECT visit_time FROM visits WHERE url_id = ? ORDER BY visit_time",
                            (url_id,),
                        )
                    ]
                times = [t for t in visit_times if chromium_time_to_datetime(t)]
                if not times:
                    ct = chromium_time_to_datetime(last_visit)
                    if ct is None:
                        result.errors.append(
                            RowError(
                                index,
                                f"urls#{url_id}",
                                "missing_timestamp",
                                "no visit_time and no usable last_visit_time",
                                raw_excerpt=str(url)[:200],
                            )
                        )
                        continue
                    times = [None]  # type: ignore[arg-type]
                    warnings = ["no per-visit timestamp; last_visit_time used"]
                else:
                    warnings = []

                raw_dt = times[0] if isinstance(times[0], int) else last_visit
                dt = chromium_time_to_datetime(raw_dt)
                description = f"Browser visit to {url}"
                if title:
                    description += f" — \"{title}\""
                if not warnings:
                    description += f" (recorded {visit_count or 1} time(s))"

                result.events.append(
                    NormalizedEvent(
                        timestamp=dt,
                        timestamp_raw=str(raw_dt),
                        timestamp_precision="second",
                        timestamp_confidence="high",
                        timezone_note=result.timezone_note,
                        event_type="browser_visit",
                        source_type=self.source_type,
                        source_file=source_name,
                        source_record_id=f"urls#{url_id}",
                        host=None,
                        user=None,
                        process_id=None,
                        process_name=None,
                        file_path=None,
                        device_id=None,
                        description=description,
                        raw_record={
                            "url": url,
                            "title": title,
                            "visit_count": visit_count,
                            "last_visit_time": last_visit,
                            "visit_times": visit_times[:20],
                            "profile_hint": source_name,
                        },
                        raw_record_reference=f"{source_name}#urls.{url_id}",
                        parser_name=self.name,
                        parser_version=self.version,
                        warnings=warnings,
                    )
                )
        finally:
            con.close()
            try:
                working.unlink(missing_ok=True)
                Path(tmp_dir).rmdir()
            except OSError:
                pass

        if not result.events and not result.errors:
            result.warnings.append("history database contained no url rows")
        return result