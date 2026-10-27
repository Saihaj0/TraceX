"""Parsing, normalization, invalid-row reporting and format detection."""

from __future__ import annotations

import hashlib
import json

from app.services.ingest import detect_file_type, preview_file, run_parser, sha256_file


def _write(tmp_path, name: str, data: bytes):
    path = tmp_path / name
    path.write_bytes(data)
    return path


def _make_history(path):
    """A minimal Chromium-compatible History SQLite database."""
    import sqlite3

    # Chrome epoch (1601-01-01) microseconds for 2026-01-05 10:00:00 UTC
    chrome_us = 13412080800000000
    con = sqlite3.connect(path)
    con.execute("""CREATE TABLE visits (
        id INTEGER PRIMARY KEY, url_id INTEGER, visit_time INTEGER,
        from_visit INTEGER, transition INTEGER, visit_duration INTEGER)""")
    con.execute("""CREATE TABLE urls (
        id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER,
        typed_count INTEGER, last_visit_time INTEGER, hidden INTEGER)""")
    con.execute(
        "INSERT INTO urls (id, url, title, visit_count, last_visit_time) "
        "VALUES (1, 'https://example.org/', 'Example', 2, ?)", (chrome_us,))
    con.execute("INSERT INTO visits (id, url_id, visit_time, transition) VALUES (1, 1, ?, 0)",
                (chrome_us,))
    con.commit()
    con.close()
    return path


def test_detect_file_type(tmp_path):
    assert detect_file_type(_write(tmp_path, "security.evtx", b"x"), "security.evtx") == "evtx"
    assert detect_file_type(_write(tmp_path, "e.json", b"[]"), "e.json") == "json"
    assert detect_file_type(_write(tmp_path, "m.csv", b"a,b"), "m.csv") == "csv"
    # A real Chromium history file (no extension, SQLite content) is sniffed.
    assert detect_file_type(_make_history(tmp_path / "History"), "History") == "browser"


def test_json_parse_normalizes_and_preserves_raw(tmp_path):
    payload = [
        {"timestamp": "2026-01-05T10:00:00Z", "event_type": "process_creation",
         "description": "cmd started", "user": "alice",
         "file_path": "C:\\Windows\\cmd.exe", "source_record_id": "r-1"},
        # missing timestamp: must be accepted with an explicit uncertainty note
        {"event_type": "file_access", "description": "undated row",
         "file_path": "C:\\temp\\a.txt", "source_record_id": "r-2"},
        # invalid row: no identifiers at all — must be rejected, not dropped silently
        {},
    ]
    path = _write(tmp_path, "events.json", json.dumps(payload).encode())
    result = run_parser("json", path, "events.json")

    assert result.record_count == 3
    assert len(result.events) == 2
    assert len(result.errors) == 1
    err = result.errors[0].to_dict()
    assert err["reason"] in {"missing_required_fields", "empty_row", "row_parse_error"}
    assert err["row_index"] is not None

    ok, undated = result.events
    assert ok.timestamp is not None
    assert ok.timestamp_raw == "2026-01-05T10:00:00Z"   # original preserved
    assert ok.timestamp_confidence in {"high", "medium", "low"}
    assert undated.timestamp is None
    assert any("timestamp" in w.lower() for w in undated.warnings) or undated.timestamp_confidence != "high"


def test_csv_parse_reports_row_errors(tmp_path):
    lines = [
        "timestamp,event_type,description,file_path",
        "2026-01-05T11:00:00Z,file_deleted,deleted note,C:\\Users\\a\\note.txt",
        ",,,,bad row with garbage",            # invalid: no timestamp
        "not-a-timestamp,process_creation,broken time,C:\\x.exe",  # unparsable
    ]
    path = _write(tmp_path, "fs.csv", ("\n".join(lines)).encode())
    result = run_parser("csv", path, "fs.csv")

    assert len(result.events) >= 1
    assert any(e.row_index == 2 for e in result.errors)  # invalid rows are located
    reasons = {e.reason for e in result.errors}
    assert reasons  # each rejection carries a machine-readable reason


def test_garbage_bytes_fail_loudly(tmp_path):
    """A corrupted JSON file must produce a parse failure, never zero events silently."""
    path = _write(tmp_path, "broken.json", b"{ not json")
    try:
        result = run_parser("json", path, "broken.json")
    except Exception:
        return  # ParserError path — surfaced to the caller
    # If the parser recovers, the failure must still be recorded.
    assert result.errors or result.warnings, "corrupt input silently ignored"


def test_preview_does_not_persist_and_reports_status(tmp_path):
    payload = [{"timestamp": "2026-01-05T10:00:00Z", "event_type": "process_creation",
                "description": "x", "file_path": "C:\\a.exe"}, {}]
    preview = preview_file("up.json", content=json.dumps(payload).encode())

    assert preview["filename"] == "up.json"
    assert preview["record_count"] == 2
    assert preview["accepted"] == 1
    assert preview["rejected"] == 1
    assert preview["status"] in {"partial", "processed"}
    assert isinstance(preview["errors"], list) and preview["errors"]
    assert preview["timezone_note"] or preview["parser"]
    assert preview["preview"][0]["timestamp"].startswith("2026-01-05")


def test_sha256_integrity_helpers(tmp_path):
    path = _write(tmp_path, "evidence.bin", b"evidence-bytes")
    expected = hashlib.sha256(b"evidence-bytes").hexdigest()
    assert sha256_file(path) == expected


def test_browser_history_parser_reads_chromium(tmp_path, client, new_investigation):
    """A minimal Chromium History DB (visits table) imports through the browser parser."""
    path = _make_history(tmp_path / "History")

    kind = detect_file_type(path, "History")
    try:
        result = run_parser(kind, path, "History")
    except Exception as exc:  # pragma: no cover - adapter gap must be explicit
        raise AssertionError(f"chromium history parser failed: {exc}")

    assert len(result.events) == 1
    event = result.events[0]
    assert "example.org" in (event.file_path or "") or "example.org" in (event.description or "")
    assert event.timestamp is not None
    assert event.source_record_id == "urls#1"


def test_evtx_parser_registered_with_adapter_note(client):
    catalog = client.get("/api/parsers").json()
    kinds = {p["file_type"] for p in catalog["parsers"]}
    assert "evtx" in kinds
    evtx = next(p for p in catalog["parsers"] if p["file_type"] == "evtx")
    assert evtx.get("source_type")
    assert "evtx" in (evtx.get("note") or "").lower() or evtx.get("library") or catalog.get("note")