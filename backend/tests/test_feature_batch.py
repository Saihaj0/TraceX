"""Tests for the October 2026 feature batch:
  * Windows artifact parsers (Recycle Bin $I, MFT/Prefetch/ShimCache/UserAssist)
  * API-key auth + investigation ownership
  * Evidence integrity re-verification
  * bodyfile / super-timeline / PDF exports
  * the af_chain demo scenario's declared ground truth
  * /api/health database identity
"""

from __future__ import annotations

import struct
from datetime import datetime, timezone

import pytest


# ---------------------------------------------------------------------------
# Recycle Bin $I (binary)
# ---------------------------------------------------------------------------

def _i_entry(path: str, size: int, deleted: datetime, version: int = 2) -> bytes:
    """Build a Vista+ $I record exactly as Windows writes it."""
    ft = int((deleted.timestamp() + 11644473600) * 10_000_000)
    encoded = (path + "\x00").encode("utf-16-le")
    return (struct.pack("<Q", version) + struct.pack("<Q", size)
            + struct.pack("<Q", ft) + struct.pack("<I", len(path) + 1) + encoded)


def _write(tmp_path, name: str, data: bytes):
    """Parsers read from disk (the ingest contract); write the payload first."""
    p = tmp_path / name
    p.write_bytes(data)
    return p


def test_recycle_bin_i_parses(tmp_path):
    from app.parsers.windows import RecycleBinIParser

    deleted = datetime(2026, 3, 2, 10, 15, 0, tzinfo=timezone.utc)
    payload = _i_entry(r"C:\Users\alice\Documents\secret.docx", 481280, deleted)
    path = _write(tmp_path, "$IA1B2C3", payload)
    result = RecycleBinIParser().parse(path, original_name="$IA1B2C3")
    assert result.accepted == 1 and result.rejected == 0
    event = result.events[0]
    assert event.file_path == r"C:\Users\alice\Documents\secret.docx"
    assert event.event_type == "file_deleted"
    assert event.timestamp is not None
    assert abs((event.timestamp - deleted).total_seconds()) < 1
    assert event.raw_record["file_size"] == 481280


def test_recycle_bin_i_short_file_raises(tmp_path):
    from app.parsers.base import ParserError
    from app.parsers.windows import RecycleBinIParser

    path = _write(tmp_path, "IX", b"\x01\x00")
    with pytest.raises(ParserError):
        RecycleBinIParser().parse(path, original_name="$IX")


def test_recycle_bin_i_bad_filetime_is_error_row(tmp_path):
    from app.parsers.windows import RecycleBinIParser

    payload = _i_entry(r"C:\x.txt", 10, datetime(2026, 1, 1, tzinfo=timezone.utc))
    payload = payload[:16] + struct.pack("<Q", 0) + payload[24:]
    path = _write(tmp_path, "$IBAD", payload)
    result = RecycleBinIParser().parse(path, original_name="$IBAD")
    # event still emitted so the row is inspectable, but timestamp error recorded
    assert any(e.reason == "missing_timestamp" for e in result.errors)
    assert result.events[0].timestamp is None


# ---------------------------------------------------------------------------
# CSV export adapters
# ---------------------------------------------------------------------------

MFT_CSV = (
    "Entry Number,Sequence Number,Full Path,Filename,Created,Modified,"
    "Entry Modified,Accessed,Record Type,In Use\r\n"
    r'42,1,"C:\Windows\System32\winevt\Logs\Security.evtx",Security.evtx,'
    "2026-01-01 10:00:00+00:00,2026-03-02 15:00:00+00:00,"
    "2026-03-02 15:05:00+00:00,2026-03-02 15:00:00+00:00,file,False\r\n"
)

PREFETCH_CSV = (
    "Process Name,Run Count,Run Times,Process Path\r\n"
    'WEVTUTIL.EXE-7A2B3C1D.pf,7,"2026-03-02 10:00:00 +00:00, '
    '2026-03-02 15:44:00 +00:00",' + r'C:\Windows\System32\wevtutil.exe' + "\r\n"
)

SHIMCACHE_CSV = (
    "Path,Modified,Entry\r\n"
    + r"C:\Windows\System32\wevtutil.exe"
    + ",2026-03-02 15:44:00 +00:00,1\r\n"
)


def _rot13(s: str) -> str:
    return s.translate(str.maketrans(
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
        "nopqrstuvwxyzabcdefghijklmNOPQRSTUVWXYZABCDEFGHIJKLM"))


def test_mft_csv_parser(tmp_path):
    from app.parsers.windows import MftCsvParser

    path = _write(tmp_path, "mft.csv", MFT_CSV.encode())
    result = MftCsvParser().parse(path, original_name="mft.csv")
    assert result.accepted == 1
    event = result.events[0]
    assert event.file_path.endswith("Security.evtx")
    assert event.event_type == "file_metadata_suspect"  # In Use = False
    assert event.timestamp is not None
    assert event.raw_record["macb"]["created"] is not None


def test_prefetch_csv_parser(tmp_path):
    from app.parsers.windows import PrefetchCsvParser

    path = _write(tmp_path, "pf.csv", PREFETCH_CSV.encode())
    result = PrefetchCsvParser().parse(path, original_name="pf.csv")
    assert result.accepted == 1
    event = result.events[0]
    assert event.process_name.startswith("WEVTUTIL")
    assert event.event_type == "process_creation"
    assert len(event.raw_record["run_times"]) == 2
    assert event.timestamp is not None  # last run used


def test_shimcache_csv_parser(tmp_path):
    from app.parsers.windows import ShimCacheCsvParser

    path = _write(tmp_path, "shim.csv", SHIMCACHE_CSV.encode())
    result = ShimCacheCsvParser().parse(path, original_name="shim.csv")
    assert result.accepted == 1
    assert result.events[0].process_name.lower() == "wevtutil.exe"


def test_userassist_reg_parser(tmp_path):
    from app.parsers.windows import UserAssistRegParser

    name = _rot13(r"C:\Windows\System32\wevtutil.exe")
    # blob: 4B unknown + 4B session count + padding up to offset 60 + 8B FILETIME
    ft = int((datetime(2026, 3, 2, 15, 44, tzinfo=timezone.utc).timestamp()
              + 11644473600) * 10_000_000)
    blob = (b"\x05\x00\x00\x00" + struct.pack("<I", 7)
            + b"\x00" * 52 + struct.pack("<Q", ft))
    hex_str = ",".join(f"{b:02x}" for b in blob)
    key = (r"[HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion"
           r"\Explorer\UserAssist\{37C4E7CC-...}\Count]")
    reg = (
        "Windows Registry Editor Version 5.00\r\n\r\n"
        + key + "\r\n"
        + f'"{name}"=hex:{hex_str}\r\n'
    )
    path = _write(tmp_path, "ua.reg", reg.encode("utf-8"))
    result = UserAssistRegParser().parse(path, original_name="ua.reg")
    assert result.accepted == 1
    event = result.events[0]
    assert event.file_path == r"C:\Windows\System32\wevtutil.exe"
    assert event.raw_record["session_count"] == 7
    assert event.timestamp is not None


# ---------------------------------------------------------------------------
# File-type detection for the new artifacts
# ---------------------------------------------------------------------------

def test_detect_recyclebin_and_csv_types(tmp_path):
    from app.parsers.base import detect_file_type

    deleted = datetime(2026, 3, 2, tzinfo=timezone.utc)
    i_file = tmp_path / "$IA1B2C3D4"
    i_file.write_bytes(_i_entry(r"C:\x.txt", 1, deleted))
    assert detect_file_type(i_file, "$IA1B2C3D4") == "recyclebin"

    mft = tmp_path / "export.csv"
    mft.write_text(MFT_CSV, encoding="utf-8")
    assert detect_file_type(mft, "export.csv") == "mft"

    pf = tmp_path / "runs.csv"
    pf.write_text(PREFETCH_CSV, encoding="utf-8")
    assert detect_file_type(pf, "runs.csv") == "prefetch"


# ---------------------------------------------------------------------------
# Auth + ownership (unit-level, no server needed)
# ---------------------------------------------------------------------------

class _FakeRequest:
    def __init__(self, headers: dict):
        self.headers = {k.lower(): v for k, v in headers.items()}


def test_auth_disabled_keeps_legacy_actor(monkeypatch):
    import app.auth as auth
    import app.config as config

    monkeypatch.setattr(config, "AUTH_ENABLED", False, raising=False)
    monkeypatch.setattr(auth, "AUTH_ENABLED", False)
    request = _FakeRequest({"X-TraceX-Actor": "alice"})
    assert auth.current_actor(request) == "alice"


def test_auth_enabled_requires_key(monkeypatch):
    from fastapi import HTTPException

    import app.auth as auth
    import app.config as config

    monkeypatch.setattr(config, "AUTH_ENABLED", True, raising=False)
    monkeypatch.setattr(auth, "AUTH_ENABLED", True)
    monkeypatch.setattr(auth, "API_KEYS", {"alice": "tok-alice"}, raising=False)
    with pytest.raises(HTTPException) as exc:
        auth.current_actor(_FakeRequest({}))
    assert exc.value.status_code == 401

    with pytest.raises(HTTPException):
        auth.current_actor(_FakeRequest({"Authorization": "Bearer wrong"}))

    assert auth.current_actor(
        _FakeRequest({"Authorization": "Bearer tok-alice"})) == "alice"
    assert auth.current_actor(_FakeRequest({"X-API-Key": "tok-alice"})) == "alice"


def test_ownership_enforced_when_auth_on(client, monkeypatch):
    import app.api.investigations as inv_api
    import app.auth as auth
    import app.config as config

    created = client.post("/api/investigations",
                          json={"name": "Ownership case", "case_id": "OWN-1"})
    assert created.status_code == 201
    inv_id = created.json()["id"]

    # auth off: default actor may patch
    resp = client.patch(f"/api/investigations/{inv_id}",
                        json={"description": "updated"})
    assert resp.status_code == 200

    # auth on: another actor is refused
    monkeypatch.setattr(config, "AUTH_ENABLED", True, raising=False)
    monkeypatch.setattr(auth, "AUTH_ENABLED", True)
    monkeypatch.setattr(auth, "API_KEYS", {"alice": "tok-a", "mallory": "tok-m"},
                        raising=False)
    # ownership now reads auth_on() at call time; force it on for this test
    monkeypatch.setattr(inv_api, "auth_on", lambda: True)
    # the investigation was created unowned, so it stays shared; make alice the owner
    from app.db import SessionLocal
    from app.models import Investigation

    with SessionLocal() as db:
        row = db.get(Investigation, inv_id)
        row.owner = "alice"
        db.commit()

    resp = client.patch(f"/api/investigations/{inv_id}",
                        json={"description": "hijack"},
                        headers={"X-API-Key": "tok-m"})
    assert resp.status_code == 403
    assert resp.json()["detail"]["code"] == "not_owner"

    resp = client.patch(f"/api/investigations/{inv_id}",
                        json={"description": "legit"},
                        headers={"X-API-Key": "tok-a"})
    assert resp.status_code == 200

    # listing: mallory does not see alice's case
    mine = client.get("/api/investigations",
                      headers={"X-API-Key": "tok-m"}).json()
    assert inv_id not in [i["id"] for i in mine["investigations"]]
    theirs = client.get("/api/investigations",
                        headers={"X-API-Key": "tok-a"}).json()
    assert inv_id in [i["id"] for i in theirs["investigations"]]


# ---------------------------------------------------------------------------
# Evidence integrity re-verification
# ---------------------------------------------------------------------------

def test_evidence_verify_detects_tampering(client, new_investigation):
    import json

    inv = new_investigation(name="Verify case")
    inv_id = inv["id"]
    payload = json.dumps([
        {"event_id": "V-1", "timestamp": "2026-03-02T10:00:00Z",
         "event_type": "file_access", "description": "access to C:\\a.txt",
         "file_path": "C:\\a.txt"},
    ]).encode()
    resp = client.post(
        f"/api/investigations/{inv_id}/evidence",
        files={"file": ("events.json", payload, "application/json")})
    assert resp.status_code == 201
    source_id = resp.json()["evidence_source_id"]

    ok = client.post(f"/api/investigations/{inv_id}/evidence/{source_id}/verify")
    assert ok.status_code == 200
    body = ok.json()
    assert body["stored_file_available"] is True
    assert body["verified"] is True
    assert body["recorded_sha256"] == body["current_sha256"]

    # tamper with the stored copy, then re-verify
    from pathlib import Path

    from app.models import EvidenceSource
    from app.db import SessionLocal
    with SessionLocal() as db:
        source = db.get(EvidenceSource, source_id)
        stored = Path(source.stored_path)
    original = stored.read_bytes()
    try:
        stored.write_bytes(original + b"\n# tampered")
        bad = client.post(
            f"/api/investigations/{inv_id}/evidence/{source_id}/verify")
        assert bad.status_code == 200
        assert bad.json()["verified"] is False
        assert "MISMATCH" in bad.json()["note"]
    finally:
        stored.write_bytes(original)

    # audit trail records both verifications
    entries = client.get(f"/api/investigations/{inv_id}/audit").json()["entries"]
    assert sum(1 for e in entries if e["action"] == "evidence.verified") == 2


# ---------------------------------------------------------------------------
# Exports: bodyfile, super-timeline, PDF
# ---------------------------------------------------------------------------

def test_new_exports(client, new_investigation):
    import json

    inv = new_investigation(name="Export case")
    payload = json.dumps([
        {"event_id": "E-1", "timestamp": "2026-03-02T10:00:00Z",
         "event_type": "file_created",
         "description": "file_created: C:\\Users\\a\\doc.txt",
         "file_path": "C:\\Users\\a\\doc.txt", "size": 123},
        {"event_id": "E-2", "timestamp": "2026-03-02T10:05:00Z",
         "event_type": "file_access",
         "description": "access to C:\\Users\\a\\doc.txt",
         "file_path": "C:\\Users\\a\\doc.txt"},
    ]).encode()
    resp = client.post(
        f"/api/investigations/{inv['id']}/evidence",
        files={"file": ("ev.json", payload, "application/json")})
    assert resp.status_code == 201

    body = client.get(f"/api/investigations/{inv['id']}/export/bodyfile.csv")
    assert body.status_code == 200
    rows = [r for r in body.text.strip().splitlines() if r]
    assert len(rows) == 2
    # bodyfile columns: MD5|name|inode|mode|UID|GID|size|atime|mtime|ctime|crtime
    cols = rows[0].split("|")
    assert len(cols) == 11
    assert cols[0] == "-"  # MD5 unknown, never fabricated
    assert "doc.txt" in cols[1]

    st = client.get(f"/api/investigations/{inv['id']}/export/supertimeline.csv")
    assert st.status_code == 200
    lines = st.text.strip().splitlines()
    assert lines[0].startswith("date,timezone,hostname,short,source,type,user,message,reference")
    assert len(lines) == 3  # header + 2 events
    assert "file_created" in lines[1]

    pdf = client.get(f"/api/investigations/{inv['id']}/report.pdf")
    assert pdf.status_code == 200
    assert pdf.headers["content-type"] == "application/pdf"
    assert pdf.content.startswith(b"%PDF-1.4")
    assert pdf.content.rstrip().endswith(b"%%EOF")


# ---------------------------------------------------------------------------
# af_chain scenario ground truth
# ---------------------------------------------------------------------------

def test_af_chain_scenario_matches_ground_truth(db):
    from app.datasets import scenario_by_id
    from app.demo import create_demo_investigation
    from app.models import Finding, SuspicionChain

    scenario = scenario_by_id("af_chain")
    assert scenario is not None
    inv = create_demo_investigation(db, scenario, analyse=True)

    rules = {f.rule_id for f in
             db.query(Finding).filter(Finding.investigation_id == inv.id)}
    chains = {c.pattern_id for c in
              db.query(SuspicionChain).filter(
                  SuspicionChain.investigation_id == inv.id)}

    assert set(scenario.expected_rules) <= rules, (
        f"declared rules did not fire: {set(scenario.expected_rules) - rules}")
    assert set(scenario.expected_chains) <= chains, (
        f"declared chains did not fire: {set(scenario.expected_chains) - chains}")


# ---------------------------------------------------------------------------
# Batch multi-file upload
# ---------------------------------------------------------------------------

def test_batch_upload_imports_each_file(client, new_investigation):
    import json

    inv = new_investigation(name="Batch case")
    inv_id = inv["id"]
    file_a = json.dumps([
        {"event_id": "B-1", "timestamp": "2026-03-02T10:00:00Z",
         "event_type": "file_access", "description": "access to C:\\a.txt",
         "file_path": "C:\\a.txt"},
    ]).encode()
    file_b = MFT_CSV.encode()
    resp = client.post(
        f"/api/investigations/{inv_id}/evidence/batch",
        files=[("files", ("a.json", file_a, "application/json")),
               ("files", ("mft.csv", file_b, "text/csv")),
               ("files", ("empty.json", b"", "application/json"))])
    assert resp.status_code == 201, resp.text
    body = resp.json()
    assert body["files_imported"] == 2
    assert body["files_failed"] == 1  # the empty file is reported, not fatal
    assert any(e["filename"] == "empty.json" for e in body["errors"])

    sources = client.get(f"/api/investigations/{inv_id}/evidence").json()["evidence"]
    assert len(sources) == 2


def test_batch_upload_all_fail_is_422(client, new_investigation):
    inv = new_investigation(name="Batch fail case")
    resp = client.post(
        f"/api/investigations/{inv['id']}/evidence/batch",
        files=[("files", ("empty.json", b"", "application/json"))])
    assert resp.status_code == 422
    assert resp.json()["detail"]["code"] == "batch_failed"


# ---------------------------------------------------------------------------
# /api/auth/verify
# ---------------------------------------------------------------------------

def test_auth_verify_reports_default_actor(client):
    body = client.get("/api/auth/verify").json()
    assert body["auth_mode"] == "trusted_local"
    assert body["actor"]  # default or header-derived actor
    assert body["authenticated"] is False


def test_auth_verify_uses_actor_header(client):
    body = client.get("/api/auth/verify",
                      headers={"X-TraceX-Actor": "analyst-9"}).json()
    assert body["actor"] == "analyst-9"


def test_auth_verify_enforces_api_key_when_enabled(client, monkeypatch):
    import app.api.auth as auth_api
    import app.auth as auth
    import app.config as config

    monkeypatch.setattr(config, "AUTH_ENABLED", True, raising=False)
    monkeypatch.setattr(auth, "AUTH_ENABLED", True)
    monkeypatch.setattr(auth, "API_KEYS", {"alice": "tok-a"}, raising=False)
    monkeypatch.setattr(auth_api, "AUTH_ENABLED", True)

    assert client.get("/api/auth/verify").status_code == 401
    ok = client.get("/api/auth/verify", headers={"X-API-Key": "tok-a"})
    assert ok.status_code == 200
    assert ok.json()["actor"] == "alice"
    assert ok.json()["auth_mode"] == "api_key"
    # tokens are never echoed back
    assert "tok-a" not in ok.text


# ---------------------------------------------------------------------------
# Timestamp serialization must not depend on the server's local timezone
# ---------------------------------------------------------------------------

def test_naive_timestamps_serialize_as_utc_not_local():
    """SQLite returns naive datetimes (stored as UTC). dt_to_iso must not
    reinterpret them via astimezone() in the server's local zone — that would
    silently shift every SQLite-backed export by the UTC offset."""
    from datetime import timedelta

    from app.normalization import dt_to_iso

    naive = datetime(2026, 3, 2, 10, 0, 0)
    assert dt_to_iso(naive) == "2026-03-02T10:00:00Z"
    # an aware value keeps its instant, whatever zone it arrives in
    ist = timezone(timedelta(hours=5, minutes=30))
    assert dt_to_iso(datetime(2026, 3, 2, 15, 30, 0, tzinfo=ist)) == "2026-03-02T10:00:00Z"
    assert dt_to_iso(None) is None


def test_timeline_export_stores_source_time_not_local(client, new_investigation):
    """End-to-end: an event imported at 10:00Z exports at 10:00Z."""
    import json

    inv = new_investigation(name="TZ export case")
    payload = json.dumps([
        {"event_id": "TZ-1", "timestamp": "2026-03-02T10:00:00Z",
         "event_type": "file_access", "description": "access to C:\\tz.txt",
         "file_path": "C:\\tz.txt"},
    ]).encode()
    resp = client.post(
        f"/api/investigations/{inv['id']}/evidence",
        files={"file": ("tz.json", payload, "application/json")})
    assert resp.status_code == 201

    row = client.get(f"/api/investigations/{inv['id']}/export/supertimeline.csv")
    assert row.status_code == 200
    line = row.text.strip().splitlines()[1]
    assert line.startswith("2026-03-02T10:00:00Z"), (
        f"timestamp shifted by server timezone: {line.split(',')[0]}")

    detail = client.get(
        f"/api/investigations/{inv['id']}/events").json()["events"][0]
    assert detail["timestamp"].startswith("2026-03-02T10:00:00Z")


# ---------------------------------------------------------------------------
# /api/health database identity
# ---------------------------------------------------------------------------

def test_health_reports_db_identity(client):
    body = client.get("/api/health").json()
    assert body["status"] == "ok"
    identity = body["db_identity"]
    assert identity["database_name"]  # sqlite file path or PG database name
    assert "server_version" in identity
