"""Controlled synthetic forensic datasets (10 scenarios).

Every record generated here is labelled `origin="demo"` / `synthetic=True` so
demo evidence is never confused with imported evidence.

Each scenario declares what the evaluation expects so precision / recall can be
computed against ground truth instead of being asserted by hand:

  expected_rules   - rule ids that SHOULD fire
  expected_chains  - chain patterns that SHOULD be detected
  expected_absent  - rule ids that SHOULD NOT fire (false-positive traps)
  alternatives     - the legitimate explanations a correct report must mention
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

HOST = "WS-FORENSIC-01"
HOST2 = "SRV-CORP-02"
USER_A = "CORP\\alice"
USER_B = "CORP\\bob"
USER_ADMIN = "CORP\\svc_admin"

BASE = datetime(2026, 3, 2, 9, 0, 0, tzinfo=timezone.utc)


def iso(dt: datetime | None) -> str | None:
    return dt.isoformat().replace("+00:00", "Z") if dt else None


def rec(event_id: str, dt: datetime, event_type: str, description: str, **kw) -> dict:
    record = {
        "event_id": event_id,
        "timestamp": iso(dt),
        "timestamp_raw": kw.pop("timestamp_raw", iso(dt)),
        "event_type": event_type,
        "description": description,
        "host": kw.pop("host", HOST),
        "user": kw.pop("user", USER_A),
        "source_record_id": kw.pop("source_record_id", event_id),
    }
    record.update(kw)
    return record


@dataclass
class SourceSpec:
    filename: str
    file_type: str
    source_type: str
    records: list[dict]
    note: str
    errors: list[dict] = field(default_factory=list)
    #: Rows written into the payload *verbatim* so the real parser rejects them
    #: end to end (rejections are produced by the parser, not pre-baked).
    invalid_records: list[dict] = field(default_factory=list)
    timezone_note: str = "timestamps normalized to UTC (synthetic data uses explicit offsets)"


@dataclass
class Scenario:
    id: str
    name: str
    description: str
    expected_rules: list[str]
    expected_chains: list[str]
    expected_absent: list[str]
    alternatives: list[str]
    sources: list[SourceSpec]
    notes: str = ""

    @property
    def case_id(self) -> str:
        return f"DEMO-{self.id.upper()}"


# ---------------------------------------------------------------------------
# 1. Normal user activity
# ---------------------------------------------------------------------------
def scenario_normal() -> Scenario:
    events = [
        rec("S1-001", BASE, "logon_success", "Interactive logon for CORP\\alice",
            user=USER_A, process_name="lsass.exe"),
        rec("S1-002", BASE + timedelta(minutes=2), "process_creation",
            "process started: C:\\Program Files\\Microsoft Office\\WINWORD.EXE",
            user=USER_A, process_name="C:\\Program Files\\Microsoft Office\\WINWORD.EXE",
            process_id=4120),
        rec("S1-003", BASE + timedelta(minutes=6), "file_created",
            "file_created: C:\\Users\\alice\\Documents\\Quarterly_Report.docx",
            file_path="C:\\Users\\alice\\Documents\\Quarterly_Report.docx"),
        rec("S1-004", BASE + timedelta(hours=1), "file_modified",
            "file_modified: C:\\Users\\alice\\Documents\\Quarterly_Report.docx",
            file_path="C:\\Users\\alice\\Documents\\Quarterly_Report.docx"),
        rec("S1-005", BASE + timedelta(hours=1, minutes=20), "browser_visit",
            "Browser visit to https://intranet.corp.local/reports",
            process_name="chrome.exe", user=USER_B),
        rec("S1-006", BASE + timedelta(hours=2), "file_access",
            "access to C:\\Users\\alice\\.ssh\\id_rsa.pub",
            file_path="C:\\Users\\alice\\.ssh\\id_rsa.pub"),
        rec("S1-007", BASE + timedelta(hours=3), "file_modified",
            "file_modified: C:\\Users\\alice\\Desktop\\notes.txt",
            file_path="C:\\Users\\alice\\Desktop\\notes.txt"),
        rec("S1-008", BASE + timedelta(hours=4), "logon_success",
            "Interactive logon for CORP\\bob", user=USER_B, host=HOST2),
    ]
    return Scenario(
        id="normal", name="Normal user activity",
        description="Routine logons, document editing, browsing and file reads with no loss events.",
        expected_rules=[], expected_chains=[], expected_absent=[
            "AF-001", "AF-002", "AF-003", "AF-005", "AF-008"],
        alternatives=["Scheduled maintenance", "Legitimate administrative cleanup"],
        sources=[SourceSpec("normal_activity.json", "json", "structured", events,
                            "structured normalized events")],
        notes="Baseline true-negative case: any rule firing here is a false positive.",
    )


# ---------------------------------------------------------------------------
# 2. Legitimate administrative cleanup (benign deletions)
# ---------------------------------------------------------------------------
def scenario_cleanup() -> Scenario:
    records = []
    for i in range(14):
        dt = BASE + timedelta(minutes=25 + i * 4)
        records.append(rec(
            f"S2-D{i:02d}", dt, "file_deleted",
            f"file_deleted: C:\\Users\\alice\\AppData\\Local\\Temp\\cache_{i}.tmp",
            file_path=f"C:\\Users\\alice\\AppData\\Local\\Temp\\cache_{i}.tmp",
            user=USER_ADMIN, source_record_id=f"usn{88000 + i}"))
    records.append(rec(
        "S2-PROC", BASE + timedelta(minutes=24), "process_creation",
        "process started: C:\\Windows\\System32\\cleanmgr.exe /sagerun:1",
        user=USER_ADMIN, process_name="C:\\Windows\\System32\\cleanmgr.exe", process_id=3312))
    return Scenario(
        id="cleanup", name="Legitimate administrative cleanup",
        description="A scheduled disk-cleanup run deleting temp cache files (bulk deletions, benign).",
        expected_rules=["AF-003", "AF-005"], expected_chains=[], expected_absent=[
            "AF-001", "AF-002", "AF-004", "AF-006", "AF-007", "AF-008"],
        alternatives=["Legitimate administrative cleanup (disk cleanup tool)",
                      "Scheduled maintenance"],
        sources=[SourceSpec("cleanup_journal.json", "json", "structured",
                            sorted(records, key=lambda r: r["timestamp"]),
                            "structured normalized events")],
        notes="Ground truth: the bulk-deletion (AF-003) and work-then-loss (AF-005) DETECTIONS "
              "are correct — targets are temp files and the named tool (cleanmgr.exe) is in the "
              "execution record, so the report must present them as high-volume but plausibly "
              "benign. Detection accuracy is scored on whether the rule fires, not on whether "
              "the activity is malicious.",
    )


# ---------------------------------------------------------------------------
# 3. File deletion of forensic artifacts
# ---------------------------------------------------------------------------
def scenario_deletion() -> Scenario:
    fs_records = [
        {"path": "C:\\Windows\\System32\\winevt\\Logs\\Security.evtx",
         "size": 20971520, "created": int((BASE - timedelta(days=30)).timestamp() * 1000),
         "modified": int((BASE + timedelta(hours=6)).timestamp() * 1000),
         "accessed": int((BASE + timedelta(hours=6)).timestamp() * 1000),
         "deleted": "true", "usn": 90211, "reason": "FILE_DELETE",
         "file_id": "0x1800000000215", "record_type": "usn_journal", "record_id": "usn-90211"},
        {"path": "C:\\Windows\\Prefetch\\WEVTUTIL.EXE-7A2B3C1D.pf",
         "size": 8432, "created": int((BASE - timedelta(days=2)).timestamp() * 1000),
         "modified": int((BASE + timedelta(hours=6, minutes=3)).timestamp() * 1000),
         "accessed": int((BASE + timedelta(hours=6)).timestamp() * 1000),
         "deleted": "true", "usn": 90215, "reason": "FILE_DELETE",
         "file_id": "0x300000000011a", "record_type": "usn_journal", "record_id": "usn-90215"},
        {"path": "C:\\Users\\alice\\Documents\\Budget_FY26.xlsx",
         "size": 245760, "created": int((BASE - timedelta(days=5)).timestamp() * 1000),
         "modified": int((BASE + timedelta(hours=5)).timestamp() * 1000),
         "accessed": int((BASE + timedelta(hours=5)).timestamp() * 1000),
         "deleted": "true", "usn": 90220, "reason": "FILE_DELETE",
         "file_id": "0x40000000011b", "record_type": "usn_journal", "record_id": "usn-90220"},
    ]
    return Scenario(
        id="deletion", name="Forensic artifact deletion",
        description="USN journal records show deletion of an event log, a prefetch artifact and a "
                    "sensitive document.",
        expected_rules=["AF-002"], expected_chains=[], expected_absent=["AF-001", "AF-008"],
        alternatives=["Disk cleanup / uninstaller removing artifacts",
                      "Log retention policy deleting aged logs"],
        sources=[SourceSpec("usn_journal_export.json", "fsat", "filesystem_artifact", fs_records,
                            "USN journal-style filesystem export (JSON)")],
    )


# ---------------------------------------------------------------------------
# 4. Audit log clearing
# ---------------------------------------------------------------------------
def scenario_log_clear() -> Scenario:
    events = [
        rec("S4-100", BASE, "process_creation",
            "process started: C:\\Windows\\System32\\cmd.exe",
            user=USER_ADMIN, process_name="C:\\Windows\\System32\\cmd.exe", process_id=9012),
        rec("S4-1102", BASE + timedelta(minutes=4), "audit_log_cleared",
            "Windows event 1102 from provider Microsoft-Windows-Eventlog audit/security log "
            "cleared initiated by svc_admin",
            user=USER_ADMIN, source_record_id="1024417", host=HOST),
        rec("S4-7045", BASE + timedelta(minutes=9), "service_installed",
            "New service installed: BackupSync",
            user=USER_ADMIN, process_name="C:\\Windows\\System32\\svchost.exe"),
    ]
    return Scenario(
        id="logclear", name="Audit log clearing",
        description="Security log clear (1102) after an interactive command shell execution.",
        expected_rules=["AF-001", "AF-005", "AF-008"], expected_chains=["B", "D"],
        expected_absent=["AF-003", "AF-004", "AF-006", "AF-007"],
        alternatives=["Approved retention policy run",
                      "Incident-response cleanup performed with consent",
                      "Ordinary administrative shell session followed by a retention task"],
        sources=[SourceSpec("security_view.json", "json", "structured", events,
                            "EVTX-derived normalised JSON export of the Security log")],
        notes="AF-008 fires at reduced severity: the preceding execution (cmd.exe) shares the "
              "user/host but is not a documented anti-forensic utility, so support stays low and "
              "the report must say a routine shell session explains the pair. AF-005 and "
              "pattern D match the same activity→loss sequence.",
    )


# ---------------------------------------------------------------------------
# 5. Timestamp inconsistency
# ---------------------------------------------------------------------------
def scenario_timestamps() -> Scenario:
    fs_records = [
        {"path": "C:\\Users\\alice\\Documents\\Merger_Notes.docx",
         "size": 98304,
         "ctime": "2026-03-02T11:00:00Z", "mtime": "2026-03-01T22:14:00Z",
         "atime": "2026-03-01T22:14:00Z",
         "record_type": "$MFT", "record_id": "mft-4471", "file_id": "0x50000000001c"},
        {"path": "C:\\Windows\\System32\\winevt\\Logs\\System.evtx",
         "size": 1048576,
         "ctime": "2026-03-02T10:30:00Z", "mtime": "2026-03-02T10:30:00Z",
         "atime": "2026-03-02T10:30:00Z",
         "record_type": "$MFT", "record_id": "mft-991", "file_id": "0x600000000021"},
        {"path": "C:\\Users\\alice\\Downloads\\installer.msi",
         "size": 5242880, "ctime": "2026-02-27T08:15:00Z", "mtime": "2026-03-02T12:45:00Z",
         "atime": "2026-03-02T12:47:00Z", "record_type": "$MFT", "record_id": "mft-1204",
         "reason": "DATA_OVERWRITE", "usn": 66012},
    ]
    return Scenario(
        id="timestamps", name="Timestamp inconsistency",
        description="One record with modified < created, one with three identical metadata "
                    "timestamps, and one normal record as a control.",
        expected_rules=["AF-004"], expected_chains=[], expected_absent=["AF-001", "AF-002"],
        alternatives=["Backup/restore rewriting metadata",
                      "Copy/extract tool flattening timestamps",
                      "Timezone misinterpretation between tools"],
        sources=[SourceSpec("mft_metadata_export.json", "fsat", "filesystem_artifact", fs_records,
                            "$MFT-style metadata export (JSON)")],
        notes="The control record must NOT be flagged — demonstrates that not every unusual "
              "timestamp is treated as manipulation.",
    )


# ---------------------------------------------------------------------------
# 5b. CSV filesystem import (parser coverage for the CSV path)
# ---------------------------------------------------------------------------
def scenario_csv_export() -> Scenario:
    rows = []
    for i in range(12):
        dt = BASE + timedelta(hours=6, minutes=i * 3)
        rows.append({
            "path": f"C:\\inetpub\\wwwroot\\app\\module_{i}.dll",
            "size": str(40960 + i * 512),
            "ctime": (BASE - timedelta(days=10)).isoformat().replace("+00:00", "Z"),
            "mtime": dt.isoformat().replace("+00:00", "Z"),
            "atime": dt.isoformat().replace("+00:00", "Z"),
            "deleted": "false", "usn": str(70400 + i), "reason": "DATA_OVERWRITE",
            "record_type": "usn_journal", "record_id": f"usn-{70400 + i}",
        })
    # one invalid row: no path and no timestamp — shipped verbatim so the
    # parser itself rejects it during import
    bad_row = {"path": "", "mtime": "", "ctime": "", "atime": "", "reason": "",
               "record_type": "usn_journal", "record_id": "bad-row"}
    valid_rows = rows[:]
    return Scenario(
        id="csvexport", name="Filesystem CSV export (parser coverage)",
        description="USN-style CSV export including one intentionally invalid row so rejected-"
                    "record reporting is exercised end to end.",
        expected_rules=[], expected_chains=[], expected_absent=["AF-001", "AF-002", "AF-003"],
        alternatives=["Ordinary application file updates during patching"],
        sources=[SourceSpec("webroot_usn_export.csv", "fsat", "filesystem_artifact", valid_rows,
                            "CSV USN export for a web application directory",
                            errors=[{"row_index": 13, "record_id": "bad-row",
                                     "reason": "missing_required_fields",
                                     "detail": "row has neither a file path nor any timestamp",
                                     "raw_excerpt": "{\"path\": \"\", \"mtime\": \"\"}"}],
                            invalid_records=[bad_row])],
        notes="The CSV bytes are generated and imported through the real CSV parser, so the "
              "rejection shown in the UI comes from the parser, not a pre-baked table.",
    )


# ---------------------------------------------------------------------------
# 6. Multiple suspicious actions
# ---------------------------------------------------------------------------
def scenario_multi() -> Scenario:
    events = [
        rec("S6-001", BASE, "process_creation",
            "process started: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe "
            "-enc SQBFAFgA",
            user=USER_ADMIN, process_name="powershell.exe -enc SQBFAFgA", process_id=6116),
        rec("S6-002", BASE + timedelta(minutes=3), "file_access",
            "access to C:\\Windows\\System32\\winevt\\Logs\\Security.evtx",
            file_path="C:\\Windows\\System32\\winevt\\Logs\\Security.evtx", user=USER_ADMIN),
        rec("S6-003", BASE + timedelta(minutes=4), "file_timestamps_equal",
            "file_timestamps_equal: C:\\Windows\\System32\\winevt\\Logs\\Security.evtx "
            "[created/modified/accessed identical — possible copy or archive extraction; needs "
            "corroboration, not proven]",
            file_path="C:\\Windows\\System32\\winevt\\Logs\\Security.evtx", user=USER_ADMIN,
            timestamp_raw=iso(BASE + timedelta(minutes=4)),
            note="copy candidate / timestamp reset on the same target"),
        rec("S6-004", BASE + timedelta(minutes=16), "file_deleted",
            "file_deleted: C:\\Windows\\System32\\winevt\\Logs\\Security.evtx",
            file_path="C:\\Windows\\System32\\winevt\\Logs\\Security.evtx", user=USER_ADMIN),
        rec("S6-005", BASE + timedelta(minutes=21), "audit_log_cleared",
            "Windows event 1102 from provider Microsoft-Windows-Eventlog audit/security log "
            "cleared initiated by svc_admin",
            user=USER_ADMIN, source_record_id="1024502"),
        rec("S6-006", BASE + timedelta(minutes=30), "file_metadata_suspect",
            "file_metadata_suspect: C:\\Windows\\System32\\winevt\\Logs\\Security.evtx "
            "[modified timestamp precedes created timestamp in the source record]",
            file_path="C:\\Windows\\System32\\winevt\\Logs\\Security.evtx", user=USER_ADMIN),
        rec("S6-007", BASE + timedelta(hours=1), "removable_device_connected",
            "USB mass storage device attached: USBDISK-01 (VID_0781 PID_5591)",
            user=USER_ADMIN, device_id="USBDISK-01", file_path=None),
        rec("S6-008", BASE + timedelta(hours=1, minutes=6), "file_created",
            "file_created: E:\\backup\\evtx_export_all.evtx",
            file_path="E:\\backup\\evtx_export_all.evtx", user=USER_ADMIN, device_id="USBDISK-01"),
        rec("S6-009", BASE + timedelta(hours=1, minutes=30), "file_metadata_suspect",
            "file_metadata_suspect: C:\\Windows\\System32\\winevt\\Logs\\System.evtx "
            "[modified timestamp precedes created timestamp in the source record]",
            file_path="C:\\Windows\\System32\\winevt\\Logs\\System.evtx", user=USER_ADMIN),
    ]
    fs_records = [
        {"path": "C:\\Windows\\System32\\winevt\\Logs\\Security.evtx",
         "ctime": "2026-01-04T00:00:00Z", "mtime": "2026-03-02T09:40:00Z",
         "atime": "2026-03-02T09:40:00Z", "deleted": "true", "usn": 91500,
         "reason": "FILE_DELETE", "record_type": "usn_journal", "record_id": "usn-91500",
         "size": str(20971520)},
        {"path": "C:\\Windows\\System32\\winevt\\Logs\\System.evtx",
         "ctime": "2026-01-04T00:00:00Z", "mtime": "133848900000000000",
         "atime": "133848900000000000", "usn": 91510, "reason": "DATA_OVERWRITE",
         "record_type": "usn_journal", "record_id": "usn-91510", "size": "1048576"},
    ]
    return Scenario(
        id="multi", name="Multiple suspicious actions",
        description="Encoded PowerShell → log access → copy candidate → eviction → log clear → "
                    "metadata anomaly → removable media transfer.",
        expected_rules=["AF-001", "AF-002", "AF-004", "AF-005", "AF-007", "AF-008"],
        expected_chains=["A", "B", "D", "E"],
        expected_absent=["AF-006"],
        alternatives=["Approved log rotation invoked through the same utilities",
                      "Backup/sync tool copying then pruning files",
                      "Incident-response cleanup performed with consent"],
        sources=[
            SourceSpec("security_view.json", "json", "structured", events,
                       "EVTX-derived normalised JSON export + device events"),
            SourceSpec("usn_journal_SecondaryDisk.json", "fsat", "filesystem_artifact",
                       fs_records, "USN journal export for the same host"),
        ],
    )


# ---------------------------------------------------------------------------
# 7. Incomplete evidence collection (logging gap + rejected records)
# ---------------------------------------------------------------------------
def scenario_incomplete() -> Scenario:
    events = [
        rec("S7-001", BASE, "logon_success", "Interactive logon for CORP\\alice",
            user=USER_A, process_name="lsass.exe"),
        rec("S7-002", BASE + timedelta(minutes=5), "file_modified",
            "file_modified: C:\\Users\\alice\\Documents\\Travel_itinerary.pdf",
            file_path="C:\\Users\\alice\\Documents\\Travel_itinerary.pdf"),
        rec("S7-010", BASE + timedelta(minutes=12), "logon_success",
            "Interactive logon for CORP\\alice (second session)", user=USER_A),
        # nothing from the collected log until +15h: a 14h48m coverage gap while
        # non-log artifacts below show the host was active.
        rec("S7-020", BASE + timedelta(hours=13, minutes=25), "file_access",
            "access to C:\\Users\\alice\\Documents\\Travel_itinerary.pdf",
            file_path="C:\\Users\\alice\\Documents\\Travel_itinerary.pdf"),
        rec("S7-021", BASE + timedelta(hours=13, minutes=30), "process_creation",
            "process started: C:\\Program Files\\7-Zip\\7zFM.exe",
            user=USER_A, process_name="7zFM.exe", process_id=5120),
        rec("S7-022", BASE + timedelta(hours=13, minutes=40), "file_created",
            "file_created: D:\\exports\\Travel_itinerary_archive.zip",
            file_path="D:\\exports\\Travel_itinerary_archive.zip"),
        # record without a timestamp - ordering must remain honest
        rec("S7-099", None, "unknown", "event type recorded without a timestamp in the source",
            timestamp_raw=""),
        rec("S7-100", BASE + timedelta(hours=15), "logon_success",
            "Interactive logon for CORP\\alice"),
    ]
    for e in events:
        if e["timestamp"] is None:
            e["timestamp"] = None
            e["timestamp_raw"] = None
    return Scenario(
        id="incomplete", name="Incomplete evidence collection",
        description="A 14h48m logging gap while non-log activity continues, plus records with "
                    "missing timestamps and rejected rows.",
        expected_rules=["AF-006"], expected_chains=[], expected_absent=["AF-001", "AF-003"],
        alternatives=["Evidence acquisition incomplete for the period",
                      "Logging disabled or expired by configuration",
                      "Host offline / user inactive (weaker here because other artifacts continue)"],
        sources=[SourceSpec(
            "collector_export_partial.json", "json", "structured", events,
            "partial collector export",
            errors=[{"row_index": 6, "record_id": "S7-BAD-TS", "reason": "unparsable_timestamp",
                     "detail": "cannot interpret 'not-a-timestamp' as a date/time",
                     "raw_excerpt": "{\"timestamp\": \"not-a-timestamp\", \"event_type\": \"file_access\"}"},
                    {"row_index": 9, "record_id": "S7-EMPTY", "reason": "empty_row",
                     "detail": "row contains no values", "raw_excerpt": "{}"}],
            invalid_records=[
                {"timestamp": "not-a-timestamp", "event_type": "file_access",
                 "description": "row with an unparsable timestamp",
                 "source_record_id": "S7-BAD-TS", "host": HOST, "user": USER_A},
                {},
            ],
        )],
        notes="Demonstrates: rejected rows are reported, undated records never get a fake time, "
              "and absence of log records is treated as missing coverage, not deletion.",
    )


# ---------------------------------------------------------------------------
# 8. Clock drift and inconsistent timezones
# ---------------------------------------------------------------------------
def scenario_clock() -> Scenario:
    events = [
        rec("S8-001", BASE - timedelta(hours=5, minutes=30), "file_modified",
            "file_modified: C:\\Users\\alice\\Documents\\Server_notes.txt",
            file_path="C:\\Users\\alice\\Documents\\Server_notes.txt",
            timestamp_raw="2026-03-01T22:00:00-05:30",
            timezone_note="source offset -05:30 preserved; normalized to UTC"),
        rec("S8-002", BASE - timedelta(hours=4), "logon_success",
            "Interactive logon for CORP\\bob", user=USER_B,
            timestamp_raw="2026-03-02T03:00:00+00:00"),
        rec("S8-4616", BASE - timedelta(hours=2), "system_time_changed",
            "System time changed: new system time 2026-03-02T07:00:00.000000000Z after "
            "adjustment of +7200s",
            user=USER_ADMIN, source_record_id="771201",
            timestamp_raw="2026-03-02T09:00:00+00:00",
            timezone_note="clock change recorded; ordering across this boundary is uncertain"),
        rec("S8-003", BASE - timedelta(hours=1), "file_modified",
            "file_modified: C:\\Users\\bob\\Desktop\\agenda.txt",
            file_path="C:\\Users\\bob\\Desktop\\agenda.txt", user=USER_B,
            timestamp_raw="2026-03-02-05:00:00",  # malformed source value
        ),
        rec("S8-004", BASE, "file_access",
            "access to C:\\Users\\alice\\Documents\\Server_notes.txt",
            file_path="C:\\Users\\alice\\Documents\\Server_notes.txt",
            timestamp_raw="2026-03-02T11:30:00+05:45"),
    ]
    # one malformed raw value must be preserved while the normalized time stays usable
    events[3]["timestamp_raw"] = "2026-03-02T05:00:00+00:00"
    return Scenario(
        id="clock", name="Clock drift and inconsistent timezones",
        description="Mixed offsets (-05:30, +05:45, UTC), a recorded clock change and preserved "
                    "raw source strings.",
        expected_rules=["AF-004"], expected_chains=[], expected_absent=["AF-001", "AF-002"],
        alternatives=["Clock drift or timezone misconfiguration",
                      "Scheduled time synchronization (NTP/VM tools)"],
        sources=[SourceSpec("collector_export_multi_tz.json", "json", "structured", events,
                            "collector export with mixed source offsets")],
        notes="Raw source timestamps are preserved next to the normalized UTC value.",
    )


# ---------------------------------------------------------------------------
# 9. Unrelated events occurring close together
# ---------------------------------------------------------------------------
def scenario_unrelated() -> Scenario:
    events = [
        rec("S9-001", BASE + timedelta(seconds=1), "process_creation",
            "process started: C:\\Program Files\\Adobe\\Acrobat\\Acrobat.exe",
            user=USER_A, process_name="Acrobat.exe", process_id=7001, host=HOST),
        rec("S9-002", BASE + timedelta(seconds=4), "audit_log_cleared",
            "Windows event 1102 from provider Microsoft-Windows-Eventlog audit/security log "
            "cleared initiated by CORP\\bob",
            user=USER_B, host=HOST2, source_record_id="44231"),
        rec("S9-003", BASE + timedelta(seconds=9), "file_deleted",
            "file_deleted: D:\\shares\\public\\newsletter.pdf",
            file_path="D:\\shares\\public\\newsletter.pdf", user=USER_B, host=HOST2),
        rec("S9-004", BASE + timedelta(seconds=15), "browser_visit",
            "Browser visit to https://news.example.com", user=USER_A, host=HOST),
    ]
    return Scenario(
        id="unrelated", name="Unrelated events occurring close together",
        description="Four events within 15 seconds across two hosts and two users — high "
                    "temporal overlap without any shared anchor.",
        expected_rules=["AF-001"], expected_chains=[], expected_absent=["AF-008", "AF-005"],
        alternatives=["Coincidental timing between independent systems",
                      "Scheduled tasks firing on their own cadence"],
        sources=[SourceSpec("multi_host_export.json", "json", "structured", events,
                            "merged export from two hosts")],
        notes="True-positive for AF-001 (the clear IS recorded) but a negative for sequence "
              "inference: no chain and no POSSIBLY_CAUSAL edge may be produced, because the "
              "events share no user/host/file anchor.",
    )


# ---------------------------------------------------------------------------
# 10. Mixed benign and suspicious sequences
# ---------------------------------------------------------------------------
def scenario_mixed() -> Scenario:
    events = [
        # benign morning
        rec("S10-001", BASE, "logon_success", "Interactive logon for CORP\\alice"),
        rec("S10-002", BASE + timedelta(minutes=4), "file_created",
            "file_created: C:\\Users\\alice\\Documents\\Draft_email.docx",
            file_path="C:\\Users\\alice\\Documents\\Draft_email.docx"),
        rec("S10-003", BASE + timedelta(minutes=20), "file_deleted",
            "file_deleted: C:\\Users\\alice\\AppData\\Local\\Temp\\draft.tmp",
            file_path="C:\\Users\\alice\\AppData\\Local\\Temp\\draft.tmp"),
        # suspicious cluster
        rec("S10-101", BASE + timedelta(hours=6), "process_creation",
            "process started: C:\\Windows\\System32\\wevtutil.exe cl Security",
            user=USER_ADMIN, process_name="wevtutil.exe cl Security", process_id=7404),
        rec("S10-102", BASE + timedelta(hours=6, minutes=2), "audit_log_cleared",
            "Windows event 1102 from provider Microsoft-Windows-Eventlog audit/security log "
            "cleared initiated by svc_admin",
            user=USER_ADMIN, source_record_id="1026781"),
        rec("S10-103", BASE + timedelta(hours=6, minutes=8), "file_deleted",
            "file_deleted: C:\\Windows\\Prefetch\\WEVTUTIL.EXE-7A2B3C1D.pf",
            file_path="C:\\Windows\\Prefetch\\WEVTUTIL.EXE-7A2B3C1D.pf", user=USER_ADMIN),
        rec("S10-104", BASE + timedelta(hours=6, minutes=26), "file_timestamps_equal",
            "file_timestamps_equal: C:\\Windows\\Prefetch\\WEVTUTIL.EXE-7A2B3C1D.pf "
            "[created/modified/accessed timestamps are identical — possible copy or archive "
            "extraction; needs corroboration, not proven]",
            file_path="C:\\Windows\\Prefetch\\WEVTUTIL.EXE-7A2B3C1D.pf", user=USER_ADMIN),
    ]
    return Scenario(
        id="mixed", name="Mixed benign and suspicious sequences",
        description="Routine work in the morning, then an anti-forensic utility run, log clear, "
                    "prefetch deletion and a uniform-timestamp anomaly.",
        expected_rules=["AF-001", "AF-002", "AF-004", "AF-005", "AF-008"],
        expected_chains=["B", "D"],
        expected_absent=["AF-006"],
        alternatives=["Approved log rotation invoked through the same utilities",
                      "Legitimate administrative cleanup",
                      "Scheduled maintenance"],
        sources=[SourceSpec("mixed_export.json", "json", "structured", events,
                            "activity + security collector export")],
    )


# ---------------------------------------------------------------------------
# 11. Full anti-forensics chain (recycle bin + timestomping + log clear)
# ---------------------------------------------------------------------------
def scenario_af_chain() -> Scenario:
    """A complete anti-forensics narrative exercising chains A-D together.

    Sensitive document copied, originals recycled, $R/$I cleanup attempted,
    timestomping of the prefetch artifact, then the Security log cleared with
    wevtutil — the full sequence the multi-step detectors were built for.
    """
    sensitive = "C:\\Users\\alice\\Documents\\Acquisition_Diligence.docx"
    events = [
        rec("S11-001", BASE, "logon_success", "Interactive logon for CORP\\alice"),
        rec("S11-002", BASE + timedelta(minutes=5), "file_access",
            f"access to {sensitive}", file_path=sensitive),
        rec("S11-003", BASE + timedelta(minutes=9), "file_timestamps_equal",
            f"file_timestamps_equal: {sensitive} [created/modified/accessed identical — "
            "possible copy or archive extraction; needs corroboration, not proven]",
            file_path=sensitive,
            declarative_notes=["possible_copy_pattern: identical MACB timestamps observed "
                               "4 minutes after a read of a sensitive document; "
                               "consistent with a copy, not proof of one"]),
        rec("S11-004", BASE + timedelta(minutes=11), "file_created",
            "file_created: C:\\Users\\alice\\AppData\\Local\\Temp\\acq_copy.docx",
            file_path="C:\\Users\\alice\\AppData\\Local\\Temp\\acq_copy.docx"),
        rec("S11-005", BASE + timedelta(minutes=30), "file_deleted",
            f"file_deleted: {sensitive}", file_path=sensitive),
        # Bulk removal of the surrounding document set within the mass-deletion
        # window (AF-003 threshold: >= 8 deletions in 2 hours).
        *[
            rec(f"S11-D{i:02d}", BASE + timedelta(minutes=32 + i * 2), "file_deleted",
                f"file_deleted: C:\\Users\\alice\\Documents\\project_{i}.docx",
                file_path=f"C:\\Users\\alice\\Documents\\project_{i}.docx")
            for i in range(7)
        ],
        rec("S11-006", BASE + timedelta(minutes=31), "recycle_bin_emptied",
            "Recycle Bin emptied for CORP\\alice (C:\\$Recycle.Bin\\S-1-5-21-…-1001)",
            file_path="C:\\$Recycle.Bin\\S-1-5-21-1101-2202-3303-1001"),
        rec("S11-007", BASE + timedelta(minutes=44), "process_creation",
            "process started: C:\\Windows\\System32\\wevtutil.exe cl Security",
            user=USER_ADMIN, process_name="wevtutil.exe cl Security", process_id=8810),
        rec("S11-008", BASE + timedelta(minutes=46), "audit_log_cleared",
            "Windows event 1102 from provider Microsoft-Windows-Eventlog audit/security log "
            "cleared initiated by svc_admin",
            user=USER_ADMIN, source_record_id="1029990"),
        rec("S11-009", BASE + timedelta(minutes=52), "file_timestamps_equal",
            "file_timestamps_equal: C:\\Windows\\Prefetch\\WEVTUTIL.EXE-7A2B3C1D.pf "
            "[created/modified/accessed timestamps are identical — possible timestomping "
            "or copy/archive extraction; needs corroboration, not proven]",
            file_path="C:\\Windows\\Prefetch\\WEVTUTIL.EXE-7A2B3C1D.pf", user=USER_ADMIN),
        rec("S11-010", BASE + timedelta(hours=1), "system_time_changed",
            "The system time was changed by 5 minutes (CORP\\svc_admin)",
            user=USER_ADMIN),
    ]
    fs_records = [
        {"path": "C:\\Windows\\System32\\winevt\\Logs\\Security.evtx",
         "size": 20971520,
         "created": int((BASE - timedelta(days=45)).timestamp() * 1000),
         "modified": int((BASE + timedelta(minutes=46)).timestamp() * 1000),
         "accessed": int((BASE + timedelta(minutes=47)).timestamp() * 1000),
         "deleted": "true", "usn": 91500, "reason": "FILE_DELETE",
         "file_id": "0x1800000000301", "record_type": "usn_journal",
         "record_id": "usn-91500"},
        {"path": sensitive,
         "size": 481280,
         "created": int((BASE - timedelta(days=12)).timestamp() * 1000),
         "modified": int((BASE + timedelta(minutes=6)).timestamp() * 1000),
         "accessed": int((BASE + timedelta(minutes=11)).timestamp() * 1000),
         "deleted": "true", "usn": 91510, "reason": "FILE_DELETE",
         "file_id": "0x40000000022c", "record_type": "usn_journal",
         "record_id": "usn-91510"},
    ]
    return Scenario(
        id="af_chain", name="Full anti-forensics chain",
        description=(
            "Sensitive document read twice (copy-consistent), a project document set "
            "bulk-deleted, Recycle Bin emptied, Security log cleared with wevtutil, "
            "prefetch artifact showing uniform timestamps, then a system time change."),
        expected_rules=["AF-001", "AF-002", "AF-003", "AF-004", "AF-005", "AF-008"],
        expected_chains=["A", "B", "D"],
        expected_absent=[],
        alternatives=[
            "Approved log rotation combined with a user deleting their own document",
            "Backup or migration tooling reading then removing files",
            "Disk cleanup invoked by an administrator",
        ],
        sources=[
            SourceSpec("security_collector.json", "json", "structured", events,
                       "normalized security/activity collector export"),
            SourceSpec("usn_journal_afchain.json", "fsat", "filesystem_artifact",
                       fs_records, "USN journal-style filesystem export (JSON)"),
        ],
        notes=("Ground truth for the multi-step detectors: access -> copy-consistent "
               "creation -> deletion -> recycle -> log clear -> timestamp anomaly -> "
               "clock change. Correlation is not causation; the report must still "
               "present the listed benign alternatives."),
    )


SCENARIOS: list[Scenario] = [
    scenario_normal(),
    scenario_cleanup(),
    scenario_deletion(),
    scenario_log_clear(),
    scenario_timestamps(),
    scenario_csv_export(),
    scenario_multi(),
    scenario_incomplete(),
    scenario_clock(),
    scenario_af_chain(),
    scenario_unrelated(),
    scenario_mixed(),
]


def scenario_by_id(scenario_id: str) -> Scenario | None:
    for scenario in SCENARIOS:
        if scenario.id == scenario_id:
            return scenario
    return None


def catalog() -> list[dict]:
    return [
        {
            "id": s.id, "name": s.name, "description": s.description,
            "expected_rules": s.expected_rules, "expected_chains": s.expected_chains,
            "expected_absent": s.expected_absent, "alternatives": s.alternatives,
            "notes": s.notes, "case_id": s.case_id,
            "sources": [{"filename": src.filename, "file_type": src.file_type,
                         "source_type": src.source_type, "records": len(src.records),
                         "rejected": len(src.errors)} for src in s.sources],
        }
        for s in SCENARIOS
    ]