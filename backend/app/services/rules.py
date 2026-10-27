"""Anti-forensics detection rules (v1 ruleset).

Each rule is deliberately conservative:
  * it declares the evidence it needs and is skipped when that evidence is absent,
  * a *missing* record is reported as missing evidence, never as proof of tampering,
  * every finding states what it does NOT establish, plausible benign explanations
    and recommended next checks.

Rule IDs: AF-001..AF-008 (see RULES_VERSION in config).
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

from ..config import RULES_VERSION
from ..models import Event
from .detection import DetectionContext, Rule, humanize_seconds
from .uncertainty import assess_support

# ---------------------------------------------------------------------------
# Watch-lists (documented, static, reviewable — no black-box scoring)
# ---------------------------------------------------------------------------

FORENSIC_RELEVANT_PATTERNS = [
    (r"\.evtx$", "Windows event log file"),
    (r"\$usnjrnl", "NTFS change journal"),
    (r"\$mft$", "NTFS master file table"),
    (r"\.pf$", "Prefetch execution artifact"),
    (r"(^|[\\/])prefetch([\\/]|$)", "Prefetch directory"),
    (r"\.hve$", "Registry hive export"),
    (r"(^|[\\/])ntuser\.dat", "User registry hive"),
    (r"(^|[\\/])(sam|system|software|security)(\.dat)?$", "SYSTEM/SAM/SOFTWARE hive"),
    (r"amcache", "Amcache execution artifact"),
    (r"shimcache|appcompatcy", "AppCompat/Shimcache artifact"),
    (r"winevt[\\/]logs", "Windows event log directory"),
    (r"(^|[\\/])logfiles([\\/]|$)", "IIS/system log directory"),
    (r"setupapi(\.dev)?\.log", "Device installation log"),
    (r"consolehost_history|powershell.*console", "PowerShell console history"),
    (r"\.bash_history|\.zsh_history|\.sh_history", "Shell history file"),
    (r"(^|[\\/])\$recycle\.bin([\\/]|$)", "Recycle Bin"),
    (r"srum|sru.*edb", "System Resource Usage Monitor database"),
    (r"tasks[\\/]scheduler", "Scheduled task store"),
    (r"\.log$", "Generic log file"),
    (r"(^|[\\/])(auth|audit|syslog)", "Auth/audit log file"),
]

SENSITIVE_DATA_PATTERNS = [
    (r"\.docx?$|\.xlsx?$|\.pptx?$", "Office document"),
    (r"\.pdf$", "PDF document"),
    (r"(^|[\\/])finance([\\/]|$)", "Finance directory"),
    (r"password|credential|secret", "Credential-bearing name"),
    (r"\.pem$|\.key$|\.pfx$|id_rsa", "Key material"),
    (r"(^|[\\/])documents([\\/]|$)|desktop", "User document area"),
    (r"wallet|blockchain\.dat", "Wallet file"),
]

SUSPICIOUS_PROCESS_PATTERNS = [
    (r"wevtutil(\.exe)?\s+cl", "wevtutil clear-log is the built-in audit clearing command"),
    (r"clear-eventlog|remove-eventlog", "PowerShell cmdlet that clears an event log"),
    (r"powershell(\.exe)?.*(-e|enc|encodedcommand)\s", "Encoded PowerShell command line"),
    (r"sdelete", "SDelete securely erases file content and free space"),
    (r"cipher(\.exe)?\s+/w", "cipher /w overwrites deleted data"),
    (r"ccleaner", "General-purpose trace cleaner"),
    (r"rm\s+(-rf|-fr)\s+.*(\.evtx|winevt|history|prefetch)", "Recursive removal of forensic artifacts"),
    (r"fsutil\s+usn\s+deletejournal", "Deletes the NTFS change journal"),
    (r"auditpol", "Changes audit policy requirements"),
]


def matches(patterns: list[tuple[str, str]], value: str | None) -> str | None:
    if not value:
        return None
    lowered = value.lower()
    for pattern, why in patterns:
        if re.search(pattern, lowered):
            return why
    return None


def is_forensic_relevant(path: str | None) -> str | None:
    return matches(FORENSIC_RELEVANT_PATTERNS, path)


def is_sensitive(path: str | None) -> str | None:
    return matches(SENSITIVE_DATA_PATTERNS, path)


def suspicious_process(event: Event) -> str | None:
    haystack = f"{event.process_name or ''} {event.description or ''}"
    return matches(SUSPICIOUS_PROCESS_PATTERNS, haystack)


DELETION_TYPES = {"file_deleted", "object_deleted", "file_deleted_archived", "recycle_bin_emptied"}
EXECUTION_TYPES = {"process_creation", "service_installed", "scheduled_task_changed",
                   "scheduled_task_updated", "script_block"}
ACTIVITY_TYPES = EXECUTION_TYPES | {"file_access", "handle_requested", "browser_visit",
                                    "file_modified", "file_created", "network_connection"}
LOG_CLEAR_TYPES = {"audit_log_cleared", "event_log_cleared"}
AUDIT_BEARING_SOURCES = {"windows_event_log", "security_audit"}
# Records a continuous security/audit log is expected to contain. Process and file
# events are deliberately NOT part of the corpus: they come from other artifacts,
# so they evidence host activity while the log shows coverage.
SECURITY_CORPUS_TYPES = {
    "logon_success", "logon_failure", "logon_locked", "logon_expired",
    "account_created", "account_deleted", "account_locked_out",
    "audit_log_cleared", "event_log_cleared", "audit_policy_change",
    "explicit_credential_logon", "event_logging_shutdown", "privilege_use",
}


def _source_ids(events: list[Event]) -> list[str]:
    return sorted({e.evidence_source_id for e in events if e.evidence_source_id})


def _is_deletion(event: Event) -> bool:
    return event.event_type in DELETION_TYPES


def _relevant_log_corpus(ctx: DetectionContext) -> list[Event]:
    """Records a continuous security log is expected to hold.

    Sources named as audit-bearing always qualify; structured imports qualify
    through their event types so a normalized EVTX export still measures coverage.
    """
    return [
        e for e in ctx.timed
        if e.source_type in AUDIT_BEARING_SOURCES or e.event_type in SECURITY_CORPUS_TYPES
    ]


# ---------------------------------------------------------------------------
# AF-001 Audit log clearing (observed directly)
# ---------------------------------------------------------------------------
class AuditLogClearing(Rule):
    id = "AF-001"
    name = "Audit log clearing"
    description = "An audit/security or Windows event log clear was recorded by the source system."
    category = "evidence_loss"
    required_evidence = ("windows_event_log", "audit_log_cleared", "event_log_cleared")
    required_evidence_note = "a record that explicitly logs the clear is required"
    detection_conditions = (
        "An event whose type is audit_log_cleared / event_log_cleared (e.g. Security 1102, System 104) exists.",
        "The record must come from an acquired event log, not from a derived or summarised source.",
    )
    exclusions = (
        "Retention policy / log rotation by an administrator",
        "Rebuild, migration or reinstallation of the logging service",
        "Scheduled maintenance documented in change records",
    )
    severity = "high"
    explanation_template = (
        "Rule {conditions} matched: a source event explicitly records that a log was cleared."
    )
    limitations = (
        "A clear event confirms the log was cleared; it does not identify who or why by itself.",
        "The identity of the operator may be unavailable or an impersonated service account.",
    )
    version = "1.0.0"
    anchor_event_types = LOG_CLEAR_TYPES

    def evaluate(self, ctx: DetectionContext):
        findings = []
        for event in sorted(
            ctx.by_type.get("audit_log_cleared", []) + ctx.by_type.get("event_log_cleared", []),
            key=lambda e: e.timestamp or e.seq,
        ):
            prior = [e for e in ctx.timed if e.timestamp and event.timestamp
                     and e.timestamp < event.timestamp]
            recent_activity = [
                e for e in prior
                if (e.user and event.user and e.user == event.user)
                and (e.host and event.host and e.host == event.host)
            ][-6:]
            observed = [
                f"Record {event.source_record_id} in {event.source_file} records a log clear at "
                f"{event.timestamp.isoformat() if event.timestamp else 'an unknown time'}.",
                f"Provider/system detail: {event.description}",
            ]
            missing = []
            if not recent_activity:
                missing.append(
                    "No other activity records from the same user/host precede this event in the "
                    "acquired evidence — related activity (if any) was not collected."
                )
            support = assess_support(
                observed=1,
                sources=len(_source_ids([event])) or 1,
                relationship_corroborated=False,
                missing_required=bool(missing),
                contradictions=0,
                notes=["Direct observation of a log-clear record — severity high, support still "
                       "rated from evidence quantity, not from severity."],
            )
            findings.append(self.base_finding(
                ctx,
                title=f"Audit log clear recorded in {event.source_file or 'event log'} "
                      f"(record {event.source_record_id})",
                events=[event],
                observed=observed,
                correlation=[
                    "No correlation is required for this rule: the clearing is directly recorded "
                    "by the source artifact.",
                ],
                hypothesis=(
                    "An audit trail on this host was cleared. Who performed it, why, and whether "
                    "it was authorised remain open investigative questions."
                ),
                does_not_establish=[
                    "It does not establish who executed the command.",
                    "It does not establish malicious intent or an attempt to hide activity.",
                    "It does not establish that other records were destroyed — only that this log "
                    "was cleared.",
                ],
                missing=missing,
                next_steps=[
                    "Correlate with process-execution records immediately preceding the clear.",
                    "Check whether other logs on the host show the same operator/session.",
                    "Request off-host copies of the cleared log (SIEM, backup, forwarded copies).",
                    "Verify the change against approved maintenance or retention records.",
                ],
                alternatives_context="log clearing has routine administrative causes too",
                alternatives_extra=[
                    "Approved retention policy run or log rotation",
                    "Post-incident cleanup performed by an administrator",
                    "Deployment script resetting logging state",
                ],
                support=support,
                dedupe_context=event.id,
            ))
        return findings


# ---------------------------------------------------------------------------
# AF-002 Suspicious deletion of forensic-relevant artifacts
# ---------------------------------------------------------------------------
class ForensicArtifactDeletion(Rule):
    id = "AF-002"
    name = "Deletion of forensic-relevant artifacts"
    description = "A record shows deletion of a file class that carries forensic value."
    category = "evidence_loss"
    required_evidence = ("filesystem_artifact", "windows_event_log", "file_deleted", "object_deleted")
    required_evidence_note = "file deletion must be observable in filesystem or event log records"
    detection_conditions = (
        "A deletion-type record exists and its target path matches a forensic-relevant pattern "
        "(event logs, journal, MFT, prefetch, hives, shell history, log directories).",
    )
    exclusions = (
        "Disk-cleanup / temp-file maintenance tooling",
        "Log rotation or archival that also applies retention deletion",
        "Operating-system upgrade removing old logs",
    )
    severity = "high"
    explanation_template = "Rule {conditions} matched: a matching deletion record exists."
    limitations = (
        "Deletion in a filesystem journal means unlink, not secure destruction — content may persist.",
        "The record does not reveal who issued the delete or whether backups exist elsewhere.",
    )
    version = "1.0.0"
    anchor_event_types = DELETION_TYPES

    def evaluate(self, ctx: DetectionContext):
        findings = []
        for event in ctx.by_type.get("file_deleted", []) + ctx.by_type.get("object_deleted", []):
            # Rules key on the path field, never on free-text descriptions: a
            # description like "… record source $MFT" must not count as a path
            # match.
            reason = is_forensic_relevant(event.file_path)
            if not reason:
                continue
            others = _source_ids([e for e in ctx.timed
                                  if e.timestamp and event.timestamp
                                  and abs((e.timestamp - event.timestamp).total_seconds()) < 86400
                                  and e.evidence_source_id != event.evidence_source_id])
            missing = []
            if not others:
                missing.append(
                    "No independent source covers the same time window — deletion cannot be "
                    "corroborated or excluded by another acquisition."
                )
            support = assess_support(
                observed=1,
                sources=len(_source_ids([event])) + len(others),
                relationship_corroborated=bool(others),
                missing_required=bool(missing),
                contradictions=0,
            )
            findings.append(self.base_finding(
                ctx,
                title=f"Deletion of forensic-relevant file: {event.file_path or 'unknown path'}",
                events=[event],
                observed=[
                    f"Record {event.source_record_id} ({event.source_type}) records deletion of "
                    f"{'a ' + reason.lower() if reason else 'an artifact'}"
                    + (f" at `{event.file_path}`" if event.file_path else "") + ".",
                ],
                correlation=([
                    "An independent source covers the same period, so the deletion is corroborated."
                ] if others else [
                    "Only one source covers this period; the record stands alone."
                ]),
                hypothesis=(
                    "The removed artifact carried forensic value, so its absence reduces the "
                    "activity history available for this investigation."
                ),
                does_not_establish=[
                    "It does not establish that the deletion was intended to conceal activity.",
                    "It does not establish that the data is unrecoverable.",
                    "It does not establish who executed the deletion.",
                ],
                missing=missing,
                next_steps=[
                    "Check volume shadow copies / backups for the deleted artifact.",
                    "Look for the deleting process in execution records around the same time.",
                    "Verify whether a cleanup utility or schedule explains the removal.",
                ],
                alternatives_context="artifact deletions often follow routine maintenance",
                alternatives_extra=[
                    "Disk cleanup or uninstaller removing transient artifacts",
                    "Log retention policy deleting aged logs",
                ],
                support=support,
                assumption_dependent=True,
                dedupe_context=event.id,
            ))
        return findings


# ---------------------------------------------------------------------------
# AF-003 Mass deletion pattern
# ---------------------------------------------------------------------------
class MassDeletion(Rule):
    id = "AF-003"
    name = "Mass deletion pattern"
    description = "Many deletions occur within a short window, above the configured threshold."
    category = "evidence_loss"
    required_evidence = ("filesystem_artifact", "windows_event_log", "file_deleted", "object_deleted")
    required_evidence_note = "deletion volumes can only be measured from deletion records"
    detection_conditions = (
        "At least `mass_deletion_threshold` deletion records fall inside "
        "`mass_deletion_window_hours` (sliding two-pointer window over all deletions).",
    )
    exclusions = (
        "Emptied Recycle Bin or a single large delete operation",
        "Software uninstall or OS upgrade",
        "User reorganising a project directory",
    )
    severity = "medium"
    explanation_template = "Rule {conditions} matched: the deletion rate exceeded the threshold."
    limitations = (
        "High deletion volume is common in normal use; volume alone is weakly indicative.",
        "Records outside the acquired evidence are not counted — the true rate may be higher.",
    )
    version = "1.0.0"
    anchor_event_types = DELETION_TYPES

    def evaluate(self, ctx: DetectionContext):
        threshold = int(ctx.config["mass_deletion_threshold"])
        window_hours = float(ctx.config["mass_deletion_window_hours"])
        deletions = sorted(
            [e for e in ctx.timed if _is_deletion(e)],
            key=lambda e: e.timestamp,
        )
        findings = []
        used: set[str] = set()
        left = 0
        for right in range(len(deletions)):
            while deletions[right].timestamp - deletions[left].timestamp > timedelta(hours=window_hours):
                left += 1
            window_events = deletions[left:right + 1]
            if len(window_events) < threshold:
                continue
            if any(e.id in used for e in window_events):
                continue
            for e in window_events:
                used.add(e.id)
            span = (window_events[-1].timestamp - window_events[0].timestamp).total_seconds()
            paths = sorted({e.file_path for e in window_events if e.file_path})
            hosts = sorted({e.host for e in window_events if e.host})
            related_users = sorted({e.user for e in window_events if e.user})
            support = assess_support(
                observed=len(window_events),
                sources=len(_source_ids(window_events)),
                relationship_corroborated=len(window_events) > threshold,
                missing_required=False,
                contradictions=0,
                notes=["Bulk deletion volume is high relative to the configured threshold."],
            )
            findings.append(self.base_finding(
                ctx,
                title=f"{len(window_events)} deletions within {humanize_seconds(span) or 'an instant'} "
                      f"on {', '.join(hosts) or 'unknown host'}",
                events=window_events[:40],
                observed=[
                    f"{len(window_events)} deletion records fall within a "
                    f"{window_hours:g}h window (threshold {threshold}).",
                    f"Distinct paths touched: {len(paths)}"
                    + (f"; e.g. `{paths[0]}`" if paths else ""),
                    f"Actor(s) recorded on these events: {', '.join(related_users) or 'unknown'}.",
                ],
                correlation=[
                    f"Deletions are temporally clustered (span {humanize_seconds(span)}, "
                    f"{len(window_events)} events, same analysis window).",
                    "Different target paths are connected only by their shared time window and "
                    "actors — no single programmatic purger is proven by the records alone.",
                ],
                hypothesis=(
                    "The cluster may be a bulk removal operation. Whether it targeted evidence "
                    "specifically cannot be established from volume alone."
                ),
                does_not_establish=[
                    "It does not establish that the deletions were automated or malicious.",
                    "It does not establish which process performed them without execution records.",
                    "It does not establish that all deleted data is lost.",
                ],
                missing=[
                    "No process-execution records naming the deleting program were matched "
                    "(required to attribute the cluster to a single tool)."
                ],
                next_steps=[
                    "Look for a single executing program covering the cluster period.",
                    "Compare with known maintenance/uninstall schedules.",
                    "Check Recycle Bin / journal contents for recoverable copies.",
                ],
                alternatives_context="bulk deletions usually have mundane causes",
                alternatives_extra=[
                    "Emptied Recycle Bin (single operation, many records)",
                    "Uninstall of a large application",
                    "Build/clean task in a development directory",
                ],
                support=support,
                severity="medium" if len(window_events) < threshold * 2 else "high",
                dedupe_context=f"{window_events[0].id}:{len(window_events)}",
            ))
        return findings


# ---------------------------------------------------------------------------
# AF-004 Timestamp inconsistencies
# ---------------------------------------------------------------------------
class TimestampInconsistency(Rule):
    id = "AF-004"
    name = "Timestamp inconsistency"
    description = ("Explicit timestamp consistency checks found conflicting time information: "
                   "created/modified inversion, uniform MACE reset, or a recorded clock change.")
    category = "integrity"
    required_evidence = ("filesystem_artifact", "system_time_changed", "file_metadata_suspect",
                          "file_timestamps_equal")
    required_evidence_note = "consistency checks need filesystem metadata and/or clock records"
    detection_conditions = (
        "modified timestamp < created timestamp in the same record, or",
        "created/modified/accessed are identical on three or more fields (possible metadata reset), or",
        "a system-time change record exists (e.g. Security 4616) near the disputed records.",
    )
    exclusions = (
        "Timezone interpretation differences between acquisition tools",
        "Backup/restore or virtual machine snapshot restoring metadata",
        "NTP correction or CMOS battery replacement changing the clock",
        "File copied between filesystems with different timestamp granularity",
    )
    severity = "medium"
    explanation_template = "Rule {conditions} matched at least one explicit consistency check."
    limitations = (
        "Timestamp conflicts can be produced by ordinary tooling and clock behaviour.",
        "A conflict alone is not evidence that times were forged.",
        "Ordering across sources with unverified clocks remains uncertain.",
    )
    version = "1.0.0"
    anchor_event_types = ("file_metadata_suspect", "file_timestamps_equal", "system_time_changed")

    def evaluate(self, ctx: DetectionContext):
        findings = []
        inverted = ctx.by_type.get("file_metadata_suspect", [])
        uniform = ctx.by_type.get("file_timestamps_equal", [])
        clock_changes = ctx.by_type.get("system_time_changed", [])

        # --- Check 1: created/modified inversion --------------------------------
        for events, label, condition in (
            (inverted, "modified timestamp precedes created timestamp",
             "modified < created inside one record"),
            (uniform, "created/modified/accessed timestamps are identical",
             "three metadata fields are byte-identical"),
        ):
            if not events:
                continue
            hosts = sorted({e.host for e in events if e.host})
            corroborating = [
                e for e in clock_changes
                if e.host in hosts or not hosts
            ]
            missing = []
            if not corroborating:
                missing.append(
                    "No clock-change or time-sync record confirms an external time shift — the "
                    "inconsistency is internal to the metadata."
                )
            support = assess_support(
                observed=len(events),
                sources=len(_source_ids(events)),
                relationship_corroborated=bool(corroborating) and len(events) > 1,
                missing_required=bool(missing),
                assumption_dependent=not corroborating,
                contradictions=0,
            )
            findings.append(self.base_finding(
                ctx,
                title=f"Timestamp consistency check failed: {label} ({len(events)} record(s))",
                events=events[:30],
                observed=[
                    f"{len(events)} record(s) fail the check: {condition}.",
                    "Example: "
                    + (events[0].description or "")[:240],
                    f"Hosts involved: {', '.join(hosts) or 'not recorded'}.",
                ],
                correlation=[
                    ("A system-time change record covers the same host, which can explain the "
                     "inconsistency without any metadata manipulation."
                     if corroborating else
                     "No clock-change record accompanies these inconsistencies."),
                    "The affected records share a host/time window, so the anomaly is not "
                    "independent noise across unrelated systems (when hosts are recorded).",
                ],
                hypothesis=(
                    "Metadata may have been rewritten, *or* the host clock, restore operation or "
                    "copy tool produced the same pattern. The records alone do not separate these."
                ),
                does_not_establish=[
                    "It does not establish deliberate timestamp forging (timestomping).",
                    "It does not establish the true original times of these records.",
                    "It does not establish which of several benign tools applied the timestamps.",
                ],
                missing=missing,
                next_steps=[
                    "Compare against shadow copies, backups or an offline second source.",
                    "Check for clock-change events (4616), NTP re-syncs or timezone changes.",
                    "Check whether an archive/copy/backup tool ran over these paths.",
                    "Cross-check related events whose times came from a different clock domain.",
                ],
                alternatives_context="timestamp mismatches commonly arise without tampering",
                alternatives_extra=[
                    "Copy/extract tool preserving or flattening timestamps",
                    "Virtual machine or container time-set at boot",
                    "Filesystem format with coarser timestamp granularity",
                ],
                support=support,
                severity="medium",
                dedupe_context=f"{label}:{hosts[0] if hosts else 'unknown'}:{event_signature(events)}",
            ))

        # --- Check 3: explicit clock change -------------------------------------
        for event in clock_changes:
            support = assess_support(
                observed=1,
                sources=len(_source_ids([event])) or 1,
                relationship_corroborated=False,
                missing_required=False,
                assumption_dependent=True,
                contradictions=0,
                notes=["A recorded clock change reduces confidence in relative ordering across "
                       "the boundary."],
            )
            findings.append(self.base_finding(
                ctx,
                title=f"System time changed (recorded) — ordering confidence reduced",
                events=[event],
                observed=[f"{event.description} (record {event.source_record_id})"],
                correlation=[
                    "Events on either side of this change may be misordered if the shift was "
                    "large; TRACE-X does not silently re-align them.",
                ],
                hypothesis=(
                    "Timeline positions spanning this change are uncertain until the drift is "
                    "quantified from a second clock source."
                ),
                does_not_establish=[
                    "It does not establish that any timestamp was forged.",
                    "It does not establish the magnitude or intent of the change.",
                ],
                missing=["No independent trusted clock reference is available in this "
                         "investigation to measure the actual drift."],
                next_steps=[
                    "Quantify the shift from the record contents and re-evaluate ordering.",
                    "Compare with an independent clock (NTP logs, another host's records).",
                ],
                alternatives_context="clock changes also happen benignly",
                alternatives_extra=[
                    "Scheduled time synchronization (NTP/VM tools)",
                    "Battery or firmware reset restoring the clock",
                    "Timezone/DST configuration change",
                ],
                support=support,
                severity="medium",
                assumption_dependent=True,
                dedupe_context=f"clock:{event.id}",
            ))
        return findings


def event_signature(events: list[Event]) -> str:
    return str(len(events))


# ---------------------------------------------------------------------------
# AF-005 Relevant activity followed by evidence loss
# ---------------------------------------------------------------------------
class ActivityThenEvidenceLoss(Rule):
    id = "AF-005"
    name = "Relevant activity followed by evidence loss"
    description = ("Activity of investigative interest is followed within the analysis window by "
                   "deletion of related evidence or clearing of a log.")
    category = "evidence_loss"
    required_evidence = ("file_deleted", "audit_log_cleared", "event_log_cleared",
                          "filesystem_artifact", "windows_event_log")
    required_evidence_note = "an evidence-loss record must exist to anchor the sequence"
    detection_conditions = (
        "An activity record (access/execution/modification) precedes a deletion or log clear.",
        "Both fall inside `activity_window_hours` and share a file path, or a user and host.",
    )
    exclusions = (
        "Normal work followed by routine cleanup of its own temporary files",
        "Application autosave/rotation deleting files it just wrote",
        "User finishing a task before archiving the folder",
    )
    severity = "high"
    explanation_template = ("Rule {conditions} matched: an activity record is followed by a loss "
                            "record inside the configured window.")
    limitations = (
        "A shared user/host/path inside a time window is a correlation, not a causal link.",
        "Both events may have independent explanations unrelated to each other.",
    )
    version = "1.0.0"
    anchor_event_types = DELETION_TYPES | LOG_CLEAR_TYPES

    def evaluate(self, ctx: DetectionContext):
        findings = []
        window_hours = float(ctx.config["activity_window_hours"])
        losses = [e for e in ctx.timed if _is_deletion(e) or e.event_type in LOG_CLEAR_TYPES]
        for loss in losses:
            start = loss.timestamp - timedelta(hours=window_hours)
            candidates = [
                e for e in ctx.timed
                if e.timestamp and start <= e.timestamp < loss.timestamp
                and e.event_type in ACTIVITY_TYPES
            ]
            same_path = [e for e in candidates
                         if e.file_path and loss.file_path and e.file_path == loss.file_path]
            related = same_path or [
                e for e in candidates
                if e.user and loss.user and e.user == loss.user
                and e.host and loss.host and e.host == loss.host
            ]
            if not related:
                continue
            related = related[-5:]
            events = related + [loss]
            support = assess_support(
                observed=len(events),
                sources=len(_source_ids(events)),
                relationship_corroborated=bool(same_path) or len(_source_ids(events)) > 1,
                missing_required=not bool(
                    {e.evidence_source_id for e in events} - {loss.evidence_source_id}
                ),
                assumption_dependent=not bool(same_path),
            )
            activity_desc = related[-1].description or related[-1].event_type
            missing = []
            if not same_path:
                missing.append(
                    "The loss record does not carry a path matching the activity record — the "
                    "link rests on shared user/host and timing only."
                )
            findings.append(self.base_finding(
                ctx,
                title=f"Activity followed by evidence loss: "
                      f"{related[-1].event_type} → {loss.event_type}",
                events=events,
                observed=[
                    f"At {related[-1].timestamp.isoformat()}: {activity_desc}",
                    f"At {loss.timestamp.isoformat()} ({humanize_seconds((loss.timestamp - related[-1].timestamp).total_seconds())} "
                    f"later): {loss.description}",
                ],
                correlation=[
                    f"Both records fall within the configured {window_hours:g}h analysis window.",
                    ("Shared file path anchors the relationship." if same_path
                     else "Shared user and host only — weaker than a shared path."),
                    f"They are drawn from {len(_source_ids(events))} evidence source(s).",
                ],
                hypothesis=(
                    "The sequence may be consistent with activity followed by removal of its "
                    "supporting records; coincidental overlap is an equally live explanation."
                ),
                does_not_establish=[
                    "It does not establish causation or a shared actor.",
                    "It does not establish intent to conceal.",
                    "It does not establish that the lost record contained evidence of wronging.",
                ],
                missing=missing,
                next_steps=[
                    "Confirm whether the same process/user performed both steps.",
                    "Locate an independent copy of the lost evidence (backup, SIEM, shadow copy).",
                    "Test whether a scheduled cleanup explains the deletion timing.",
                ],
                alternatives_context="sequences of work-then-cleanup are routine",
                support=support,
                severity="high" if same_path else "medium",
                assumption_dependent=not bool(same_path),
                dedupe_context=f"{loss.id}:{related[-1].id}",
            ))
        return findings


# ---------------------------------------------------------------------------
# AF-006 Suspicious gaps in expected logging
# ---------------------------------------------------------------------------
class LoggingGap(Rule):
    id = "AF-006"
    name = "Suspicious gap in expected logging"
    description = ("A period with no records from a source that normally produces them falls while "
                   "other artifacts show the host was active.")
    category = "coverage"
    required_evidence = ("windows_event_log", "security_audit")
    required_evidence_note = "a continuous log source is needed to measure a logging gap"
    detection_conditions = (
        "The gap between consecutive records of the same log source exceeds "
        "`logging_gap_hours`, AND non-log artifacts show activity inside the gap.",
    )
    exclusions = (
        "Host offline, asleep, or re-imaged",
        "User genuinely inactive during the period",
        "Logging configured off / collection paused by policy",
        "Evidence acquisition incomplete for the period",
    )
    severity = "medium"
    explanation_template = ("Rule {conditions} matched: coverage gap found while other artifacts "
                            "indicate host activity.")
    limitations = (
        "Absence of a record is not evidence that a record was deleted.",
        "Normal inactivity produces the same signature as collection failure.",
        "The gap may reflect an incomplete acquisition rather than host-side tampering.",
    )
    version = "1.0.0"
    anchor_event_types: tuple[str, ...] = ()   # availability handled in available()

    def available(self, ctx: DetectionContext):
        corpus = _relevant_log_corpus(ctx)
        if len(corpus) < 3:
            return False, (f"skipped: at least 3 records from a continuous log source are required "
                           f"to measure coverage (found {len(corpus)})")
        return True, ""

    def evaluate(self, ctx: DetectionContext):
        gap_hours = float(ctx.config["logging_gap_hours"])
        corpus = sorted(_relevant_log_corpus(ctx), key=lambda e: e.timestamp)
        other_activity = [
            e for e in ctx.timed
            if e.source_type not in AUDIT_BEARING_SOURCES and e.event_type in ACTIVITY_TYPES
        ]
        findings = []
        emitted = 0
        for earlier, later in zip(corpus, corpus[1:]):
            gap = (later.timestamp - earlier.timestamp).total_seconds() / 3600.0
            if gap < gap_hours:
                continue
            inside = [
                e for e in other_activity
                if earlier.timestamp < e.timestamp < later.timestamp
            ]
            if not inside:
                # Nothing else happened: consistent with idle host, not suspicious.
                continue
            support = assess_support(
                observed=1 + min(len(inside), 3),
                sources=len(_source_ids(corpus[0:1] + [later] + inside[:1])),
                relationship_corroborated=len(inside) > 0,
                missing_required=True,   # the gap *is* missing evidence of the log's coverage
                assumption_dependent=True,
                contradictions=0,
                notes=["The gap itself is missing coverage — it can never become 'observed' "
                       "evidence without external copies."],
            )
            findings.append(self.base_finding(
                ctx,
                title=f"{gap:.1f}h logging gap on {earlier.host or 'host'} while other "
                      f"activity was recorded",
                events=[earlier, later] + inside[:4],
                observed=[
                    f"No records in {earlier.source_file or earlier.source_type} between "
                    f"{earlier.timestamp.isoformat()} and {later.timestamp.isoformat()} ({gap:.1f} hours).",
                    f"{len(inside)} non-log record(s) show host activity inside that period, "
                    f"e.g. {(inside[0].description or '')[:160]}",
                ],
                correlation=[
                    "The log source resumes immediately before other acquired activity, so the "
                    "gap overlaps demonstrably active periods.",
                ],
                hypothesis=(
                    "Logging may have been interrupted, disabled, or excluded from the "
                    "acquisition. Deletion is only one of several explanations."
                ),
                does_not_establish=[
                    "It does not establish that log records were deleted.",
                    "It does not establish intentional suppression of logging.",
                    "It does not establish which events occurred during the gap.",
                ],
                missing=[
                    "The log records covering the gap are not present in the acquired evidence, "
                    "so their removal, non-collection or non-generation cannot be distinguished.",
                ],
                next_steps=[
                    "Obtain the log's own retention/rotation configuration for the period.",
                    "Check event collector health or forwarding failures (collector-side logs).",
                    "Look for host uptime/shutdown records covering the gap.",
                    "Request an independent copy of the same log from another system.",
                ],
                alternatives_context="coverage gaps usually have infrastructure causes",
                support=support,
                severity="medium",
                assumption_dependent=True,
                dedupe_context=f"gap:{earlier.id}:{later.id}",
            ))
            emitted += 1
            if emitted >= 8:
                break
        return findings


# ---------------------------------------------------------------------------
# AF-007 Modification of forensic-relevant artifacts
# ---------------------------------------------------------------------------
class ForensicArtifactModification(Rule):
    id = "AF-007"
    name = "Modification of forensic-relevant artifacts"
    description = ("A record shows creation, modification or renaming of a file class with "
                   "forensic value.")
    category = "integrity"
    required_evidence = ("filesystem_artifact", "windows_event_log")
    required_evidence_note = "artifact modification must be observable in filesystem records"
    detection_conditions = (
        "A modification/creation/rename record targets a path matching a forensic-relevant "
        "pattern, and the change is not simply the log's own append behaviour.",
    )
    exclusions = (
        "Normal append/write by the logging subsystem itself",
        "Scheduled maintenance writing new log files",
        "Antivirus or indexing service touching log directories",
    )
    severity = "medium"
    explanation_template = "Rule {conditions} matched: a relevant artifact was modified."
    limitations = (
        "Modification records do not reveal content changes versus benign append operations.",
        "Timestamps of the modification may themselves be affected by AF-004 anomalies.",
    )
    version = "1.0.0"
    anchor_event_types = ("file_modified", "file_created", "file_renamed", "usn_journal_record",
                          "permissions_changed")

    def evaluate(self, ctx: DetectionContext):
        findings = []
        candidates: list[Event] = []
        for etype in self.anchor_event_types:
            candidates.extend(ctx.by_type.get(etype, []))
        for event in candidates:
            # Path-field matching only (see AF-002): descriptions are free text.
            reason = is_forensic_relevant(event.file_path)
            if not reason:
                continue
            if event.event_type == "permissions_changed":
                detail = "permissions on a forensic-relevant object were changed"
            else:
                detail = f"{'modified artifact class: ' + reason}"
            support = assess_support(
                observed=1,
                sources=len(_source_ids([event])) or 1,
                relationship_corroborated=False,
                missing_required=False,
                assumption_dependent=True,
                contradictions=0,
            )
            findings.append(self.base_finding(
                ctx,
                title=f"Forensic-relevant artifact changed: {event.file_path or 'unknown path'}",
                events=[event],
                observed=[
                    f"Record {event.source_record_id} shows {detail}.",
                    f"Event type {event.event_type} at "
                    f"{event.timestamp.isoformat() if event.timestamp else 'time unknown'}.",
                ],
                correlation=[
                    "Connected to the rest of the timeline only through shared path/host/time "
                    "windows — no causal statement is made.",
                ],
                hypothesis=(
                    "Alteration of a forensic artifact can indicate misconfiguration or "
                    "structured interference; the record alone does not separate them."
                ),
                does_not_establish=[
                    "It does not establish that the modification was unauthorized.",
                    "It does not establish that prior contents were destroyed.",
                    "It does not establish who or which process performed it.",
                ],
                next_steps=[
                    "Identify the writing process from execution/access records.",
                    "Compare with known administration or maintenance schedules.",
                    "Check for retention copies of the original artifact.",
                ],
                alternatives_context="forensic-relevant files are written by routine services too",
                support=support,
                severity="medium",
                assumption_dependent=True,
                dedupe_context=event.id,
            ))
        return findings


# ---------------------------------------------------------------------------
# AF-008 Suspicious execution followed by log clearing
# ---------------------------------------------------------------------------
class ExecutionThenLogClear(Rule):
    id = "AF-008"
    name = "Suspicious execution followed by audit log clearing"
    description = ("A process execution of investigative interest precedes a log clear inside the "
                   "analysis window.")
    category = "anti_forensic_tooling"
    required_evidence = ("windows_event_log", "security_audit", "process_creation")
    required_evidence_note = "execution records and log-clear records are both required"
    detection_conditions = (
        "A process-execution record occurs within `activity_window_hours` before a log-clear "
        "record.",
        "Elevation occurs when the command line matches a documented anti-forensic utility "
        "(wevtutil cl, Clear-EventLog, fsutil usn deletejournal, sdelete, cipher /w ...).",
    )
    exclusions = (
        "Approved log rotation invoked through the same utilities",
        "Incident-response cleanup performed with consent",
        "Administrative script resetting logging as part of provisioning",
    )
    severity = "critical"
    explanation_template = ("Rule {conditions} matched: execution record followed by log clear "
                            "inside the window.")
    limitations = (
        "Sequence within a window does not prove the execution caused the clear.",
        "Command lines may be truncated or absent in the acquired records.",
        "Service accounts may be shared, weakening actor attribution.",
    )
    version = "1.0.0"
    anchor_event_types = LOG_CLEAR_TYPES

    def available(self, ctx: DetectionContext):
        ok, reason = super().available(ctx)
        if not ok:
            return ok, reason
        if not any(t in ctx.by_type for t in EXECUTION_TYPES):
            return False, "skipped: no process-execution records in this investigation"
        return True, ""

    def evaluate(self, ctx: DetectionContext):
        findings = []
        window_hours = float(ctx.config["activity_window_hours"])
        for clear in ctx.by_type.get("audit_log_cleared", []) + ctx.by_type.get("event_log_cleared", []):
            start = clear.timestamp - timedelta(hours=window_hours)
            execs = [
                e for e in ctx.by_type.get("process_creation", [])
                if e.timestamp and start <= e.timestamp < clear.timestamp
                and (e.host == clear.host or e.user == clear.user)
            ]
            if not execs:
                for etype in EXECUTION_TYPES - {"process_creation"}:
                    execs += [
                        e for e in ctx.by_type.get(etype, [])
                        if e.timestamp and start <= e.timestamp < clear.timestamp
                        and (e.host == clear.host or e.user == clear.user)
                    ]
            if not execs:
                continue
            last = execs[-1]
            tool_reason = suspicious_process(last)
            same_user = bool(last.user and clear.user and last.user == clear.user)
            severity = "critical" if tool_reason else ("high" if same_user else "medium")
            events = execs[-4:] + [clear]
            support = assess_support(
                observed=len(events),
                sources=len(_source_ids(events)),
                relationship_corroborated=bool(tool_reason),
                missing_required=False,
                assumption_dependent=not tool_reason,
                contradictions=0,
            )
            observed = [
                f"{last.timestamp.isoformat()}: execution record — {last.description}",
                f"{clear.timestamp.isoformat()} ({humanize_seconds((clear.timestamp - last.timestamp).total_seconds())} "
                f"later): {clear.description}",
            ]
            if tool_reason:
                observed.append(f"Command/path matches a documented anti-forensic utility: {tool_reason}.")
            else:
                observed.append("No documented anti-forensic utility is identifiable in the "
                                 "acquired execution record (command line may be absent).")
            contradictions = []
            if not same_user:
                contradictions.append({
                    "what": "The execution and the clear record name different users.",
                    "impact": "A single-actor sequence is not supported; service accounts or "
                              "record quality are alternatives.",
                })
            findings.append(self.base_finding(
                ctx,
                title=("Anti-forensic utility execution followed by log clear"
                       if tool_reason else
                       "Process execution followed by log clear"),
                events=events,
                observed=observed,
                correlation=[
                    f"Execution precedes the log clear by "
                    f"{humanize_seconds((clear.timestamp - last.timestamp).total_seconds())}, "
                    f"inside the {window_hours:g}h analysis window.",
                    "Pairing requires a shared host or user — records from unrelated systems "
                    "are never linked by clock proximity alone.",
                    f"Recorded user for execution: {last.user or 'not recorded'}; "
                    f"for the clear: {clear.user or 'not recorded'}.",
                    f"Records span {len(_source_ids(events))} evidence source(s).",
                ],
                hypothesis=(
                    "The pairing may be consistent with a deliberate clearing run following "
                    "preparatory execution. Identical timing produced by independent scheduled "
                    "tasks remains possible."
                ),
                does_not_establish=[
                    "It does not establish that the execution *caused* the clear.",
                    "It does not establish operator identity or intent.",
                    "It does not establish what was destroyed beyond the cleared log.",
                ],
                missing=([] if tool_reason else [
                    "Command-line detail identifying the executed utility is not present, so "
                    "tool attribution is unavailable.",
                ]),
                contradicting=contradictions,
                next_steps=[
                    "Retrieve full command lines from process-creation policy/EDR telemetry.",
                    "Verify scheduling history for automated log maintenance.",
                    "Search other hosts for the same utility invocation.",
                    "Obtain an independent copy of the cleared log.",
                ],
                alternatives_context="log-clearing tooling is also used by admins",
                alternatives_extra=[
                    "Provisioning or rotation script using the same commands",
                    "Responder/analyst performing agreed cleanup",
                ],
                support=support,
                severity=severity,
                assumption_dependent=not tool_reason,
                dedupe_context=f"{clear.id}:{last.id}",
            ))
        return findings


ALL_RULES: list[Rule] = [
    AuditLogClearing(),
    ForensicArtifactDeletion(),
    MassDeletion(),
    TimestampInconsistency(),
    ActivityThenEvidenceLoss(),
    LoggingGap(),
    ForensicArtifactModification(),
    ExecutionThenLogClear(),
]


def rule_catalog() -> list[dict]:
    """Public rule metadata - lets the UI explain every rule version."""
    return [
        {
            "id": r.id,
            "name": r.name,
            "description": r.description,
            "category": r.category,
            "required_evidence": list(r.required_evidence),
            "required_evidence_note": r.required_evidence_note,
            "detection_conditions": list(r.detection_conditions),
            "exclusions": list(r.exclusions),
            "severity": r.severity,
            "explanation_template": r.explanation_template,
            "limitations": list(r.limitations),
            "version": r.version,
            "ruleset_version": RULES_VERSION,
            "anchor_event_types": list(r.anchor_event_types),
        }
        for r in ALL_RULES
    ]