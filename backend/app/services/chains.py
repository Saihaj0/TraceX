"""Suspicion-chain detection: multi-event candidate sequences (Patterns A-E).

Key discipline:
  * patterns are *candidates*, not verdicts — every chain carries missing steps,
    alternative explanations and its triggered rules,
  * incomplete patterns are still reported (with which evidence is missing)
    rather than silently dropped,
  * duplicate chains are collapsed by a dedupe key,
  * no POSSIBLY_CAUSAL claim without a documented inference rule.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import timedelta

from sqlalchemy.orm import Session

from ..models import Finding, Investigation, SuspicionChain, new_id
from .detection import DetectionContext, humanize_seconds
from .rules import (
    ACTIVITY_TYPES,
    DELETION_TYPES,
    LOG_CLEAR_TYPES,
    is_forensic_relevant,
    is_sensitive,
    suspicious_process,
)
from .uncertainty import alternative_explanations, assess_support


@dataclass
class StepMatch:
    event_ids: list[str] = field(default_factory=list)
    label: str = ""
    detail: str = ""
    relationships: list[str] = field(default_factory=list)


def _window_events(ctx: DetectionContext, anchor, hours: float, earlier: bool = True):
    if anchor.timestamp is None:
        return []
    if earlier:
        start = anchor.timestamp - timedelta(hours=hours)
        return [e for e in ctx.timed
                if e.timestamp and start <= e.timestamp <= anchor.timestamp and e.id != anchor.id]
    start = anchor.timestamp
    end = start + timedelta(hours=hours)
    return [e for e in ctx.timed if e.timestamp and start <= e.timestamp <= end and e.id != anchor.id]


# --- step matchers ----------------------------------------------------------

def find_removable_activity(ctx: DetectionContext, start, end):
    """Removable-media signals: explicit device events, or writes to other drives."""
    hits = []
    for event in ctx.timed:
        if not event.timestamp or not (start <= event.timestamp <= end):
            continue
        etype = (event.event_type or "").lower()
        desc = (event.description or "").lower()
        path = event.file_path or ""
        explicit = (
            event.device_id
            and ("removable" in etype or "usb" in etype or "device" in etype
                 or "mass_storage" in etype or "removable" in desc or "usb" in desc)
        ) or etype in {"removable_device_connected", "usb_device_attached", "device_mounted",
                       "removable_media_mounted", "drive_letter_assigned"}
        drive_write = bool(path) and len(path) > 2 and path[1] == ":" and path[0].lower() in "efgh"
        if explicit or drive_write:
            hits.append(event)
    return hits


def step_match_sensitive_access(ctx, start, end):
    hits = []
    for event in ctx.timed:
        if not event.timestamp or not (start <= event.timestamp <= end):
            continue
        if event.event_type in ("file_access", "handle_requested", "file_modified",
                                "usn_journal_record", "file_read"):
            # "Sensitive" covers data assets; forensic artifacts (logs, journal,
            # hives, prefetch) are equally worth protecting from access.
            if (is_sensitive(event.file_path) or is_sensitive(event.description or "")
                    or is_forensic_relevant(event.file_path)):
                hits.append(event)
    return hits


def step_match_copy(ctx, start, end, since_event=None):
    """Copy is 'corroborated' only when a *normalization warning* or a dedicated
    record supports it - never inferred from timestamps alone."""
    hits = []
    for event in ctx.timed:
        if not event.timestamp or not (start <= event.timestamp <= end):
            continue
        notes = event.raw_record.get("declarative_notes", []) if isinstance(event.raw_record, dict) else []
        desc = event.description or ""
        explicit = any("copy" in str(n).lower() for n in notes) or \
            event.event_type in {"file_copied", "file_copy_confirmed"} or "copied" in desc.lower()
        corrobored = any("possible_copy_pattern" in str(n).lower() for n in notes) or \
            event.event_type == "file_timestamps_equal"
        if explicit or corrobored:
            hits.append(event)
        elif event.event_type in {"file_created", "file_renamed", "file_modified"} and is_sensitive(event.file_path):
            # candidate, still recorded as unconfirmed in the chain narrative
            hits.append(event)
    return hits


def step_match_metadata_change(ctx, start, end):
    return [
        e for e in ctx.timed
        if e.timestamp and start <= e.timestamp <= end
        and e.event_type in ("file_metadata_suspect", "file_renamed", "file_created", "file_modified")
        and is_forensic_relevant(e.file_path)
    ]


def step_match_timestamp_anomaly(ctx, start, end):
    return [
        e for e in ctx.timed
        if e.timestamp and start <= e.timestamp <= end
        and e.event_type in ("file_metadata_suspect", "file_timestamps_equal", "system_time_changed")
    ]


def step_match_evidence_loss(ctx, start, end):
    return [
        e for e in ctx.timed
        if e.timestamp and start <= e.timestamp <= end
        and (e.event_type in DELETION_TYPES or e.event_type in LOG_CLEAR_TYPES)
    ]


def step_match_supporting_evidence_loss(ctx, start, end):
    """Pattern D loss step: deletion of *supporting* evidence (forensic-relevant or
    sensitive target) or clearing of a log — never just any file removal."""
    hits = []
    for event in ctx.timed:
        if not event.timestamp or not (start <= event.timestamp <= end):
            continue
        if event.event_type in LOG_CLEAR_TYPES:
            hits.append(event)
        elif event.event_type in DELETION_TYPES:
            target = event.file_path or event.description or ""
            if is_forensic_relevant(target) or is_sensitive(target):
                hits.append(event)
    return hits


def step_match_suspicious_execution(ctx, start, end):
    hits = []
    for event in ctx.timed:
        if not event.timestamp or not (start <= event.timestamp <= end):
            continue
        if event.event_type in ("process_creation", "service_installed", "script_block") \
                and suspicious_process(event):
            hits.append(event)
    return hits


def step_match_log_clear(ctx, start, end):
    return [e for e in ctx.timed if e.timestamp and start <= e.timestamp <= end
            and e.event_type in LOG_CLEAR_TYPES]


def step_match_activity(ctx, start, end):
    return [e for e in ctx.timed if e.timestamp and start <= e.timestamp <= end
            and e.event_type in ACTIVITY_TYPES]


def steps_linked(previous, candidate) -> bool:
    """Two chain steps must share an anchor — never linked by time alone.

    * when **both** records name a file path they must name the *same* path
      (strict: two different files are different objects);
    * otherwise both records must share host **and** user (single actor, single
      system) — a record carrying neither path nor identity cannot link.
    """
    if previous.file_path and candidate.file_path:
        return previous.file_path == candidate.file_path
    if previous.host and candidate.host and previous.user and candidate.user:
        return previous.host == candidate.host and previous.user == candidate.user
    if previous.user and candidate.user and previous.host and candidate.host:
        return previous.user == candidate.user and previous.host == candidate.host
    return False


# --- patterns ---------------------------------------------------------------

def step_match_suspicious_execution_fallback(ctx, start, end):
    explicit = step_match_suspicious_execution(ctx, start, end)
    if explicit:
        return explicit
    # No named utility: fall back to any execution inside the window so an
    # incomplete pattern can still be reported as a candidate.
    return step_match_activity(ctx, start, end)


@dataclass
class Pattern:
    id: str
    name: str
    summary: str
    steps: list[dict]
    severity: str
    relationship_rule: str
    explanation: str
    limitations: tuple[str, ...]
    alternatives: tuple[str, ...]
    window_hours: float = 72.0
    require_anchor: bool = True


PATTERNS: list[Pattern] = [
    Pattern(
        id="A",
        name="Sensitive access → possible copy → deletion",
        summary="Sensitive file access, corroborated copy-like activity, then deletion.",
        steps=[
            {"key": "sensitive_access", "label": "Sensitive file access",
             "matcher": step_match_sensitive_access},
            {"key": "copy", "label": "Corroborated copy activity",
             "matcher": lambda ctx, s, e: step_match_copy(ctx, s, e)},
            {"key": "deletion", "label": "Deletion of that target",
             "matcher": step_match_evidence_loss},
        ],
        severity="high",
        relationship_rule="TEMPORALLY_NEAR + PRECEDES (same file path, within window)",
        explanation=("'copy' qualifies only when a source record explicitly states it or the "
                      "timestamps match the documented copy/reset pattern; timestamps alone "
                      "never confirm a copy."),
        limitations=("Copy confirmation requires records beyond timestamps.",
                     "The three steps may be produced by unrelated processes."),
        alternatives=("Normal document workflow ending in the user deleting a file.",
                      "Backup/sync tool copying then pruning files.",
                      "Application rewriting its data files."),
    ),
    Pattern(
        id="B",
        name="Suspicious execution → audit log clearing",
        summary="An anti-forensic-capable tool executes shortly before a log clear.",
        steps=[
            {"key": "execution", "label": "Suspicious execution (or any execution near a clear)",
             "matcher": step_match_suspicious_execution_fallback},
            {"key": "log_clear", "label": "Audit log clearing",
             "matcher": step_match_log_clear},
        ],
        severity="critical",
        relationship_rule="PRECEDES within activity_window (documented rule AF-008)",
        explanation=("The executables that clear logs (wevtutil cl, Clear-EventLog, fsutil usn "
                     "deletejournal) are documented as anti-forensic utilities; their use plus a "
                     "subsequent clear raises support."),
        limitations=("Sequence does not prove causation.",
                     "Command lines may be missing from the acquired record."),
        alternatives=("Approved log rotation using the same commands.",
                      "Provisioning script resetting logging."),
        window_hours=24.0,
    ),
    Pattern(
        id="C",
        name="Metadata modification → timestamp inconsistency",
        summary="A forensic artifact's metadata changed and a timestamp check then fails.",
        steps=[
            {"key": "metadata", "label": "File metadata modification",
             "matcher": step_match_metadata_change},
            {"key": "timestamp", "label": "Corroborated timestamp inconsistency",
             "matcher": step_match_timestamp_anomaly},
        ],
        severity="medium",
        relationship_rule="SAME_FILE/host + TEMPORALLY_NEAR (corroboration of one anomaly by another)",
        explanation=("Two independent checks (metadata mutation record + a consistency check "
                     "failing on the same asset) corroborate each other."),
        limitations=("Both observations can result from tooling or clock behaviour.",
                     "Same-host relation is weaker than same-file relation."),
        alternatives=("Backup/restore rewriting metadata.",
                      "Disk cleanup or indexing touching the path.",
                      "NTP/DST producing apparent inversions."),
        window_hours=48.0,
    ),
    Pattern(
        id="D",
        name="Relevant activity → loss of supporting evidence",
        summary="Activity of interest is followed by deletion of its supporting records.",
        steps=[
            {"key": "activity", "label": "Relevant activity",
             "matcher": step_match_activity},
            {"key": "loss", "label": "Disappearance/deletion of supporting evidence",
             "matcher": step_match_supporting_evidence_loss},
        ],
        severity="high",
        relationship_rule="PRECEDES within activity_window (rule AF-005)",
        explanation=("Sequence-level view of AF-005: the loss record removes corroboration for "
                     "earlier activity."),
        limitations=("Timing alone cannot link actor to activity.",
                     "Cleanup after normal work reproduces this pattern."),
        alternatives=("Routine cleanup after finishing work.",
                      "Retention policy firing on schedule.",
                      "Application rotating or pruning its own files."),
        window_hours=24.0,
    ),
    Pattern(
        id="E",
        name="File access → removable media → evidence anomaly",
        summary="File access, activity on removable media, possible transfer, then anomalies.",
        steps=[
            {"key": "access", "label": "File access (possibly sensitive)",
             "matcher": lambda ctx, s, e: step_match_sensitive_access(ctx, s, e)
             or step_match_activity(ctx, s, e)},
            {"key": "removable", "label": "Removable-device activity",
             "matcher": lambda ctx, s, e: find_removable_activity(ctx, s, e)},
            {"key": "transfer", "label": "Possible transfer to removable media",
             "matcher": lambda ctx, s, e: find_removable_activity(ctx, s, e)},
            {"key": "anomaly", "label": "Evidence-related anomaly afterwards",
             "matcher": lambda ctx, s, e: step_match_evidence_loss(ctx, s, e)
             or step_match_timestamp_anomaly(ctx, s, e)},
        ],
        severity="medium",
        relationship_rule="TEMPORALLY_NEAR + POSSIBLY_CAUSAL (sequence, not proven causation)",
        explanation=("Drive-letter writes (E:/F:/G:) after file access are treated as *possible* "
                     "transfer only; no exfiltration is asserted without a corroborated record."),
        limitations=("Other volumes share those drive letters (substitutions, network mapping).",
                     "No content comparison between source and target was performed."),
        alternatives=("User saving work to a USB drive for legitimate reasons.",
                      "Backup or imaging utility writing to external storage.",
                      "Insertion of a device by an unrelated person."),
        window_hours=48.0,
    ),
]


def step_match_suspicious_execution_fallback(ctx, start, end):
    explicit = step_match_suspicious_execution(ctx, start, end)
    if explicit:
        return explicit
    # No named utility: fall back to any execution inside the window so the
    # incomplete pattern can still be reported as a candidate.
    return step_match_activity(ctx, start, end)


def evaluate_pattern(pattern: Pattern, ctx: DetectionContext) -> list[dict]:
    """Return candidate chains: matched runs, including partial matches."""
    window_hours = float(pattern.window_hours or ctx.config["chain_window_hours"])
    if not ctx.timed:
        return []
    first_step = pattern.steps[0]
    full_start = ctx.timed[0].timestamp
    full_end = ctx.timed[-1].timestamp
    anchors = first_step["matcher"](ctx, full_start, full_end)
    if not anchors:
        return []

    chains = []
    used_anchor: set[str] = set()
    for anchor in sorted(anchors, key=lambda e: e.timestamp):
        if anchor.id in used_anchor:
            continue
        start = anchor.timestamp
        end = anchor.timestamp + timedelta(hours=window_hours)
        matched: dict[str, StepMatch] = {}
        matched_events: list = []
        last_ts = anchor.timestamp
        stopped = False
        for step in pattern.steps:
            candidates = step["matcher"](ctx, start, end)
            # Steps must occur in declared order; step 0 is the anchor itself.
            candidates = [c for c in candidates if c.timestamp >= last_ts]
            if step is pattern.steps[0]:
                candidates = [c for c in candidates if c.id == anchor.id]
            else:
                candidates = [c for c in candidates if c.id not in {e.id for e in matched_events}]
                # sequence steps must share an anchor with the preceding step
                previous = matched_events[-1]
                candidates = [c for c in candidates if steps_linked(previous, c)]
            if not candidates:
                # Patterns are matched as ordered prefixes: the first missing step
                # ends the candidate sequence instead of hopping over it.
                stopped = True
                break
            next_event = min(candidates, key=lambda c: c.timestamp)
            matched[step["key"]] = StepMatch(
                event_ids=[next_event.id],
                label=step["label"],
                detail=(next_event.description or "")[:300],
                relationships=[pattern.relationship_rule],
            )
            matched_events.append(next_event)
            last_ts = next_event.timestamp

        missing_steps = [s for s in pattern.steps if s["key"] not in matched]
        if len(matched) < 2:
            # A single matched step is not a sequence — never emit a lone anchor as a
            # "suspicion chain".
            continue
        completeness = "complete" if len(matched) == len(pattern.steps) else "partial"

        used_anchor.add(anchor.id)
        chains.append({
            "pattern": pattern,
            "matched": matched,
            "missing": missing_steps,
            "completeness": completeness,
            "events": matched_events,
            "window_hours": window_hours,
        })
    return chains


def detect_chains(db: Session, investigation: Investigation, ctx: DetectionContext,
                  findings: list[Finding], run_id: str) -> list[SuspicionChain]:
    """Replace this investigation's chains with freshly detected, deduped chains."""
    db.query(SuspicionChain).filter(
        SuspicionChain.investigation_id == investigation.id
    ).delete()

    rules_by_event: dict[str, list[str]] = {}
    for finding in findings:
        for event_id in finding.event_ids:
            rules_by_event.setdefault(event_id, []).append(finding.rule_id)

    created: list[SuspicionChain] = []
    seen: set[str] = set()
    for pattern in PATTERNS:
        for result in evaluate_pattern(pattern, ctx):
            events = result["events"]
            key = f"{pattern.id}:{events[0].id}:{events[-1].id}:{result['completeness']}"
            if key in seen:
                continue
            seen.add(key)
            created.append(
                _build_chain(investigation, pattern, result, rules_by_event, ctx)
            )

    # Sort: complete first, then by severity, then by first event time.
    severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    created.sort(key=lambda c: (
        0 if c.completeness == "complete" else 1,
        severity_rank.get(c.severity, 5),
        c.created_at.timestamp() if c.created_at else 0,
    ))
    for chain in created:
        db.add(chain)
    db.flush()
    return created


def _build_chain(investigation: Investigation, pattern: Pattern, result: dict,
                 rules_by_event: dict[str, list[str]], ctx: DetectionContext) -> SuspicionChain:
    matched: dict[str, StepMatch] = result["matched"]
    events = result["events"]
    missing = result["missing"]

    steps = []
    relationship_types = {"PRECEDES"}
    for index, step in enumerate(pattern.steps):
        if step["key"] in matched:
            match = matched[step["key"]]
            event = next(e for e in events if e.id in match.event_ids)
            steps.append({
                "position": index + 1,
                "key": step["key"],
                "label": step["label"],
                "matched": True,
                "event_ids": match.event_ids,
                "timestamp": event.timestamp.isoformat() if event.timestamp else None,
                "description": match.detail,
                "relationships": match.relationships,
                "evidence_ref": event.raw_record_reference,
                "source_file": event.source_file,
                "source_record_id": event.source_record_id,
                "is_anchor": index == 0,
            })
            for rel in match.relationships:
                for piece in rel.split("+"):
                    relationship_types.add(piece.strip().split(" ")[0])
        else:
            steps.append({
                "position": index + 1,
                "key": step["key"],
                "label": step["label"],
                "matched": False,
                "event_ids": [],
                "relationships": [],
                "missing_reason": (
                    f"No {step['label'].lower()} record was found in the "
                    f"{result['window_hours']:g}h window — this does not prove the step "
                    "did not happen, only that it is not in the acquired evidence."
                ),
            })
    if "POSSIBLY_CAUSAL" in pattern.relationship_rule and matched:
        relationship_types.add("POSSIBLY_CAUSAL")

    triggered_rules = sorted({
        rule for event_id in [e.id for e in events] for rule in rules_by_event.get(event_id, [])
    })
    contradictory_ids = [e.id for e in events if e.timestamp is None]

    support = assess_support(
        observed=len(events),
        sources=len({e.evidence_source_id for e in events if e.evidence_source_id}),
        relationship_corroborated=result["completeness"] == "complete",
        missing_required=bool(missing),
        assumption_dependent=pattern.id in ("A", "E"),
        contradictions=0,
        notes=[
            f"Pattern {pattern.id} matched {len(matched)}/{len(pattern.steps)} step(s) "
            f"({result['completeness']}).",
        ] + ([f"Missing step(s): {', '.join(s['label'] for s in missing)}"] if missing else []),
    )

    title = f"Pattern {pattern.id}: {pattern.name}"
    if result["completeness"] == "partial":
        title += f" (incomplete — {len(missing)} step(s) not evidenced)"

    alt_explanations = alternative_explanations(
        "These are candidate sequences; routine activity reproduces them.",
        list(pattern.alternatives),
    )
    dedupe = f"{pattern.id}:{events[0].id}:{events[-1].id}"
    return SuspicionChain(
        id=new_id(),
        investigation_id=investigation.id,
        pattern_id=pattern.id,
        pattern_name=pattern.name,
        title=title,
        event_ids=[e.id for e in events],
        steps=steps,
        relationship_types=sorted(relationship_types),
        severity=pattern.severity,
        support=support.level,
        completeness=result["completeness"],
        missing_steps=[
            {
                "label": s["label"],
                "reason": next(x["missing_reason"] for x in steps if x["key"] == s["key"]),
            }
            for s in missing if any(x["key"] == s["key"] and not x["matched"] for x in steps)
        ],
        alternative_explanations=alt_explanations,
        triggered_rules=triggered_rules,
        status="open",
        dedupe_key=dedupe,
    )


def chain_to_dict(chain: SuspicionChain) -> dict:
    return {
        "id": chain.id,
        "investigation_id": chain.investigation_id,
        "pattern_id": chain.pattern_id,
        "pattern_name": chain.pattern_name,
        "title": chain.title,
        "event_ids": chain.event_ids,
        "steps": chain.steps,
        "relationship_types": chain.relationship_types,
        "severity": chain.severity,
        "support": chain.support,
        "completeness": chain.completeness,
        "missing_steps": chain.missing_steps,
        "alternative_explanations": chain.alternative_explanations,
        "triggered_rules": chain.triggered_rules,
        "status": chain.status,
        "created_at": chain.created_at.isoformat() if chain.created_at else None,
        "note": (
            "Candidate sequence — not proof of malicious activity. Severity reflects "
            "investigative priority, not probability."
        ),
    }