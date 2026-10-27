"""Uncertainty and evidence-strength methodology.

TRACE-X reports *qualitative* support levels.  It deliberately does not present
arbitrary percentages as calibrated probabilities.

Concepts kept separate (never merged into one number):
  1. source reliability   - whether the record itself is intact/parseable
  2. timestamp confidence - how precisely/credibly an event can be placed in time
  3. relationship strength - how well two observations are connected
  4. hypothesis support    - cumulative backing for an investigative hypothesis
  5. severity              - investigative priority (NOT probability)

Every support classification records its components so the arithmetic is
inspectable.  If a numeric value is exposed it is labelled `heuristic_score`
and is not a probability.
"""

from __future__ import annotations

from dataclasses import dataclass, field


SUPPORT_LEVELS = ("insufficient", "low", "moderate", "strong")

SUPPORT_DEFINITIONS = {
    "insufficient": {
        "rule": (
            "No directly observed record for the claimed activity, or a required "
            "evidence type for the rule is absent from the investigation."
        ),
        "requires": ["at least one source record directly observing the activity"],
    },
    "low": {
        "rule": (
            "A single observation in one source, an inference that depends on an "
            "unverified assumption (e.g. only timestamps), or corroborating "
            "evidence is missing."
        ),
        "requires": ["one observed record", "assumption flagged as unverified"],
    },
    "moderate": {
        "rule": (
            "Two or more supporting observations from at least two independently "
            "acquired sources, no contradicting evidence recorded."
        ),
        "requires": ["2+ supporting observations", "2+ sources", "no contradictions"],
    },
    "strong": {
        "rule": (
            "Three or more supporting observations across 2+ independent sources, "
            "including at least one relationship-derived observation, with no "
            "recorded contradiction and no missing required input."
        ),
        "requires": [
            "3+ supporting observations",
            "2+ independent sources",
            "one relationship-derived observation",
            "no contradictions",
            "all required evidence present",
        ],
    },
}

BENIGN_EXPLANATIONS_CATALOG = [
    "Scheduled maintenance or a routine retention policy run",
    "Legitimate administrative cleanup (disk cleanup, temp-file removal, log rotation)",
    "Logging disabled, expired or rotated by configuration rather than removed",
    "Incomplete evidence acquisition - the record may never have been collected",
    "Clock drift or timezone misconfiguration changing apparent ordering",
    "Application-generated metadata changes (sync clients, indexers, backup tools)",
    "Operating-system or software upgrade rewriting metadata",
    "User reorganising their own files without concealment intent",
]


@dataclass
class SupportAssessment:
    level: str
    rationale: str
    components: list[dict] = field(default_factory=list)
    heuristic_score: float | None = None

    def to_dict(self) -> dict:
        return {
            "level": self.level,
            "rationale": self.rationale,
            "components": self.components,
            "heuristic_score": self.heuristic_score,
            "scale": SUPPORT_LEVELS,
            "is_calibrated_probability": False,
            "definition": SUPPORT_DEFINITIONS.get(self.level, {}),
        }


# Weighted, transparent heuristic components (labelled heuristic, not calibrated)
COMPONENT_WEIGHTS = {
    "observed_records": 1.0,        # +1 per supporting observation, cap 3
    "independent_sources": 1.5,     # +1.5 per extra source beyond the first, cap 3
    "relationship_corroboration": 1.5,
    "missing_required_input": -3.0,
    "single_source_only": -1.0,
    "assumption_dependent": -0.5,
    "contradiction_present": -2.0,
}


def assess_support(
    observed: int,
    sources: int,
    relationship_corroborated: bool = False,
    missing_required: bool = False,
    assumption_dependent: bool = False,
    contradictions: int = 0,
    notes: list[str] | None = None,
) -> SupportAssessment:
    """Assign one of the four qualitative support levels.

    The mapping (documented so reviewers can challenge it):
      * missing required input            -> insufficient
      * observed == 0                     -> insufficient
      * contradictions and no relationship corroboration -> low
      * observed == 1, or single source, or assumption-dependent with <2 sources -> low
      * observed 2, sources >= 2, no contradictions -> moderate
      * observed >= 3, sources >= 2, relationship corroborated, no contradictions -> strong
    """
    components: list[dict] = []
    score = 0.0
    notes = list(notes or [])

    obs_component = min(observed, 3)
    components.append({"name": "observed_records", "value": obs_component,
                       "weight": COMPONENT_WEIGHTS["observed_records"]})
    score += obs_component * COMPONENT_WEIGHTS["observed_records"]

    extra_sources = max(sources - 1, 0)
    src_component = min(extra_sources, 2)
    components.append({"name": "independent_sources", "value": src_component,
                       "weight": COMPONENT_WEIGHTS["independent_sources"]})
    score += src_component * COMPONENT_WEIGHTS["independent_sources"]

    if relationship_corroborated:
        components.append({"name": "relationship_corroboration", "value": 1,
                           "weight": COMPONENT_WEIGHTS["relationship_corroboration"]})
        score += COMPONENT_WEIGHTS["relationship_corroboration"]
    if missing_required:
        components.append({"name": "missing_required_input", "value": 1,
                           "weight": COMPONENT_WEIGHTS["missing_required_input"]})
        score += COMPONENT_WEIGHTS["missing_required_input"]
        notes.append("A required evidence type for this rule is absent from the investigation.")
    if observed and sources <= 1:
        components.append({"name": "single_source_only", "value": 1,
                           "weight": COMPONENT_WEIGHTS["single_source_only"]})
        score += COMPONENT_WEIGHTS["single_source_only"]
        notes.append("All observations come from a single acquisition source.")
    if assumption_dependent:
        components.append({"name": "assumption_dependent", "value": 1,
                           "weight": COMPONENT_WEIGHTS["assumption_dependent"]})
        score += COMPONENT_WEIGHTS["assumption_dependent"]
        notes.append("The conclusion depends on an unverified assumption about time or environment.")
    if contradictions:
        components.append({"name": "contradiction_present", "value": contradictions,
                           "weight": COMPONENT_WEIGHTS["contradiction_present"]})
        score += contradictions * COMPONENT_WEIGHTS["contradiction_present"]
        notes.append(f"{contradictions} contradicting record(s) were identified for this finding.")

    if missing_required or observed == 0:
        level = "insufficient"
    elif contradictions and not relationship_corroborated:
        level = "low"
    elif observed == 1 or sources <= 1 or (assumption_dependent and sources < 2):
        level = "low"
    elif observed >= 3 and sources >= 2 and relationship_corroborated and not contradictions:
        level = "strong"
    elif observed >= 2 and sources >= 2 and not contradictions:
        level = "moderate"
    else:
        level = "low"

    rationale_bits = [
        f"{observed} supporting observation(s)",
        f"{sources} independent source(s)",
        "relationship corroboration present" if relationship_corroborated
        else "no relationship corroboration",
    ]
    if contradictions:
        rationale_bits.append(f"{contradictions} contradiction(s)")
    if missing_required:
        rationale_bits.append("required input missing")
    rationale = "; ".join(rationale_bits) + ". " + (" ".join(notes) if notes else "")

    return SupportAssessment(
        level=level,
        rationale=rationale,
        components=components,
        heuristic_score=round(max(score, 0.0), 2),
    )


def source_reliability(source) -> dict:
    """Evidence-source reliability statement (kept separate from support)."""
    integrity_ok = bool(getattr(source, "sha256", None))
    return {
        "evidence_source_id": source.id,
        "filename": source.filename,
        "status": source.status,
        "hash_computed": integrity_ok,
        "integrity_note": (
            "SHA-256 detects later modification of the stored file. A hash alone "
            "does not prove authenticity or chain of custody."
        ),
        "accepted": source.accepted_count,
        "rejected": source.rejected_count,
    }


def alternative_explanations(context: str, extra: list[str] | None = None) -> list[dict]:
    """Return candidate benign explanations with the reason they matter here."""
    items = [
        {"explanation": text, "why_relevant": context}
        for text in BENIGN_EXPLANATIONS_CATALOG
    ]
    for text in extra or []:
        items.append({"explanation": text, "why_relevant": context})
    # Deduplicate while preserving order
    seen, unique = set(), []
    for item in items:
        if item["explanation"] not in seen:
            seen.add(item["explanation"])
            unique.append(item)
    return unique