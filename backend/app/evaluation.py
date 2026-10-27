"""Evaluation harness for the controlled synthetic scenarios.

Metrics are computed against the ground truth declared next to each scenario in
`app/datasets.py`:

  * precision / recall / false-positive rate - per rule decision, micro-averaged
  * chain (pattern) precision / recall
  * event-order accuracy                     - timeline vs ground-truth order
  * relationship accuracy                    - observed coverage, temporal
                                                direction, anchor validity of
                                                inferred edges
  * processing time                          - wall-clock per scenario
  * explainability coverage                  - findings carrying the full
                                                explanation contract

Configurations compared (same scenarios, same ruleset, same code path apart
from the two switches):
  A. timeline only
  B. timeline + detection rules
  C. timeline + rules + graph correlation + uncertainty-aware reasoning

Every configuration runs on a throwaway in-memory database, so an evaluation
never touches the user's investigations.  CLI:  python -m app.evaluation
"""

from __future__ import annotations

import time
from datetime import datetime, timezone

from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from .config import ENGINE_VERSION, RULES_VERSION
from .datasets import SCENARIOS, Scenario, scenario_by_id
from .db import Base
from .demo import create_demo_investigation
from .models import Event, Finding, GraphEdge, GraphNode, SuspicionChain
from .normalization import coerce_datetime
from .services.detection import run_analysis

CONFIGURATIONS = {
    "A": {"label": "Timeline only", "rules": False, "correlation": False},
    "B": {"label": "Timeline + detection rules", "rules": True, "correlation": False},
    "C": {"label": "Timeline + rules + graph correlation + uncertainty reasoning",
          "rules": True, "correlation": True},
}

PATTERN_IDS = ["A", "B", "C", "D", "E"]


def rule_ids() -> list[str]:
    from .services.rules import ALL_RULES

    return [r.id for r in ALL_RULES]


def fresh_session() -> Session:
    engine = create_engine(
        "sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool, future=True)
    Base.metadata.create_all(engine)
    return Session(engine, expire_on_commit=False)


def _record_time(record: dict) -> datetime | None:
    """Ground-truth time for one source record.

    Normalized records carry `timestamp`.  Filesystem artifact rows do not: the
    documented column-selection rule (deleted -> created, otherwise modified
    when present, else created) is applied, mirroring the parser's published
    field-selection behaviour.
    """
    raw = record.get("timestamp")
    if raw:
        value = coerce_datetime(raw)
        return value.replace(tzinfo=None) if value else None
    if not any(key in record for key in ("mtime", "ctime", "created", "modified", "accessed")):
        return None
    deleted = str(record.get("deleted", "")).lower() in {"1", "true", "yes", "deleted"}
    if deleted:
        primary = record.get("created") or record.get("ctime")
    else:
        primary = record.get("modified") or record.get("mtime") or record.get("created") \
            or record.get("ctime")
    if primary in (None, ""):
        return None
    value = coerce_datetime(primary)
    return value.replace(tzinfo=None) if value else None


def _ground_truth_times(scenario: Scenario) -> list[datetime | None]:
    times = []
    for source in scenario.sources:
        for record in source.records:
            times.append(_record_time(record))
    timed = sorted(t for t in times if t is not None)
    return timed + [None] * sum(1 for t in times if t is None)


def _decision_metrics(tp: int, fp: int, fn: int, tn: int) -> dict:
    precision = tp / (tp + fp) if (tp + fp) else None
    recall = tp / (tp + fn) if (tp + fn) else None
    fpr = fp / (fp + tn) if (fp + tn) else None
    return {
        "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "precision": round(precision, 4) if precision is not None else None,
        "recall": round(recall, 4) if recall is not None else None,
        "false_positive_rate": round(fpr, 4) if fpr is not None else None,
        "precision_note": "null when no positive prediction was made (0/0 is undefined)",
    }


def _rule_metrics(db: Session, scenario: Scenario, investigation_id: str,
                  with_rules: bool) -> dict:
    fired = {f.rule_id for f in db.query(Finding)
             .filter(Finding.investigation_id == investigation_id)} if with_rules else set()
    declared = set(scenario.expected_rules)
    tp = len(fired & declared)
    fp = len(fired - declared)
    fn = len(declared - fired)
    tn = len(set(rule_ids()) - fired - declared)
    metrics = _decision_metrics(tp, fp, fn, tn)
    metrics.update({
        "fired": sorted(fired), "expected": sorted(declared),
        "false_positives": sorted(fired - declared), "missed": sorted(declared - fired),
    })
    return metrics


def _chain_metrics(db: Session, scenario: Scenario, investigation_id: str,
                   with_correlation: bool) -> dict:
    fired = {c.pattern_id for c in db.query(SuspicionChain)
             .filter(SuspicionChain.investigation_id == investigation_id)} \
        if with_correlation else set()
    declared = set(scenario.expected_chains)
    tp = len(fired & declared)
    fp = len(fired - declared)
    fn = len(declared - fired)
    tn = len(set(PATTERN_IDS) - fired - declared)
    metrics = _decision_metrics(tp, fp, fn, tn)
    metrics.update({"fired": sorted(fired), "expected": sorted(declared),
                    "false_positives": sorted(fired - declared),
                    "missed": sorted(declared - fired)})
    return metrics


def _order_metrics(db: Session, scenario: Scenario, investigation_id: str) -> dict:
    expected = _ground_truth_times(scenario)
    rows = (
        db.query(Event).filter(Event.investigation_id == investigation_id)
        .order_by(Event.timestamp.is_(None), Event.timestamp.asc(), Event.seq.asc()).all()
    )
    actual = [e.timestamp for e in rows]
    actual = [t.replace(tzinfo=None) if t is not None else None for t in actual]
    timed_expected = [t for t in expected if t is not None]
    timed_actual = [t for t in actual if t is not None]
    if len(timed_expected) == len(timed_actual) and timed_expected:
        accuracy = sum(1 for a, b in zip(timed_expected, timed_actual) if a == b) / len(timed_expected)
    elif not timed_expected and not timed_actual:
        accuracy = 1.0
    else:
        accuracy = min(len(timed_expected), len(timed_actual)) / max(
            len(timed_expected), len(timed_actual), 1)
    undated = [t for t in actual if t is None]
    undated_last = all(
        t is None for t in actual[len(expected) - len(actual):]) if actual else True
    return {
        "accuracy": round(accuracy, 4),
        "timed_expected": len(timed_expected),
        "timed_actual": len(timed_actual),
        "undated_events": len(undated),
        "undated_sorted_last": bool(undated_last),
        "record_count_match": len(expected) == len(actual),
        "note": "accuracy compares the retrieved timeline against the ground-truth sort "
                "(UTC, undated last); ties may legitimately permute within identical "
                "timestamps but must not invert distinct ones.",
    }


def _relationship_metrics(db: Session, investigation_id: str) -> dict:
    total_events = db.query(Event).filter(Event.investigation_id == investigation_id).count()
    observed_in = db.query(GraphEdge).filter(
        GraphEdge.investigation_id == investigation_id,
        GraphEdge.relation == "OBSERVED_IN").count()
    edges = db.query(GraphEdge).filter(GraphEdge.investigation_id == investigation_id).all()
    event_nodes = {
        n.id: n for n in db.query(GraphNode)
        .filter(GraphNode.investigation_id == investigation_id, GraphNode.node_type == "event")
    }

    sequence_relations = {"PRECEDES", "TEMPORALLY_NEAR", "POSSIBLY_CAUSAL"}
    temporal_checked = temporal_valid = 0
    causal_checked = causal_valid = 0
    for edge in edges:
        if edge.relation not in sequence_relations:
            continue
        src, dst = event_nodes.get(edge.source_key), event_nodes.get(edge.target_key)
        if src is None or dst is None:
            continue
        src_ts = (src.properties or {}).get("timestamp")
        dst_ts = (dst.properties or {}).get("timestamp")
        if not src_ts or not dst_ts:
            continue
        temporal_checked += 1
        if src_ts <= dst_ts:
            temporal_valid += 1
        if edge.relation == "POSSIBLY_CAUSAL":
            causal_checked += 1
            src_path = (src.properties or {}).get("file_path")
            same_anchor = bool(src_path and src_path == (dst.properties or {}).get("file_path")) or (
                (src.properties or {}).get("host") == (dst.properties or {}).get("host")
                and (src.properties or {}).get("user") == (dst.properties or {}).get("user"))
            if same_anchor:
                causal_valid += 1

    coverage = (observed_in / total_events) if total_events else 1.0
    temporal = (temporal_valid / temporal_checked) if temporal_checked else None
    anchor = (causal_valid / causal_checked) if causal_checked else None
    parts = [coverage] + [v for v in (temporal, anchor) if v is not None]
    return {
        "applicable": True,
        "observed_edge_coverage": round(coverage, 4),
        "observed_definition": "OBSERVED_IN edges present ÷ events ingested; every event must "
                               "stay linked to the artifact that recorded it",
        "temporal_direction_accuracy": round(temporal, 4) if temporal is not None else None,
        "temporal_definition": "fraction of ordered edges whose source timestamp ≤ target "
                               "timestamp (no backwards PRECEDES / POSSIBLY_CAUSAL)",
        "possible_causal_anchor_validity": round(anchor, 4) if anchor is not None else None,
        "possible_causal_definition": "POSSIBLY_CAUSAL edges sharing a file path or host+user "
                                      "anchor; proximity alone may never create one",
        "edges_total": len(edges),
        "relationship_accuracy": round(sum(parts) / len(parts), 4),
    }


EXPLANATION_KEYS = ("observed_evidence", "correlation", "hypothesis", "does_not_establish",
                    "limitations", "alternative_explanations", "recommended_next_checks",
                    "evidence", "rule_metadata")


def _explainability_metrics(db: Session, investigation_id: str) -> dict:
    findings = db.query(Finding).filter(Finding.investigation_id == investigation_id).all()
    if not findings:
        return {"applicable": False, "findings": 0,
                "note": "no findings produced (normal for negative scenarios)"}
    support_levels = {"insufficient", "low", "moderate", "strong"}
    complete = 0
    for finding in findings:
        explanation = finding.explanation or {}
        if (all(explanation.get(key) for key in EXPLANATION_KEYS)
                and finding.support in support_levels
                and all(e.get("source_record_id") for e in (explanation.get("evidence") or [])[:3])):
            complete += 1
    return {
        "applicable": True,
        "findings": len(findings),
        "full_contract_findings": complete,
        "coverage": round(complete / len(findings), 4),
        "contract": list(EXPLANATION_KEYS) + ["qualitative support level",
                                              "source record id on every evidence row"],
    }


def evaluate_scenario(db: Session, scenario: Scenario, configuration: str) -> dict:
    spec = CONFIGURATIONS[configuration]
    wall_start = time.perf_counter()

    ingest_start = time.perf_counter()
    investigation = create_demo_investigation(
        db, scenario, analyse=False)
    ingest_ms = int((time.perf_counter() - ingest_start) * 1000)

    analysis_ms = None
    run_summary = None
    if spec["rules"]:
        run_summary = run_analysis(
            db, investigation, trigger="evaluation",
            include_correlation=spec["correlation"])
        analysis_ms = run_summary["duration_ms"]
    else:
        db.commit()

    row = {
        "scenario": scenario.id,
        "name": scenario.name,
        "configuration": configuration,
        "events": db.query(Event).filter(
            Event.investigation_id == investigation.id).count(),
        "ingest_ms": ingest_ms,
        "analysis_ms": analysis_ms,
        "wall_ms": int((time.perf_counter() - wall_start) * 1000),
        "rules": _rule_metrics(db, scenario, investigation.id, spec["rules"]),
        "chains": _chain_metrics(db, scenario, investigation.id, spec["correlation"]),
        "event_order": _order_metrics(db, scenario, investigation.id),
        "explainability": _explainability_metrics(db, investigation.id)
        if spec["rules"] else {"applicable": False, "findings": 0,
                               "note": "configuration A does not produce findings"},
    }
    if spec["correlation"]:
        row["relationships"] = _relationship_metrics(db, investigation.id)
    else:
        row["relationships"] = {
            "applicable": False,
            "note": "configuration without the graph correlation layer",
        }
    if spec["rules"]:  # ordering is still measured in every configuration
        row["event_order"] = _order_metrics(db, scenario, investigation.id)
    else:
        row["event_order"] = _order_metrics(db, scenario, investigation.id)
    if run_summary:
        row["rules_skipped"] = run_summary["summary"].get("skipped_rules", [])
    return row


def aggregate(rows: list[dict], configuration: str) -> dict:
    spec = CONFIGURATIONS[configuration]
    tp = sum(r["rules"]["tp"] for r in rows)
    fp = sum(r["rules"]["fp"] for r in rows)
    fn = sum(r["rules"]["fn"] for r in rows)
    tn = sum(r["rules"]["tn"] for r in rows)
    rules = _decision_metrics(tp, fp, fn, tn)

    ctp = sum(r["chains"]["tp"] for r in rows)
    cfp = sum(r["chains"]["fp"] for r in rows)
    cfn = sum(r["chains"]["fn"] for r in rows)
    ctn = sum(r["chains"]["tn"] for r in rows)
    chains = _decision_metrics(ctp, cfp, cfn, ctn)

    order_values = [r["event_order"]["accuracy"] for r in rows]
    explain = [r["explainability"] for r in rows if r["explainability"].get("applicable")]
    explain_coverage = (
        (sum(e["full_contract_findings"] for e in explain) / sum(e["findings"] for e in explain))
        if explain and sum(e["findings"] for e in explain) else None
    )
    rel_rows = [r["relationships"] for r in rows if r["relationships"].get("applicable")]
    rel_accuracy = (
        sum(r["relationship_accuracy"] for r in rel_rows) / len(rel_rows) if rel_rows else None)
    analysis_times = [r["analysis_ms"] for r in rows if r["analysis_ms"] is not None]

    return {
        "configuration": configuration,
        "label": spec["label"],
        "scenarios": len(rows),
        "rule_decisions": rules,
        "chain_decisions": chains,
        "event_order_accuracy": round(sum(order_values) / len(order_values), 4)
        if order_values else None,
        "event_order_macro_note": "macro average of per-scenario positional accuracy",
        "relationship_accuracy": round(rel_accuracy, 4) if rel_accuracy is not None else None,
        "explainability_coverage": round(explain_coverage, 4)
        if explain_coverage is not None else None,
        "processing_time_ms": {
            "mean_analysis": int(sum(analysis_times) / len(analysis_times))
            if analysis_times else None,
            "median_analysis": sorted(analysis_times)[len(analysis_times) // 2]
            if analysis_times else None,
            "mean_wall": int(sum(r["wall_ms"] for r in rows) / len(rows)),
            "mean_ingest": int(sum(r["ingest_ms"] for r in rows) / len(rows)),
        },
        "events_total": sum(r["events"] for r in rows),
    }


def run_evaluation(scenario_ids: list[str] | None = None,
                   configurations: list[str] | None = None) -> dict:
    configurations = [c.upper() for c in (configurations or ["A", "B", "C"])]
    unknown = [c for c in configurations if c not in CONFIGURATIONS]
    if unknown:
        return {"error": f"unknown configuration(s): {', '.join(unknown)}"}

    selected = []
    for sid in (scenario_ids or [s.id for s in SCENARIOS]):
        scenario = scenario_by_id(sid)
        if scenario is None:
            return {"error": f"unknown scenario id: {sid}"}
        selected.append(scenario)
    if not selected:
        return {"error": "no scenarios selected"}

    started = time.perf_counter()
    rows_by_config: dict[str, list] = {c: [] for c in configurations}
    errors: list[dict] = []
    for configuration in configurations:
        db = fresh_session()
        try:
            for scenario in selected:
                try:
                    rows_by_config[configuration].append(
                        evaluate_scenario(db, scenario, configuration))
                except Exception as exc:  # surface rather than fabricate a score
                    db.rollback()
                    errors.append({"scenario": scenario.id, "configuration": configuration,
                                   "error": f"{type(exc).__name__}: {str(exc)[:400]}"})
        finally:
            db.close()

    comparison = [aggregate(rows_by_config[c], c) for c in configurations
                  if rows_by_config[c]]
    return {
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "engine_version": ENGINE_VERSION,
        "ruleset_version": RULES_VERSION,
        "scenarios": [{"id": s.id, "name": s.name,
                       "expected_rules": s.expected_rules,
                       "expected_chains": s.expected_chains,
                       "alternatives": s.alternatives} for s in selected],
        "configurations": {
            c: {"label": CONFIGURATIONS[c]["label"], "rules": CONFIGURATIONS[c]["rules"],
                "graph_correlation": CONFIGURATIONS[c]["correlation"],
                "uncertainty_reasoning": CONFIGURATIONS[c]["correlation"]}
            for c in configurations
        },
        "aggregate": comparison,
        "per_scenario": {c: rows_by_config[c] for c in configurations},
        "total_ms": int((time.perf_counter() - started) * 1000),
        "errors": errors,
        "methodology": [
            "Ground truth (expected rules, expected chains, benign alternatives) is authored "
            "with each synthetic scenario in app/datasets.py and is shared by all three "
            "configurations — the rule code path is identical, only the switches differ.",
            "A scenario that omits a rule id declares it as a negative; an unexpected firing "
            "counts as a false positive.",
            "Detection is scored on whether a rule *should* fire, not on whether the underlying "
            "activity is malicious: AF-005 firing on a legitimate cleanup is a correct detection "
            "of a work-then-loss sequence.",
            "Null precision means no positive prediction was made for that side of the matrix.",
            "Relationship metrics are only computed for configuration C because A and B do not "
            "build graph edges by design.",
        ],
        "limitations": [
            "The dataset is synthetic and authored by the same project: precision/recall here "
            "measure consistency with that declared ground truth, not real-world validity.",
            "Eleven small scenarios cannot represent the diversity of real casework; results are "
            "a regression baseline, not a published benchmark.",
            "No independently labelled corpus or inter-rater agreement was used; treatment of "
            "ambiguous scenarios (e.g. bulk cleanup) is a design decision documented per "
            "scenario rather than an external standard.",
            "Processing times are wall-clock on one developer machine and are reported for "
            "regression comparison only.",
        ],
    }


def _main() -> None:  # pragma: no cover
    import json

    result = run_evaluation()
    print(json.dumps({
        "aggregate": result.get("aggregate"),
        "errors": result.get("errors"),
        "total_ms": result.get("total_ms"),
    }, indent=2))


if __name__ == "__main__":  # pragma: no cover
    _main()