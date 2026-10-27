"""Detection rules, explanation contract and suspicion chains — scored against
the ground truth declared in app/datasets.py (scenarios with expectations)."""

from __future__ import annotations

import pytest

from app.datasets import SCENARIOS, scenario_by_id
from app.models import Finding, SuspicionChain

POSITIVE_SCENARIOS = [s for s in SCENARIOS if s.expected_rules]
NEGATIVE_SCENARIOS = [s for s in SCENARIOS if s.expected_rules == [] and s.expected_absent != [] or (
    s.expected_rules == [] and not s.expected_chains)]


@pytest.mark.parametrize("scenario", POSITIVE_SCENARIOS, ids=lambda s: s.id)
def test_expected_rules_fire(db, demo, scenario):
    inv_id = demo(scenario.id, analyse=True)
    fired = {f.rule_id for f in db.query(Finding)
             .filter(Finding.investigation_id == inv_id).all()}
    missing = set(scenario.expected_rules) - fired
    assert not missing, f"scenario {scenario.id}: expected {missing} to fire, fired={fired}"


@pytest.mark.parametrize("scenario_id", [s.id for s in SCENARIOS])
def test_no_unexpected_rules_fire(db, demo, scenario_id):
    """Rules listed as absent (or not expected) must not fire — FP guard."""
    scenario = scenario_by_id(scenario_id)
    inv_id = demo(scenario_id, analyse=True)
    fired = {f.rule_id for f in db.query(Finding)
             .filter(Finding.investigation_id == inv_id).all()}
    forbidden = set(scenario.expected_absent)
    # wholly unexpected rules also count as false positives on clean scenarios
    if not scenario.expected_rules:
        forbidden |= fired - set(scenario.expected_rules)
    overlap = fired & forbidden
    assert not overlap, f"scenario {scenario_id}: unexpected rules {overlap}"


@pytest.mark.parametrize("scenario", [s for s in SCENARIOS if s.expected_chains],
                         ids=lambda s: s.id)
def test_expected_chains_detected(db, demo, scenario):
    inv_id = demo(scenario.id, analyse=True)
    detected = {c.pattern_id for c in db.query(SuspicionChain)
                .filter(SuspicionChain.investigation_id == inv_id).all()}
    missing = set(scenario.expected_chains) - detected
    assert not missing, f"scenario {scenario.id}: missing chains {missing}; got {detected}"


def test_chain_completeness_and_missing_steps_are_disclosed(db, demo):
    """A partial chain must expose exactly why it is partial."""
    scenario = scenario_by_id("incomplete")
    if scenario is None or not scenario.expected_chains:
        pytest.skip("no deliberately incomplete scenario in this ruleset")
    inv_id = demo("incomplete", analyse=True)
    chains = db.query(SuspicionChain).filter(
        SuspicionChain.investigation_id == inv_id).all()
    assert chains, "an incomplete pattern should still be reported as a candidate"
    for chain in chains:
        if chain.completeness == "partial":
            assert chain.missing_steps, "partial chains must list their missing steps"
            for step in chain.missing_steps:
                assert step.get("reason")
        assert chain.alternative_explanations, "chains must offer alternative explanations"


def test_findings_explain_three_layers(db, demo):
    scenario = scenario_by_id("logclear")
    inv_id = demo("logclear", analyse=True)
    findings = db.query(Finding).filter(Finding.investigation_id == inv_id).all()
    assert findings, "logclear scenario should raise at least one finding"

    for finding in findings:
        ex = finding.explanation or {}
        # evidence layer
        assert ex.get("observed_evidence"), f"{finding.rule_id} lacks observed evidence"
        # hypothesis layer
        assert ex.get("hypothesis"), f"{finding.rule_id} lacks a stated hypothesis"
        # never overclaim
        assert ex.get("does_not_establish"), f"{finding.rule_id} must say what it does not establish"
        assert ex.get("alternative_explanations"), (
            f"{finding.rule_id} must offer at least one benign alternative")
        # evidence rows trace back to real events
        for row in ex.get("evidence", []):
            assert row.get("event_id") or row.get("description")
        assert finding.severity in {"critical", "high", "medium", "low", "info"}
        assert finding.support in {"insufficient", "low", "moderate", "strong"}
        assert finding.rule_version and finding.rule_name


def test_findings_reference_persisted_events(db, demo):
    inv_id = demo("logclear", analyse=True)
    from app.models import Event
    for finding in db.query(Finding).filter(Finding.investigation_id == inv_id):
        assert finding.event_ids, "finding without supporting events"
        for event_id in finding.event_ids:
            # every cited event must actually exist in THIS investigation
            row = db.query(Event).filter(Event.id == event_id,
                                         Event.investigation_id == inv_id).first()
            assert row is not None, f"{finding.rule_id} cites foreign/missing event {event_id}"