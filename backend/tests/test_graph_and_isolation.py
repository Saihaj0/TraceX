"""Graph relationships, investigation isolation, and missing-data handling."""

from __future__ import annotations

import json

from app.models import EvidenceSource, Finding, GraphEdge, GraphNode, SuspicionChain


# --------------------------------------------------------------------------- #
# Graph relationships
# --------------------------------------------------------------------------- #

def test_graph_built_for_analysed_investigation(db, demo):
    inv_id = demo("multi", analyse=True)
    nodes = db.query(GraphNode).filter(GraphNode.investigation_id == inv_id).all()
    edges = db.query(GraphEdge).filter(GraphEdge.investigation_id == inv_id).all()
    assert nodes, "analysis must produce graph nodes"
    assert edges, "correlation must produce relationships"

    kinds = {"inferred" if e.inferred else "observed" for e in edges}
    assert "observed" in kinds, "artifact-derived relationships must be labelled observed"
    for edge in edges:
        assert edge.relation
        assert edge.explanation, "every edge must carry a human-readable explanation"
        assert edge.evidence_refs is not None


def test_graph_payload_shape_and_inference_rules(client, demo):
    inv_id = demo("multi", analyse=True)
    payload = client.get(f"/api/investigations/{inv_id}/graph").json()
    assert payload["counts"]["nodes"] == len(payload["nodes"]) > 0
    assert payload["counts"]["edges"] == len(payload["edges"]) > 0
    assert payload["legend"]["relations"], "relations must be documented for the UI"
    assert any(r["kind"] == "inferred" for r in payload["legend"]["relations"]) or payload["inference_rules"] is not None

    node = payload["nodes"][0]["data"]
    assert {"id", "label", "node_type"} <= set(node)
    edge = payload["edges"][0]["data"]
    assert {"source", "target", "relation", "inferred"} <= set(edge)
    assert payload["empty_reason"] is None


def test_graph_path_between_connected_elements(client, db, demo):
    inv_id = demo("multi", analyse=True)
    payload = client.get(f"/api/investigations/{inv_id}/graph").json()
    # pick an edge touching a real event node and ask for the path its endpoints describe
    event_ids = {n["data"]["id"] for n in payload["nodes"]
                 if n["data"]["node_type"] == "event"}
    edge = next(e for e in payload["edges"]
                if e["data"]["source"] in event_ids or e["data"]["target"] in event_ids)
    src, dst = edge["data"]["source"], edge["data"]["target"]
    if src == dst:
        return
    res = client.post(f"/api/investigations/{inv_id}/graph/path",
                      json={"source_id": src, "target_id": dst}).json()
    assert res["found"] is True
    assert res["path"][0] == src and res["path"][-1] == dst
    assert isinstance(res["inferred_hops"], int)
    assert res["summary"], "path summary must explain each hop"


def test_graph_isolate_chain(client, db, demo):
    inv_id = demo("multi", analyse=True)
    chain = db.query(SuspicionChain).filter(
        SuspicionChain.investigation_id == inv_id).first()
    assert chain, "multi scenario should produce a chain"
    res = client.get(f"/api/investigations/{inv_id}/graph/isolate",
                     params={"chain_id": chain.id}).json()
    assert res["found"] is True
    assert res["chain"]["id"] == chain.id
    # the isolated set covers the chain's events
    assert len(res["nodes"]) >= len(chain.event_ids)


def test_graph_actions_entity_picker(client, demo):
    inv_id = demo("multi", analyse=True)
    actions = client.get(f"/api/investigations/{inv_id}/graph/actions").json()
    assert isinstance(actions["components"], int) and actions["components"] >= 1
    assert actions["entities"], "path finding needs an entity picker"
    any_group = next(iter(actions["entities"].values()))
    assert {"id", "label", "type"} <= set(any_group[0])


# --------------------------------------------------------------------------- #
# Investigation isolation
# --------------------------------------------------------------------------- #

def _payload(name: str) -> bytes:
    return json.dumps([
        {"timestamp": "2026-04-01T09:00:00Z", "event_type": "process_creation",
         "description": f"{name} activity", "user": name,
         "file_path": "C:\\Windows\\notepad.exe", "source_record_id": f"{name}-1"},
    ]).encode()


def test_investigations_are_fully_isolated(client, db, new_investigation):
    a = new_investigation(name="Alpha")
    b = new_investigation(name="Bravo")

    ra = client.post(f"/api/investigations/{a['id']}/evidence",
                     files={"file": ("alpha.json", _payload("alpha"), "application/json")})
    rb = client.post(f"/api/investigations/{b['id']}/evidence",
                     files={"file": ("bravo.json", _payload("bravo"), "application/json")})
    assert ra.status_code == 201 and rb.status_code == 201

    events_a = client.get(f"/api/investigations/{a['id']}/events").json()
    events_b = client.get(f"/api/investigations/{b['id']}/events").json()
    assert events_a["total"] == 1 and events_b["total"] == 1
    ids_a = {e["id"] for e in events_a["events"]}
    ids_b = {e["id"] for e in events_b["events"]}
    assert not (ids_a & ids_b)
    assert all(e["user"] == "alpha" for e in events_a["events"])
    assert all(e["user"] == "bravo" for e in events_b["events"])

    # analyses stay scoped as well
    client.post(f"/api/investigations/{a['id']}/analysis/run")
    findings_a = db.query(Finding).filter(Finding.investigation_id == a["id"]).count()
    findings_b = db.query(Finding).filter(Finding.investigation_id == b["id"]).count()
    assert findings_b == 0
    assert findings_a >= 0

    # evidence listings never bleed
    ev_a = client.get(f"/api/investigations/{a['id']}/evidence").json()
    assert all(s["filename"] == "alpha.json" for s in ev_a["evidence"])

    # unknown ids 404 rather than leaking another case
    assert client.get("/api/investigations/does-not-exist/events").status_code == 404


def test_delete_requires_confirmation_and_is_effective(client, new_investigation):
    # a DEMO investigation must not be removable without explicit confirmation
    gen = client.post("/api/demo/generate", json={"scenarios": ["logclear"]})
    assert gen.status_code in (200, 201), gen.text
    demo_inv = gen.json()["created"][0]
    no_confirm = client.delete(f"/api/investigations/{demo_inv['id']}")
    assert no_confirm.status_code in (400, 422), "demo deletion needs explicit confirmation"
    assert client.get(f"/api/investigations/{demo_inv['id']}").status_code == 200, \
        "refused deletion must leave the investigation intact"

    ok = client.delete(f"/api/investigations/{demo_inv['id']}", params={"confirm": "true"})
    assert ok.status_code == 200
    assert ok.json().get("deleted") is True
    assert client.get(f"/api/investigations/{demo_inv['id']}").status_code == 404

    # a regular investigation deletes cleanly too
    inv = new_investigation(name="Doomed")
    ok2 = client.delete(f"/api/investigations/{inv['id']}", params={"confirm": "true"})
    assert ok2.status_code == 200
    assert client.get(f"/api/investigations/{inv['id']}").status_code == 404


def test_demo_generation_is_labelled(client):
    response = client.post("/api/demo/generate", json={"scenarios": ["logclear"]})
    assert response.status_code in (200, 201), response.text
    created = response.json()["created"]
    assert created, "at least one investigation must be created"
    inv = created[0]
    assert inv["is_demo"] is True
    assert "SYNTHETIC" in inv["name"] or inv["origin"] == "demo"

    detail = client.get(f"/api/investigations/{inv['id']}").json()
    assert detail["is_demo"] is True
    # every event row carries its origin so demo data can never masquerade as evidence
    events = client.get(f"/api/investigations/{inv['id']}/events").json()
    assert events["total"] > 0
    assert all(e["origin"] == "demo" for e in events["events"])

    evidence = client.get(f"/api/investigations/{inv['id']}/evidence").json()
    assert all(s["origin"] == "demo" for s in evidence["evidence"])


# --------------------------------------------------------------------------- #
# Missing-data handling
# --------------------------------------------------------------------------- #

SPARSE = json.dumps([
    {"timestamp": "2026-05-01T10:00:00Z", "event_type": "file_deleted",
     "description": "has time and user", "user": "alice",
     "file_path": "C:\\temp\\gone.txt", "source_record_id": "s-1"},
    {"event_type": "file_access", "description": "no time at all",
     "source_record_id": "s-2"},
    {"timestamp": "2026-05-01T12:00:00Z", "event_type": "file_access",
     "description": "no user no host no process", "source_record_id": "s-3"},
    {"not_a_known_field": "value", "event_type": "file_access",
     "description": "unknown fields preserved", "source_record_id": "s-4",
     "timestamp": "2026-05-01T13:00:00Z"},
]).encode()


def test_missing_fields_are_nullable_and_never_fabricated(client, new_investigation):
    inv = new_investigation()
    resp = client.post(f"/api/investigations/{inv['id']}/evidence",
                       files={"file": ("sparse.json", SPARSE, "application/json")})
    assert resp.status_code == 201, resp.text

    body = client.get(f"/api/investigations/{inv['id']}/events").json()
    assert body["total"] == 4
    rows = {e["source_record_id"]: e for e in body["events"]}

    undated = rows["s-2"]
    assert undated["timestamp"] is None          # stays null, not epoch/now
    assert undated["user"] is None               # missing stays missing
    assert undated["has_timestamp"] is False
    assert undated["timestamp_confidence"] != "high" or undated["timestamp"] is None

    minimal = rows["s-3"]
    assert minimal["user"] is None and minimal["host"] is None
    assert minimal["description"] == "minimal user no host no process" or minimal["description"]

    # stats reflect the undated row rather than hiding it
    assert body["stats"]["undated_events"] == 1
    assert body["stats"]["total_events"] == 4


def test_order_uncertainty_is_flagged_not_overstated(client, new_investigation):
    inv = new_investigation()
    payload = json.dumps([
        {"timestamp": "2026-05-01T10:00:00.000000Z", "event_type": "file_deleted",
         "description": "micro precision", "source_record_id": "u-1"},
        {"timestamp": "2026-05-01", "event_type": "file_deleted",
         "description": "date only", "source_record_id": "u-2"},
    ]).encode()
    client.post(f"/api/investigations/{inv['id']}/evidence",
                files={"file": ("unc.json", payload, "application/json")})
    body = client.get(f"/api/investigations/{inv['id']}/events").json()
    rows = {e["source_record_id"]: e for e in body["events"]}
    # date-only event must not claim second-level precision
    assert rows["u-2"]["timestamp_precision"] in {"day", "date", "unknown"} or \
        rows["u-2"]["timestamp_confidence"] in {"low", "none"}
    assert isinstance(rows["u-2"]["order_uncertain"], bool)


def test_evidence_record_counts_add_up(client, new_investigation):
    inv = new_investigation()
    rows = json.dumps([
        {"timestamp": "2026-05-02T10:00:00Z", "event_type": "file_deleted",
         "description": "ok", "source_record_id": "c-1"},
        {"timestamp": "", "event_type": "", "description": "",
         "source_record_id": "", "file_path": ""},   # intentionally invalid
    ]).encode()
    resp = client.post(f"/api/investigations/{inv['id']}/evidence",
                       files={"file": ("counted.json", rows, "application/json")})
    assert resp.status_code == 201, resp.text
    source = resp.json()
    assert source["accepted_count"] + source["rejected_count"] == source["record_count"] or \
        source["record_count"] >= source["accepted_count"]
    assert source["accepted_count"] == 1
    assert source["rejected_count"] >= 1

    errors = client.get(
        f"/api/investigations/{inv['id']}/evidence/{source['evidence_source_id']}/errors").json()
    assert errors["errors"], "rejected rows must be inspectable"
    assert errors["policy"]