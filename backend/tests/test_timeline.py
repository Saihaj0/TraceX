"""Timeline ordering, filtering, search and missing-timestamp behavior."""

from __future__ import annotations

import json

EVENTS = [
    # delivered deliberately OUT of order
    {"timestamp": "2026-02-01T12:00:00Z", "event_type": "file_deleted",
     "description": "third event", "user": "alice",
     "file_path": "C:\\Users\\alice\\c\\secret.txt", "source_record_id": "t-3"},
    {"timestamp": "2026-02-01T10:00:00Z", "event_type": "process_creation",
     "description": "first event", "user": "bob",
     "file_path": "C:\\Windows\\cmd.exe", "source_record_id": "t-1"},
    {"timestamp": "2026-02-01T11:00:00Z", "event_type": "audit_log_cleared",
     "description": "second event", "user": "alice",
     "file_path": "C:\\Windows\\System32\\winevt\\Logs\\Security.evtx",
     "source_record_id": "t-2"},
    # undated: must never be dropped silently nor injected into the sequence
    {"event_type": "file_access", "description": "undated event",
     "file_path": "C:\\temp\\notes.dat", "source_record_id": "t-4"},
]


def _seed(client, inv_id: str) -> str:
    resp = client.post(
        f"/api/investigations/{inv_id}/evidence",
        files={"file": ("mixed.json", json.dumps(EVENTS).encode(), "application/json")},
    )
    assert resp.status_code == 201, resp.text
    return resp.json()["evidence_source_id"]


def test_timeline_orders_chronologically_ascending(client, new_investigation):
    inv = new_investigation()
    _seed(client, inv["id"])

    body = client.get(f"/api/investigations/{inv['id']}/events",
                      params={"sort": "asc", "limit": 50}).json()
    timed = [e for e in body["events"] if e["timestamp"]]
    stamps = [e["timestamp"] for e in timed]
    assert stamps == sorted(stamps), "ascending timeline must be sorted"
    assert timed[0]["source_record_id"] == "t-1"
    assert timed[-1]["source_record_id"] == "t-3"


def test_timeline_orders_descending(client, new_investigation):
    inv = new_investigation()
    _seed(client, inv["id"])
    body = client.get(f"/api/investigations/{inv['id']}/events",
                      params={"sort": "desc"}).json()
    timed = [e for e in body["events"] if e["timestamp"]]
    stamps = [e["timestamp"] for e in timed]
    assert stamps == sorted(stamps, reverse=True)


def test_undated_events_kept_but_excluded_on_request(client, new_investigation):
    inv = new_investigation()
    _seed(client, inv["id"])

    included = client.get(f"/api/investigations/{inv['id']}/events",
                          params={"include_undated": "true"}).json()
    assert included["total"] == 4
    assert included["undated_in_page"] == 1
    assert included["stats"]["undated_events"] == 1
    undated = [e for e in included["events"] if not e["timestamp"]]
    assert len(undated) == 1
    assert undated[0]["source_record_id"] == "t-4"   # explicit, not fabricated

    excluded = client.get(f"/api/investigations/{inv['id']}/events",
                          params={"include_undated": "false"}).json()
    assert excluded["total"] == 3


def test_date_range_and_type_filters(client, new_investigation):
    inv = new_investigation()
    _seed(client, inv["id"])

    window = client.get(
        f"/api/investigations/{inv['id']}/events",
        params={"start": "2026-02-01T10:30:00", "end": "2026-02-01T11:30:00"},
    ).json()
    ids = {e["source_record_id"] for e in window["events"] if e["timestamp"]}
    assert ids == {"t-2"}

    typed = client.get(f"/api/investigations/{inv['id']}/events",
                       params={"event_types": "file_deleted"}).json()
    assert typed["total"] == 1
    assert typed["events"][0]["event_type"] == "file_deleted"


def test_search_by_description_path_and_identifier(client, new_investigation):
    inv = new_investigation()
    _seed(client, inv["id"])

    by_desc = client.get(f"/api/investigations/{inv['id']}/events",
                         params={"search": "second event"}).json()
    assert by_desc["total"] == 1

    by_path = client.get(f"/api/investigations/{inv['id']}/events",
                         params={"search": "secret.txt"}).json()
    assert by_path["total"] == 1
    assert by_path["events"][0]["source_record_id"] == "t-3"

    by_id = client.get(f"/api/investigations/{inv['id']}/events",
                       params={"search": "t-2"}).json()
    assert by_id["total"] == 1


def test_user_process_facets(client, new_investigation):
    inv = new_investigation()
    source_id = _seed(client, inv["id"])

    by_user = client.get(f"/api/investigations/{inv['id']}/events",
                         params={"users": "alice"}).json()
    assert by_user["total"] == 2

    by_process = client.get(f"/api/investigations/{inv['id']}/events",
                            params={"files": "C:\\Windows\\cmd.exe"}).json()
    assert by_process["total"] == 1

    facets = client.get(f"/api/investigations/{inv['id']}/timeline/facets").json()
    assert "process_creation" in facets["event_types"]
    assert "alice" in facets["users"]
    assert any(s["id"] == source_id for s in facets["sources"])


def test_uncertain_timestamps_reported_not_sorted_silently(client, new_investigation):
    inv = new_investigation()
    payload = [
        {"timestamp": "2026-02-01T10:00:00Z", "event_type": "file_modified",
         "description": "precise", "source_record_id": "p-1"},
        # date only: precision must drop and confidence too
        {"timestamp": "2026-02-01", "event_type": "file_modified",
         "description": "date only", "source_record_id": "p-2"},
        {"timestamp": "2026-02-01T10:00:00", "event_type": "file_modified",
         "description": "naive local", "source_record_id": "p-3"},
    ]
    client.post(f"/api/investigations/{inv['id']}/evidence",
                files={"file": ("times.json", json.dumps(payload).encode(), "application/json")})
    body = client.get(f"/api/investigations/{inv['id']}/events").json()
    rows = {e["source_record_id"]: e for e in body["events"]}

    assert rows["p-1"]["timestamp_precision"] in {"second", "millisecond", "microsecond"}
    assert rows["p-2"]["timestamp_precision"] in {"day", "date", "unknown"}
    assert rows["p-2"]["timestamp_precision"] != "second"
    assert rows["p-2"]["timestamp_confidence"] != "high"
    # a row with an unparseable timestamp is rejected with a reason, never coerced
    bad = [
        {"timestamp": "ificate", "event_type": "file_modified",
         "description": "broken time", "source_record_id": "bad-1"},
    ]
    client.post(f"/api/investigations/{inv['id']}/evidence",
                files={"file": ("bad.json", json.dumps(bad).encode(), "application/json")})
    evidence = client.get(f"/api/investigations/{inv['id']}/evidence").json()
    sources = [s for s in evidence["evidence"] if s["filename"] == "bad.json"]
    assert sources, "bad.json must be recorded as a source"
    errors = client.get(
        f"/api/investigations/{inv['id']}/evidence/{sources[0]['id']}/errors").json()
    assert errors["rejected_count"] >= 1
    assert any("timestamp" in (e.get("reason") or "") for e in errors["errors"])