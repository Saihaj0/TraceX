"""Forensic graph construction (NetworkX) served to Cytoscape.js.

Node types:    event, file, user, process, device, evidence_source, finding, hypothesis
Relationships: OBSERVED_IN, ASSOCIATED_WITH, SAME_USER, SAME_PROCESS, SAME_FILE,
               TEMPORALLY_NEAR, PRECEDES, SUPPORTS, CONTRADICTS, POSSIBLY_CAUSAL

Every edge carries an explanation, the source artifacts it derives from and
the documented rule that licenses an *inferred* relationship.  Observed edges
(directly recorded in a source artifact) are style-distinct from inferred ones.
"""

from __future__ import annotations

import hashlib

import networkx as nx
from sqlalchemy.orm import Session

from ..config import DEFAULT_ANALYSIS_CONFIG
from ..models import EvidenceSource, Event, Finding, GraphEdge, GraphNode, Investigation, SuspicionChain
from ..normalization import dt_to_iso
from .rules import LOG_CLEAR_TYPES, suspicious_process

NODE_TYPES = ("event", "file", "user", "process", "device", "evidence_source", "finding", "hypothesis")
RELATIONS = ("OBSERVED_IN", "ASSOCIATED_WITH", "SAME_USER", "SAME_PROCESS", "SAME_FILE",
             "TEMPORALLY_NEAR", "PRECEDES", "SUPPORTS", "CONTRADICTS", "POSSIBLY_CAUSAL")

NEAR_MINUTES_DEFAULT = 10
MAX_NEAR_EDGES_PER_EVENT = 3

RELATION_LEGEND = {
    "OBSERVED_IN": {"kind": "observed", "meaning": "The event is a record inside this source artifact."},
    "ASSOCIATED_WITH": {"kind": "observed", "meaning": "The event's record names this host/device."},
    "SAME_USER": {"kind": "observed", "meaning": "The event record names this account/user identity."},
    "SAME_PROCESS": {"kind": "observed", "meaning": "The event record names this process."},
    "SAME_FILE": {"kind": "observed", "meaning": "The event record names this file path."},
    "PRECEDES": {"kind": "observed", "meaning": "Documented temporal order inside an analysed sequence."},
    "TEMPORALLY_NEAR": {"kind": "inferred", "meaning": "Two events are close in time AND share an anchor (same user/file/process/host). Proximity alone never implies causation."},
    "SUPPORTS": {"kind": "inferred", "meaning": "A finding cites this record as supporting evidence."},
    "CONTRADICTS": {"kind": "inferred", "meaning": "A finding cites this record as contradicting evidence."},
    "POSSIBLY_CAUSAL": {"kind": "inferred", "meaning": "A documented chain rule links the steps (sequence, not proven causation). Requires the pattern's rule to fire — never emitted from time proximity alone."},
}


def _h(value: str, length: int = 24) -> str:
    return hashlib.sha1(str(value).encode("utf-8", "ignore")).hexdigest()[:length]


def event_key(event_id: str) -> str:
    return f"evt:{event_id}"


def file_key(path: str) -> str:
    return f"file:{_h(path)}"


def user_key(user: str) -> str:
    return f"user:{_h(user)}"


def proc_key(name: str) -> str:
    return f"proc:{_h(name)}"


def device_key(name: str) -> str:
    return f"dev:{_h(name)}"


def source_key(source_id: str) -> str:
    return f"src:{source_id}"


def finding_key(finding_id: str) -> str:
    return f"fd:{finding_id}"


def hypothesis_key(chain_id: str) -> str:
    return f"hyp:{chain_id}"


def edge_id(relation: str, source: str, target: str) -> str:
    return _h(f"{relation}|{source}|{target}", 40)


def _short(text: str | None, limit: int = 90) -> str:
    text = (text or "").strip()
    return text if len(text) <= limit else text[: limit - 1] + "…"


# ---------------------------------------------------------------------------
# Graph rebuild (persisted, one per analysis run)
# ---------------------------------------------------------------------------

def rebuild_graph(db: Session, investigation: Investigation, ctx, findings: list[Finding],
                  chains: list[SuspicionChain], run_id: str) -> dict:
    db.query(GraphNode).filter(GraphNode.investigation_id == investigation.id).delete()
    db.query(GraphEdge).filter(GraphEdge.investigation_id == investigation.id).delete()

    max_nodes = int((ctx.config or DEFAULT_ANALYSIS_CONFIG).get("graph_max_nodes", 600))
    nodes: dict[str, GraphNode] = {}
    edges: dict[str, GraphEdge] = {}
    stats = {"nodes": 0, "edges": 0, "truncated": False, "requested_nodes": 0}

    def add_node(key: str, node_type: str, label: str, props: dict, event_id: str | None = None):
        if key in nodes:
            return True
        if len(nodes) >= max_nodes:
            stats["truncated"] = True
            return False
        nodes[key] = GraphNode(
            id=key, investigation_id=investigation.id, node_type=node_type,
            label=_short(label, 200), properties=props, event_id=event_id,
        )
        return True

    def add_edge(source: str, target: str, relation: str, explanation: str,
                 evidence_refs: list, rule_ref: str | None = None,
                 inferred: bool | None = None, confidence: str | None = None,
                 weight: float = 1.0) -> None:
        if source not in nodes or target not in nodes or source == target:
            return
        key = edge_id(relation, source, target)
        if key in edges:
            # Keep the first (usually the stronger, rule-based) explanation.
            existing = edges[key]
            existing.weight = max(existing.weight, weight)
            if rule_ref and not existing.rule_ref:
                existing.rule_ref = rule_ref
                existing.inferred = inferred if inferred is not None else existing.inferred
            return
        meta = RELATION_LEGEND.get(relation, {})
        edges[key] = GraphEdge(
            id=key, investigation_id=investigation.id, source_key=source, target_key=target,
            relation=relation, explanation=explanation, evidence_refs=evidence_refs[:25],
            rule_ref=rule_ref,
            inferred=meta.get("kind") == "inferred" if inferred is None else inferred,
            confidence=confidence or ("observed" if meta.get("kind") == "observed" else "low"),
            weight=weight,
        )

    # --- priority: findings + chains first so truncation never drops them ----
    flagged_event_ids: list[str] = []
    for chain in chains:
        flagged_event_ids.extend(chain.event_ids)
    for finding in findings:
        flagged_event_ids.extend(finding.event_ids or [])

    ordered_events = sorted(
        ctx.events,
        key=lambda e: (0 if e.id in set(flagged_event_ids) else 1,
                       -(e.timestamp.timestamp() if e.timestamp else 0)),
    )
    stats["requested_nodes"] = len(ordered_events)

    events_by_id: dict[str, Event] = {e.id: e for e in ctx.events}
    sources_by_id: dict[str, EvidenceSource] = {s.id: s for s in ctx.sources}

    # Evidence-source nodes (always kept — provenance must survive truncation)
    for source in ctx.sources:
        add_node(source_key(source.id), "evidence_source", source.filename, {
            "file_type": source.file_type, "source_type": source.source_type,
            "sha256": source.sha256, "accepted": source.accepted_count,
            "rejected": source.rejected_count, "origin": source.origin,
            "parser": f"{source.parser_name}@{source.parser_version}",
            "imported_at": source.imported_at.isoformat() if source.imported_at else None,
        })

    included_events: list[Event] = []
    for event in ordered_events:
        if add_node(event_key(event.id), "event", _short(event.description or event.event_type, 120), {
            "event_type": event.event_type, "timestamp": dt_to_iso(event.timestamp),
            "timestamp_precision": event.timestamp_precision,
            "timestamp_confidence": event.timestamp_confidence,
            "host": event.host, "user": event.user, "file_path": event.file_path,
            "process_name": event.process_name, "device_id": event.device_id,
            "source_file": event.source_file, "source_record_id": event.source_record_id,
            "evidence_source_id": event.evidence_source_id, "origin": event.origin,
            "ingestion_status": event.ingestion_status, "has_timestamp": event.timestamp is not None,
        }, event_id=event.id):
            included_events.append(event)

    included_ids = {e.id for e in included_events}

    # --- observed relationships ------------------------------------------
    for event in included_events:
        ekey = event_key(event.id)
        if event.evidence_source_id and event.evidence_source_id in sources_by_id:
            source = sources_by_id[event.evidence_source_id]
            add_edge(ekey, source_key(event.evidence_source_id), "OBSERVED_IN",
                     f"Directly observed: record {event.source_record_id or '?'} is contained in "
                     f"{source.filename} (SHA-256 {source.sha256[:12]}…).",
                     [event.raw_record_reference or event.id, source.id],
                     inferred=False, confidence="observed")
        if event.file_path:
            add_node(file_key(event.file_path), "file", event.file_path, {"path": event.file_path})
            add_edge(ekey, file_key(event.file_path), "SAME_FILE",
                     f"Observed relationship: the record names file `{event.file_path}` "
                     f"(source record {event.source_record_id or '?'}).",
                     [event.raw_record_reference or event.id],
                     inferred=False, confidence="observed")
        if event.user:
            add_node(user_key(event.user), "user", event.user, {"user": event.user, "host": event.host})
            add_edge(ekey, user_key(event.user), "SAME_USER",
                     f"Observed relationship: the record attributes this event to user "
                     f"`{event.user}` (source record {event.source_record_id or '?'}).",
                     [event.raw_record_reference or event.id],
                     inferred=False, confidence="observed")
        if event.process_name:
            add_node(proc_key(event.process_name), "process", event.process_name,
                     {"process_name": event.process_name, "process_id": event.process_id})
            add_edge(ekey, proc_key(event.process_name), "SAME_PROCESS",
                     f"Observed relationship: the record names process `{event.process_name}` "
                     f"(PID {event.process_id if event.process_id is not None else 'n/a'}).",
                     [event.raw_record_reference or event.id],
                     inferred=False, confidence="observed")
        if event.device_id:
            add_node(device_key(event.device_id), "device", event.device_id,
                     {"device_id": event.device_id, "kind": "removable_or_volume"})
            add_edge(ekey, device_key(event.device_id), "ASSOCIATED_WITH",
                     f"Observed relationship: the record identifies device `{event.device_id}`.",
                     [event.raw_record_reference or event.id],
                     inferred=False, confidence="observed")
        elif event.host:
            add_node(device_key(event.host), "device", event.host, {"host": event.host, "kind": "host"})
            add_edge(ekey, device_key(event.host), "ASSOCIATED_WITH",
                     f"Observed relationship: the record originated from host `{event.host}`.",
                     [event.raw_record_reference or event.id],
                     inferred=False, confidence="observed")

    # --- TEMPORALLY_NEAR: proximity AND a shared anchor -------------------
    near_edges = 0
    by_host_user: dict[str, list[Event]] = {}
    for event in sorted([e for e in included_events if e.timestamp], key=lambda e: e.timestamp):
        for anchor in filter(None, [event.file_path, event.user, event.process_name, event.host]):
            by_host_user.setdefault(anchor, []).append(event)
    near_budget: dict[str, int] = {}
    near_minutes = NEAR_MINUTES_DEFAULT
    seen_pairs: set[tuple[str, str]] = set()
    for anchor, group in by_host_user.items():
        for a, b in zip(group, group[1:]):
            delta_seconds = (b.timestamp - a.timestamp).total_seconds()
            if delta_seconds > near_minutes * 60:
                continue
            pair = (a.id, b.id)
            if pair in seen_pairs:
                continue
            seen_pairs.add(pair)
            if near_budget.get(a.id, 0) >= MAX_NEAR_EDGES_PER_EVENT:
                continue
            near_budget[a.id] = near_budget.get(a.id, 0) + 1
            add_edge(
                event_key(a.id), event_key(b.id), "TEMPORALLY_NEAR",
                f"Inferred: the two records are {delta_seconds:.0f}s apart and share the anchor "
                f"`{_short(anchor, 60)}`. Temporal proximity + shared anchor is a correlation "
                "only — no causal claim is made.",
                [a.raw_record_reference or a.id, b.raw_record_reference or b.id],
                inferred=True, confidence="low", weight=0.6,
            )
            near_edges += 1

    # --- findings, hypotheses, sequence edges ------------------------------
    for finding in findings:
        fkey = finding_key(finding.id)
        add_node(fkey, "finding", finding.title, {
            "rule_id": finding.rule_id, "rule_name": finding.rule_name,
            "rule_version": finding.rule_version, "severity": finding.severity,
            "support": finding.support, "heuristic_score": finding.heuristic_score,
            "investigative_priority": finding.severity,
        })
        support_events = [e for eid in (finding.event_ids or []) for e in [events_by_id.get(eid)]
                          if e and e.id in included_ids]
        ordered = sorted(support_events, key=lambda e: (e.timestamp or 0)) if all(
            e.timestamp for e in support_events) else support_events
        for event in support_events:
            add_edge(fkey, event_key(event.id), "SUPPORTS",
                     f"Inferred by rule {finding.rule_id}@{finding.rule_version}: this record "
                     f"({event.raw_record_reference or event.id}) supplies supporting evidence — "
                     f"{_short(event.description, 120)}",
                     [event.raw_record_reference or event.id],
                     rule_ref=f"{finding.rule_id}@{finding.rule_version}",
                     inferred=True, confidence=finding.support, weight=1.4)
        for item in (finding.explanation or {}).get("contradicting_evidence", []) or []:
            event_id = item.get("event_id") if isinstance(item, dict) else None
            if event_id and event_id in included_ids:
                add_edge(fkey, event_key(event_id), "CONTRADICTS",
                         f"Inferred by rule {finding.rule_id}: this record contradicts the "
                         f"proposed sequence — {_short(item.get('what'))}",
                         [event_id], rule_ref=f"{finding.rule_id}@{finding.rule_version}",
                         inferred=True, confidence="low")
        for a, b in zip(ordered, ordered[1:]):
            add_edge(event_key(a.id), event_key(b.id), "PRECEDES",
                     f"Documented temporal order within finding {finding.rule_id}: "
                     f"{dt_to_iso(a.timestamp)} → {dt_to_iso(b.timestamp)} "
                     f"({human_delta(a, b)}).",
                     [a.raw_record_reference or a.id, b.raw_record_reference or b.id],
                     rule_ref=f"{finding.rule_id}@{finding.rule_version}",
                     inferred=False, confidence="observed", weight=1.1)

    causal_rule_refs = {"B": "chain-pattern-B (AF-008)", "D": "chain-pattern-D (AF-005)",
                        "E": "chain-pattern-E (removable-media sequence)"}
    for chain in chains:
        hkey = hypothesis_key(chain.id)
        add_node(hkey, "hypothesis", chain.title, {
            "pattern_id": chain.pattern_id, "pattern_name": chain.pattern_name,
            "severity": chain.severity, "support": chain.support,
            "completeness": chain.completeness, "status": chain.status,
            "relationship_types": chain.relationship_types,
            "triggered_rules": chain.triggered_rules,
            "missing_steps": chain.missing_steps,
        })
        chain_events = [events_by_id.get(eid) for eid in chain.event_ids]
        chain_events = [e for e in chain_events if e and e.id in included_ids]
        for event in chain_events:
            add_edge(hkey, event_key(event.id), "SUPPORTS",
                     f"Hypothesis {chain.pattern_id} cites this record as a step "
                     f"({_short(event.description, 100)})",
                     [event.raw_record_reference or event.id],
                     rule_ref=",".join(chain.triggered_rules or []) or None,
                     inferred=True, confidence=chain.support, weight=1.2)
        matched_steps = [s for s in chain.steps if s.get("matched") and s.get("event_ids")]
        for step_a, step_b in zip(matched_steps, matched_steps[1:]):
            a_id, b_id = step_a["event_ids"][0], step_b["event_ids"][0]
            if a_id not in included_ids or b_id not in included_ids:
                continue
            if "POSSIBLY_CAUSAL" in chain.relationship_types:
                add_edge(event_key(a_id), event_key(b_id), "POSSIBLY_CAUSAL",
                         f"Filter: pattern {chain.pattern_id} step '{step_a['label']}' → "
                         f"'{step_b['label']}'; inferred by rule "
                         f"{chain.triggered_rules or ['n/a']} within the pattern's window. "
                         "Sequence only — the evidence does not establish causation.",
                         [step_a.get("evidence_ref"), step_b.get("evidence_ref")],
                         rule_ref=causal_rule_refs.get(chain.pattern_id),
                         inferred=True, confidence="low", weight=1.6)
            else:
                add_edge(event_key(a_id), event_key(b_id), "PRECEDES",
                         f"Pattern {chain.pattern_id} step order: '{step_a['label']}' → "
                         f"'{step_b['label']}'.",
                         [step_a.get("evidence_ref"), step_b.get("evidence_ref")],
                         rule_ref=",".join(chain.triggered_rules or []) or None,
                         inferred=False, confidence="observed", weight=1.2)

    for node in nodes.values():
        db.add(node)
    for edge in edges.values():
        db.add(edge)
    db.flush()

    stats.update({
        "nodes": len(nodes),
        "edges": len(edges),
        "hypotheses": len(chains),
        "findings": len(findings),
        "possibly_causal_edges": sum(1 for e in edges.values() if e.relation == "POSSIBLY_CAUSAL"),
        "inferred_edges": sum(1 for e in edges.values() if e.inferred),
        "observed_edges": sum(1 for e in edges.values() if not e.inferred),
        "near_edges": near_edges,
        "analysis_run_id": run_id,
    })
    return stats


def human_delta(a: Event, b: Event) -> str:
    from .detection import humanize_seconds

    if not a.timestamp or not b.timestamp:
        return "unknown interval"
    return humanize_seconds((b.timestamp - a.timestamp).total_seconds())


# ---------------------------------------------------------------------------
# Graph payload for the UI
# ---------------------------------------------------------------------------

def graph_payload(db: Session, investigation_id: str, *, node_types=None, relation_types=None,
                  search: str | None = None, flagged_event_ids=None) -> dict:
    nodes = db.query(GraphNode).filter(GraphNode.investigation_id == investigation_id).all()
    edges = db.query(GraphEdge).filter(GraphEdge.investigation_id == investigation_id).all()
    flagged_event_ids = set(flagged_event_ids or [])

    node_type_filter = set(node_types or [])
    relation_filter = set(relation_types or [])
    if search:
        needle = search.lower()
    else:
        needle = None

    visible: dict[str, GraphNode] = {}
    for node in nodes:
        if node_type_filter and node.node_type not in node_type_filter:
            continue
        if needle and needle not in (node.label or "").lower() \
                and needle not in str(node.properties or {}).lower() \
                and node.event_id not in flagged_event_ids:
            continue
        visible[node.id] = node

    element_edges = []
    for edge in edges:
        if edge.source_key not in visible or edge.target_key not in visible:
            continue
        if relation_filter and edge.relation not in relation_filter:
            continue
        element_edges.append({
            "data": {
                "id": edge.id, "source": edge.source_key, "target": edge.target_key,
                "relation": edge.relation, "explanation": edge.explanation,
                "evidence_refs": edge.evidence_refs, "rule_ref": edge.rule_ref,
                "inferred": edge.inferred, "confidence": edge.confidence, "weight": edge.weight,
                "kind": RELATION_LEGEND.get(edge.relation, {}).get("kind", "observed"),
            },
        })

    element_nodes = []
    for node in visible.values():
        props = dict(node.properties or {})
        element_nodes.append({
            "data": {
                "id": node.id, "label": node.label, "node_type": node.node_type,
                "event_id": node.event_id, "flagged": bool(
                    node.event_id and node.event_id in flagged_event_ids),
                **{k: v for k, v in props.items() if v is not None},
            },
        })

    return {
        "nodes": element_nodes,
        "edges": element_edges,
        "counts": {
            "nodes": len(element_nodes),
            "edges": len(element_edges),
            "by_node_type": _countby([n["data"]["node_type"] for n in element_nodes]),
            "by_relation": _countby([e["data"]["relation"] for e in element_edges]),
        },
        "legend": {
            "node_types": list(NODE_TYPES),
            "relations": [
                {"relation": r, **RELATION_LEGEND[r]} for r in RELATIONS if r in RELATION_LEGEND
            ],
        },
        "inference_rules": [
            {"relation": "TEMPORALLY_NEAR", "rule": "delta ≤ 10 minutes AND shared "
             "(file | user | process | host) anchor", "requires": ["timestamps", "shared anchor"]},
            {"relation": "PRECEDES", "rule": "order inside a detected finding or chain step list",
             "requires": ["two timestamped records"]},
            {"relation": "POSSIBLY_CAUSAL", "rule": "documented chain pattern rule "
             "(patterns B/D/E) fires on both steps inside its window",
             "requires": ["chain rule satisfied"]},
            {"relation": "SUPPORTS / CONTRADICTS", "rule": "a detection rule cited the record as "
             "supporting or contradicting evidence", "requires": ["rule run"]},
        ],
    }


def _countby(values: list) -> dict:
    out: dict = {}
    for value in values:
        out[value] = out.get(value, 0) + 1
    return out


def flagged_event_ids_for(db: Session, investigation_id: str) -> set[str]:
    ids: set[str] = set()
    for (chain_ids,) in db.query(SuspicionChain.event_ids).filter(
        SuspicionChain.investigation_id == investigation_id
    ):
        ids.update(chain_ids or [])
    for (event_ids,) in db.query(Finding.event_ids).filter(
        Finding.investigation_id == investigation_id
    ):
        ids.update(event_ids or [])
    return ids


# ---------------------------------------------------------------------------
# NetworkX helpers: path highlighting, chain isolation
# ---------------------------------------------------------------------------

def _nx_graph(db: Session, investigation_id: str) -> nx.Graph:
    graph = nx.Graph()
    for edge in db.query(GraphEdge).filter(GraphEdge.investigation_id == investigation_id):
        graph.add_edge(edge.source_key, edge.target_key, **{
            "id": edge.id, "relation": edge.relation, "explanation": edge.explanation,
            "evidence_refs": edge.evidence_refs, "rule_ref": edge.rule_ref,
            "inferred": edge.inferred, "confidence": edge.confidence,
        })
    return graph


def graph_actions(db: Session, investigation_id: str) -> dict:
    """Stats + entity picker used by the graph page controls."""
    graph = _nx_graph(db, investigation_id)
    nodes = db.query(GraphNode).filter(GraphNode.investigation_id == investigation_id).all()
    by_type: dict[str, list[dict]] = {}
    for node in nodes:
        by_type.setdefault(node.node_type, []).append({
            "id": node.id, "label": node.label, "type": node.node_type,
            "event_id": node.event_id,
        })
    return {
        "components": nx.number_connected_components(graph) if graph.number_of_nodes() else 0,
        "density": round(nx.density(graph), 5) if graph.number_of_nodes() > 1 else 0.0,
        "entities": {k: sorted(v, key=lambda x: x["label"])[:200] for k, v in by_type.items()},
        "isolated_nodes": list(nx.isolates(graph))[:50],
    }


def highlight_path(db: Session, investigation_id: str, source_id: str, target_id: str) -> dict:
    graph = _nx_graph(db, investigation_id)
    if source_id not in graph or target_id not in graph:
        return {"found": False, "reason": "one or both elements are not in the graph",
                "path": []}
    try:
        path = nx.shortest_path(graph, source_id, target_id)
    except nx.NetworkXNoPath:
        return {"found": False, "reason": "no relationship path exists between these elements",
                "path": []}
    links = []
    total_inferred = 0
    for a, b in zip(path, path[1:]):
        data = graph[a][b]
        links.append({"from": a, "to": b, **data})
        if data.get("inferred"):
            total_inferred += 1
    return {
        "found": True,
        "path": path,
        "hops": links,
        "inferred_hops": total_inferred,
        "summary": _path_summary(db, investigation_id, path, links),
    }


def _path_summary(db, investigation_id, path, links) -> str:
    labels = {}
    for node in db.query(GraphNode).filter(GraphNode.investigation_id == investigation_id,
                                           GraphNode.id.in_(path)):
        labels[node.id] = node.label
    parts = []
    for link in links:
        parts.append(f"{labels.get(link['from'], link['from'])} "
                     f"—{link['relation']}→ {labels.get(link['to'], link['to'])}")
    return " | ".join(parts)


def isolate_chain(db: Session, investigation_id: str, chain_id: str) -> dict:
    chain = db.query(SuspicionChain).filter(
        SuspicionChain.investigation_id == investigation_id, SuspicionChain.id == chain_id
    ).first()
    if chain is None:
        return {"found": False, "reason": "chain not found"}
    wanted = {hypothesis_key(chain.id)}
    for event_id in chain.event_ids:
        wanted.add(event_key(event_id))
        event = db.query(Event).filter(Event.id == event_id).first()
        if event and event.file_path:
            wanted.add(file_key(event.file_path))
        if event and event.user:
            wanted.add(user_key(event.user))
        if event and event.process_name:
            wanted.add(proc_key(event.process_name))
        if event and event.evidence_source_id:
            wanted.add(source_key(event.evidence_source_id))
    return {
        "found": True,
        "nodes": list(wanted),
        "chain": {"id": chain.id, "title": chain.title, "steps": chain.steps},
    }