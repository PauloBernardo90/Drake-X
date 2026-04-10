"""Tests for the Evidence Graph model and storage."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from drake_x.models.evidence_graph import (
    EdgeType,
    EvidenceEdge,
    EvidenceGraph,
    EvidenceNode,
    NodeKind,
)


def _sample_graph() -> EvidenceGraph:
    g = EvidenceGraph()
    g.add_node(EvidenceNode(node_id="a", kind=NodeKind.ARTIFACT, domain="apk", label="sample"))
    g.add_node(EvidenceNode(node_id="b", kind=NodeKind.FINDING, domain="apk", label="dropper"))
    g.add_node(EvidenceNode(node_id="c", kind=NodeKind.INDICATOR, domain="apk", label="evil.com"))
    g.link("b", "a", EdgeType.DERIVED_FROM)
    g.link("c", "b", EdgeType.SUPPORTS, confidence=0.8)
    g.link("c", "a", EdgeType.DERIVED_FROM)
    return g


def test_add_nodes_and_edges() -> None:
    g = _sample_graph()
    assert len(g.nodes) == 3
    assert len(g.edges) == 3


def test_get_node() -> None:
    g = _sample_graph()
    assert g.get_node("a") is not None
    assert g.get_node("a").label == "sample"
    assert g.get_node("z") is None


def test_edges_from() -> None:
    g = _sample_graph()
    edges = g.edges_from("b")
    assert len(edges) == 1
    assert edges[0].target_id == "a"


def test_edges_to() -> None:
    g = _sample_graph()
    edges = g.edges_to("a")
    assert len(edges) == 2  # b→a and c→a


def test_neighbors() -> None:
    g = _sample_graph()
    assert sorted(g.neighbors("a")) == ["b", "c"]


def test_subgraph_by_domain() -> None:
    g = _sample_graph()
    g.add_node(EvidenceNode(node_id="w", kind=NodeKind.FINDING, domain="web", label="hsts"))
    sub = g.subgraph("apk")
    assert len(sub.nodes) == 3
    assert g.get_node("w") is not None
    assert sub.get_node("w") is None


def test_nodes_by_kind() -> None:
    g = _sample_graph()
    findings = g.nodes_by_kind(NodeKind.FINDING)
    assert len(findings) == 1
    assert findings[0].node_id == "b"


def test_stats() -> None:
    g = _sample_graph()
    s = g.stats()
    assert s["total_nodes"] == 3
    assert s["total_edges"] == 3
    assert s["nodes_by_kind"]["finding"] == 1
    assert s["edges_by_type"]["derived_from"] == 2


def test_json_round_trip() -> None:
    g = _sample_graph()
    data = g.to_dict()
    g2 = EvidenceGraph.from_dict(data)
    assert len(g2.nodes) == 3
    assert len(g2.edges) == 3
    assert g2.get_node("b").label == "dropper"


def test_json_string_round_trip() -> None:
    g = _sample_graph()
    j = g.to_json(indent=2)
    data = json.loads(j)
    g2 = EvidenceGraph.from_dict(data)
    assert g2.stats() == g.stats()


def test_storage_round_trip(tmp_path: Path) -> None:
    from drake_x.core.storage import WorkspaceStorage
    from drake_x.core.workspace import Workspace
    from drake_x.models.session import Session
    from drake_x.scope import parse_target

    ws = Workspace.init("graph-test", root=tmp_path)
    storage = WorkspaceStorage(ws.db_path)

    session = Session(target=parse_target("example.com"), profile="test")
    storage.legacy.save_session(session)

    g = _sample_graph()
    storage.save_evidence_graph(session.id, g)

    loaded = storage.load_evidence_graph(session.id)
    assert loaded is not None
    assert loaded.stats()["total_nodes"] == 3
    assert loaded.stats()["total_edges"] == 3
    assert loaded.get_node("b").label == "dropper"


def test_storage_returns_none_for_missing(tmp_path: Path) -> None:
    from drake_x.core.storage import WorkspaceStorage
    from drake_x.core.workspace import Workspace

    ws = Workspace.init("graph-missing", root=tmp_path)
    storage = WorkspaceStorage(ws.db_path)
    assert storage.load_evidence_graph("nonexistent") is None
