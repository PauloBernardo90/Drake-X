"""Tests for v0.5 graph intelligence: query, context serializer, renderers, web builder, CLI."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from drake_x.graph.context import graph_context_to_prompt_json, serialize_graph_context
from drake_x.graph.query import (
    filter_by_edge_type,
    filter_by_kind,
    neighborhood,
    top_connected,
)
from drake_x.graph.render_ascii import render_ascii
from drake_x.graph.render_summary import render_summary
from drake_x.models.evidence_graph import (
    EdgeType,
    EvidenceGraph,
    EvidenceNode,
    NodeKind,
)


def _big_graph() -> EvidenceGraph:
    """A realistic 10-node graph with multiple kinds and edge types."""
    g = EvidenceGraph()
    g.add_node(EvidenceNode(node_id="root", kind=NodeKind.ARTIFACT, domain="web", label="target"))
    g.add_node(EvidenceNode(node_id="f1", kind=NodeKind.FINDING, domain="web", label="missing HSTS"))
    g.add_node(EvidenceNode(node_id="f2", kind=NodeKind.FINDING, domain="web", label="missing CSP"))
    g.add_node(EvidenceNode(node_id="f3", kind=NodeKind.FINDING, domain="web", label="server version leak"))
    g.add_node(EvidenceNode(node_id="a1", kind=NodeKind.ARTIFACT, domain="web", label="curl:http_meta"))
    g.add_node(EvidenceNode(node_id="a2", kind=NodeKind.ARTIFACT, domain="web", label="httpx:http_probe"))
    g.add_node(EvidenceNode(node_id="i1", kind=NodeKind.INDICATOR, domain="web", label="https://example.com"))
    g.add_node(EvidenceNode(node_id="e1", kind=NodeKind.EVIDENCE, domain="web", label="no HSTS header"))
    g.add_node(EvidenceNode(node_id="dup", kind=NodeKind.FINDING, domain="web", label="duplicate"))
    g.add_node(EvidenceNode(node_id="far", kind=NodeKind.FINDING, domain="web", label="far away"))

    g.link("f1", "root", EdgeType.RELATED_TO)
    g.link("f2", "root", EdgeType.RELATED_TO)
    g.link("f3", "root", EdgeType.RELATED_TO)
    g.link("a1", "root", EdgeType.DERIVED_FROM)
    g.link("a2", "root", EdgeType.DERIVED_FROM)
    g.link("a1", "f1", EdgeType.SUPPORTS, confidence=0.9)
    g.link("e1", "f1", EdgeType.SUPPORTS, confidence=0.95)
    g.link("i1", "a2", EdgeType.DERIVED_FROM)
    g.link("dup", "f1", EdgeType.DUPLICATE_OF)
    g.link("far", "dup", EdgeType.RELATED_TO)  # 3 hops from root
    return g


# --- neighborhood extraction ---


def test_neighborhood_from_root_depth_1() -> None:
    g = _big_graph()
    sub = neighborhood(g, ["root"], max_depth=1)
    assert "root" in {n.node_id for n in sub.nodes}
    assert "f1" in {n.node_id for n in sub.nodes}
    # "far" is 3+ hops away, should not appear at depth 1.
    assert "far" not in {n.node_id for n in sub.nodes}


def test_neighborhood_from_root_depth_2() -> None:
    g = _big_graph()
    sub = neighborhood(g, ["root"], max_depth=2)
    assert "e1" in {n.node_id for n in sub.nodes}  # 2 hops via f1


def test_neighborhood_respects_max_nodes() -> None:
    g = _big_graph()
    sub = neighborhood(g, ["root"], max_depth=10, max_nodes=3)
    assert len(sub.nodes) <= 3


def test_neighborhood_is_deterministic() -> None:
    g = _big_graph()
    a = neighborhood(g, ["root"], max_depth=2)
    b = neighborhood(g, ["root"], max_depth=2)
    assert [n.node_id for n in a.nodes] == [n.node_id for n in b.nodes]


def test_neighborhood_missing_seed_ignored() -> None:
    g = _big_graph()
    sub = neighborhood(g, ["nonexistent", "root"], max_depth=1)
    assert "root" in {n.node_id for n in sub.nodes}


# --- filtering ---


def test_filter_by_kind() -> None:
    g = _big_graph()
    findings = filter_by_kind(g, {NodeKind.FINDING})
    assert all(n.kind == NodeKind.FINDING for n in findings.nodes)
    assert len(findings.nodes) == 5


def test_filter_by_edge_type() -> None:
    g = _big_graph()
    supports = filter_by_edge_type(g, {EdgeType.SUPPORTS})
    assert all(e.edge_type == EdgeType.SUPPORTS for e in supports.edges)
    assert len(supports.edges) == 2


def test_top_connected() -> None:
    g = _big_graph()
    top = top_connected(g, n=3)
    # "root" should be the most connected node.
    assert top[0][0] == "root"


# --- graph context serializer ---


def test_serialize_produces_bounded_output() -> None:
    g = _big_graph()
    ctx = serialize_graph_context(g, max_nodes=5, max_chars=10000)
    assert len(ctx["nodes"]) <= 5
    assert "stats" in ctx


def test_serialize_deterministic() -> None:
    g = _big_graph()
    a = serialize_graph_context(g, max_nodes=10)
    b = serialize_graph_context(g, max_nodes=10)
    assert json.dumps(a, sort_keys=True) == json.dumps(b, sort_keys=True)


def test_serialize_with_seed_focuses_subgraph() -> None:
    g = _big_graph()
    ctx = serialize_graph_context(g, seed_ids=["f1"], max_depth=1, max_nodes=10)
    node_ids = {n["id"] for n in ctx["nodes"]}
    assert "f1" in node_ids
    # "far" is 2+ hops from f1, should not appear at depth 1.
    assert "far" not in node_ids


def test_serialize_respects_max_chars() -> None:
    g = _big_graph()
    ctx_big = serialize_graph_context(g, max_chars=100000)
    ctx_small = serialize_graph_context(g, max_chars=200)
    # The constrained version should have fewer edges or stripped data.
    big_text = json.dumps(ctx_big, default=str)
    small_text = json.dumps(ctx_small, default=str)
    assert len(small_text) < len(big_text)


def test_serialize_empty_graph() -> None:
    g = EvidenceGraph()
    ctx = serialize_graph_context(g)
    assert ctx["nodes"] == []
    assert ctx["edges"] == []


def test_prompt_json_returns_string() -> None:
    g = _big_graph()
    j = graph_context_to_prompt_json(g, max_nodes=5)
    assert isinstance(j, str)
    parsed = json.loads(j)
    assert "nodes" in parsed


# --- fallback: AI context without graph ---


def test_task_context_graph_context_defaults_to_none() -> None:
    from drake_x.ai.tasks.base import TaskContext
    ctx = TaskContext(target_display="example.com", profile="safe")
    assert ctx.graph_context is None


# --- ASCII renderer ---


def test_render_ascii_non_empty() -> None:
    g = _big_graph()
    text = render_ascii(g)
    assert "Evidence Graph" in text
    assert "root" in text
    assert "[FND]" in text
    assert "derived_from" in text


def test_render_ascii_empty_graph() -> None:
    g = EvidenceGraph()
    assert "(empty graph)" in render_ascii(g)


# --- summary renderer ---


def test_render_summary_counts() -> None:
    g = _big_graph()
    text = render_summary(g)
    assert "Total nodes: 10" in text
    assert "finding" in text.lower()
    assert "Top connected" in text


# --- web graph builder ---


def test_web_graph_builder_produces_nodes_and_edges() -> None:
    from drake_x.models.artifact import Artifact
    from drake_x.models.finding import Finding, FindingEvidence, FindingSeverity, FindingSource
    from drake_x.models.session import Session
    from drake_x.normalize.web_graph import build_web_evidence_graph
    from drake_x.scope import parse_target

    session = Session(target=parse_target("example.com"), profile="safe")
    artifacts = [
        Artifact(tool_name="curl", kind="web.http_meta", payload={"final_status": 200}, confidence=0.9, notes=[]),
    ]
    findings = [
        Finding(
            title="Missing HSTS",
            summary="No HSTS header",
            severity=FindingSeverity.MEDIUM,
            source=FindingSource.RULE,
            fact_or_inference="fact",
            evidence=[FindingEvidence(artifact_kind="web.http_meta", tool_name="curl")],
            tags=["security-header"],
        ),
    ]
    graph = build_web_evidence_graph(session=session, artifacts=artifacts, findings=findings)
    assert len(graph.nodes) >= 3  # root + artifact + finding
    assert len(graph.edges) >= 2
    # Finding should be linked to root.
    finding_nodes = graph.nodes_by_kind(NodeKind.FINDING)
    assert len(finding_nodes) == 1
    # Evidence edge should link artifact to finding.
    supports = [e for e in graph.edges if e.edge_type == EdgeType.SUPPORTS]
    assert len(supports) >= 1


def test_web_graph_builder_handles_empty_session() -> None:
    from drake_x.models.session import Session
    from drake_x.normalize.web_graph import build_web_evidence_graph
    from drake_x.scope import parse_target

    session = Session(target=parse_target("example.com"), profile="safe")
    graph = build_web_evidence_graph(session=session, artifacts=[], findings=[])
    assert len(graph.nodes) == 1  # just the root target node


# --- CLI smoke test ---


def test_graph_command_registered() -> None:
    from typer.testing import CliRunner
    from drake_x.cli import app

    runner = CliRunner()
    result = runner.invoke(app, ["graph", "--help"])
    assert result.exit_code == 0
    assert "show" in result.output
