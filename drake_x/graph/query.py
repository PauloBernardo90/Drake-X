"""Bounded neighborhood extraction and filtering on Evidence Graphs.

All operations are read-only and produce new :class:`EvidenceGraph`
instances rather than mutating the source. Outputs are deterministically
ordered (sorted by node_id) so that repeated queries on the same graph
produce identical results — important for reproducible AI prompts and
stable test assertions.
"""

from __future__ import annotations

from collections import deque

from ..models.evidence_graph import (
    EdgeType,
    EvidenceEdge,
    EvidenceGraph,
    EvidenceNode,
    NodeKind,
)


def neighborhood(
    graph: EvidenceGraph,
    seed_ids: list[str],
    *,
    max_depth: int = 2,
    max_nodes: int = 50,
    max_edges: int = 100,
) -> EvidenceGraph:
    """BFS-expand from *seed_ids* up to *max_depth* hops.

    Returns a new graph containing only the reachable subgraph, bounded
    by the specified limits. Deterministic: nodes are visited in sorted
    order at each BFS level.
    """
    visited: set[str] = set()
    queue: deque[tuple[str, int]] = deque()

    for sid in seed_ids:
        if graph.get_node(sid) is not None:
            queue.append((sid, 0))

    while queue and len(visited) < max_nodes:
        nid, depth = queue.popleft()
        if nid in visited:
            continue
        visited.add(nid)
        if depth >= max_depth:
            continue
        # Expand neighbors in sorted order for determinism.
        for neighbor_id in sorted(graph.neighbors(nid)):
            if neighbor_id not in visited and len(visited) < max_nodes:
                queue.append((neighbor_id, depth + 1))

    sub = EvidenceGraph()
    for nid in sorted(visited):
        node = graph.get_node(nid)
        if node is not None:
            sub.add_node(node)

    edge_count = 0
    for e in graph.edges:
        if edge_count >= max_edges:
            break
        if e.source_id in visited and e.target_id in visited:
            sub.add_edge(e)
            edge_count += 1

    return sub


def filter_by_kind(
    graph: EvidenceGraph,
    kinds: set[NodeKind],
) -> EvidenceGraph:
    """Return a subgraph containing only nodes whose kind is in *kinds*."""
    sub = EvidenceGraph()
    node_ids: set[str] = set()
    for node in graph.nodes:
        if node.kind in kinds:
            sub.add_node(node)
            node_ids.add(node.node_id)
    for e in graph.edges:
        if e.source_id in node_ids and e.target_id in node_ids:
            sub.add_edge(e)
    return sub


def filter_by_edge_type(
    graph: EvidenceGraph,
    edge_types: set[EdgeType],
) -> EvidenceGraph:
    """Return a subgraph keeping only edges of the specified types.

    Nodes that become isolated (no remaining edges) are still included
    if they were connected by at least one original edge of any type.
    """
    # Collect node IDs that participate in matching edges.
    node_ids: set[str] = set()
    kept_edges: list[EvidenceEdge] = []
    for e in graph.edges:
        if e.edge_type in edge_types:
            kept_edges.append(e)
            node_ids.add(e.source_id)
            node_ids.add(e.target_id)

    sub = EvidenceGraph()
    for nid in sorted(node_ids):
        node = graph.get_node(nid)
        if node is not None:
            sub.add_node(node)
    for e in kept_edges:
        sub.add_edge(e)
    return sub


def top_connected(
    graph: EvidenceGraph,
    n: int = 10,
) -> list[tuple[str, int]]:
    """Return the *n* most-connected node IDs (by total edge count)."""
    counts: dict[str, int] = {}
    for e in graph.edges:
        counts[e.source_id] = counts.get(e.source_id, 0) + 1
        counts[e.target_id] = counts.get(e.target_id, 0) + 1
    ranked = sorted(counts.items(), key=lambda x: (-x[1], x[0]))
    return ranked[:n]
