"""Evidence Graph — structured relationships between findings and artifacts.

The graph represents the analysis knowledge base as a directed graph where:

- **Nodes** are findings, artifacts, indicators, or raw evidence items.
  Each node has a ``domain`` (web, apk, recon, etc.) and a ``kind``
  (finding, artifact, indicator, evidence).
- **Edges** are typed relationships between nodes.

Supported edge types:

- ``derived_from`` — finding B was derived from artifact A
- ``supports`` — evidence A supports conclusion B
- ``related_to`` — A and B are related but neither derives from the other
- ``duplicate_of`` — A is a duplicate of B (mirrors the dedupe tag)
- ``contradicts`` — A and B produce conflicting assessments

The graph is serializable to JSON and can be persisted alongside the
session in the workspace database. It is consumed by:

- the reporting layer (for inline evidence links)
- the AI tasks (for structured reasoning context)
- future CTI enrichment pipelines
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class EdgeType(StrEnum):
    DERIVED_FROM = "derived_from"
    SUPPORTS = "supports"
    RELATED_TO = "related_to"
    DUPLICATE_OF = "duplicate_of"
    CONTRADICTS = "contradicts"


class NodeKind(StrEnum):
    FINDING = "finding"
    ARTIFACT = "artifact"
    INDICATOR = "indicator"
    EVIDENCE = "evidence"
    PROTECTION = "protection"
    CAMPAIGN = "campaign"


@dataclass
class EvidenceNode:
    """One node in the evidence graph."""

    node_id: str
    kind: NodeKind
    domain: str = ""          # web, apk, recon, api, etc.
    label: str = ""           # human-readable short label
    data: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "node_id": self.node_id,
            "kind": self.kind.value,
            "domain": self.domain,
            "label": self.label,
            "data": self.data,
        }


@dataclass
class EvidenceEdge:
    """One directed edge in the evidence graph."""

    source_id: str
    target_id: str
    edge_type: EdgeType
    confidence: float = 1.0
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_id": self.source_id,
            "target_id": self.target_id,
            "edge_type": self.edge_type.value,
            "confidence": self.confidence,
            "notes": self.notes,
        }


class EvidenceGraph:
    """In-memory directed evidence graph.

    Nodes are keyed by ``node_id``. Edges are stored as a flat list.
    The graph is append-only during an analysis session — nodes and edges
    are added but never removed.
    """

    def __init__(self) -> None:
        self._nodes: dict[str, EvidenceNode] = {}
        self._edges: list[EvidenceEdge] = []

    # ----- mutation -------------------------------------------------------

    def add_node(self, node: EvidenceNode) -> None:
        self._nodes[node.node_id] = node

    def add_edge(self, edge: EvidenceEdge) -> None:
        self._edges.append(edge)

    def link(
        self,
        source_id: str,
        target_id: str,
        edge_type: EdgeType,
        *,
        confidence: float = 1.0,
        notes: str = "",
    ) -> None:
        """Convenience: create and add an edge in one call."""
        self.add_edge(EvidenceEdge(
            source_id=source_id,
            target_id=target_id,
            edge_type=edge_type,
            confidence=confidence,
            notes=notes,
        ))

    # ----- queries --------------------------------------------------------

    @property
    def nodes(self) -> list[EvidenceNode]:
        return list(self._nodes.values())

    @property
    def edges(self) -> list[EvidenceEdge]:
        return list(self._edges)

    def get_node(self, node_id: str) -> EvidenceNode | None:
        return self._nodes.get(node_id)

    def edges_from(self, node_id: str) -> list[EvidenceEdge]:
        return [e for e in self._edges if e.source_id == node_id]

    def edges_to(self, node_id: str) -> list[EvidenceEdge]:
        return [e for e in self._edges if e.target_id == node_id]

    def neighbors(self, node_id: str) -> list[str]:
        """Return all node IDs reachable from *node_id* in one hop."""
        ids: set[str] = set()
        for e in self._edges:
            if e.source_id == node_id:
                ids.add(e.target_id)
            if e.target_id == node_id:
                ids.add(e.source_id)
        return sorted(ids)

    def subgraph(self, domain: str) -> "EvidenceGraph":
        """Return a new graph containing only nodes in *domain*."""
        g = EvidenceGraph()
        node_ids = {n.node_id for n in self._nodes.values() if n.domain == domain}
        for nid in node_ids:
            g.add_node(self._nodes[nid])
        for e in self._edges:
            if e.source_id in node_ids and e.target_id in node_ids:
                g.add_edge(e)
        return g

    def nodes_by_kind(self, kind: NodeKind) -> list[EvidenceNode]:
        return [n for n in self._nodes.values() if n.kind == kind]

    # ----- serialization --------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        return {
            "nodes": [n.to_dict() for n in self._nodes.values()],
            "edges": [e.to_dict() for e in self._edges],
            "node_count": len(self._nodes),
            "edge_count": len(self._edges),
        }

    def to_json(self, **kwargs: Any) -> str:
        return json.dumps(self.to_dict(), default=str, **kwargs)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "EvidenceGraph":
        g = cls()
        for nd in data.get("nodes", []):
            g.add_node(EvidenceNode(
                node_id=nd["node_id"],
                kind=NodeKind(nd["kind"]),
                domain=nd.get("domain", ""),
                label=nd.get("label", ""),
                data=nd.get("data", {}),
            ))
        for ed in data.get("edges", []):
            g.add_edge(EvidenceEdge(
                source_id=ed["source_id"],
                target_id=ed["target_id"],
                edge_type=EdgeType(ed["edge_type"]),
                confidence=ed.get("confidence", 1.0),
                notes=ed.get("notes", ""),
            ))
        return g

    # ----- stats ----------------------------------------------------------

    def stats(self) -> dict[str, int]:
        kind_counts = {}
        for n in self._nodes.values():
            kind_counts[n.kind.value] = kind_counts.get(n.kind.value, 0) + 1
        edge_counts = {}
        for e in self._edges:
            edge_counts[e.edge_type.value] = edge_counts.get(e.edge_type.value, 0) + 1
        return {
            "total_nodes": len(self._nodes),
            "total_edges": len(self._edges),
            "nodes_by_kind": kind_counts,
            "edges_by_type": edge_counts,
        }
