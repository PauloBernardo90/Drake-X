"""Summary statistics renderer for Evidence Graphs."""

from __future__ import annotations

from ..models.evidence_graph import EvidenceGraph
from .query import top_connected


def render_summary(graph: EvidenceGraph) -> str:
    """Render statistics, kind/edge counts, and top-connected nodes."""
    if not graph.nodes:
        return "(empty graph)\n"

    stats = graph.stats()
    lines: list[str] = []
    lines.append("Evidence Graph Summary")
    lines.append("=" * 40)
    lines.append(f"Total nodes: {stats['total_nodes']}")
    lines.append(f"Total edges: {stats['total_edges']}")
    lines.append("")

    lines.append("Nodes by kind:")
    for kind, count in sorted(stats.get("nodes_by_kind", {}).items()):
        lines.append(f"  {kind:12s}  {count}")
    lines.append("")

    lines.append("Edges by type:")
    for etype, count in sorted(stats.get("edges_by_type", {}).items()):
        lines.append(f"  {etype:15s}  {count}")
    lines.append("")

    top = top_connected(graph, n=5)
    if top:
        lines.append("Top connected nodes:")
        for nid, degree in top:
            node = graph.get_node(nid)
            label = f" ({node.label})" if node and node.label else ""
            lines.append(f"  {nid}{label}  — {degree} edge(s)")
    lines.append("")

    return "\n".join(lines)
