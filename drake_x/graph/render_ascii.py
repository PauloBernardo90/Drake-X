"""Terminal-friendly ASCII rendering of Evidence Graphs.

Produces a readable text view for dark-background Kali terminals.
No curses or heavy UI — just formatted text suitable for piping,
redirection, or direct reading.
"""

from __future__ import annotations

from ..models.evidence_graph import EvidenceGraph, EvidenceNode, NodeKind

_KIND_ICON = {
    NodeKind.ARTIFACT: "[ART]",
    NodeKind.FINDING: "[FND]",
    NodeKind.INDICATOR: "[IOC]",
    NodeKind.EVIDENCE: "[EVD]",
    NodeKind.PROTECTION: "[PRT]",
    NodeKind.CAMPAIGN: "[CMP]",
}


def render_ascii(graph: EvidenceGraph) -> str:
    """Render the graph as indented text with edge annotations."""
    if not graph.nodes:
        return "(empty graph)\n"

    lines: list[str] = []
    lines.append(f"Evidence Graph: {len(graph.nodes)} nodes, {len(graph.edges)} edges")
    lines.append("=" * 60)
    lines.append("")

    # Group nodes by kind.
    by_kind: dict[str, list[EvidenceNode]] = {}
    for node in sorted(graph.nodes, key=lambda n: n.node_id):
        by_kind.setdefault(node.kind.value, []).append(node)

    for kind_label in sorted(by_kind):
        nodes = by_kind[kind_label]
        lines.append(f"--- {kind_label.upper()} ({len(nodes)}) ---")
        for node in nodes:
            icon = _KIND_ICON.get(node.kind, "[???]")
            lines.append(f"  {icon} {node.node_id}")
            if node.label:
                lines.append(f"       label: {node.label}")
            if node.domain:
                lines.append(f"       domain: {node.domain}")
            # Show outgoing edges.
            outgoing = graph.edges_from(node.node_id)
            for e in outgoing:
                conf_str = f" (conf={e.confidence:.1f})" if e.confidence < 1.0 else ""
                lines.append(f"       --> [{e.edge_type.value}] {e.target_id}{conf_str}")
            # Show incoming edges.
            incoming = graph.edges_to(node.node_id)
            for e in incoming:
                conf_str = f" (conf={e.confidence:.1f})" if e.confidence < 1.0 else ""
                lines.append(f"       <-- [{e.edge_type.value}] {e.source_id}{conf_str}")
        lines.append("")

    return "\n".join(lines)
