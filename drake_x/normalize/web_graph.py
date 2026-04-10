"""Build an :class:`EvidenceGraph` from web/recon session artifacts and findings.

This is the web-domain counterpart to
:mod:`drake_x.normalize.apk.graph_builder`. It converts standard Drake-X
artifacts and findings from a recon session into a graph that the AI
tasks, ``drake graph show``, and reporting layer can consume.

Node IDs are prefixed with ``web:`` to avoid collisions with APK-domain
nodes in a unified graph.
"""

from __future__ import annotations

from ..models.artifact import Artifact
from ..models.evidence_graph import (
    EdgeType,
    EvidenceGraph,
    EvidenceNode,
    NodeKind,
)
from ..models.finding import Finding
from ..models.session import Session


def build_web_evidence_graph(
    *,
    session: Session,
    artifacts: list[Artifact],
    findings: list[Finding],
) -> EvidenceGraph:
    """Convert a web/recon session into an evidence graph."""
    g = EvidenceGraph()

    # Root node — the session target.
    root_id = f"web:target:{session.target.host}"
    g.add_node(EvidenceNode(
        node_id=root_id,
        kind=NodeKind.ARTIFACT,
        domain="web",
        label=session.target.canonical,
        data={
            "target_type": session.target.target_type,
            "host": session.target.host,
            "profile": session.profile,
        },
    ))

    # Artifact nodes.
    for i, art in enumerate(artifacts):
        aid = f"web:artifact:{i}:{art.kind}"
        g.add_node(EvidenceNode(
            node_id=aid,
            kind=NodeKind.ARTIFACT,
            domain="web",
            label=f"{art.tool_name}:{art.kind}",
            data={
                "tool": art.tool_name,
                "kind": art.kind,
                "confidence": art.confidence,
                "degraded": art.degraded,
            },
        ))
        g.link(aid, root_id, EdgeType.DERIVED_FROM, confidence=art.confidence)

    # Finding nodes.
    for f in findings:
        fid = f"web:finding:{f.id}"
        g.add_node(EvidenceNode(
            node_id=fid,
            kind=NodeKind.FINDING,
            domain="web",
            label=f.title[:60],
            data={
                "severity": f.severity.value,
                "confidence": f.confidence,
                "source": f.source.value,
                "fact_or_inference": f.fact_or_inference,
                "cwe": f.cwe,
                "owasp": f.owasp,
            },
        ))
        g.link(fid, root_id, EdgeType.RELATED_TO)

        # Link findings to the artifacts that support them.
        for ev in f.evidence:
            for i, art in enumerate(artifacts):
                if art.kind == ev.artifact_kind and art.tool_name == ev.tool_name:
                    aid = f"web:artifact:{i}:{art.kind}"
                    g.link(aid, fid, EdgeType.SUPPORTS, confidence=ev.confidence)
                    break

        # Duplicate-of relationships from tags.
        for tag in f.tags:
            if tag.startswith("duplicate-of:"):
                other_id = tag.split(":", 1)[1]
                g.link(fid, f"web:finding:{other_id}", EdgeType.DUPLICATE_OF)

    return g
