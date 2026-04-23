"""Merge DEX deep analysis results into an existing :class:`EvidenceGraph`.

Adds DEX-specific nodes (DEX files, sensitive APIs, obfuscation signals,
packing indicators, string IoCs, call-graph edges) into the APK evidence
graph, linked to the sample root node.

Node IDs are prefixed with ``dex:`` to avoid collisions with the
``apk:`` prefixed nodes from the base APK graph builder.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from ...models.evidence_graph import (
    EdgeType,
    EvidenceEdge,
    EvidenceGraph,
    EvidenceNode,
    NodeKind,
)

if TYPE_CHECKING:
    from ...models.dex import DexAnalysisResult


def merge_dex_into_evidence_graph(
    graph: EvidenceGraph,
    dex_result: DexAnalysisResult,
    *,
    root_sha256: str = "",
) -> EvidenceGraph:
    """Add DEX deep analysis nodes and edges to an existing evidence graph.

    Parameters
    ----------
    graph:
        The existing APK evidence graph to extend.
    dex_result:
        The DEX analysis result to merge in.
    root_sha256:
        SHA-256 of the APK sample (used to find the root node).

    Returns the same graph object (mutated in place).
    """
    # Find the APK root node to link DEX findings to
    root_id = f"apk:sample:{root_sha256[:12]}" if root_sha256 else ""
    if root_id and not graph.get_node(root_id):
        root_id = ""  # Fallback: don't link if root doesn't exist

    # DEX inventory nodes
    for dex in dex_result.dex_files:
        nid = f"dex:file:{dex.filename}"
        graph.add_node(EvidenceNode(
            node_id=nid,
            kind=NodeKind.ARTIFACT,
            domain="dex",
            label=dex.filename,
            data={
                "size": dex.size,
                "sha256": dex.sha256,
                "class_count": dex.class_count,
                "method_count": dex.method_count,
                "string_count": dex.string_count,
                "dex_version": dex.dex_version,
            },
        ))
        if root_id:
            graph.link(nid, root_id, EdgeType.DERIVED_FROM)

    # Sensitive API hits as finding nodes
    seen_apis: set[str] = set()
    for i, hit in enumerate(dex_result.sensitive_api_hits):
        key = f"{hit.api_category.value}:{hit.api_name}"
        if key in seen_apis:
            continue
        seen_apis.add(key)

        nid = f"dex:api:{i}:{hit.api_category.value}"
        graph.add_node(EvidenceNode(
            node_id=nid,
            kind=NodeKind.FINDING,
            domain="dex",
            label=f"{hit.api_category.value}: {hit.api_name}",
            data={
                "api_name": hit.api_name,
                "category": hit.api_category.value,
                "confidence": hit.confidence,
                "severity": hit.severity.value,
                "mitre_attck": hit.mitre_attck,
                "raw_match": hit.raw_match[:200],
            },
        ))
        if root_id:
            graph.link(nid, root_id, EdgeType.DERIVED_FROM, confidence=hit.confidence)

        # Link to originating DEX file
        dex_node_id = f"dex:file:{hit.source_dex}"
        if graph.get_node(dex_node_id):
            graph.link(nid, dex_node_id, EdgeType.DERIVED_FROM, confidence=hit.confidence)

        # Link API findings to relevant APK permissions
        _link_api_to_permissions(graph, nid, hit.api_category.value)

    # Obfuscation indicators
    for i, ind in enumerate(dex_result.obfuscation_indicators):
        nid = f"dex:obfuscation:{i}:{ind.signal.value}"
        graph.add_node(EvidenceNode(
            node_id=nid,
            kind=NodeKind.EVIDENCE,
            domain="dex",
            label=ind.signal.value,
            data={
                "description": ind.description,
                "confidence": ind.confidence,
                "evidence": ind.evidence[:3],
            },
        ))
        if root_id:
            graph.link(nid, root_id, EdgeType.DERIVED_FROM, confidence=ind.confidence)

        # Link to existing APK obfuscation nodes if they exist
        for existing in graph.nodes:
            if existing.node_id.startswith("apk:obfuscation:"):
                graph.link(nid, existing.node_id, EdgeType.SUPPORTS, confidence=0.6)
                break

    # Packing indicators
    for i, pi in enumerate(dex_result.packing_indicators):
        nid = f"dex:packing:{i}:{pi.indicator_type}"
        graph.add_node(EvidenceNode(
            node_id=nid,
            kind=NodeKind.EVIDENCE,
            domain="dex",
            label=pi.indicator_type,
            data={
                "description": pi.description,
                "confidence": pi.confidence,
                "affected_files": pi.affected_files,
            },
        ))
        if root_id:
            graph.link(nid, root_id, EdgeType.DERIVED_FROM, confidence=pi.confidence)

    # String IoCs as indicator nodes
    ioc_strings = [s for s in dex_result.classified_strings if s.is_potential_ioc]
    for i, cs in enumerate(ioc_strings[:50]):  # cap to avoid graph explosion
        nid = f"dex:string:{i}:{cs.category.value}"
        graph.add_node(EvidenceNode(
            node_id=nid,
            kind=NodeKind.INDICATOR,
            domain="dex",
            label=cs.value[:60],
            data={
                "value": cs.value,
                "category": cs.category.value,
                "confidence": cs.confidence,
                "source_dex": cs.source_dex,
            },
        ))
        if root_id:
            graph.link(nid, root_id, EdgeType.DERIVED_FROM, confidence=cs.confidence)

        # Link C2/URL strings to network-related APK nodes
        if cs.category.value in ("url", "ip", "domain", "c2_indicator"):
            for existing in graph.nodes:
                if existing.node_id.startswith("apk:net:"):
                    graph.link(nid, existing.node_id, EdgeType.RELATED_TO, confidence=0.5)
                    break

    # Obfuscation score as a summary node
    if dex_result.obfuscation_score > 0:
        score_id = "dex:obfuscation_score"
        graph.add_node(EvidenceNode(
            node_id=score_id,
            kind=NodeKind.EVIDENCE,
            domain="dex",
            label=f"Obfuscation score: {dex_result.obfuscation_score:.0%}",
            data={
                "score": dex_result.obfuscation_score,
                "indicator_count": len(dex_result.obfuscation_indicators),
            },
        ))
        if root_id:
            graph.link(score_id, root_id, EdgeType.DERIVED_FROM)

    return graph


def _link_api_to_permissions(
    graph: EvidenceGraph,
    api_node_id: str,
    api_category: str,
) -> None:
    """Link a DEX API finding to related APK permission nodes."""
    # Category → permission keyword mapping
    category_keywords: dict[str, list[str]] = {
        "sms": ["sms"],
        "telephony": ["phone", "call_log"],
        "contacts": ["contacts"],
        "camera": ["camera"],
        "location": ["location"],
        "accessibility_service": ["accessibility"],
    }

    keywords = category_keywords.get(api_category, [])
    if not keywords:
        return

    for node in graph.nodes:
        if not node.node_id.startswith("apk:perm:"):
            continue
        perm_lower = node.node_id.lower()
        if any(kw in perm_lower for kw in keywords):
            graph.link(node.node_id, api_node_id, EdgeType.SUPPORTS, confidence=0.7)
