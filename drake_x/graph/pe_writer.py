"""Graph-first ingestion of PE static-analysis results (v0.9).

This module makes the Evidence Graph the canonical integration bus for
PE analysis. Given a :class:`PeAnalysisResult`, it produces a populated
:class:`EvidenceGraph` whose node IDs are stable and deterministic, so
that downstream consumers (reports, AI context builder, detection
writers, session diffs) can reference evidence by ID instead of by
reconstructed string keys.

Design rules:

- **Deterministic IDs.** Node IDs are derived from the sample SHA-256
  plus a domain-stable local path. The same analysis ingested twice
  produces identical graphs (enables merge/dedupe and reproducible AI
  context).
- **Additive.** This does not replace :class:`PeAnalysisResult`; it
  writes a parallel graph view whose edges carry the same evidence as
  ``evidence_refs`` on the Pydantic models.
- **Evidence-first.** Every indicator/shellcode/protection-interaction
  node links ``supports``/``derived_from`` to the underlying import,
  section, or protection node that justifies it.

The graph produced here is the input to:

- :mod:`drake_x.ai.context_builder` (subgraph selection for AI tasks)
- :mod:`drake_x.reporting.detection_writer` (YARA / STIX generation)
- future dedupe/merge passes across sessions
"""

from __future__ import annotations

from typing import Any

from ..models.evidence_graph import (
    EdgeType,
    EvidenceEdge,
    EvidenceGraph,
    EvidenceNode,
    NodeKind,
)
from ..models.pe import PeAnalysisResult

_DOMAIN = "pe"


# ---------------------------------------------------------------------------
# Deterministic ID helpers
# ---------------------------------------------------------------------------


def _short_sha(sha256: str) -> str:
    """Short, stable fingerprint for use in node IDs."""
    return sha256[:16] if sha256 else "unknown"


def artifact_id(sha256: str) -> str:
    return f"pe:{_short_sha(sha256)}:artifact"


def section_id(sha256: str, section_name: str, ordinal: int = 0) -> str:
    """Deterministic ID for a PE section node.

    PE files can contain multiple sections with the same name (e.g. two
    ``.text`` sections after an incremental linker pass or a malformed
    sample). Keying only on the name causes the second section to
    silently overwrite the first in the graph's dict-backed node store,
    which is a correctness bug — v0.9 fix keys on *(name, ordinal)*
    where ``ordinal`` is the 0-based section index in the PE section
    table.

    ``ordinal`` defaults to ``0`` so existing callers that look up
    "the first section named X" (including tests) continue to resolve
    correctly when names are unique.
    """
    # Section names may contain NUL or non-printable bytes; normalize.
    safe = "".join(c if c.isalnum() or c in "._-" else "_" for c in section_name)
    return f"pe:{_short_sha(sha256)}:section:{safe or 'unnamed'}:{int(ordinal)}"


def import_id(
    sha256: str, dll: str, function: str, ordinal: int | None = None
) -> str:
    """Deterministic ID for a PE import node.

    Named imports are keyed on ``(dll, function)`` — for any real PE,
    that tuple is unique within the import table. Ordinal-only imports
    (no function name) were previously collapsed onto a single
    ``<dll>:ordinal`` ID, silently discarding every ordinal-only
    import after the first. v0.9 hardening keys ordinal-only imports
    on their ordinal: ``<dll>:ord:<N>``.

    ``ordinal`` is optional and only consulted when ``function`` is
    empty, so existing callers that pass just ``(sha, dll, function)``
    for named imports continue to produce the same IDs.
    """
    safe_dll = dll.lower().replace(" ", "_")
    if function:
        return f"pe:{_short_sha(sha256)}:import:{safe_dll}:{function}"
    # ordinal-only import — disambiguate by ordinal
    ord_key = str(ordinal) if ordinal is not None else "unknown"
    return f"pe:{_short_sha(sha256)}:import:{safe_dll}:ord:{ord_key}"


def protection_id(sha256: str, protection: str) -> str:
    return f"pe:{_short_sha(sha256)}:protection:{protection.lower()}"


def indicator_id(sha256: str, indicator_type: str, index: int) -> str:
    return f"pe:{_short_sha(sha256)}:indicator:{indicator_type}:{index}"


def shellcode_id(sha256: str, offset: int, index: int) -> str:
    return f"pe:{_short_sha(sha256)}:shellcode:{offset:x}:{index}"


def protection_interaction_id(sha256: str, protection: str, index: int) -> str:
    return f"pe:{_short_sha(sha256)}:protection_interaction:{protection.lower()}:{index}"


def ai_assessment_id(sha256: str) -> str:
    return f"pe:{_short_sha(sha256)}:ai_exploit_assessment"


# ---------------------------------------------------------------------------
# Main ingestion
# ---------------------------------------------------------------------------


def build_pe_graph(result: PeAnalysisResult) -> EvidenceGraph:
    """Build a PE-domain Evidence Graph from an analysis result.

    The root node is the analyzed artifact. All other nodes link back to
    it via ``derived_from``. Indicators and protection-interactions
    link to their underlying import/section/protection evidence via
    ``supports``.
    """
    graph = EvidenceGraph()
    sha256 = result.metadata.sha256 or "unknown"

    root_id = artifact_id(sha256)
    graph.add_node(
        EvidenceNode(
            node_id=root_id,
            kind=NodeKind.ARTIFACT,
            domain=_DOMAIN,
            label=f"PE sample {sha256[:12]}",
            data={
                "sha256": sha256,
                "md5": result.metadata.md5,
                "file_type": result.metadata.file_type,
                "file_size": result.metadata.file_size,
                "machine": result.header.machine.value,
                "is_dll": result.header.is_dll,
                "entry_point": result.header.entry_point,
            },
        )
    )

    _ingest_sections(graph, result, root_id)
    _ingest_imports(graph, result, root_id)
    _ingest_protections(graph, result, root_id)
    _ingest_exploit_indicators(graph, result, root_id)
    _ingest_shellcode(graph, result, root_id)
    _ingest_protection_interactions(graph, result, root_id)

    return graph


# ---------------------------------------------------------------------------
# Per-domain ingestion
# ---------------------------------------------------------------------------


def _ingest_sections(graph: EvidenceGraph, result: PeAnalysisResult, root: str) -> None:
    sha = result.metadata.sha256
    for idx, sec in enumerate(result.sections):
        # Key on (name, ordinal) so duplicate section names do not
        # collapse into a single surviving node. See section_id() docstring.
        nid = section_id(sha, sec.name, ordinal=idx)
        graph.add_node(
            EvidenceNode(
                node_id=nid,
                kind=NodeKind.EVIDENCE,
                domain=_DOMAIN,
                label=f"section {sec.name}",
                data={
                    "name": sec.name,
                    "ordinal": idx,
                    "virtual_address": sec.virtual_address,
                    "virtual_size": sec.virtual_size,
                    "raw_size": sec.raw_size,
                    "entropy": sec.entropy,
                    "is_executable": sec.is_executable,
                    "is_writable": sec.is_writable,
                    "characteristics": list(sec.characteristics),
                },
            )
        )
        graph.add_edge(EvidenceEdge(
            source_id=nid,
            target_id=root,
            edge_type=EdgeType.DERIVED_FROM,
            notes="section parsed from PE artifact",
        ))


def _ingest_imports(graph: EvidenceGraph, result: PeAnalysisResult, root: str) -> None:
    sha = result.metadata.sha256
    # Build a risk map first so import nodes can carry risk metadata.
    risk_map: dict[tuple[str, str], dict[str, Any]] = {}
    for f in result.import_risk_findings:
        risk_map[(f.get("dll", ""), f.get("function", ""))] = f

    for imp in result.imports:
        nid = import_id(sha, imp.dll, imp.function, ordinal=imp.ordinal)
        risk = risk_map.get((imp.dll, imp.function))
        data: dict[str, Any] = {
            "dll": imp.dll,
            "function": imp.function,
            "ordinal": imp.ordinal,
        }
        if risk:
            data["risk"] = risk.get("risk")
            data["category"] = risk.get("category")
            if risk.get("technique_id"):
                data["attck"] = risk["technique_id"]
        graph.add_node(
            EvidenceNode(
                node_id=nid,
                kind=NodeKind.EVIDENCE,
                domain=_DOMAIN,
                label=f"import {imp.dll}!{imp.function}",
                data=data,
            )
        )
        graph.add_edge(EvidenceEdge(
            source_id=nid,
            target_id=root,
            edge_type=EdgeType.DERIVED_FROM,
            notes="import parsed from PE import table",
        ))


def _ingest_protections(graph: EvidenceGraph, result: PeAnalysisResult, root: str) -> None:
    sha = result.metadata.sha256
    p = result.protection
    protections = [
        ("DEP", p.dep_enabled),
        ("ASLR", p.aslr_enabled),
        ("CFG", p.cfg_enabled),
        ("SafeSEH", p.safe_seh),
        ("GS", p.stack_cookies),
        ("HighEntropyVA", p.high_entropy_va),
        ("ForceIntegrity", p.force_integrity),
    ]
    for name, enabled in protections:
        nid = protection_id(sha, name)
        graph.add_node(
            EvidenceNode(
                node_id=nid,
                kind=NodeKind.PROTECTION,
                domain=_DOMAIN,
                label=f"protection {name}",
                data={"protection": name, "enabled": bool(enabled)},
            )
        )
        graph.add_edge(EvidenceEdge(
            source_id=nid,
            target_id=root,
            edge_type=EdgeType.DERIVED_FROM,
            notes="protection parsed from PE headers",
        ))


def _ingest_exploit_indicators(
    graph: EvidenceGraph, result: PeAnalysisResult, root: str
) -> None:
    sha = result.metadata.sha256
    for i, ind in enumerate(result.exploit_indicators):
        nid = indicator_id(sha, ind.indicator_type.value, i)
        graph.add_node(
            EvidenceNode(
                node_id=nid,
                kind=NodeKind.INDICATOR,
                domain=_DOMAIN,
                label=ind.title,
                data={
                    "indicator_type": ind.indicator_type.value,
                    "description": ind.description,
                    "severity": ind.severity,
                    "confidence": ind.confidence,
                    "mitre_attck": list(ind.mitre_attck),
                    "requires_dynamic_validation": ind.requires_dynamic_validation,
                    "caveats": list(ind.caveats),
                    "evidence_refs_raw": list(ind.evidence_refs),
                },
            )
        )
        # indicator → artifact
        graph.add_edge(EvidenceEdge(
            source_id=nid,
            target_id=root,
            edge_type=EdgeType.DERIVED_FROM,
            notes="indicator derived from static analysis",
        ))
        # indicator → supporting evidence (imports that match the ref).
        # Matching is deterministic: case-insensitive function-name match.
        for ref in ind.evidence_refs:
            supporting = _find_import_nodes_for_ref(graph, sha, ref)
            for supp_id in supporting:
                graph.add_edge(EvidenceEdge(
                    source_id=supp_id,
                    target_id=nid,
                    edge_type=EdgeType.SUPPORTS,
                    confidence=ind.confidence,
                    notes=f"supporting evidence: {ref}",
                ))


def _ingest_shellcode(graph: EvidenceGraph, result: PeAnalysisResult, root: str) -> None:
    sha = result.metadata.sha256
    for i, sc in enumerate(result.suspected_shellcode):
        nid = shellcode_id(sha, sc.offset, i)
        graph.add_node(
            EvidenceNode(
                node_id=nid,
                kind=NodeKind.ARTIFACT,
                domain=_DOMAIN,
                label=f"suspected shellcode @ {sc.source_location}",
                data={
                    "source_location": sc.source_location,
                    "offset": sc.offset,
                    "size": sc.size,
                    "entropy": sc.entropy,
                    "detection_reason": sc.detection_reason,
                    "confidence": sc.confidence,
                    "preview_hex": sc.preview_hex[:128],
                    "caveats": list(sc.caveats),
                },
            )
        )
        graph.add_edge(EvidenceEdge(
            source_id=nid,
            target_id=root,
            edge_type=EdgeType.DERIVED_FROM,
            notes="shellcode-like blob carved from sample",
        ))
        # Link shellcode to the section(s) it was carved from. When two
        # sections share a name we cannot disambiguate purely from the
        # carver's ``source_location``; linking to every match preserves
        # the evidence rather than silently picking one.
        for sect_nid in _find_section_nodes_by_name(graph, sha, sc.source_location):
            graph.add_edge(EvidenceEdge(
                source_id=sect_nid,
                target_id=nid,
                edge_type=EdgeType.SUPPORTS,
                confidence=sc.confidence,
                notes="shellcode carved from this section",
            ))


def _ingest_protection_interactions(
    graph: EvidenceGraph, result: PeAnalysisResult, root: str
) -> None:
    sha = result.metadata.sha256
    for i, pi in enumerate(result.protection_interactions):
        nid = protection_interaction_id(sha, pi.protection, i)
        graph.add_node(
            EvidenceNode(
                node_id=nid,
                kind=NodeKind.INDICATOR,
                domain=_DOMAIN,
                label=f"interaction {pi.protection}",
                data={
                    "protection": pi.protection,
                    "protection_enabled": pi.protection_enabled,
                    "observed_capability": pi.observed_capability,
                    "interaction_assessment": pi.interaction_assessment,
                    "severity": pi.severity,
                    "confidence": pi.confidence,
                    "caveats": list(pi.caveats),
                },
            )
        )
        graph.add_edge(EvidenceEdge(
            source_id=nid,
            target_id=root,
            edge_type=EdgeType.DERIVED_FROM,
        ))
        # Link to the protection node it concerns.
        prot_node = protection_id(sha, pi.protection)
        if graph.get_node(prot_node) is not None:
            graph.add_edge(EvidenceEdge(
                source_id=prot_node,
                target_id=nid,
                edge_type=EdgeType.SUPPORTS,
                confidence=pi.confidence,
                notes="protection status justifies interaction assessment",
            ))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _find_section_nodes_by_name(
    graph: EvidenceGraph, sha256: str, name: str
) -> list[str]:
    """Return all section-node IDs for this artifact whose data.name matches.

    Deterministic: sorted by node_id. Used to link shellcode artifacts to
    the section(s) they were carved from even when two sections share a
    name.
    """
    if not name:
        return []
    sha_short = _short_sha(sha256)
    prefix = f"pe:{sha_short}:section:"
    matches: list[str] = []
    for node in graph.nodes_by_kind(NodeKind.EVIDENCE):
        if not node.node_id.startswith(prefix):
            continue
        if str(node.data.get("name", "")) == name:
            matches.append(node.node_id)
    return sorted(matches)


def _find_import_nodes_for_ref(
    graph: EvidenceGraph, sha256: str, ref: str
) -> list[str]:
    """Find import-node IDs whose function name matches *ref*.

    ``evidence_refs`` on an :class:`ExploitIndicator` are bare API
    names. We match case-insensitively against the ``function`` field
    of import nodes in this artifact's domain. Order is deterministic
    (sorted node_id).
    """
    needle = ref.strip().lower()
    if not needle:
        return []
    matches: list[str] = []
    sha_short = _short_sha(sha256)
    prefix = f"pe:{sha_short}:import:"
    for node in graph.nodes_by_kind(NodeKind.EVIDENCE):
        if not node.node_id.startswith(prefix):
            continue
        fn = str(node.data.get("function", "")).lower()
        if fn == needle:
            matches.append(node.node_id)
    return sorted(matches)


# ---------------------------------------------------------------------------
# Merge / dedupe scaffolding (v0.9 minimum)
# ---------------------------------------------------------------------------


def merge_graphs(*graphs: EvidenceGraph) -> EvidenceGraph:
    """Merge multiple graphs into one, deduplicating by node_id.

    When two graphs contain nodes with the same ID, the later graph's
    data wins (shallow). Edges are deduplicated by
    ``(source_id, target_id, edge_type)``.
    """
    out = EvidenceGraph()
    seen_edges: set[tuple[str, str, str]] = set()
    for g in graphs:
        for n in g.nodes:
            out.add_node(n)
        for e in g.edges:
            key = (e.source_id, e.target_id, e.edge_type.value)
            if key in seen_edges:
                continue
            seen_edges.add(key)
            out.add_edge(e)
    return out


def dedupe_graph(graph: EvidenceGraph) -> EvidenceGraph:
    """Return a graph with duplicate edges removed.

    Duplicates are edges with identical ``(source, target, type)``.
    The highest-confidence edge wins. Nodes are passed through
    unchanged. This is the v0.9 minimum dedupe pass.
    """
    out = EvidenceGraph()
    for n in graph.nodes:
        out.add_node(n)
    best: dict[tuple[str, str, str], EvidenceEdge] = {}
    for e in graph.edges:
        key = (e.source_id, e.target_id, e.edge_type.value)
        prior = best.get(key)
        if prior is None or e.confidence > prior.confidence:
            best[key] = e
    for e in best.values():
        out.add_edge(e)
    return out
