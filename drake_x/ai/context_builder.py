"""Graph-aware, bounded context builders for AI tasks (v0.9).

v0.8 tasks stuffed a flat list of observations into prompts. v0.9 moves
retrieval onto the Evidence Graph: the builder picks a seed set of
nodes appropriate to a task, expands a bounded neighborhood, and
serializes the result deterministically.

The builder:

- selects seeds deterministically (no randomness)
- enforces explicit node / edge / character budgets
- records truncation notes when caps are hit
- returns both a :class:`drake_x.ai.tasks.base.TaskContext` and the
  exact ordered list of node IDs that entered the prompt (for audit)

This module is PE-focused for v0.9, but ``build_context`` is generic;
domain-specific seed pickers live in their own functions.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..graph.context import serialize_graph_context
from ..graph.pe_writer import artifact_id as pe_artifact_id
from ..models.evidence_graph import EvidenceGraph, NodeKind
from ..models.pe import PeAnalysisResult
from .tasks.base import TaskContext

# Default budgets. Keep them conservative: Ollama default num_ctx is 2048
# tokens (~6–8 KB of text), and the prompt template plus schema already
# eat ~1 KB. Leaves ~4 KB for graph + flat evidence.
DEFAULT_MAX_NODES = 30
DEFAULT_MAX_EDGES = 60
DEFAULT_MAX_CHARS = 4000
DEFAULT_MAX_EVIDENCE_ITEMS = 12


@dataclass
class BuiltContext:
    """Result of a context build.

    ``task_context`` is what the AI task receives. ``context_node_ids``
    is the sorted ID list the builder actually surfaced in the prompt,
    ready for the audit record. ``truncation_notes`` surfaces any caps
    that bit so downstream components (and ops) can see them.
    """

    task_context: TaskContext
    context_node_ids: list[str]
    truncation_notes: list[str] = field(default_factory=list)


def build_pe_exploit_context(
    *,
    graph: EvidenceGraph,
    pe_result: PeAnalysisResult,
    target_display: str,
    session_id: str | None = None,
    max_nodes: int = DEFAULT_MAX_NODES,
    max_edges: int = DEFAULT_MAX_EDGES,
    max_chars: int = DEFAULT_MAX_CHARS,
    max_evidence_items: int = DEFAULT_MAX_EVIDENCE_ITEMS,
) -> BuiltContext:
    """Build a :class:`TaskContext` for the PE exploit-assessment task.

    Seeds are, in order of priority:

    1. the artifact root node (always present)
    2. all exploit-indicator nodes (most informative)
    3. all protection-interaction nodes
    4. shellcode nodes
    5. high-risk import nodes (risk == "high")

    The neighborhood is then bounded by ``max_nodes`` / ``max_edges``
    in :func:`serialize_graph_context`. Flat evidence is filled from
    the same priority order so that even if the graph is truncated,
    the most important observations still reach the prompt.
    """
    truncation: list[str] = []

    # ----- seed selection (deterministic) ---------------------------------
    sha256 = pe_result.metadata.sha256 or "unknown"
    seeds: list[str] = []

    root = pe_artifact_id(sha256)
    if graph.get_node(root) is not None:
        seeds.append(root)

    # Indicators + protection-interactions (both NodeKind.INDICATOR)
    indicator_nodes = [
        n for n in graph.nodes_by_kind(NodeKind.INDICATOR)
        if n.domain == "pe"
    ]
    seeds.extend(sorted(n.node_id for n in indicator_nodes))

    # Suspected shellcode artifacts (NodeKind.ARTIFACT except root).
    artifact_nodes = [
        n for n in graph.nodes_by_kind(NodeKind.ARTIFACT)
        if n.domain == "pe" and n.node_id != root
    ]
    seeds.extend(sorted(n.node_id for n in artifact_nodes))

    # High-risk imports only — plain EVIDENCE of a section is rarely
    # useful for the model. Filter to risk=="high".
    high_risk_imports = [
        n for n in graph.nodes_by_kind(NodeKind.EVIDENCE)
        if n.domain == "pe" and n.data.get("risk") == "high"
    ]
    seeds.extend(sorted(n.node_id for n in high_risk_imports))

    # Deduplicate while preserving first-seen order.
    seen: set[str] = set()
    deduped_seeds: list[str] = []
    for sid in seeds:
        if sid not in seen:
            seen.add(sid)
            deduped_seeds.append(sid)

    # ----- graph context (bounded) ----------------------------------------
    graph_ctx = serialize_graph_context(
        graph,
        seed_ids=deduped_seeds,
        max_nodes=max_nodes,
        max_edges=max_edges,
        max_chars=max_chars,
    )

    included_ids = sorted({n["id"] for n in graph_ctx.get("nodes", [])})
    total_seed_nodes = len(deduped_seeds)
    if len(included_ids) < total_seed_nodes:
        truncation.append(
            f"graph truncated: {len(included_ids)}/{total_seed_nodes} "
            f"seed nodes retained (max_nodes={max_nodes})"
        )

    # ----- flat evidence (bounded) ----------------------------------------
    evidence = _pe_flat_evidence(pe_result, max_items=max_evidence_items)
    if _pe_flat_evidence_total(pe_result) > max_evidence_items:
        truncation.append(
            f"flat evidence truncated: {len(evidence)}/"
            f"{_pe_flat_evidence_total(pe_result)} items "
            f"(max_evidence_items={max_evidence_items})"
        )

    findings = _pe_flat_findings(pe_result, max_items=max_evidence_items)

    task_context = TaskContext(
        target_display=target_display,
        profile="pe-exploit-assessment",
        session_id=session_id,
        evidence=evidence,
        findings=findings,
        graph_context=graph_ctx,
    )

    return BuiltContext(
        task_context=task_context,
        context_node_ids=included_ids,
        truncation_notes=truncation,
    )


# ---------------------------------------------------------------------------
# Flat evidence extractors (PE)
# ---------------------------------------------------------------------------


def _pe_flat_evidence(
    pe_result: PeAnalysisResult, *, max_items: int
) -> list[dict[str, Any]]:
    """Highest-signal observations in priority order, capped at *max_items*."""
    out: list[dict[str, Any]] = []

    # Exploit indicators first — they're the most targeted evidence.
    for ind in pe_result.exploit_indicators:
        out.append({
            "kind": "exploit_indicator",
            "payload": {
                "type": ind.indicator_type.value,
                "title": ind.title,
                "description": ind.description,
                "severity": ind.severity,
                "confidence": ind.confidence,
                "evidence_refs": list(ind.evidence_refs),
                "mitre_attck": list(ind.mitre_attck),
            },
        })
        if len(out) >= max_items:
            return out

    for pi in pe_result.protection_interactions:
        out.append({
            "kind": "protection_interaction",
            "payload": {
                "protection": pi.protection,
                "enabled": pi.protection_enabled,
                "observed_capability": pi.observed_capability,
                "assessment": pi.interaction_assessment,
                "severity": pi.severity,
                "confidence": pi.confidence,
            },
        })
        if len(out) >= max_items:
            return out

    for sc in pe_result.suspected_shellcode:
        out.append({
            "kind": "suspected_shellcode",
            "payload": {
                "location": sc.source_location,
                "size": sc.size,
                "entropy": sc.entropy,
                "reason": sc.detection_reason,
                "confidence": sc.confidence,
            },
        })
        if len(out) >= max_items:
            return out

    high_risk = [f for f in pe_result.import_risk_findings if f.get("risk") == "high"]
    for f in high_risk:
        out.append({
            "kind": "high_risk_import",
            "payload": {
                "dll": f.get("dll"),
                "function": f.get("function"),
                "category": f.get("category"),
                "attck": f.get("technique_id"),
            },
        })
        if len(out) >= max_items:
            return out

    return out


def _pe_flat_evidence_total(pe_result: PeAnalysisResult) -> int:
    return (
        len(pe_result.exploit_indicators)
        + len(pe_result.protection_interactions)
        + len(pe_result.suspected_shellcode)
        + len([f for f in pe_result.import_risk_findings if f.get("risk") == "high"])
    )


def _pe_flat_findings(
    pe_result: PeAnalysisResult, *, max_items: int
) -> list[dict[str, Any]]:
    """Known structural findings for the prompt's 'findings' slot."""
    out: list[dict[str, Any]] = []
    p = pe_result.protection
    out.append({
        "finding": "protection_status",
        "dep": p.dep_enabled,
        "aslr": p.aslr_enabled,
        "cfg": p.cfg_enabled,
        "safe_seh": p.safe_seh,
    })
    for a in pe_result.anomalies[: max_items - 1]:
        out.append({
            "finding": "pe_anomaly",
            "type": a.anomaly_type,
            "severity": a.severity,
            "description": a.description,
        })
    return out[:max_items]
