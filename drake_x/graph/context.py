"""Graph-aware AI prompt context serializer.

Given an :class:`EvidenceGraph` (or a session ID from which one can be
loaded), produces a compact, deterministic, size-bounded JSON structure
suitable for embedding in an AI prompt.

Design principles:

- **Bounded.** The output never exceeds configurable limits on nodes,
  edges, and total characters so it fits within the LLM context window.
- **Deterministic.** Identical graphs produce identical serializations
  (sorted by node_id, edges by source then target).
- **Structured.** The output is a JSON object, not prose, so the model
  can parse relationships instead of guessing from paragraphs.
- **Faithful.** Only relationships present in the graph appear. No
  edges are invented or implied.

Usage::

    from drake_x.graph.context import serialize_graph_context
    ctx = serialize_graph_context(graph, max_nodes=30)
    # → dict suitable for json.dumps() and prompt embedding
"""

from __future__ import annotations

import json
from typing import Any

from ..models.evidence_graph import EvidenceGraph, EvidenceNode
from .query import neighborhood, top_connected


def serialize_graph_context(
    graph: EvidenceGraph,
    *,
    seed_ids: list[str] | None = None,
    max_nodes: int = 30,
    max_edges: int = 60,
    max_depth: int = 2,
    max_chars: int = 4000,
) -> dict[str, Any]:
    """Serialize a bounded subgraph into a prompt-friendly dict.

    If *seed_ids* is provided, the serialization starts from those nodes
    and expands via BFS. Otherwise the top-connected nodes are used as
    seeds to capture the most informative portion of the graph.

    Returns a dict with keys ``nodes``, ``edges``, ``stats`` — ready for
    ``json.dumps()`` and template interpolation.
    """
    if not graph.nodes:
        return {"nodes": [], "edges": [], "stats": {"total_nodes": 0, "total_edges": 0}}

    if seed_ids:
        sub = neighborhood(
            graph, seed_ids,
            max_depth=max_depth,
            max_nodes=max_nodes,
            max_edges=max_edges,
        )
    else:
        # Use top-connected nodes as seeds to get the densest subgraph.
        top = top_connected(graph, n=min(5, len(graph.nodes)))
        seeds = [nid for nid, _ in top]
        if not seeds:
            seeds = [graph.nodes[0].node_id]
        sub = neighborhood(
            graph, seeds,
            max_depth=max_depth,
            max_nodes=max_nodes,
            max_edges=max_edges,
        )

    # Serialize nodes compactly.
    nodes = []
    for n in sorted(sub.nodes, key=lambda x: x.node_id):
        entry: dict[str, Any] = {
            "id": n.node_id,
            "kind": n.kind.value,
            "label": n.label,
        }
        # Include only the most relevant data fields to stay compact.
        compact_data = _compact_node_data(n)
        if compact_data:
            entry["data"] = compact_data
        nodes.append(entry)

    # Serialize edges compactly.
    edges = []
    for e in sorted(sub.edges, key=lambda x: (x.source_id, x.target_id)):
        edge_entry: dict[str, Any] = {
            "from": e.source_id,
            "to": e.target_id,
            "type": e.edge_type.value,
        }
        if e.confidence < 1.0:
            edge_entry["conf"] = round(e.confidence, 2)
        edges.append(edge_entry)

    result: dict[str, Any] = {
        "nodes": nodes,
        "edges": edges,
        "stats": sub.stats(),
    }

    # Enforce the documented ``max_chars`` contract: the serialized form
    # of the returned dict MUST be <= max_chars. The trimming is staged
    # and deterministic — we never break structure, and we never return
    # a dict whose serialization exceeds the bound.
    result = _enforce_char_budget(result, max_chars=max_chars)

    return result


# ---------------------------------------------------------------------------
# Budget enforcement
# ---------------------------------------------------------------------------


def _serialized_size(obj: dict[str, Any]) -> int:
    """Size of the compact JSON serialization that callers will embed."""
    return len(json.dumps(obj, default=str))


def _enforce_char_budget(
    result: dict[str, Any], *, max_chars: int
) -> dict[str, Any]:
    """Iteratively trim *result* until its JSON serialization fits.

    Trimming order (most-recoverable first):
      1. drop edges from the tail, halving each round
      2. strip non-essential ``data`` on nodes
      3. shorten long labels
      4. drop nodes from the tail, halving each round
      5. last resort: return a minimal stats-only dict

    Each step re-measures. The final returned dict is guaranteed to
    serialize within ``max_chars``. Output stays deterministic because
    we always drop tail items first and sort keys implicitly via the
    already-sorted input produced upstream.
    """
    if _serialized_size(result) <= max_chars:
        return result

    edges = list(result.get("edges", []))
    # --- step 1: halve edges until they're gone or the budget fits ----
    while edges and _serialized_size(result) > max_chars:
        edges = edges[: len(edges) // 2]
        result["edges"] = edges
    if _serialized_size(result) <= max_chars:
        return result

    # --- step 2: strip node data ---------------------------------------
    for node in result.get("nodes", []):
        node.pop("data", None)
    if _serialized_size(result) <= max_chars:
        return result

    # --- step 3: shorten labels ----------------------------------------
    for node in result.get("nodes", []):
        label = node.get("label", "")
        if isinstance(label, str) and len(label) > 24:
            node["label"] = label[:24] + "..."
    if _serialized_size(result) <= max_chars:
        return result

    # --- step 4: drop nodes from the tail, halving each round ----------
    nodes = list(result.get("nodes", []))
    while nodes and _serialized_size(result) > max_chars:
        nodes = nodes[: len(nodes) // 2]
        result["nodes"] = nodes
    if _serialized_size(result) <= max_chars:
        return result

    # --- step 5: last resort — minimal stats-only dict -----------------
    #
    # We guarantee we never exceed the bound, even if the budget is so
    # tight that only a summary fits. ``stats`` may itself be too large;
    # we drop it if necessary and annotate the truncation.
    stats = result.get("stats", {})
    minimal: dict[str, Any] = {
        "nodes": [],
        "edges": [],
        "stats": stats,
        "truncated": True,
    }
    if _serialized_size(minimal) > max_chars:
        minimal["stats"] = {}
    if _serialized_size(minimal) > max_chars:
        minimal = {"truncated": True}
    if _serialized_size(minimal) > max_chars:
        # Absolute fallback: an empty object (``"{}"`` is 2 chars) is
        # the smallest valid JSON dict. For any ``max_chars >= 2`` this
        # satisfies the bound. Smaller budgets are semantically
        # meaningless for prompt context and the caller still gets a
        # valid, parseable dict.
        minimal = {}
    return minimal


def graph_context_to_prompt_json(
    graph: EvidenceGraph,
    **kwargs: Any,
) -> str:
    """Convenience: serialize and return a JSON string for prompt embedding."""
    ctx = serialize_graph_context(graph, **kwargs)
    return json.dumps(ctx, indent=2, default=str)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _compact_node_data(node: EvidenceNode) -> dict[str, Any]:
    """Return a trimmed copy of node.data for prompt embedding."""
    if not node.data:
        return {}
    out: dict[str, Any] = {}
    for k, v in node.data.items():
        if v is None or v == "" or v == [] or v == {}:
            continue
        if isinstance(v, str) and len(v) > 120:
            out[k] = v[:120] + "..."
        elif isinstance(v, list) and len(v) > 5:
            out[k] = v[:5]
        else:
            out[k] = v
    return out
