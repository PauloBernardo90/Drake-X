"""Deterministic cross-sample correlator.

Given a :class:`WorkspaceStorage`, this module loads every persisted
evidence graph, extracts canonical evidence signatures from each, and
emits :class:`SampleCorrelation` records for pairs that share concrete
evidence. Every correlation carries the exact node IDs in both
sessions that produced the match, so analysts can jump straight from
"these samples share X" to "here is where X lives in each sample".

Design:

- **Deterministic.** No randomness, no sampling. Repeated runs over
  the same workspace produce identical output (sorted).
- **Observational.** A correlation is a statement about shared
  evidence, not an inference of shared provenance or intent.
- **Bounded and cheap.** O(N²) in sessions is fine for realistic
  workspaces. If needed, signature-bucket join can replace the naive
  pairwise pass without changing the output schema.

The correlator works entirely against the SQLite-backed evidence
graph; it does not re-run any analysis.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from ..core.storage import WorkspaceStorage
from ..models.correlation import (
    SampleCorrelation,
    SharedEvidence,
    WorkspaceCorrelationReport,
)
from ..models.evidence_graph import EvidenceGraph, NodeKind


@dataclass
class _Signature:
    """Canonical evidence fingerprint extracted from a graph."""

    # map basis → {value: [node_id, ...]}
    by_basis: dict[str, dict[str, list[str]]]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def load_all_graphs(storage: WorkspaceStorage) -> dict[str, EvidenceGraph]:
    """Load every persisted evidence graph in the workspace.

    Returns a dict keyed on session ID. Sessions with no graph are
    silently skipped.
    """
    sessions = storage.legacy.list_sessions(limit=10_000)
    out: dict[str, EvidenceGraph] = {}
    for sess in sessions:
        sid = getattr(sess, "id", None)
        if not sid:
            continue
        graph = storage.load_evidence_graph(sid)
        if graph is not None and graph.nodes:
            out[sid] = graph
    return out


def query_nodes(
    storage: WorkspaceStorage,
    *,
    kind: str | None = None,
    domain: str | None = None,
    label_contains: str | None = None,
    data_contains: str | None = None,
    min_confidence: float | None = None,
) -> list[dict[str, Any]]:
    """Workspace-wide node query.

    Scans every persisted graph and returns matching nodes annotated
    with their owning session ID. Deterministic ordering (session,
    then node_id).
    """
    graphs = load_all_graphs(storage)
    out: list[dict[str, Any]] = []
    needle_label = (label_contains or "").lower()
    needle_data = (data_contains or "").lower()

    for sid in sorted(graphs.keys()):
        for node in sorted(graphs[sid].nodes, key=lambda n: n.node_id):
            if kind and node.kind.value != kind:
                continue
            if domain and node.domain != domain:
                continue
            if needle_label and needle_label not in node.label.lower():
                continue
            if needle_data:
                blob = str(node.data).lower()
                if needle_data not in blob:
                    continue
            if min_confidence is not None:
                conf = node.data.get("confidence")
                if not isinstance(conf, (int, float)) or conf < min_confidence:
                    continue
            out.append({
                "session_id": sid,
                "node_id": node.node_id,
                "kind": node.kind.value,
                "domain": node.domain,
                "label": node.label,
                "data": node.data,
            })
    return out


def correlate_samples(
    storage: WorkspaceStorage,
    *,
    min_shared: int = 1,
) -> WorkspaceCorrelationReport:
    """Compute pairwise evidence-backed correlations across the workspace.

    ``min_shared`` is the minimum number of shared evidence pieces
    required for a correlation to be surfaced; defaults to 1 so any
    real shared signal surfaces. Bump it on crowded workspaces where
    every sample imports ``GetProcAddress``.
    """
    graphs = load_all_graphs(storage)
    signatures = {sid: _extract_signature(g) for sid, g in graphs.items()}

    correlations: list[SampleCorrelation] = []
    ids = sorted(signatures.keys())
    for i, sid_a in enumerate(ids):
        for sid_b in ids[i + 1 :]:
            sig_a = signatures[sid_a]
            sig_b = signatures[sid_b]
            shared = _pair_shared(sig_a, sig_b)
            if len(shared) < min_shared:
                continue
            correlations.append(SampleCorrelation(
                source_session=sid_a,
                target_session=sid_b,
                shared=shared,
                score=_score(shared),
            ))

    correlations.sort(
        key=lambda c: (-c.score, c.source_session, c.target_session)
    )
    return WorkspaceCorrelationReport(
        correlations=correlations,
        session_count=len(graphs),
    )


# ---------------------------------------------------------------------------
# Signature extraction
# ---------------------------------------------------------------------------


def _extract_signature(graph: EvidenceGraph) -> _Signature:
    by_basis: dict[str, dict[str, list[str]]] = {
        "shared_import": {},
        "shared_shellcode_prefix": {},
        "shared_indicator": {},
        "shared_protection_profile": {},
        "shared_ioc": {},
    }

    for node in graph.nodes:
        # Imports — key by dll!function (case-insensitive) for PE + ELF.
        if node.kind == NodeKind.EVIDENCE and (
            node.node_id.count(":import:") == 1
        ):
            dll = str(node.data.get("dll", "")).lower()
            func = str(node.data.get("function", "")).lower()
            if dll and func:
                key = f"{dll}!{func}"
                by_basis["shared_import"].setdefault(key, []).append(node.node_id)

        # Shellcode prefixes — first 16 hex chars of preview.
        if node.kind == NodeKind.ARTIFACT:
            preview = str(node.data.get("preview_hex", ""))
            if preview and len(preview) >= 16:
                prefix = preview[:16].lower()
                by_basis["shared_shellcode_prefix"].setdefault(prefix, []).append(
                    node.node_id
                )

        # Indicators by type+severity — a crude but deterministic cluster key.
        if node.kind == NodeKind.INDICATOR:
            ind_type = str(node.data.get("indicator_type", ""))
            sev = str(node.data.get("severity", ""))
            if ind_type:
                key = f"{ind_type}:{sev}"
                by_basis["shared_indicator"].setdefault(key, []).append(node.node_id)

        # Protection profile — concatenated enabled/disabled summary.
        if node.kind == NodeKind.PROTECTION:
            prot = str(node.data.get("protection", ""))
            state = "on" if node.data.get("enabled") else "off"
            if prot:
                key = f"{prot}:{state}"
                by_basis["shared_protection_profile"].setdefault(key, []).append(
                    node.node_id
                )

        # IOCs — surface URL/IP/domain values from any node's data.
        for iocish in ("url", "ip", "domain", "host"):
            val = node.data.get(iocish)
            if isinstance(val, str) and val:
                by_basis["shared_ioc"].setdefault(val.lower(), []).append(node.node_id)

    # Sort node ID lists for determinism.
    for basis in by_basis:
        for val in by_basis[basis]:
            by_basis[basis][val].sort()

    return _Signature(by_basis=by_basis)


# ---------------------------------------------------------------------------
# Pairing
# ---------------------------------------------------------------------------


def _pair_shared(a: _Signature, b: _Signature) -> list[SharedEvidence]:
    shared: list[SharedEvidence] = []
    for basis, a_map in a.by_basis.items():
        b_map = b.by_basis.get(basis, {})
        if not b_map:
            continue
        common = sorted(set(a_map) & set(b_map))
        for value in common:
            shared.append(SharedEvidence(
                basis=basis,  # type: ignore[arg-type]
                value=value,
                source_node_ids=list(a_map[value]),
                target_node_ids=list(b_map[value]),
            ))
    # Deterministic output order.
    shared.sort(key=lambda s: (s.basis, s.value))
    return shared


def _score(shared: Iterable[SharedEvidence]) -> float:
    """Map a list of shared-evidence items to a 0..1 score.

    Weighting reflects evidence specificity: a shared indicator-type
    cluster is weaker than a shared shellcode prefix. The floor is
    ~0.05 for a single low-specificity overlap; a dense match
    saturates near 0.95.
    """
    weights = {
        "shared_shellcode_prefix": 0.35,
        "shared_ioc": 0.25,
        "shared_import": 0.10,
        "shared_indicator": 0.15,
        "shared_protection_profile": 0.05,
    }
    total = 0.0
    for item in shared:
        total += weights.get(item.basis, 0.05)
    # Smooth saturating transform: 1 - exp(-total)
    import math
    return round(min(0.95, 1.0 - math.exp(-total)), 3)
