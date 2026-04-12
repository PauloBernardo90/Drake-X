"""External evidence ingestion (v1.0).

Adapter registry + top-level ``ingest_file`` entry point.

Writing an adapter:

.. code-block:: python

    from drake_x.integrations.ingest.base import BaseIngestAdapter, register

    @register("my_format")
    class MyAdapter(BaseIngestAdapter):
        name = "my_format"

        def parse(self, path: Path) -> list[ExternalEvidenceRecord]:
            ...

Every record returned by ``parse`` must carry a populated
``provenance`` block (see :mod:`drake_x.models.external_evidence`).
Adapters MUST NOT invent data — they translate source content into
normalized records or skip it.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from ...core.workspace import WORKSPACE_FILE, load_workspace_config_file
from ...graph.pe_writer import dedupe_graph
from ...models.evidence_graph import (
    EdgeType,
    EvidenceEdge,
    EvidenceGraph,
    EvidenceNode,
    NodeKind,
)
from ...models.external_evidence import (
    ExternalEvidenceRecord,
    IngestResult,
)
from .base import BaseIngestAdapter, adapter_registry  # noqa: F401  (re-export)

# Import concrete adapters so they self-register.
from . import json_adapter  # noqa: F401

_TRUST_RANK = {"low": 0, "medium": 1, "high": 2}


def _normalize_trust(value: str | None) -> str:
    val = str(value or "medium").lower()
    return val if val in _TRUST_RANK else "medium"


def _load_producer_registry(storage) -> dict[str, str]:
    cfg_path = Path(storage.db_path).parent / WORKSPACE_FILE
    if not cfg_path.exists():
        return {}
    cfg = load_workspace_config_file(cfg_path)
    return {
        str(source_tool): _normalize_trust(trust)
        for source_tool, trust in cfg.ingest_producers.items()
    }


def _allow_merge_into_analysis(storage) -> bool:
    cfg_path = Path(storage.db_path).parent / WORKSPACE_FILE
    if not cfg_path.exists():
        return False
    cfg = load_workspace_config_file(cfg_path)
    return bool(cfg.allow_ingest_merge_into_analysis)


def _attest_records(
    records: list[ExternalEvidenceRecord],
    *,
    requested_trust: str,
    producer_registry: dict[str, str],
    warnings: list[str],
) -> list[ExternalEvidenceRecord]:
    requested = _normalize_trust(requested_trust)
    out: list[ExternalEvidenceRecord] = []
    warned_downgrades: set[str] = set()

    for rec in records:
        source_tool = rec.provenance.source_tool or "unknown"
        registered = producer_registry.get(source_tool)
        if requested == "high" and registered != "high":
            raise ValueError(
                f"trust=high requires a producer registered at high trust "
                f"(source_tool={source_tool!r})"
            )
        effective = "low"
        if registered is not None:
            effective = min(
                requested,
                registered,
                key=lambda level: _TRUST_RANK[level],
            )
        if effective != requested and source_tool not in warned_downgrades:
            warnings.append(
                f"producer {source_tool!r} not attested for requested trust "
                f"{requested}; effective trust downgraded to {effective}"
            )
            warned_downgrades.add(source_tool)
        prov = rec.provenance.model_copy(update={
            "trust": effective,
            "requested_trust": requested,
            "attested": registered is not None,
            "registry_trust": registered,
        })
        out.append(rec.model_copy(update={"provenance": prov}))
    return out


def ingest_file(
    *,
    file: Path,
    adapter_name: str,
    storage,
    session_id: str | None = None,
    trust: str = "medium",
    allow_merge_into_analysis: bool = False,
) -> IngestResult:
    """Run an adapter over *file* and persist results to the workspace.

    A fresh session is created when ``session_id`` is omitted. Records
    are materialized as graph nodes with provenance preserved under
    ``node.data['provenance']`` so every imported record remains
    distinguishable from Drake-generated evidence.
    """
    registry = adapter_registry()
    adapter_cls = registry[adapter_name]
    adapter = adapter_cls()

    records = adapter.parse(Path(file), trust=trust)
    warnings: list[str] = []
    producer_registry = _load_producer_registry(storage)
    records = _attest_records(
        records,
        requested_trust=trust,
        producer_registry=producer_registry,
        warnings=warnings,
    )

    # Resolve or create a session.
    if session_id is None:
        from ...models.session import Session, SessionStatus
        from ...models.target import Target

        target = Target(
            raw=str(file), canonical=str(file),
            target_type="domain", host=Path(file).name or "external",
        )
        sess = Session(
            profile="ingest",
            target=target,
            status=SessionStatus.COMPLETED,
        )
        storage.legacy.save_session(sess)
        session_id = sess.id
    else:
        existing = storage.legacy.load_session(session_id)
        if existing is None:
            raise ValueError(f"session not found: {session_id}")
        profile = str(getattr(existing, "profile", "") or "")
        if profile != "ingest" and not allow_merge_into_analysis:
            raise ValueError(
                "refusing to merge external evidence into a non-ingest session without "
                "--merge-into-analysis"
            )
        if profile != "ingest" and allow_merge_into_analysis and not _allow_merge_into_analysis(storage):
            raise ValueError(
                "merge into analysis sessions is disabled by workspace ingest policy "
                "(release default); enable allow_merge_into_analysis in workspace.toml "
                "to permit this unsafe operation"
            )

    # Merge records into the existing graph if present; otherwise start fresh.
    graph = storage.load_evidence_graph(session_id) or EvidenceGraph()

    # Add a root "ingest" node representing this ingestion run.
    file_hash = hashlib.sha256(Path(file).read_bytes()).hexdigest()[:16]
    ingest_root_id = f"ingest:{adapter_name}:{session_id}:{file_hash}"
    graph.add_node(EvidenceNode(
        node_id=ingest_root_id,
        kind=NodeKind.ARTIFACT,
        domain="external",
        label=f"ingest[{adapter_name}] {Path(file).name}",
        data={
            "adapter": adapter_name,
            "source_file": str(file),
            "requested_trust": _normalize_trust(trust),
            "trust": (
                records[0].provenance.trust
                if records and len({r.provenance.trust for r in records}) == 1
                else "mixed"
            ),
            "attested_producers": sorted({
                r.provenance.source_tool
                for r in records
                if r.provenance.attested
            }),
            "external": True,  # marker: this is imported, not Drake-generated
        },
    ))

    node_count = 1
    edge_count = 0
    for i, rec in enumerate(records):
        nid = f"ext:{adapter_name}:{session_id}:{i}"
        data = dict(rec.data)
        # Preserve provenance on every node — non-negotiable.
        data["provenance"] = rec.provenance.model_dump()
        data["external"] = True
        graph.add_node(EvidenceNode(
            node_id=nid,
            kind=NodeKind(rec.kind),
            domain="external",
            label=rec.label or rec.kind,
            data=data,
        ))
        graph.add_edge(EvidenceEdge(
            source_id=nid,
            target_id=ingest_root_id,
            edge_type=EdgeType.DERIVED_FROM,
            notes="imported via external ingestion",
        ))
        node_count += 1
        edge_count += 1

    storage.save_evidence_graph(session_id, dedupe_graph(graph))

    return IngestResult(
        session_id=session_id,
        adapter=adapter_name,
        node_count=node_count,
        edge_count=edge_count,
        warnings=warnings,
    )


__all__ = [
    "BaseIngestAdapter",
    "adapter_registry",
    "ingest_file",
]
