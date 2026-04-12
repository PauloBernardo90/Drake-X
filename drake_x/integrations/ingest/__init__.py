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

import datetime as _dt
import hashlib
from pathlib import Path

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


def ingest_file(
    *,
    file: Path,
    adapter_name: str,
    storage,
    session_id: str | None = None,
    trust: str = "medium",
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

    # Merge records into the existing graph if present; otherwise start fresh.
    graph = storage.load_evidence_graph(session_id) or EvidenceGraph()

    # Add a root "ingest" node representing this ingestion run.
    ts = _dt.datetime.now(tz=_dt.timezone.utc).isoformat(timespec="seconds")
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
            "trust": trust,
            "ingested_at": ts,
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

    storage.save_evidence_graph(session_id, graph)

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
