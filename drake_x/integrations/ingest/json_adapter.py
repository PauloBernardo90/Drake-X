"""Generic JSON ingestion adapter (v1.0).

Accepts two shapes:

1. A top-level JSON array of records, each object having at minimum a
   ``kind`` and ``data`` field and an optional ``label``.
2. A top-level object with ``{"records": [...], "source_tool": "...", ...}``
   — the object can carry producer metadata that is propagated into
   the provenance block.

Any record without ``kind`` is skipped silently (adapters do not
invent data). Unknown kinds are mapped to ``evidence``.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ...models.external_evidence import (
    ExternalEvidenceRecord,
    ExternalProvenance,
    TrustLevel,
)
from .base import BaseIngestAdapter, register


_VALID_KINDS = {"finding", "indicator", "evidence", "artifact"}


@register("json")
class JsonIngestAdapter(BaseIngestAdapter):
    """Deterministic JSON adapter."""

    def parse(
        self, path: Path, *, trust: str = "medium"
    ) -> list[ExternalEvidenceRecord]:
        raw = path.read_text(encoding="utf-8")
        doc = json.loads(raw)

        if isinstance(doc, list):
            records_in: list[dict[str, Any]] = doc
            source_tool = "unknown"
            extra_notes = ""
        elif isinstance(doc, dict):
            records_in = doc.get("records", [])
            source_tool = str(doc.get("source_tool", "unknown"))
            extra_notes = str(doc.get("notes", ""))
        else:
            raise ValueError("JSON ingest adapter expects a list or object at the top level")

        trust_level: TrustLevel = trust if trust in ("low", "medium", "high") else "medium"  # type: ignore[assignment]

        out: list[ExternalEvidenceRecord] = []
        for item in records_in:
            if not isinstance(item, dict):
                continue
            kind = str(item.get("kind", "")).lower()
            if kind not in _VALID_KINDS:
                continue
            label = str(item.get("label", "") or "")
            data = dict(item.get("data", {})) if isinstance(item.get("data"), dict) else {}
            prov = ExternalProvenance(
                source_tool=source_tool,
                source_file=str(path),
                adapter="json",
                trust=trust_level,
                notes=extra_notes,
            )
            out.append(ExternalEvidenceRecord(
                kind=kind,  # type: ignore[arg-type]
                label=label,
                data=data,
                provenance=prov,
            ))
        return out
