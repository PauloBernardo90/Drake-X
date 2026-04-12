"""External evidence ingestion model (v1.0).

Evidence produced outside Drake-X (debugger traces, sandbox event
logs, analyst-curated findings, auxiliary tool exports) enters the
platform through this model. Provenance is mandatory — imported
evidence is always distinguishable from Drake-generated evidence.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


TrustLevel = Literal["low", "medium", "high"]
INGESTED_AT_SENTINEL = "1970-01-01T00:00:00+00:00"


class ExternalProvenance(BaseModel):
    """Mandatory provenance block carried on every imported record."""

    model_config = ConfigDict(frozen=True)

    source_tool: str = Field(description="Originating tool / producer identifier.")
    source_file: str = Field(description="Absolute or relative path of the ingested file.")
    ingested_at: str = Field(
        default=INGESTED_AT_SENTINEL,
    )
    adapter: str = Field(description="Drake-X adapter name that produced the record.")
    trust: TrustLevel = "medium"
    notes: str = ""


class ExternalEvidenceRecord(BaseModel):
    """One normalized piece of external evidence.

    Maps cleanly onto a graph node: ``kind`` becomes ``NodeKind``,
    ``data`` becomes the node's data payload, ``provenance`` is
    preserved under the ``data.provenance`` key so downstream consumers
    cannot accidentally treat it as Drake-generated.
    """

    model_config = ConfigDict(frozen=True)

    kind: Literal["finding", "indicator", "evidence", "artifact"] = "evidence"
    label: str = ""
    data: dict[str, Any] = Field(default_factory=dict)
    provenance: ExternalProvenance


class IngestResult(BaseModel):
    """Summary of one ingestion run."""

    session_id: str
    adapter: str
    node_count: int = 0
    edge_count: int = 0
    warnings: list[str] = Field(default_factory=list)
