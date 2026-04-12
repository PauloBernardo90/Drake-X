"""Correlation output schema (v1.0).

A :class:`SampleCorrelation` represents one evidence-backed link between
two sessions (samples) in the workspace. Correlations are produced by
deterministic rules over graph node data — they are observations, not
inferences.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


# Categories of shared evidence Drake-X correlates on. Extend by adding
# a new literal + a matching extractor in correlator.py.
CorrelationBasis = Literal[
    "shared_import",
    "shared_shellcode_prefix",
    "shared_indicator",
    "shared_protection_profile",
    "shared_ioc",
]


class SharedEvidence(BaseModel):
    """One piece of evidence shared between two sessions."""

    model_config = ConfigDict(frozen=True)

    basis: CorrelationBasis
    value: str = Field(description="The shared evidence value (API name, hex prefix, etc.)")
    source_node_ids: list[str] = Field(
        default_factory=list,
        description="Node IDs in the source session that carried this evidence.",
    )
    target_node_ids: list[str] = Field(
        default_factory=list,
        description="Node IDs in the target session that carried this evidence.",
    )


class SampleCorrelation(BaseModel):
    """One evidence-backed correlation between two sessions."""

    model_config = ConfigDict(frozen=True)

    source_session: str
    target_session: str
    shared: list[SharedEvidence] = Field(default_factory=list)
    source_external: bool = False
    target_external: bool = False
    external_shared: bool = False
    score: float = Field(
        default=0.0, ge=0.0, le=1.0,
        description="Deterministic strength based on number and kind of shared evidence.",
    )

    @property
    def total_shared(self) -> int:
        return len(self.shared)


class WorkspaceCorrelationReport(BaseModel):
    """All pairwise correlations discovered in a workspace scan."""

    model_config = ConfigDict(frozen=True)

    correlations: list[SampleCorrelation] = Field(default_factory=list)
    session_count: int = 0
    caveats: list[str] = Field(
        default_factory=lambda: [
            "correlations are observations over shared evidence, not attribution",
            "score is a deterministic count-based heuristic, not a confidence probability",
            "external ingested evidence is excluded from correlation by default",
        ],
    )
