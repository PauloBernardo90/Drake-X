"""Consolidated multi-domain case report model (v1.0).

A *case* spans multiple sessions (PE + APK + ELF + imported) in one
workspace. This model is what the writer consumes; it is built by
aggregating persisted evidence graphs and plans from SQLite.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class SessionSummary(BaseModel):
    model_config = ConfigDict(frozen=True)

    session_id: str
    profile: str
    target_display: str
    domain: str = ""          # inferred from graph (pe/apk/elf/external)
    node_count: int = 0
    edge_count: int = 0


class CaseReport(BaseModel):
    """What the consolidated writer renders."""

    model_config = ConfigDict(frozen=True)

    workspace: str
    sessions: list[SessionSummary] = Field(default_factory=list)
    correlations: dict[str, Any] = Field(default_factory=dict)
    validation_plans: dict[str, dict[str, Any]] = Field(default_factory=dict)
    caveats: list[str] = Field(
        default_factory=lambda: [
            "this case report is an aggregation view; specialized PE/APK/ELF reports "
            "remain the authoritative per-session documents",
            "correlations are observational — they track shared evidence, not attribution",
        ],
    )
