"""Normalized artifact model.

An artifact is the structured (parsed) form of a tool result. It carries:

- the originating tool name
- a stable artifact ``kind`` (e.g. ``nmap.ports``, ``dns.records``)
- the parsed payload (any JSON-serializable structure)
- a confidence value the parser is willing to commit to
- execution provenance (tool exit status / exit code / degraded flag) so
  downstream consumers (reports, AI) can tell a clean run from a partial one
- a back-reference to the raw :class:`drake_x.models.tool_result.ToolResult`
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class Artifact(BaseModel):
    """A normalized artifact derived from one tool result."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    tool_name: str
    kind: str = Field(..., description="Stable artifact kind, e.g. 'nmap.ports'.")
    payload: dict[str, Any] = Field(default_factory=dict)
    confidence: float = Field(default=0.7, ge=0.0, le=1.0)
    notes: list[str] = Field(default_factory=list)

    # Execution provenance — populated by the normalization dispatcher from
    # the originating ToolResult. Lets reports and AI evidence flag artifacts
    # produced from a degraded (e.g. non-zero exit) execution.
    tool_status: str = Field(
        default="ok",
        description="Originating ToolResultStatus value (ok, nonzero, ...).",
    )
    exit_code: int | None = Field(
        default=None,
        description="Originating tool exit code, when known.",
    )
    degraded: bool = Field(
        default=False,
        description="True when the artifact came from a non-clean execution.",
    )

    # Soft link back to the raw output for auditability.
    raw_command: list[str] | None = None
    raw_stdout_excerpt: str | None = None
