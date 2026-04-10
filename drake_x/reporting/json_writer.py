"""JSON report writer.

The JSON report is the canonical machine-readable form of a Drake-X
session. Downstream tooling (CI, dashboards, custom triage) should consume
this rather than parse the Markdown.
"""

from __future__ import annotations

import json
from typing import Any

from ..models.artifact import Artifact
from ..models.finding import Finding
from ..models.scope import ScopeAsset
from ..models.session import Session
from ..models.tool_result import ToolResult


def render_json_report(
    *,
    session: Session,
    tool_results: list[ToolResult],
    artifacts: list[Artifact],
    findings: list[Finding],
    scope_in: list[ScopeAsset] | None = None,
    scope_out: list[ScopeAsset] | None = None,
    extras: dict[str, Any] | None = None,
) -> str:
    """Return a UTF-8 JSON string capturing the session, evidence and findings."""
    payload: dict[str, Any] = {
        "schema_version": 2,
        "session": session.model_dump(mode="json"),
        "scope_snapshot": {
            "in_scope": [a.model_dump(mode="json") for a in (scope_in or [])],
            "out_of_scope": [a.model_dump(mode="json") for a in (scope_out or [])],
        },
        "tool_results": [r.model_dump(mode="json") for r in tool_results],
        "artifacts": [a.model_dump(mode="json") for a in artifacts],
        "findings": [f.model_dump(mode="json") for f in findings],
    }
    if extras:
        payload["extras"] = extras
    return json.dumps(payload, indent=2, default=str, sort_keys=False)
