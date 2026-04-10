"""Scan manifest builder.

The manifest is a small JSON document that lists every artifact a session
produced and the metadata required to reproduce it: command line, exit
code, duration, integration version (best-effort).

Operators reading the manifest should be able to answer "what did Drake-X
do here, and could I rerun it?" without opening the SQLite database.
"""

from __future__ import annotations

import json
import platform
from datetime import datetime
from typing import Any

from .. import __version__
from ..models.artifact import Artifact
from ..models.session import Session
from ..models.tool_result import ToolResult
from ..utils.timefmt import isoformat_utc, utcnow


def build_scan_manifest(
    *,
    session: Session,
    tool_results: list[ToolResult],
    artifacts: list[Artifact],
    workspace_name: str,
) -> dict[str, Any]:
    """Build a JSON-serializable manifest of one session."""
    return {
        "manifest_version": 1,
        "drake_x_version": __version__,
        "generated_at": isoformat_utc(utcnow()),
        "workspace": workspace_name,
        "session": {
            "id": session.id,
            "profile": session.profile,
            "status": session.status.value,
            "started_at": _iso(session.started_at),
            "finished_at": _iso(session.finished_at),
            "duration_seconds": session.duration_seconds,
            "target": session.target.model_dump(mode="json"),
            "tools_planned": session.tools_planned,
            "tools_ran": session.tools_ran,
            "tools_skipped": session.tools_skipped,
            "warnings": session.warnings,
            "ai_enabled": session.ai_enabled,
            "ai_model": session.ai_model,
        },
        "timeline": [
            {
                "tool_name": r.tool_name,
                "started_at": _iso(r.started_at),
                "duration_seconds": r.duration_seconds,
                "status": r.status.value,
            }
            for r in sorted(tool_results, key=lambda x: x.started_at)
        ],
        "tool_results": [
            {
                "tool_name": r.tool_name,
                "command": r.command,
                "started_at": _iso(r.started_at),
                "finished_at": _iso(r.finished_at),
                "duration_seconds": r.duration_seconds,
                "exit_code": r.exit_code,
                "status": r.status.value,
                "error_message": r.error_message,
            }
            for r in tool_results
        ],
        "artifacts": [
            {
                "tool_name": a.tool_name,
                "kind": a.kind,
                "confidence": a.confidence,
                "degraded": a.degraded,
                "tool_status": a.tool_status,
                "exit_code": a.exit_code,
                "notes": a.notes,
            }
            for a in artifacts
        ],
        "host": {
            "platform": platform.platform(),
            "python": platform.python_version(),
            "node": platform.node(),
        },
    }


def write_manifest_json(manifest: dict[str, Any]) -> str:
    return json.dumps(manifest, indent=2, default=str, sort_keys=False)


def _iso(dt: datetime | None) -> str | None:
    return isoformat_utc(dt) if dt else None
