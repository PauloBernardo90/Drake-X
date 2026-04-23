"""Sandbox execution report — structured evidence output.

Every sandbox run produces a :class:`SandboxReport` containing full
provenance metadata for auditability and reproducibility:

- Run identity (correlation ID, timestamps)
- Sample metadata (path, hash)
- Execution details (command, exit code, timing)
- Isolation status
- Captured output
- Audit observations
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..utils.ids import new_session_id


@dataclass
class SandboxReport:
    """Complete audit record of one sandboxed execution."""

    # Identity
    run_id: str = field(default_factory=lambda: f"sbx-{new_session_id()}")

    # Sample metadata
    sample_path: str = ""
    sample_sha256: str = ""
    sample_size: int = 0

    # Execution details
    backend: str = ""
    command: list[str] = field(default_factory=list)
    network_policy: str = "deny"
    timeout_seconds: int = 0
    workspace_path: str = ""

    # Timing
    started_at: str = ""
    finished_at: str = ""
    duration_seconds: float = 0.0

    # Outcome
    exit_code: int | None = None
    timed_out: bool = False
    status: str = ""
    error: str | None = None

    # Captured output
    stdout: str = ""
    stderr: str = ""

    # Isolation verification
    isolation_verified: bool = False
    isolation_notes: list[str] = field(default_factory=list)

    # Audit trail
    audit_observations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a plain dictionary."""
        return {
            "run_id": self.run_id,
            "sample": {
                "path": self.sample_path,
                "sha256": self.sample_sha256,
                "size": self.sample_size,
            },
            "execution": {
                "backend": self.backend,
                "command": self.command,
                "network_policy": self.network_policy,
                "timeout_seconds": self.timeout_seconds,
                "workspace_path": self.workspace_path,
            },
            "timing": {
                "started_at": self.started_at,
                "finished_at": self.finished_at,
                "duration_seconds": self.duration_seconds,
            },
            "outcome": {
                "exit_code": self.exit_code,
                "timed_out": self.timed_out,
                "status": self.status,
                "error": self.error,
            },
            "output": {
                "stdout": self.stdout,
                "stderr": self.stderr,
            },
            "isolation": {
                "verified": self.isolation_verified,
                "notes": self.isolation_notes,
            },
            "audit": {
                "observations": self.audit_observations,
            },
        }

    def to_json(self, **kwargs: Any) -> str:
        """Serialize to JSON string."""
        return json.dumps(self.to_dict(), indent=2, default=str, **kwargs)

    def write_json(self, path: Path) -> Path:
        """Write the report as JSON to the given path."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self.to_json(), encoding="utf-8")
        return path


def now_utc_iso() -> str:
    """Return current UTC time as ISO 8601 string."""
    return datetime.now(timezone.utc).isoformat(timespec="seconds")
