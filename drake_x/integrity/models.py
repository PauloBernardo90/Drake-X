"""Data models for integrity, provenance, and chain-of-custody.

All models are Pydantic BaseModel for JSON serialization, validation,
and compatibility with the existing Drake-X model ecosystem.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from ..utils.ids import new_session_id


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class CustodyAction(StrEnum):
    """Actions tracked in the chain of custody."""
    INGEST = "ingest"
    STAGE = "stage"
    UNPACK = "unpack"
    DEX_EXTRACT = "dex_extract"
    ANALYZE = "analyze"
    REPORT_GENERATE = "report_generate"
    ARTIFACT_REGISTER = "artifact_register"
    VERIFY = "verify"
    FAIL = "fail"
    EXPORT = "export"


class CustodyStatus(StrEnum):
    OK = "ok"
    FAILED = "failed"
    SKIPPED = "skipped"


class ToolAvailability(StrEnum):
    AVAILABLE = "available"
    UNAVAILABLE = "unavailable"
    UNKNOWN = "unknown"


# ---------------------------------------------------------------------------
# Artifact tracking
# ---------------------------------------------------------------------------


class ArtifactRecord(BaseModel):
    """Integrity record for one artifact in the analysis pipeline.

    Every artifact that matters to the evidence chain gets a record
    with its SHA-256 hash, origin, and relationship to the sample.
    """

    model_config = ConfigDict(frozen=True)

    artifact_id: str = ""
    artifact_type: str = ""           # "apk", "dex", "report_json", "report_md", etc.
    file_name: str = ""
    file_path: str = ""
    sha256: str = ""
    file_size: int = 0
    parent_sha256: str = ""           # SHA-256 of the original sample
    run_id: str = ""
    notes: str = ""
    registered_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds")
    )


# ---------------------------------------------------------------------------
# Chain of custody
# ---------------------------------------------------------------------------


class CustodyEvent(BaseModel):
    """One event in the chain of custody for an analysis run."""

    model_config = ConfigDict(frozen=True)

    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds")
    )
    run_id: str = ""
    action: CustodyAction = CustodyAction.INGEST
    artifact_sha256: str = ""
    actor: str = ""                   # subsystem or tool name
    details: str = ""
    status: CustodyStatus = CustodyStatus.OK


# ---------------------------------------------------------------------------
# Versioning
# ---------------------------------------------------------------------------


class ToolVersionInfo(BaseModel):
    """Version or availability status of one external tool."""

    model_config = ConfigDict(frozen=True)

    tool_name: str = ""
    version: str = ""
    availability: ToolAvailability = ToolAvailability.UNKNOWN
    notes: str = ""


class AnalysisVersionInfo(BaseModel):
    """Complete version snapshot for one analysis execution."""

    drake_x_version: str = ""
    pipeline_version: str = ""
    analysis_profile: str = ""
    tools: list[ToolVersionInfo] = Field(default_factory=list)
    python_version: str = ""


# ---------------------------------------------------------------------------
# Execution context
# ---------------------------------------------------------------------------


class ExecutionContext(BaseModel):
    """Configuration and environment snapshot for one analysis run."""

    run_id: str = Field(default_factory=lambda: f"run-{new_session_id()}")
    sample_sha256: str = ""
    sandbox_enabled: bool = False
    sandbox_backend: str = ""
    network_enabled: bool = False
    timeout_seconds: int = 0
    analysis_mode: str = ""
    profile_name: str = ""
    started_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds")
    )
    finished_at: str = ""
    version_info: AnalysisVersionInfo = Field(default_factory=AnalysisVersionInfo)


# ---------------------------------------------------------------------------
# Integrity report
# ---------------------------------------------------------------------------


class IntegrityReport(BaseModel):
    """Complete integrity and provenance report for one analysis run.

    This is the top-level container that ties together sample identity,
    artifact records, custody chain, versioning, and verification status.
    """

    # Identity
    run_id: str = ""
    sample_sha256: str = ""
    sample_identity: dict[str, Any] = Field(default_factory=dict)

    # Context
    execution_context: ExecutionContext = Field(default_factory=ExecutionContext)
    version_info: AnalysisVersionInfo = Field(default_factory=AnalysisVersionInfo)

    # Artifacts
    artifacts: list[ArtifactRecord] = Field(default_factory=list)

    # Custody chain
    custody_events: list[CustodyEvent] = Field(default_factory=list)

    # Verification
    verified: bool = False
    verification_errors: list[str] = Field(default_factory=list)
    report_sha256: str = ""

    # Metadata
    generated_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds")
    )
