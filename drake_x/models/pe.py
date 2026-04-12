"""Data models for Windows PE static analysis.

Every model is a Pydantic ``BaseModel`` for JSON serialization and
evidence graph integration. Terminology follows the v0.8 doctrine:

- **observed evidence** — directly extracted by parser
- **analytic assessment** — conclusion with confidence
- **pending confirmation** — hypothesis requiring validation
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class PeMachine(StrEnum):
    I386 = "i386"
    AMD64 = "amd64"
    ARM = "arm"
    ARM64 = "arm64"
    UNKNOWN = "unknown"


class SectionFlag(StrEnum):
    EXECUTABLE = "executable"
    WRITABLE = "writable"
    READABLE = "readable"
    CONTAINS_CODE = "contains_code"
    CONTAINS_DATA = "contains_initialized_data"
    CONTAINS_UDATA = "contains_uninitialized_data"


# ---------------------------------------------------------------------------
# Component models
# ---------------------------------------------------------------------------


class PeHeader(BaseModel):
    """PE optional and file header metadata."""

    model_config = ConfigDict(frozen=True)

    machine: PeMachine = PeMachine.UNKNOWN
    image_base: str = ""
    entry_point: str = ""
    number_of_sections: int = 0
    timestamp: str = ""
    subsystem: str = ""
    dll_characteristics: list[str] = Field(default_factory=list)
    size_of_image: int = 0
    size_of_headers: int = 0
    checksum: str = ""
    linker_version: str = ""
    is_dll: bool = False
    is_exe: bool = False


class PeSection(BaseModel):
    """One PE section with anomaly indicators."""

    model_config = ConfigDict(frozen=True)

    name: str = ""
    virtual_address: str = ""
    virtual_size: int = 0
    raw_size: int = 0
    entropy: float = 0.0
    characteristics: list[str] = Field(default_factory=list)
    is_executable: bool = False
    is_writable: bool = False
    notes: str | None = None


class PeImport(BaseModel):
    """One imported function from a DLL."""

    model_config = ConfigDict(frozen=True)

    dll: str = ""
    function: str = ""
    ordinal: int | None = None
    notes: str | None = None


class PeExport(BaseModel):
    """One exported function."""

    model_config = ConfigDict(frozen=True)

    name: str = ""
    ordinal: int = 0
    address: str = ""


class PeResource(BaseModel):
    """One embedded resource entry."""

    model_config = ConfigDict(frozen=True)

    name: str = ""
    resource_type: str = ""
    language: str = ""
    size: int = 0
    entropy: float = 0.0
    notes: str | None = None


class PeAnomaly(BaseModel):
    """A detected PE structural anomaly."""

    model_config = ConfigDict(frozen=True)

    anomaly_type: str = ""
    description: str = ""
    severity: Literal["info", "low", "medium", "high"] = "info"
    evidence: str = ""


class PeProtectionStatus(BaseModel):
    """Binary-level protection status parsed from PE headers."""

    model_config = ConfigDict(frozen=True)

    dep_enabled: bool = False
    aslr_enabled: bool = False
    cfg_enabled: bool = False
    safe_seh: bool = False
    stack_cookies: bool = False
    high_entropy_va: bool = False
    force_integrity: bool = False
    no_isolation: bool = False
    notes: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Top-level analysis result
# ---------------------------------------------------------------------------


class PeMetadata(BaseModel):
    """Basic PE surface metadata."""

    file_path: str = ""
    file_size: int = 0
    md5: str = ""
    sha256: str = ""
    file_type: str = ""


class PeAnalysisResult(BaseModel):
    """Complete output of one PE static analysis run."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    # Phase 1 — file intake
    metadata: PeMetadata = Field(default_factory=PeMetadata)

    # Phase 2 — PE parsing
    header: PeHeader = Field(default_factory=PeHeader)
    sections: list[PeSection] = Field(default_factory=list)
    imports: list[PeImport] = Field(default_factory=list)
    exports: list[PeExport] = Field(default_factory=list)
    resources: list[PeResource] = Field(default_factory=list)
    anomalies: list[PeAnomaly] = Field(default_factory=list)
    protection: PeProtectionStatus = Field(default_factory=PeProtectionStatus)

    # Phase 3+ — analysis outputs (populated in later phases)
    import_risk_findings: list[dict[str, Any]] = Field(default_factory=list)
    suspicious_patterns: list[dict[str, Any]] = Field(default_factory=list)

    # Metadata
    warnings: list[str] = Field(default_factory=list)
    tools_ran: list[str] = Field(default_factory=list)
    tools_skipped: list[str] = Field(default_factory=list)
