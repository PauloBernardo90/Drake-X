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
    """One imported function from a DLL.

    Also used as the unified in-memory representation for .NET
    P/Invokes and MemberRefs. For P/Invokes, ``dll`` is the native
    module and ``function`` is the Win32 API name; ``notes='pinvoke'``
    identifies them. For MemberRefs, ``dll='(managed)'`` and
    ``function`` is the qualified ``Namespace.Type.Member`` string;
    ``notes='member_ref'`` identifies them. This projection keeps the
    downstream risk classifier, evidence graph, and rule baseline
    uniform across native and managed samples.
    """

    model_config = ConfigDict(frozen=True)

    dll: str = ""
    function: str = ""
    ordinal: int | None = None
    notes: str | None = None


class ManagedMetadata(BaseModel):
    """CLR metadata extracted from a .NET PE binary.

    Populated by :mod:`drake_x.integrations.binary.dotnet_parser` when
    the COM descriptor directory is present. For native samples this
    field stays at its default (all-empty) state and participates in
    no downstream computation.
    """

    model_config = ConfigDict(arbitrary_types_allowed=True)

    is_dotnet: bool = False
    runtime_version: str = ""
    il_only: bool = False
    has_strong_name: bool = False
    requires_32bit: bool = False
    entry_point_token: str = ""

    # Metadata tables (flattened)
    assembly_refs: list[dict[str, str]] = Field(default_factory=list)
    type_refs: list[str] = Field(default_factory=list)
    member_refs: list[str] = Field(default_factory=list)
    pinvokes: list[dict[str, str]] = Field(default_factory=list)

    # Heaps
    user_strings: list[str] = Field(default_factory=list)

    # Derived signals
    obfuscator_fingerprints: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


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
# v0.9 — Exploit-Awareness Models
# ---------------------------------------------------------------------------


class ExploitIndicatorType(StrEnum):
    """Categories for exploit-related indicators.

    Each type represents a class of exploit-related signal, not a
    confirmed exploit.
    """

    STACK_CORRUPTION = "stack_corruption"
    CONTROL_FLOW_HIJACK = "control_flow_hijack"
    INJECTION_CHAIN = "injection_chain"
    SHELLCODE_SETUP = "shellcode_setup"
    ROP_INDICATOR = "rop_indicator"
    FORMAT_STRING = "format_string"
    HEAP_MANIPULATION = "heap_manipulation"


class ExploitIndicator(BaseModel):
    """A suspected exploit-related indicator detected by heuristics.

    These are **analytical hypotheses**, not confirmed exploit capability.
    All indicators use conservative language: *suspected*, *potential*,
    *requires validation*.
    """

    model_config = ConfigDict(frozen=True)

    indicator_type: ExploitIndicatorType
    title: str
    description: str
    severity: Literal["info", "low", "medium", "high"] = "medium"
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    evidence_refs: list[str] = Field(
        default_factory=list,
        description="Concrete evidence backing this indicator (API names, section names, patterns).",
    )
    mitre_attck: list[str] = Field(default_factory=list)
    caveats: list[str] = Field(
        default_factory=list,
        description="Explicit uncertainty language: 'suspected', 'requires validation', etc.",
    )
    requires_dynamic_validation: bool = True


class SuspectedShellcodeArtifact(BaseModel):
    """A bounded shellcode-like blob extracted as evidence.

    This is a **suspected** artifact — not a confirmed payload.
    Drake-X does not execute, validate, or weaponize shellcode.
    """

    model_config = ConfigDict(frozen=True)

    source_location: str = Field(
        default="",
        description="Where the blob was found: section name, resource, or overlay.",
    )
    offset: int = 0
    size: int = 0
    entropy: float = 0.0
    detection_reason: str = ""
    confidence: float = Field(default=0.4, ge=0.0, le=1.0)
    preview_hex: str = Field(
        default="",
        description="First N bytes as hex string for triage — never a complete dump.",
    )
    caveats: list[str] = Field(
        default_factory=list,
        description="Always includes 'suspected shellcode-like blob — requires dynamic validation'.",
    )


class BoundedDecodingArtifact(BaseModel):
    """Result of bounded decoding applied to a suspected artifact.

    Decoding is strictly for classification and evidence extraction.
    Decoded output must never be framed as reusable payload.
    """

    model_config = ConfigDict(frozen=True)

    source_artifact: str = Field(
        default="",
        description="Reference to the SuspectedShellcodeArtifact source.",
    )
    decode_method: str = Field(
        default="",
        description="Method used: xor_single, xor_rolling, base64, etc.",
    )
    decoded_size: int = 0
    decoded_entropy: float = 0.0
    classification_hint: str = Field(
        default="",
        description="What the decoded content appears to be: PE header, ELF header, script, unknown.",
    )
    confidence: float = Field(default=0.3, ge=0.0, le=1.0)
    partial: bool = True
    caveats: list[str] = Field(
        default_factory=list,
        description="Always includes 'bounded decoding for classification only — not operational'.",
    )


class ProtectionInteractionAssessment(BaseModel):
    """Analytical assessment of how observed capability interacts with protections.

    This is an **analytic assessment**, not bypass guidance.
    Drake-X does not produce operational bypass steps.
    """

    model_config = ConfigDict(frozen=True)

    protection: str = Field(
        default="",
        description="Protection being assessed: DEP, ASLR, CFG, SafeSEH.",
    )
    protection_enabled: bool = False
    observed_capability: str = Field(
        default="",
        description="What the sample appears to do that relates to this protection.",
    )
    interaction_assessment: str = Field(
        default="",
        description="Analytical conclusion: how the capability interacts with the protection status.",
    )
    severity: Literal["info", "low", "medium", "high"] = "info"
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    caveats: list[str] = Field(
        default_factory=list,
        description="Always includes 'requires dynamic validation'.",
    )


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

    # v0.9 — Exploit-Awareness outputs
    exploit_indicators: list[ExploitIndicator] = Field(default_factory=list)
    suspected_shellcode: list[SuspectedShellcodeArtifact] = Field(default_factory=list)
    bounded_decodings: list[BoundedDecodingArtifact] = Field(default_factory=list)
    protection_interactions: list[ProtectionInteractionAssessment] = Field(default_factory=list)

    # v0.9 — AI exploit assessment (optional; populated when
    # --ai-exploit-assessment is requested and the Ollama runtime is
    # reachable). This is an analytic assessment, NOT operational guidance.
    ai_exploit_assessment: dict[str, Any] | None = None

    # v1.1 — CLR metadata (populated when the sample is a .NET binary).
    # For native samples this stays at its default (is_dotnet=False) and
    # participates in no downstream computation.
    managed: ManagedMetadata = Field(default_factory=ManagedMetadata)

    # v1.2 — printable strings extracted from raw PE bytes (ASCII + UTF-16LE)
    # classified into categories. Empty when the string extractor is not
    # available or the sample is too small.
    strings: list[dict[str, Any]] = Field(default_factory=list)

    # v1.2 — sensitive API names that appear as strings but NOT in the
    # static import table; strong indicator of GetProcAddress-based
    # dynamic resolution used by ransomware and packed malware.
    dynamic_api_resolution: list[dict[str, Any]] = Field(default_factory=list)

    # v0.9 — Graph snapshot (optional). When set, this is a JSON-serialized
    # EvidenceGraph for the PE subgraph. Reports and detection writers
    # may consult it; the canonical in-memory graph lives off the model.
    graph_snapshot: dict[str, Any] | None = None

    # Metadata
    warnings: list[str] = Field(default_factory=list)
    tools_ran: list[str] = Field(default_factory=list)
    tools_skipped: list[str] = Field(default_factory=list)
