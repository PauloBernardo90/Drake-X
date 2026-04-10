"""Data models for APK static analysis.

Every model in this module is a Pydantic ``BaseModel`` so it serializes
to JSON, integrates with the existing :class:`Finding` / :class:`Artifact`
ecosystem, and round-trips through the SQLite storage layer.

Terminology used throughout:

- **observed evidence** — something the tool or parser directly extracted
- **analytic assessment** — a conclusion the analysis engine drew from
  evidence (always labeled with confidence)
- **pending confirmation** — a hypothesis that requires further
  investigation (dynamic analysis, manual review, etc.)
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from .native_analysis import NativeBinaryAnalysis


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class ComponentType(StrEnum):
    ACTIVITY = "activity"
    SERVICE = "service"
    RECEIVER = "receiver"
    PROVIDER = "provider"


class ProtectionStatus(StrEnum):
    OBSERVED = "observed"
    SUSPECTED = "suspected"
    NOT_OBSERVED = "not_observed"


class ObfuscationConfidence(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NONE = "none"


class CampaignSimilarity(StrEnum):
    CONSISTENT_WITH = "consistent_with"
    SHARES_TRAITS = "shares_traits"
    TENTATIVELY_RESEMBLES = "tentatively_resembles"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"


# ---------------------------------------------------------------------------
# Component-level models
# ---------------------------------------------------------------------------


class ApkPermission(BaseModel):
    """One Android permission declared in the manifest."""

    model_config = ConfigDict(frozen=True)

    name: str
    is_dangerous: bool = False
    is_suspicious: bool = False
    notes: str | None = None


class ApkComponent(BaseModel):
    """One declared Android component (Activity, Service, Receiver, Provider)."""

    model_config = ConfigDict(frozen=True)

    component_type: ComponentType
    name: str
    exported: bool = False
    intent_filters: list[str] = Field(default_factory=list)
    notes: str | None = None


class ApkNativeLib(BaseModel):
    """One native shared library found in the APK."""

    model_config = ConfigDict(frozen=True)

    path: str
    arch: str = ""
    size: int = 0
    notes: str | None = None


class ApkEmbeddedFile(BaseModel):
    """A notable embedded file (secondary dex, jar, zip, encrypted blob)."""

    model_config = ConfigDict(frozen=True)

    path: str
    file_type: str = ""
    size: int = 0
    entropy: float | None = None
    notes: str | None = None


# ---------------------------------------------------------------------------
# Indicator-level models
# ---------------------------------------------------------------------------


class NetworkIndicator(BaseModel):
    """A URL, domain, or IP found during static analysis."""

    model_config = ConfigDict(frozen=True)

    value: str
    indicator_type: Literal["url", "domain", "ip"] = "url"
    context: str = ""
    source_file: str = ""


class BehaviorIndicator(BaseModel):
    """A suspicious code or resource pattern found during static analysis."""

    category: str = ""
    pattern: str = ""
    evidence: str = ""
    source_file: str = ""
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)


class ProtectionIndicator(BaseModel):
    """Evidence of an anti-analysis protection."""

    protection_type: str = ""
    status: ProtectionStatus = ProtectionStatus.NOT_OBSERVED
    evidence: list[str] = Field(default_factory=list)
    analyst_next_steps: str = ""


class ObfuscationTrait(BaseModel):
    """One observed or suspected obfuscation technique."""

    trait: str = ""
    confidence: ObfuscationConfidence = ObfuscationConfidence.NONE
    evidence: list[str] = Field(default_factory=list)
    notes: str = ""


class CampaignAssessment(BaseModel):
    """Similarity assessment against a known campaign category."""

    category: str = ""
    similarity: CampaignSimilarity = CampaignSimilarity.INSUFFICIENT_EVIDENCE
    matching_traits: list[str] = Field(default_factory=list)
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    notes: str = ""


class VtEnrichment(BaseModel):
    """VirusTotal enrichment data for a sample (opt-in, external intel)."""

    available: bool = False
    sha256: str = ""
    detection_ratio: str = ""          # e.g. "42/72"
    detections: int = 0
    total_engines: int = 0
    scan_date: str = ""
    popular_threat_label: str = ""
    suggested_threat_label: str = ""
    tags: list[str] = Field(default_factory=list)
    top_detections: list[dict[str, str]] = Field(default_factory=list)
    error: str | None = None
    source_label: str = "virustotal_v3_api"


class FridaHookTarget(BaseModel):
    """One candidate for Frida dynamic validation — NOT an auto-bypass."""

    target_class: str = ""
    target_method: str = ""
    protection_type: str = ""
    evidence_basis: list[str] = Field(default_factory=list)
    expected_observation: str = ""
    analyst_notes: str = ""
    suggested_validation_objective: str = ""
    priority: Literal["high", "medium", "low"] = "medium"
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)


class GhidraAnalysis(BaseModel):
    """Results from optional Ghidra headless deeper analysis."""

    available: bool = False
    analyzed_binaries: list[str] = Field(default_factory=list)
    function_names: list[str] = Field(default_factory=list)
    suspicious_symbols: list[str] = Field(default_factory=list)
    native_strings: list[str] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)
    error: str | None = None
    source_label: str = "ghidra_headless"


# ---------------------------------------------------------------------------
# Top-level analysis result
# ---------------------------------------------------------------------------


class ApkMetadata(BaseModel):
    """Basic APK surface metadata."""

    file_path: str = ""
    file_size: int = 0
    md5: str = ""
    sha256: str = ""
    file_type: str = ""
    package_name: str = ""
    version_name: str = ""
    version_code: str = ""
    min_sdk: str = ""
    target_sdk: str = ""
    main_activity: str = ""


class ApkAnalysisResult(BaseModel):
    """Complete output of one APK static analysis run.

    This is the top-level container that the analysis engine produces and
    the report writer consumes.
    """

    model_config = ConfigDict(arbitrary_types_allowed=True)

    # Phase 1 — file intake
    metadata: ApkMetadata = Field(default_factory=ApkMetadata)

    # Phase 2 — manifest / surface
    permissions: list[ApkPermission] = Field(default_factory=list)
    components: list[ApkComponent] = Field(default_factory=list)

    # Phase 3 — extraction inventory
    native_libs: list[ApkNativeLib] = Field(default_factory=list)
    embedded_files: list[ApkEmbeddedFile] = Field(default_factory=list)
    extracted_paths: list[str] = Field(default_factory=list)

    # Phase 4 — static behavior
    behavior_indicators: list[BehaviorIndicator] = Field(default_factory=list)
    network_indicators: list[NetworkIndicator] = Field(default_factory=list)

    # Phase 5 — obfuscation
    obfuscation_traits: list[ObfuscationTrait] = Field(default_factory=list)

    # Phase 6 — protections
    protection_indicators: list[ProtectionIndicator] = Field(default_factory=list)

    # Phase 7 — campaign similarity
    campaign_assessments: list[CampaignAssessment] = Field(default_factory=list)

    # VT enrichment (opt-in, external intel)
    vt_enrichment: VtEnrichment = Field(default_factory=VtEnrichment)

    # Frida dynamic validation targets (analyst-assisted, not auto-bypass)
    frida_targets: list[FridaHookTarget] = Field(default_factory=list)

    # Ghidra deeper analysis (opt-in)
    ghidra_analysis: GhidraAnalysis = Field(default_factory=GhidraAnalysis)

    # Structured native binary analysis (Ghidra structured export)
    native_analysis: list[NativeBinaryAnalysis] = Field(default_factory=list)

    # Warnings accumulated during analysis
    warnings: list[str] = Field(default_factory=list)
    tools_ran: list[str] = Field(default_factory=list)
    tools_skipped: list[str] = Field(default_factory=list)
