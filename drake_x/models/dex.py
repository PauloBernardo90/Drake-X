"""Data models for DEX/APK deep disassembly and semantic extraction.

Every model follows the same conventions as the existing APK/PE/ELF models:

- Pydantic ``BaseModel`` for JSON serialization and validation
- Evidence-oriented fields (source, raw snippet, confidence)
- Frozen sub-models where immutability is expected
- Clean separation between observed evidence and analytic assessment
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from ..utils.ids import new_finding_id


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class DexFindingSeverity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class StringCategory(StrEnum):
    URL = "url"
    IP = "ip"
    DOMAIN = "domain"
    IOC = "ioc"
    CRYPTO = "crypto"
    ENCODED_BLOB = "encoded_blob"
    PHISHING = "phishing"
    PACKAGE_TARGET = "package_target"
    C2_INDICATOR = "c2_indicator"
    FILESYSTEM_PATH = "filesystem_path"
    COMMAND = "command"
    GENERIC = "generic"


class ObfuscationSignal(StrEnum):
    SHORT_IDENTIFIERS = "short_identifiers"
    REFLECTION_ABUSE = "reflection_abuse"
    ENCODED_STRINGS = "encoded_strings"
    MULTI_DEX_SPLITTING = "multi_dex_splitting"
    DYNAMIC_LOADING = "dynamic_loading"
    IDENTIFIER_RENAMING = "identifier_renaming"
    CONTROL_FLOW = "control_flow"
    NATIVE_BRIDGE = "native_bridge"


class SensitiveApiCategory(StrEnum):
    ACCESSIBILITY = "accessibility_service"
    PACKAGE_INSTALLER = "package_installer"
    FILE_PROVIDER = "file_provider"
    WEBVIEW = "webview"
    SMS = "sms"
    TELEPHONY = "telephony"
    DEVICE_ADMIN = "device_admin"
    RUNTIME_EXEC = "runtime_exec"
    DEX_LOADING = "dex_loading"
    REFLECTION = "reflection"
    CRYPTO = "crypto"
    CAMERA = "camera"
    LOCATION = "location"
    CLIPBOARD = "clipboard"
    CONTACTS = "contacts"
    NETWORK = "network"


# ---------------------------------------------------------------------------
# DEX file-level models
# ---------------------------------------------------------------------------


class DexFileInfo(BaseModel):
    """Metadata for a single DEX file within an APK."""

    model_config = ConfigDict(frozen=True)

    filename: str
    path: str
    size: int = 0
    sha256: str = ""
    class_count: int = 0
    method_count: int = 0
    string_count: int = 0
    dex_version: str = ""
    notes: str = ""


class DexClassInfo(BaseModel):
    """Extracted information about a single class from a DEX file."""

    model_config = ConfigDict(frozen=True)

    class_name: str
    source_dex: str = ""
    access_flags: str = ""
    superclass: str = ""
    interfaces: list[str] = Field(default_factory=list)
    method_count: int = 0
    field_count: int = 0
    is_abstract: bool = False
    is_interface: bool = False
    package: str = ""


class DexMethodInfo(BaseModel):
    """Extracted information about a single method."""

    model_config = ConfigDict(frozen=True)

    class_name: str
    method_name: str
    source_dex: str = ""
    access_flags: str = ""
    descriptor: str = ""
    is_native: bool = False
    is_constructor: bool = False
    code_size: int = 0


# ---------------------------------------------------------------------------
# Finding / evidence models
# ---------------------------------------------------------------------------


class DexFinding(BaseModel):
    """A single evidence-based finding from DEX analysis.

    Designed for structured output — every finding carries provenance
    and can be linked to other findings via ``relation_links``.
    """

    finding_id: str = Field(default_factory=new_finding_id)
    source_tool: str = ""
    dex_origin: str = ""
    file_origin: str = ""
    evidence_type: str = ""
    raw_snippet: str = ""
    normalized_interpretation: str = ""
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    severity: DexFindingSeverity = DexFindingSeverity.INFO
    category: str = ""
    tags: list[str] = Field(default_factory=list)
    relation_links: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class SensitiveApiHit(BaseModel):
    """One detected usage of a sensitive Android API."""

    model_config = ConfigDict(frozen=True)

    api_category: SensitiveApiCategory
    api_name: str
    class_name: str = ""
    method_name: str = ""
    source_dex: str = ""
    raw_match: str = ""
    confidence: float = Field(default=0.7, ge=0.0, le=1.0)
    severity: DexFindingSeverity = DexFindingSeverity.MEDIUM
    mitre_attck: list[str] = Field(default_factory=list)
    notes: str = ""


class ClassifiedString(BaseModel):
    """A string extracted from DEX, classified by likely purpose."""

    model_config = ConfigDict(frozen=True)

    value: str
    category: StringCategory = StringCategory.GENERIC
    source_dex: str = ""
    context: str = ""
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    is_potential_ioc: bool = False


class ObfuscationIndicator(BaseModel):
    """One observed obfuscation signal with supporting evidence."""

    signal: ObfuscationSignal
    description: str = ""
    evidence: list[str] = Field(default_factory=list)
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    severity: DexFindingSeverity = DexFindingSeverity.LOW
    affected_dex: list[str] = Field(default_factory=list)


class CallEdge(BaseModel):
    """A single call relationship in the call graph."""

    model_config = ConfigDict(frozen=True)

    caller_class: str
    caller_method: str
    callee_class: str
    callee_method: str
    source_dex: str = ""
    edge_type: Literal["invoke", "reference", "component"] = "invoke"


class PackingIndicator(BaseModel):
    """Indicator of packing or payload distribution across DEX files."""

    model_config = ConfigDict(frozen=True)

    indicator_type: str
    description: str
    evidence: list[str] = Field(default_factory=list)
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    affected_files: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Top-level DEX analysis result
# ---------------------------------------------------------------------------


class DexAnalysisResult(BaseModel):
    """Complete output of DEX deep analysis for one APK.

    Consolidates all DEX files, cross-references, findings, and
    structured evidence into a single serializable container.
    """

    model_config = ConfigDict(arbitrary_types_allowed=True)

    # Multi-DEX inventory
    dex_files: list[DexFileInfo] = Field(default_factory=list)
    total_classes: int = 0
    total_methods: int = 0
    total_strings: int = 0

    # Class and method inventory
    classes: list[DexClassInfo] = Field(default_factory=list)
    methods: list[DexMethodInfo] = Field(default_factory=list)

    # Sensitive API detection
    sensitive_api_hits: list[SensitiveApiHit] = Field(default_factory=list)

    # String analysis
    classified_strings: list[ClassifiedString] = Field(default_factory=list)

    # Obfuscation assessment
    obfuscation_indicators: list[ObfuscationIndicator] = Field(default_factory=list)
    obfuscation_score: float = Field(default=0.0, ge=0.0, le=1.0)

    # Call graph / relations
    call_edges: list[CallEdge] = Field(default_factory=list)

    # Packing / multi-DEX indicators
    packing_indicators: list[PackingIndicator] = Field(default_factory=list)

    # Consolidated findings
    findings: list[DexFinding] = Field(default_factory=list)

    # Android components detected in code
    android_components: dict[str, list[str]] = Field(default_factory=dict)

    # Pipeline metadata
    tools_used: list[str] = Field(default_factory=list)
    tools_skipped: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    analysis_phases_completed: list[str] = Field(default_factory=list)
