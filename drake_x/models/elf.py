"""Data models for ELF static analysis (v1.0).

Designed to mirror the PE model shape so downstream consumers
(reporting, graph writers, correlator) can share code paths without
special-casing format. Parity with PE's exploit-awareness model is
explicitly NOT a v1.0 goal; we ship surface, imports, protections,
and basic findings.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class ElfArch(StrEnum):
    X86 = "x86"
    X86_64 = "x86_64"
    ARM = "arm"
    AARCH64 = "aarch64"
    MIPS = "mips"
    MIPS64 = "mips64"
    RISCV = "riscv"
    UNKNOWN = "unknown"


class ElfHeader(BaseModel):
    model_config = ConfigDict(frozen=True)

    arch: ElfArch = ElfArch.UNKNOWN
    bits: int = 0
    little_endian: bool = True
    file_type: str = "unknown"  # EXEC, DYN, REL, CORE
    entry_point: str = ""
    os_abi: str = ""


class ElfSection(BaseModel):
    model_config = ConfigDict(frozen=True)

    name: str = ""
    size: int = 0
    flags: list[str] = Field(default_factory=list)
    is_executable: bool = False
    is_writable: bool = False


class ElfImport(BaseModel):
    """One imported/unresolved symbol."""

    model_config = ConfigDict(frozen=True)

    library: str = ""       # DT_NEEDED soname or "" when unknown
    symbol: str = ""
    binding: str = ""       # GLOBAL, WEAK, LOCAL
    type: str = ""          # FUNC, OBJECT, ...


class ElfProtection(BaseModel):
    """High-level protection profile parsed from ELF metadata."""

    model_config = ConfigDict(frozen=True)

    nx_enabled: bool = False       # GNU_STACK readable but not executable
    pie_enabled: bool = False      # ET_DYN with PIE semantics
    relro: str = "none"            # "none", "partial", "full"
    canary: bool = False           # __stack_chk_fail / __stack_chk_guard present
    fortify_source: bool = False   # __*_chk functions referenced
    notes: list[str] = Field(default_factory=list)


class ElfMetadata(BaseModel):
    file_path: str = ""
    file_size: int = 0
    md5: str = ""
    sha256: str = ""
    file_type: str = ""


class ElfAnalysisResult(BaseModel):
    """Complete output of one ELF static analysis run."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    metadata: ElfMetadata = Field(default_factory=ElfMetadata)
    header: ElfHeader = Field(default_factory=ElfHeader)
    sections: list[ElfSection] = Field(default_factory=list)
    imports: list[ElfImport] = Field(default_factory=list)
    protection: ElfProtection = Field(default_factory=ElfProtection)

    import_risk_findings: list[dict[str, Any]] = Field(default_factory=list)
    graph_snapshot: dict[str, Any] | None = None

    warnings: list[str] = Field(default_factory=list)
    tools_ran: list[str] = Field(default_factory=list)
    tools_skipped: list[str] = Field(default_factory=list)
