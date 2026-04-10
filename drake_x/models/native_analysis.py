"""Data models for native binary analysis (Ghidra-derived)."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class NativeFunction(BaseModel):
    """One function extracted from a native binary."""

    name: str = ""
    address: str = ""
    signature: str = ""
    is_external: bool = False
    is_thunk: bool = False
    is_jni: bool = False
    body_size: int = 0
    callers: list[str] = Field(default_factory=list)
    callees: list[str] = Field(default_factory=list)


class NativeString(BaseModel):
    """One defined string from a native binary."""

    address: str = ""
    value: str = ""


class NativeImport(BaseModel):
    """One imported symbol."""

    name: str = ""
    namespace: str = ""


class NativeExport(BaseModel):
    """One exported symbol."""

    name: str = ""
    address: str = ""
    is_jni: bool = False


class NativeBinaryAnalysis(BaseModel):
    """Structured analysis of one native binary (.so)."""

    binary_path: str = ""
    program_name: str = ""
    architecture: str = ""
    executable_format: str = ""

    functions: list[NativeFunction] = Field(default_factory=list)
    strings: list[NativeString] = Field(default_factory=list)
    imports: list[NativeImport] = Field(default_factory=list)
    exports: list[NativeExport] = Field(default_factory=list)

    function_count: int = 0
    string_count: int = 0
    import_count: int = 0
    export_count: int = 0

    jni_exports: list[NativeExport] = Field(default_factory=list)
    suspicious_functions: list[str] = Field(default_factory=list)

    error: str | None = None
    source_label: str = "ghidra_structured_export"
