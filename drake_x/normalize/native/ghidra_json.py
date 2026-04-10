"""Parse Ghidra structured JSON export into NativeBinaryAnalysis models."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from ...models.native_analysis import (
    NativeBinaryAnalysis,
    NativeExport,
    NativeFunction,
    NativeImport,
    NativeString,
)

_SUSPICIOUS_PATTERNS = re.compile(
    r"decrypt|cipher|obfuscat|anti[_-]?debug|anti[_-]?frida|anti[_-]?root|"
    r"emulat|inject|hook|dex[_-]?load|class[_-]?load|reflect|ptrace|"
    r"su_check|root_check|frida|xposed|magisk|substrate",
    re.IGNORECASE,
)


def parse_ghidra_json(json_path: Path, *, binary_path: str = "") -> NativeBinaryAnalysis:
    """Parse a Ghidra structured JSON export file."""
    if not json_path.exists():
        return NativeBinaryAnalysis(binary_path=binary_path, error="JSON file not found")

    try:
        data = json.loads(json_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        return NativeBinaryAnalysis(binary_path=binary_path, error=str(exc))

    meta = data.get("metadata", {})

    functions = [
        NativeFunction(
            name=f.get("name", ""),
            address=f.get("address", ""),
            signature=f.get("signature", ""),
            is_external=f.get("is_external", False),
            is_thunk=f.get("is_thunk", False),
            body_size=f.get("body_size", 0),
            callers=f.get("callers", []),
            callees=f.get("callees", []),
        )
        for f in data.get("functions", [])
    ]

    strings = [
        NativeString(address=s.get("address", ""), value=s.get("value", ""))
        for s in data.get("strings", [])
    ]

    imports = [
        NativeImport(name=i.get("name", ""), namespace=i.get("namespace", ""))
        for i in data.get("imports", [])
    ]

    exports = [
        NativeExport(
            name=e.get("name", ""),
            address=e.get("address", ""),
            is_jni=e.get("is_jni", False),
        )
        for e in data.get("exports", [])
    ]

    jni_exports = [e for e in exports if e.is_jni]

    suspicious = []
    for func in functions:
        if _SUSPICIOUS_PATTERNS.search(func.name):
            suspicious.append(func.name)
    for s in strings:
        if _SUSPICIOUS_PATTERNS.search(s.value):
            suspicious.append(s.value[:100])

    return NativeBinaryAnalysis(
        binary_path=binary_path,
        program_name=meta.get("program_name", ""),
        architecture=meta.get("language", ""),
        executable_format=meta.get("executable_format", ""),
        functions=functions,
        strings=strings,
        imports=imports,
        exports=exports,
        function_count=data.get("function_count", len(functions)),
        string_count=data.get("string_count", len(strings)),
        import_count=data.get("import_count", len(imports)),
        export_count=data.get("export_count", len(exports)),
        jni_exports=jni_exports,
        suspicious_functions=suspicious[:50],
    )
