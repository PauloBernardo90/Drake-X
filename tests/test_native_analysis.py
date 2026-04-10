"""Tests for native analysis: Ghidra structured export, JSON parsing, models."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from drake_x.integrations.native.ghidra_headless import analyze_with_structured_export
from drake_x.models.native_analysis import NativeBinaryAnalysis, NativeExport, NativeFunction
from drake_x.normalize.native.ghidra_json import parse_ghidra_json


# --- Model ---

def test_native_analysis_defaults() -> None:
    na = NativeBinaryAnalysis()
    assert na.function_count == 0
    assert na.source_label == "ghidra_structured_export"


def test_native_function_jni() -> None:
    f = NativeFunction(name="Java_com_example_Native_init", is_jni=True)
    assert f.is_jni


# --- JSON parser ---

SAMPLE_GHIDRA_JSON = {
    "metadata": {
        "program_name": "libnative.so",
        "language": "AARCH64:LE:64:v8A",
        "compiler": "default",
        "image_base": "00100000",
        "executable_format": "ELF",
    },
    "functions": [
        {"name": "Java_com_evil_JNI_decrypt", "address": "001000a0", "signature": "undefined Java_com_evil_JNI_decrypt()",
         "is_external": False, "is_thunk": False, "body_size": 128, "callers": ["main"], "callees": ["AES_decrypt"]},
        {"name": "anti_debug_check", "address": "00100200", "signature": "int anti_debug_check(void)",
         "is_external": False, "is_thunk": False, "body_size": 64, "callers": [], "callees": ["ptrace"]},
        {"name": "normal_func", "address": "00100300", "signature": "void normal_func(void)",
         "is_external": False, "is_thunk": False, "body_size": 32, "callers": [], "callees": []},
    ],
    "function_count": 3,
    "strings": [
        {"address": "00200000", "value": "frida-server"},
        {"address": "00200010", "value": "Hello World"},
    ],
    "string_count": 2,
    "imports": [
        {"name": "ptrace", "namespace": "libc"},
        {"name": "AES_decrypt", "namespace": "libcrypto"},
    ],
    "import_count": 2,
    "exports": [
        {"name": "Java_com_evil_JNI_decrypt", "address": "001000a0", "is_jni": True},
        {"name": "JNI_OnLoad", "address": "001000b0", "is_jni": False},
    ],
    "export_count": 2,
}


def test_parse_ghidra_json(tmp_path: Path) -> None:
    p = tmp_path / "libnative.json"
    p.write_text(json.dumps(SAMPLE_GHIDRA_JSON), encoding="utf-8")
    result = parse_ghidra_json(p, binary_path="lib/arm64-v8a/libnative.so")

    assert result.binary_path == "lib/arm64-v8a/libnative.so"
    assert result.architecture == "AARCH64:LE:64:v8A"
    assert result.function_count == 3
    assert result.string_count == 2
    assert result.import_count == 2
    assert result.export_count == 2
    assert len(result.jni_exports) == 1
    assert result.jni_exports[0].name == "Java_com_evil_JNI_decrypt"


def test_parse_ghidra_json_detects_suspicious(tmp_path: Path) -> None:
    p = tmp_path / "libnative.json"
    p.write_text(json.dumps(SAMPLE_GHIDRA_JSON), encoding="utf-8")
    result = parse_ghidra_json(p)
    # anti_debug_check and frida-server should be flagged
    assert any("anti_debug" in s for s in result.suspicious_functions)
    assert any("frida" in s for s in result.suspicious_functions)


def test_parse_missing_file(tmp_path: Path) -> None:
    result = parse_ghidra_json(tmp_path / "nope.json")
    assert result.error is not None
    assert "not found" in result.error


def test_parse_invalid_json(tmp_path: Path) -> None:
    p = tmp_path / "bad.json"
    p.write_text("not json", encoding="utf-8")
    result = parse_ghidra_json(p)
    assert result.error is not None


# --- Ghidra wrapper ---

def test_ghidra_wrapper_unavailable() -> None:
    with patch("drake_x.integrations.native.ghidra_headless.find_analyze_headless", return_value=None):
        result = analyze_with_structured_export(Path("/tmp/fake.so"), Path("/tmp/proj"), Path("/tmp/out.json"))
    assert result.available is False
    assert "not found" in result.error
