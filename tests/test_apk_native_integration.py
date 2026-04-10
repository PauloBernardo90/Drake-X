"""Tests for APK + native analysis integration.

Verifies that the structured Ghidra export is wired correctly into the
APK analysis pipeline: discovery, normalization, findings, graph, and
report rendering.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from drake_x.models.apk import (
    ApkAnalysisResult,
    ApkMetadata,
    ApkNativeLib,
    GhidraAnalysis,
    ProtectionStatus,
)
from drake_x.models.native_analysis import (
    NativeBinaryAnalysis,
    NativeExport,
    NativeFunction,
    NativeImport,
    NativeString,
)
from drake_x.normalize.apk.bridge import apk_result_to_findings
from drake_x.normalize.apk.graph_builder import build_apk_evidence_graph
from drake_x.reporting.apk_report_writer import render_apk_markdown


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _native_result() -> NativeBinaryAnalysis:
    """A realistic structured native analysis result."""
    return NativeBinaryAnalysis(
        binary_path="lib/arm64-v8a/libnative.so",
        program_name="libnative.so",
        architecture="AARCH64:LE:64:v8A",
        executable_format="ELF",
        functions=[
            NativeFunction(name="Java_com_evil_JNI_decrypt", address="001000a0",
                           signature="undefined Java_com_evil_JNI_decrypt()",
                           body_size=128, callers=["main"], callees=["AES_decrypt"]),
            NativeFunction(name="anti_debug_check", address="00100200",
                           signature="int anti_debug_check(void)",
                           body_size=64, callees=["ptrace"]),
            NativeFunction(name="normal_func", address="00100300",
                           body_size=32),
        ],
        strings=[
            NativeString(address="00200000", value="frida-server"),
            NativeString(address="00200010", value="Hello World"),
        ],
        imports=[
            NativeImport(name="ptrace", namespace="libc"),
            NativeImport(name="AES_decrypt", namespace="libcrypto"),
        ],
        exports=[
            NativeExport(name="Java_com_evil_JNI_decrypt", address="001000a0", is_jni=True),
            NativeExport(name="JNI_OnLoad", address="001000b0"),
        ],
        function_count=3,
        string_count=2,
        import_count=2,
        export_count=2,
        jni_exports=[
            NativeExport(name="Java_com_evil_JNI_decrypt", address="001000a0", is_jni=True),
        ],
        suspicious_functions=["anti_debug_check", "frida-server"],
    )


def _apk_with_native() -> ApkAnalysisResult:
    """An APK result with structured native analysis."""
    return ApkAnalysisResult(
        metadata=ApkMetadata(
            file_path="/tmp/sample.apk",
            file_size=5_000_000,
            md5="d41d8cd98f00b204e9800998ecf8427e",
            sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            package_name="com.example.malware",
            version_name="1.0",
            version_code="1",
        ),
        native_libs=[
            ApkNativeLib(path="lib/arm64-v8a/libnative.so", arch="arm64-v8a", size=50000),
        ],
        ghidra_analysis=GhidraAnalysis(
            available=True,
            analyzed_binaries=["lib/arm64-v8a/libnative.so"],
            suspicious_symbols=["anti_debug_check", "frida-server"],
        ),
        native_analysis=[_native_result()],
        tools_ran=["aapt", "unzip", "ghidra"],
    )


# ---------------------------------------------------------------------------
# Native library discovery
# ---------------------------------------------------------------------------


def test_apk_result_holds_native_analysis() -> None:
    result = _apk_with_native()
    assert len(result.native_analysis) == 1
    assert result.native_analysis[0].architecture == "AARCH64:LE:64:v8A"


def test_empty_native_analysis_default() -> None:
    result = ApkAnalysisResult()
    assert result.native_analysis == []


# ---------------------------------------------------------------------------
# Findings bridge
# ---------------------------------------------------------------------------


def test_native_jni_finding_created() -> None:
    findings = apk_result_to_findings(_apk_with_native())
    jni_findings = [f for f in findings if "JNI" in f.title]
    assert len(jni_findings) == 1
    assert jni_findings[0].fact_or_inference == "fact"
    assert "ghidra" in jni_findings[0].related_tools


def test_native_suspicious_finding_created() -> None:
    findings = apk_result_to_findings(_apk_with_native())
    suspicious_findings = [f for f in findings if "suspicious" in f.title.lower() and "native" in f.title.lower()]
    assert len(suspicious_findings) == 1
    assert suspicious_findings[0].confidence == 0.7
    assert suspicious_findings[0].caveats  # should have analyst verification caveat


def test_no_native_findings_without_analysis() -> None:
    result = ApkAnalysisResult()
    findings = apk_result_to_findings(result)
    native_findings = [f for f in findings if "native" in f.title.lower()]
    assert native_findings == []


# ---------------------------------------------------------------------------
# Evidence graph integration
# ---------------------------------------------------------------------------


def test_graph_includes_native_binary_node() -> None:
    graph = build_apk_evidence_graph(_apk_with_native())
    native_nodes = [n for n in graph.nodes if "native:" in n.node_id and n.kind.value == "artifact"]
    assert len(native_nodes) == 1
    assert native_nodes[0].data["architecture"] == "AARCH64:LE:64:v8A"


def test_graph_includes_jni_indicator() -> None:
    graph = build_apk_evidence_graph(_apk_with_native())
    jni_nodes = [n for n in graph.nodes if "native_jni:" in n.node_id]
    assert len(jni_nodes) == 1
    assert "decrypt" in jni_nodes[0].label.lower()


def test_graph_includes_suspicious_indicator() -> None:
    graph = build_apk_evidence_graph(_apk_with_native())
    suspicious_nodes = [n for n in graph.nodes if "native_suspicious:" in n.node_id]
    assert len(suspicious_nodes) == 2  # anti_debug_check + frida-server


def test_graph_links_native_to_root() -> None:
    graph = build_apk_evidence_graph(_apk_with_native())
    native_nodes = [n for n in graph.nodes if "native:" in n.node_id and n.kind.value == "artifact"]
    assert native_nodes
    edges = graph.edges_from(native_nodes[0].node_id)
    root_edges = [e for e in edges if "sample:" in e.target_id]
    assert len(root_edges) == 1


def test_graph_empty_without_native() -> None:
    result = ApkAnalysisResult(
        metadata=ApkMetadata(sha256="abc123"),
    )
    graph = build_apk_evidence_graph(result)
    native_nodes = [n for n in graph.nodes if "native:" in n.node_id]
    assert native_nodes == []


# ---------------------------------------------------------------------------
# Report rendering
# ---------------------------------------------------------------------------


def test_report_contains_native_overview_table() -> None:
    md = render_apk_markdown(_apk_with_native())
    assert "### Native Analysis Overview" in md
    assert "AARCH64" in md
    assert "libnative.so" in md


def test_report_contains_jni_exports_section() -> None:
    md = render_apk_markdown(_apk_with_native())
    assert "### JNI Exports" in md
    assert "Java_com_evil_JNI_decrypt" in md


def test_report_contains_suspicious_indicators() -> None:
    md = render_apk_markdown(_apk_with_native())
    assert "### Suspicious Native Indicators" in md
    assert "anti_debug_check" in md


def test_report_contains_notable_imports() -> None:
    md = render_apk_markdown(_apk_with_native())
    assert "### Notable Native Imports" in md
    assert "ptrace" in md
    assert "AES_decrypt" in md


def test_report_contains_limitations_section() -> None:
    md = render_apk_markdown(_apk_with_native())
    assert "### Native Analysis Limitations" in md
    assert "analyst verification" in md.lower()


def test_report_ghidra_unavailable() -> None:
    result = ApkAnalysisResult(
        metadata=ApkMetadata(sha256="abc123"),
        ghidra_analysis=GhidraAnalysis(available=False, error="Ghidra not installed"),
    )
    md = render_apk_markdown(result)
    assert "Ghidra not installed" in md


def test_report_no_ghidra_section_when_not_requested() -> None:
    result = ApkAnalysisResult(metadata=ApkMetadata(sha256="abc123"))
    md = render_apk_markdown(result)
    assert "## Ghidra Native Analysis" not in md


# ---------------------------------------------------------------------------
# Graceful degradation
# ---------------------------------------------------------------------------


def test_native_analysis_with_error_does_not_crash() -> None:
    """A NativeBinaryAnalysis with an error should not break findings/graph/report."""
    result = ApkAnalysisResult(
        metadata=ApkMetadata(sha256="abc123", package_name="test"),
        ghidra_analysis=GhidraAnalysis(
            available=True,
            analyzed_binaries=["lib/arm64-v8a/libfail.so"],
        ),
        native_analysis=[
            NativeBinaryAnalysis(
                binary_path="lib/arm64-v8a/libfail.so",
                error="Ghidra analysis timed out",
            ),
        ],
    )
    # Should not raise
    findings = apk_result_to_findings(result)
    graph = build_apk_evidence_graph(result)
    md = render_apk_markdown(result)
    assert "## Ghidra Native Analysis" in md


def test_existing_apk_tests_unaffected() -> None:
    """Verify that a basic ApkAnalysisResult without native data still works."""
    result = ApkAnalysisResult(
        metadata=ApkMetadata(package_name="com.clean.app", sha256="aaa"),
        tools_ran=["aapt"],
    )
    findings = apk_result_to_findings(result)
    graph = build_apk_evidence_graph(result)
    md = render_apk_markdown(result)
    assert "com.clean.app" in md
    # No native sections
    assert "### Native Analysis Overview" not in md


# ---------------------------------------------------------------------------
# CLI smoke test
# ---------------------------------------------------------------------------


def test_apk_command_still_registered() -> None:
    from typer.testing import CliRunner
    from drake_x.cli import app

    runner = CliRunner()
    result = runner.invoke(app, ["apk", "--help"])
    assert result.exit_code == 0
    assert "ghidra" in result.output.lower()
