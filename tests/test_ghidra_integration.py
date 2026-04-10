"""Tests for Ghidra headless integration: wrapper, model, report rendering."""

from __future__ import annotations

import json
from unittest.mock import patch

import pytest

from drake_x.integrations.apk.ghidra import find_analyze_headless, is_available
from drake_x.models.apk import (
    ApkAnalysisResult,
    ApkMetadata,
    GhidraAnalysis,
)
from drake_x.reporting.apk_report_writer import render_apk_json, render_apk_markdown


# ======================================================================
# Ghidra availability detection
# ======================================================================


def test_ghidra_not_available_when_not_installed() -> None:
    with patch("drake_x.integrations.apk.ghidra.shutil.which", return_value=None), \
         patch("drake_x.integrations.apk.ghidra.find_ghidra_home", return_value=None):
        assert is_available() is False


def test_ghidra_available_when_on_path() -> None:
    with patch("drake_x.integrations.apk.ghidra.shutil.which", return_value="/opt/ghidra/support/analyzeHeadless"):
        assert find_analyze_headless() is not None


# ======================================================================
# GhidraAnalysis model
# ======================================================================


def test_ghidra_model_defaults() -> None:
    ga = GhidraAnalysis()
    assert ga.available is False
    assert ga.analyzed_binaries == []
    assert ga.source_label == "ghidra_headless"


def test_ghidra_model_serializes() -> None:
    ga = GhidraAnalysis(
        available=True,
        analyzed_binaries=["lib/arm64-v8a/libnative.so"],
        suspicious_symbols=["decrypt_payload", "anti_debug_check"],
        notes=["Analysis completed in 45s"],
    )
    data = ga.model_dump(mode="json")
    assert data["available"] is True
    assert len(data["analyzed_binaries"]) == 1
    assert "decrypt_payload" in data["suspicious_symbols"]


# ======================================================================
# Report rendering — Ghidra section
# ======================================================================


def _result_with_ghidra() -> ApkAnalysisResult:
    return ApkAnalysisResult(
        metadata=ApkMetadata(
            package_name="com.evil.native",
            sha256="a" * 64,
        ),
        ghidra_analysis=GhidraAnalysis(
            available=True,
            analyzed_binaries=["lib/arm64-v8a/libnative.so", "lib/armeabi-v7a/libnative.so"],
            suspicious_symbols=["decrypt_dex", "check_root", "anti_frida"],
            notes=["2 binaries analyzed successfully"],
        ),
        tools_ran=["aapt", "ghidra"],
    )


def _result_without_ghidra() -> ApkAnalysisResult:
    return ApkAnalysisResult(
        metadata=ApkMetadata(package_name="com.clean.app"),
    )


def _result_ghidra_unavailable() -> ApkAnalysisResult:
    return ApkAnalysisResult(
        metadata=ApkMetadata(package_name="com.test.app"),
        ghidra_analysis=GhidraAnalysis(
            available=False,
            error="Ghidra not installed",
        ),
    )


def test_report_contains_ghidra_section() -> None:
    md = render_apk_markdown(_result_with_ghidra())
    assert "## Ghidra Native Analysis" in md
    assert "static fact" in md
    assert "libnative.so" in md
    assert "decrypt_dex" in md
    assert "check_root" in md


def test_report_ghidra_omitted_when_not_requested() -> None:
    md = render_apk_markdown(_result_without_ghidra())
    assert "Ghidra" not in md


def test_report_ghidra_shows_error_when_unavailable() -> None:
    md = render_apk_markdown(_result_ghidra_unavailable())
    assert "## Ghidra Native Analysis" in md
    assert "unavailable" in md
    assert "Ghidra not installed" in md


def test_json_includes_ghidra() -> None:
    body = render_apk_json(_result_with_ghidra())
    data = json.loads(body)
    assert data["ghidra_analysis"]["available"] is True
    assert len(data["ghidra_analysis"]["analyzed_binaries"]) == 2
    assert "decrypt_dex" in data["ghidra_analysis"]["suspicious_symbols"]


def test_json_ghidra_default_when_not_used() -> None:
    body = render_apk_json(_result_without_ghidra())
    data = json.loads(body)
    assert data["ghidra_analysis"]["available"] is False
    assert data["ghidra_analysis"]["analyzed_binaries"] == []


# ======================================================================
# CLI flag registration
# ======================================================================


def test_ghidra_flag_in_cli() -> None:
    from typer.testing import CliRunner
    from drake_x.cli import app

    runner = CliRunner()
    result = runner.invoke(app, ["apk", "analyze", "--help"])
    assert result.exit_code == 0
    assert "--ghidra" in result.output
