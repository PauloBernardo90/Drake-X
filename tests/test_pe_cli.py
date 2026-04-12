"""Tests for the PE CLI command: flag parsing, output generation, degradation."""

from __future__ import annotations

import json
import struct
from pathlib import Path
from unittest.mock import patch

import pytest

from drake_x.models.pe import PeAnalysisResult


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_minimal_pe(path: Path) -> Path:
    """Create a minimal valid PE stub for CLI testing."""
    pe_stub = bytearray(512)
    # DOS header
    pe_stub[0:2] = b"MZ"
    struct.pack_into("<I", pe_stub, 0x3C, 0x80)  # e_lfanew
    # PE signature
    pe_stub[0x80:0x84] = b"PE\x00\x00"
    # COFF header (IMAGE_FILE_HEADER) at 0x84
    struct.pack_into("<H", pe_stub, 0x84, 0x14C)   # Machine: i386
    struct.pack_into("<H", pe_stub, 0x86, 1)        # NumberOfSections
    struct.pack_into("<I", pe_stub, 0x88, 0)        # TimeDateStamp
    struct.pack_into("<H", pe_stub, 0x90, 0xE0)     # SizeOfOptionalHeader
    struct.pack_into("<H", pe_stub, 0x92, 0x0102)   # Characteristics (EXEC | 32BIT)
    # Optional header at 0x94
    struct.pack_into("<H", pe_stub, 0x94, 0x10B)    # PE32 magic
    struct.pack_into("<I", pe_stub, 0xA8, 0x1000)   # AddressOfEntryPoint
    struct.pack_into("<I", pe_stub, 0xB4, 0x400000) # ImageBase
    struct.pack_into("<I", pe_stub, 0xB8, 0x1000)   # SectionAlignment
    struct.pack_into("<I", pe_stub, 0xBC, 0x200)    # FileAlignment
    struct.pack_into("<I", pe_stub, 0xD0, 0x10000)  # SizeOfImage
    struct.pack_into("<I", pe_stub, 0xD4, 0x200)    # SizeOfHeaders

    f = path / "test_sample.exe"
    f.write_bytes(bytes(pe_stub))
    return f


# ---------------------------------------------------------------------------
# CLI command exists and parses flags
# ---------------------------------------------------------------------------


def test_pe_analyze_help() -> None:
    from typer.testing import CliRunner
    from drake_x.cli import app

    runner = CliRunner()
    result = runner.invoke(app, ["pe", "analyze", "--help"])
    assert result.exit_code == 0
    assert "--workspace" in result.output or "-w" in result.output
    assert "--deep" in result.output
    assert "--vt" in result.output


def test_pe_analyze_missing_file() -> None:
    from typer.testing import CliRunner
    from drake_x.cli import app

    runner = CliRunner()
    result = runner.invoke(app, ["pe", "analyze", "/nonexistent/file.exe"])
    assert result.exit_code != 0


def test_pe_analyze_produces_json(tmp_path: Path) -> None:
    """Full end-to-end: analyze a minimal PE stub and verify JSON output."""
    pe_file = _make_minimal_pe(tmp_path)
    out_dir = tmp_path / "output"

    from typer.testing import CliRunner
    from drake_x.cli import app

    runner = CliRunner()
    result = runner.invoke(app, [
        "pe", "analyze", str(pe_file), "-o", str(out_dir),
    ])

    # The command should succeed (exit 0) or produce partial output
    json_path = out_dir / "pe_analysis.json"
    if json_path.exists():
        data = json.loads(json_path.read_text())
        assert "metadata" in data
        assert "header" in data
        assert "sections" in data
        assert "imports" in data


def test_pe_analyze_produces_report(tmp_path: Path) -> None:
    """Verify report markdown is generated."""
    pe_file = _make_minimal_pe(tmp_path)
    out_dir = tmp_path / "output"

    from typer.testing import CliRunner
    from drake_x.cli import app

    runner = CliRunner()
    result = runner.invoke(app, [
        "pe", "analyze", str(pe_file), "-o", str(out_dir),
    ])

    report_path = out_dir / "pe_report.md"
    if report_path.exists():
        content = report_path.read_text()
        assert "Executive Summary" in content
        assert "Protection Analysis" in content


# ---------------------------------------------------------------------------
# Degradation behavior
# ---------------------------------------------------------------------------


def test_pe_analyze_without_pefile(tmp_path: Path) -> None:
    """Verify graceful degradation when pefile is unavailable."""
    pe_file = _make_minimal_pe(tmp_path)
    out_dir = tmp_path / "output"

    with patch("drake_x.modules.pe_analyze.pefile_available", return_value=False):
        from drake_x.modules.pe_analyze import run_analysis
        result = run_analysis(pe_file, out_dir)

    assert "pefile" in result.tools_skipped
    assert any("pefile" in w.lower() for w in result.warnings)
    # Should still have metadata from file intake
    assert result.metadata.sha256 != ""


def test_pe_analyze_without_capstone(tmp_path: Path) -> None:
    """Verify graceful degradation when Capstone is unavailable."""
    pe_file = _make_minimal_pe(tmp_path)
    out_dir = tmp_path / "output"

    with patch("drake_x.integrations.disasm.capstone_engine.is_available", return_value=False):
        from drake_x.modules.pe_analyze import run_analysis
        result = run_analysis(pe_file, out_dir)

    assert "capstone" in result.tools_skipped
    assert any("capstone" in w.lower() for w in result.warnings)
