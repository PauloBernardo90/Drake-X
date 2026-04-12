"""Tests for PE parsing: format detection, parser, models, and CLI."""

from __future__ import annotations

import json
import struct
from pathlib import Path

import pytest

from drake_x.integrations.binary.format_detect import BinaryFormat, detect_format
from drake_x.integrations.binary.pe_parser import is_available as pefile_available
from drake_x.models.pe import (
    PeAnalysisResult,
    PeAnomaly,
    PeExport,
    PeHeader,
    PeImport,
    PeMachine,
    PeMetadata,
    PeProtectionStatus,
    PeSection,
)


# ---------------------------------------------------------------------------
# Format detection
# ---------------------------------------------------------------------------


def test_detect_pe_from_mz_header(tmp_path: Path) -> None:
    """MZ header with valid e_lfanew should be detected as PE."""
    pe_stub = bytearray(256)
    pe_stub[0:2] = b"MZ"
    # e_lfanew at offset 0x3C pointing to 0x80
    struct.pack_into("<I", pe_stub, 0x3C, 0x80)
    # PE signature at 0x80
    pe_stub[0x80:0x84] = b"PE\x00\x00"
    f = tmp_path / "test.exe"
    f.write_bytes(bytes(pe_stub))
    assert detect_format(f) == BinaryFormat.PE


def test_detect_elf_format(tmp_path: Path) -> None:
    f = tmp_path / "test.elf"
    f.write_bytes(b"\x7fELF" + b"\x00" * 60)
    assert detect_format(f) == BinaryFormat.ELF


def test_detect_unknown_format(tmp_path: Path) -> None:
    f = tmp_path / "test.bin"
    f.write_bytes(b"\x00\x00\x00\x00" * 16)
    assert detect_format(f) == BinaryFormat.UNKNOWN


def test_detect_nonexistent_file(tmp_path: Path) -> None:
    assert detect_format(tmp_path / "nope.exe") == BinaryFormat.UNKNOWN


def test_detect_empty_file(tmp_path: Path) -> None:
    f = tmp_path / "empty"
    f.write_bytes(b"")
    assert detect_format(f) == BinaryFormat.UNKNOWN


# ---------------------------------------------------------------------------
# PE models
# ---------------------------------------------------------------------------


def test_pe_analysis_result_defaults() -> None:
    result = PeAnalysisResult()
    assert result.sections == []
    assert result.imports == []
    assert result.exports == []
    assert result.anomalies == []
    assert result.protection.dep_enabled is False


def test_pe_header_model() -> None:
    h = PeHeader(machine=PeMachine.AMD64, entry_point="0x1000", is_exe=True)
    assert h.machine == PeMachine.AMD64
    assert h.is_exe is True
    assert h.is_dll is False


def test_pe_section_model() -> None:
    s = PeSection(name=".text", entropy=6.5, is_executable=True)
    assert s.name == ".text"
    assert s.entropy == 6.5


def test_pe_import_model() -> None:
    i = PeImport(dll="kernel32.dll", function="VirtualAlloc")
    assert i.dll == "kernel32.dll"
    assert i.function == "VirtualAlloc"


def test_pe_protection_model() -> None:
    p = PeProtectionStatus(dep_enabled=True, aslr_enabled=True, cfg_enabled=False)
    assert p.dep_enabled is True
    assert p.cfg_enabled is False


def test_pe_anomaly_model() -> None:
    a = PeAnomaly(
        anomaly_type="high_entropy_section",
        description="Section .upx has entropy 7.9",
        severity="medium",
    )
    assert a.severity == "medium"


def test_pe_analysis_result_serializes() -> None:
    result = PeAnalysisResult(
        metadata=PeMetadata(sha256="a" * 64, file_size=1024),
        header=PeHeader(machine=PeMachine.I386, is_exe=True),
        sections=[PeSection(name=".text", entropy=6.2)],
        imports=[PeImport(dll="kernel32.dll", function="CreateProcessA")],
        anomalies=[PeAnomaly(anomaly_type="test", description="test anomaly")],
    )
    data = json.loads(result.model_dump_json())
    assert data["metadata"]["sha256"] == "a" * 64
    assert data["header"]["machine"] == "i386"
    assert len(data["sections"]) == 1
    assert len(data["imports"]) == 1


# ---------------------------------------------------------------------------
# pefile availability
# ---------------------------------------------------------------------------


def test_pefile_is_available() -> None:
    assert pefile_available() is True


# ---------------------------------------------------------------------------
# CLI registration
# ---------------------------------------------------------------------------


def test_pe_command_registered() -> None:
    from typer.testing import CliRunner
    from drake_x.cli import app

    runner = CliRunner()
    result = runner.invoke(app, ["pe", "--help"])
    assert result.exit_code == 0
    assert "analyze" in result.output
