"""Tests for suspected shellcode carving (v0.9)."""

from __future__ import annotations

from drake_x.integrations.exploit.shellcode_carver import (
    carve_suspected_shellcode,
    _calculate_entropy,
)
from drake_x.models.pe import PeAnalysisResult, PeSection


def test_heuristic_carving_detects_suspicious_section():
    result = PeAnalysisResult(
        sections=[
            PeSection(name=".text", entropy=5.5, is_executable=True, raw_size=4096),
            PeSection(name=".enc", entropy=7.0, is_executable=True, is_writable=True, raw_size=2048),
        ],
    )
    artifacts = carve_suspected_shellcode(result, pe_data=None)
    assert len(artifacts) >= 1
    assert artifacts[0].source_location == "section:.enc"
    assert any("suspected" in c.lower() for c in artifacts[0].caveats)


def test_heuristic_skips_standard_text_section():
    result = PeAnalysisResult(
        sections=[
            PeSection(name=".text", entropy=7.5, is_executable=True, raw_size=8192),
        ],
    )
    artifacts = carve_suspected_shellcode(result, pe_data=None)
    text_artifacts = [a for a in artifacts if ".text" in a.source_location]
    assert len(text_artifacts) == 0


def test_no_artifacts_for_benign_sections():
    result = PeAnalysisResult(
        sections=[
            PeSection(name=".text", entropy=5.0, is_executable=True, raw_size=4096),
            PeSection(name=".data", entropy=3.0, is_executable=False, raw_size=1024),
            PeSection(name=".rdata", entropy=4.0, is_executable=False, raw_size=512),
        ],
    )
    artifacts = carve_suspected_shellcode(result, pe_data=None)
    assert len(artifacts) == 0


def test_artifacts_bounded_to_max():
    """Ensure output is bounded even with many suspicious sections."""
    sections = [
        PeSection(name=f".s{i}", entropy=7.5, is_executable=True, is_writable=True, raw_size=4096)
        for i in range(20)
    ]
    result = PeAnalysisResult(sections=sections)
    artifacts = carve_suspected_shellcode(result, pe_data=None)
    assert len(artifacts) <= 10  # _MAX_ARTIFACTS


def test_artifacts_use_suspected_language():
    result = PeAnalysisResult(
        sections=[
            PeSection(name=".packed", entropy=7.2, is_executable=True, raw_size=4096),
        ],
    )
    artifacts = carve_suspected_shellcode(result, pe_data=None)
    for art in artifacts:
        has_suspected = any("suspected" in c.lower() for c in art.caveats)
        assert has_suspected, f"Missing 'suspected' in caveats for {art.source_location}"


def test_entropy_calculation():
    # All same byte -> entropy 0
    assert _calculate_entropy(b"\x00" * 256) == 0.0
    # All different bytes -> max entropy ~8
    all_bytes = bytes(range(256))
    ent = _calculate_entropy(all_bytes)
    assert 7.9 < ent <= 8.0
    # Empty -> 0
    assert _calculate_entropy(b"") == 0.0
