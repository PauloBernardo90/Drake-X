"""Tests for PE normalization: import risk, section anomalies, findings."""

from __future__ import annotations

import pytest

from drake_x.models.pe import (
    PeAnalysisResult,
    PeHeader,
    PeImport,
    PeMachine,
    PeMetadata,
    PeProtectionStatus,
    PeSection,
)
from drake_x.normalize.binary.imports_risk import classify_imports
from drake_x.normalize.binary.section_anomaly import assess_sections
from drake_x.normalize.binary.pe_normalize import pe_result_to_findings


# ---------------------------------------------------------------------------
# Import risk classification
# ---------------------------------------------------------------------------


def test_classify_injection_imports() -> None:
    imports = [
        PeImport(dll="kernel32.dll", function="VirtualAllocEx"),
        PeImport(dll="kernel32.dll", function="WriteProcessMemory"),
        PeImport(dll="kernel32.dll", function="CreateRemoteThread"),
    ]
    risks = classify_imports(imports)
    assert len(risks) == 3
    assert all(r["category"] == "injection" for r in risks)
    assert all(r["risk"] == "high" for r in risks)


def test_classify_mixed_imports() -> None:
    imports = [
        PeImport(dll="kernel32.dll", function="CreateProcessA"),
        PeImport(dll="kernel32.dll", function="GetProcAddress"),
        PeImport(dll="ws2_32.dll", function="connect"),
        PeImport(dll="kernel32.dll", function="ReadFile"),
    ]
    risks = classify_imports(imports)
    categories = {r["category"] for r in risks}
    assert "execution" in categories
    assert "communication" in categories


def test_classify_no_risk_imports() -> None:
    imports = [
        PeImport(dll="kernel32.dll", function="ReadFile"),
        PeImport(dll="kernel32.dll", function="WriteFile"),
        PeImport(dll="kernel32.dll", function="CloseHandle"),
    ]
    risks = classify_imports(imports)
    assert risks == []


def test_classify_deduplicates() -> None:
    imports = [
        PeImport(dll="kernel32.dll", function="VirtualAlloc"),
        PeImport(dll="ntdll.dll", function="VirtualAlloc"),
    ]
    risks = classify_imports(imports)
    assert len(risks) == 1  # same function, deduplicated


# ---------------------------------------------------------------------------
# Section anomaly assessment
# ---------------------------------------------------------------------------


def test_detect_packer_section() -> None:
    sections = [PeSection(name=".upx0", entropy=7.5, is_executable=True)]
    findings = assess_sections(sections)
    packer = [f for f in findings if f["finding_type"] == "packer_section_name"]
    assert len(packer) == 1


def test_detect_high_entropy() -> None:
    sections = [PeSection(name=".text", entropy=7.8)]
    findings = assess_sections(sections)
    high = [f for f in findings if f["finding_type"] == "high_entropy"]
    assert len(high) == 1


def test_detect_multiple_high_entropy() -> None:
    sections = [
        PeSection(name=".text", entropy=7.5),
        PeSection(name=".data", entropy=7.9),
    ]
    findings = assess_sections(sections)
    agg = [f for f in findings if f["finding_type"] == "multiple_high_entropy"]
    assert len(agg) == 1
    assert agg[0]["severity"] == "high"


def test_normal_sections_no_findings() -> None:
    sections = [
        PeSection(name=".text", entropy=6.2, is_executable=True),
        PeSection(name=".data", entropy=3.1, is_writable=True),
        PeSection(name=".rdata", entropy=4.5),
    ]
    findings = assess_sections(sections)
    assert findings == []


# ---------------------------------------------------------------------------
# Full normalization to findings
# ---------------------------------------------------------------------------


def _pe_result_with_risks() -> PeAnalysisResult:
    return PeAnalysisResult(
        metadata=PeMetadata(sha256="b" * 64, file_size=50000),
        header=PeHeader(machine=PeMachine.I386, is_exe=True),
        sections=[
            PeSection(name=".text", entropy=6.5, is_executable=True),
            PeSection(name=".upx0", entropy=7.8, is_executable=True, is_writable=True),
        ],
        imports=[
            PeImport(dll="kernel32.dll", function="VirtualAllocEx"),
            PeImport(dll="kernel32.dll", function="WriteProcessMemory"),
            PeImport(dll="kernel32.dll", function="CreateRemoteThread"),
            PeImport(dll="kernel32.dll", function="CreateProcessA"),
            PeImport(dll="wininet.dll", function="InternetOpenA"),
        ],
        protection=PeProtectionStatus(dep_enabled=False, aslr_enabled=False),
        tools_ran=["pefile"],
    )


def test_pe_findings_include_injection() -> None:
    findings = pe_result_to_findings(_pe_result_with_risks())
    injection = [f for f in findings if "injection" in f.title]
    assert len(injection) >= 1
    assert injection[0].fact_or_inference == "fact"


def test_pe_findings_include_protection_absence() -> None:
    findings = pe_result_to_findings(_pe_result_with_risks())
    aslr = [f for f in findings if "ASLR" in f.title]
    dep = [f for f in findings if "DEP" in f.title]
    assert len(aslr) >= 1
    assert len(dep) >= 1


def test_pe_findings_include_packer() -> None:
    findings = pe_result_to_findings(_pe_result_with_risks())
    packer = [f for f in findings if "packer" in f.title.lower()]
    assert len(packer) >= 1


def test_pe_findings_include_entropy() -> None:
    findings = pe_result_to_findings(_pe_result_with_risks())
    packed = [f for f in findings if "packed" in f.title.lower() or "entropy" in f.title.lower()]
    assert len(packed) >= 1


def test_pe_findings_have_tags() -> None:
    findings = pe_result_to_findings(_pe_result_with_risks())
    for f in findings:
        assert "pe" in f.tags


def test_clean_pe_no_risk_findings() -> None:
    result = PeAnalysisResult(
        metadata=PeMetadata(sha256="c" * 64),
        header=PeHeader(machine=PeMachine.AMD64),
        sections=[PeSection(name=".text", entropy=6.0, is_executable=True)],
        imports=[PeImport(dll="kernel32.dll", function="ReadFile")],
        protection=PeProtectionStatus(dep_enabled=True, aslr_enabled=True, cfg_enabled=True),
    )
    findings = pe_result_to_findings(result)
    # No injection, no packer, protections enabled — minimal findings
    injection = [f for f in findings if "injection" in f.title]
    assert injection == []


# ---------------------------------------------------------------------------
# Capstone availability
# ---------------------------------------------------------------------------


def test_capstone_available() -> None:
    from drake_x.integrations.disasm.capstone_engine import is_available
    assert is_available() is True


def test_disassemble_bytes() -> None:
    from drake_x.integrations.disasm.capstone_engine import disassemble_entry_region
    # x86 NOP sled + RET
    code = b"\x90\x90\x90\xc3"
    instrs = disassemble_entry_region(code, 0x401000, arch="x86", mode="32")
    assert len(instrs) == 4
    assert instrs[0]["mnemonic"] == "nop"
    assert instrs[3]["mnemonic"] == "ret"
