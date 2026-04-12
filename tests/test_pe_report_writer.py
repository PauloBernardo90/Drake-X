"""Tests for PE report writer."""

from __future__ import annotations

import json

from drake_x.models.pe import (
    PeAnalysisResult,
    PeAnomaly,
    PeHeader,
    PeImport,
    PeMachine,
    PeMetadata,
    PeProtectionStatus,
    PeSection,
)
from drake_x.reporting.pe_report_writer import render_pe_executive, render_pe_json, render_pe_markdown


def _full_pe_result() -> PeAnalysisResult:
    return PeAnalysisResult(
        metadata=PeMetadata(
            file_path="/tmp/malware.exe",
            file_size=102400,
            md5="d" * 32,
            sha256="e" * 64,
            file_type="PE32 executable (GUI) Intel 80386",
        ),
        header=PeHeader(
            machine=PeMachine.I386,
            image_base="0x00400000",
            entry_point="0x00012345",
            number_of_sections=4,
            timestamp="2024-01-15 12:00:00",
            subsystem="windows_gui",
            dll_characteristics=["NX_COMPAT"],
            is_exe=True,
        ),
        sections=[
            PeSection(name=".text", virtual_size=32768, raw_size=32768, entropy=6.5,
                      characteristics=["CODE", "EXECUTE", "READ"], is_executable=True),
            PeSection(name=".data", virtual_size=4096, raw_size=4096, entropy=3.2,
                      characteristics=["INITIALIZED_DATA", "READ", "WRITE"], is_writable=True),
            PeSection(name=".upx0", virtual_size=65536, raw_size=0, entropy=0.0,
                      characteristics=["CODE", "EXECUTE", "READ", "WRITE"],
                      is_executable=True, is_writable=True),
        ],
        imports=[
            PeImport(dll="kernel32.dll", function="VirtualAllocEx"),
            PeImport(dll="kernel32.dll", function="WriteProcessMemory"),
            PeImport(dll="kernel32.dll", function="CreateRemoteThread"),
            PeImport(dll="kernel32.dll", function="CreateProcessA"),
            PeImport(dll="wininet.dll", function="InternetOpenA"),
            PeImport(dll="kernel32.dll", function="IsDebuggerPresent"),
        ],
        anomalies=[
            PeAnomaly(anomaly_type="writable_executable_section", severity="high",
                      description=".upx0 is W+X", evidence="W+X flags"),
            PeAnomaly(anomaly_type="zero_timestamp", severity="medium",
                      description="Timestamp is zero", evidence="TimeDateStamp = 0"),
        ],
        protection=PeProtectionStatus(
            dep_enabled=True, aslr_enabled=False, cfg_enabled=False,
        ),
        import_risk_findings=[
            {"dll": "kernel32.dll", "function": "VirtualAllocEx", "category": "injection",
             "risk": "high", "technique_id": "T1055"},
            {"dll": "kernel32.dll", "function": "WriteProcessMemory", "category": "injection",
             "risk": "high", "technique_id": "T1055"},
            {"dll": "kernel32.dll", "function": "CreateRemoteThread", "category": "injection",
             "risk": "high", "technique_id": "T1055.001"},
            {"dll": "wininet.dll", "function": "InternetOpenA", "category": "communication",
             "risk": "medium", "technique_id": "T1071"},
            {"dll": "kernel32.dll", "function": "IsDebuggerPresent", "category": "evasion",
             "risk": "medium", "technique_id": "T1622"},
        ],
        suspicious_patterns=[
            {"section": ".upx0", "finding_type": "packer_section_name",
             "description": "Known packer section", "severity": "medium", "confidence": 0.8},
        ],
        tools_ran=["pefile", "capstone"],
    )


def test_report_contains_all_sections() -> None:
    md = render_pe_markdown(_full_pe_result())
    for heading in [
        "## 1. Executive Summary",
        "## 2. Methodology",
        "## 3. Surface Analysis",
        "## 4. PE Metadata",
        "## 5. Section Analysis",
        "## 6. Import Risk Assessment",
        "## 7. Protection Analysis",
        "## 8. Structural Anomalies",
        "## 9. Behavioral Signals",
        "## 10. Validation Recommendations",
    ]:
        assert heading in md, f"Missing section: {heading}"


def test_report_contains_evidence_labels() -> None:
    md = render_pe_markdown(_full_pe_result())
    assert "observed evidence" in md.lower() or "static fact" in md.lower()
    assert "analytic assessment" in md.lower() or "Analytic Assessment" in md


def test_report_contains_injection_chain() -> None:
    md = render_pe_markdown(_full_pe_result())
    assert "Process Injection Chain" in md
    assert "T1055" in md


def test_report_shows_protection_status() -> None:
    md = render_pe_markdown(_full_pe_result())
    assert "ASLR" in md
    assert "DEP" in md
    assert "Disabled" in md


def test_report_shows_anomalies() -> None:
    md = render_pe_markdown(_full_pe_result())
    assert "writable_executable_section" in md


def test_report_shows_import_table() -> None:
    md = render_pe_markdown(_full_pe_result())
    assert "VirtualAllocEx" in md
    assert "injection" in md


def test_executive_is_short() -> None:
    exec_md = render_pe_executive(_full_pe_result())
    assert "## 1. Executive Summary" in exec_md
    assert "## 2." not in exec_md  # Should only contain section 1


def test_json_round_trips() -> None:
    body = render_pe_json(_full_pe_result())
    data = json.loads(body)
    assert data["metadata"]["sha256"] == "e" * 64
    assert data["header"]["machine"] == "i386"
    assert len(data["sections"]) == 3


def test_empty_pe_result_report() -> None:
    result = PeAnalysisResult(
        metadata=PeMetadata(sha256="f" * 64),
    )
    md = render_pe_markdown(result)
    assert "## 1. Executive Summary" in md
    assert "No high-risk API imports" in md or "No behavioral signals" in md
