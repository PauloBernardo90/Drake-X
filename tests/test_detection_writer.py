"""Tests for the candidate YARA/STIX writers (v0.9)."""

from __future__ import annotations

import json

from drake_x.models.pe import (
    ExploitIndicator,
    ExploitIndicatorType,
    PeAnalysisResult,
    PeMetadata,
    PeSection,
    SuspectedShellcodeArtifact,
)
from drake_x.reporting.detection_writer import (
    render_pe_stix_bundle,
    render_pe_yara_candidates,
)

SHA = "e" * 64


def test_no_output_when_no_signals():
    r = PeAnalysisResult(metadata=PeMetadata(sha256=SHA))
    assert render_pe_yara_candidates(r) == ""


def test_shellcode_yara_candidate_emitted():
    r = PeAnalysisResult(
        metadata=PeMetadata(sha256=SHA),
        suspected_shellcode=[
            SuspectedShellcodeArtifact(
                source_location=".text",
                offset=0x1000,
                size=256,
                entropy=7.5,
                detection_reason="x86 prologue",
                confidence=0.6,
                preview_hex="558bec83ec10ff7508e8aa55cc33",
            ),
        ],
    )
    out = render_pe_yara_candidates(r)
    assert "rule Drake_Candidate_Shellcode_" in out
    assert '"candidate"' in out
    assert "analyst review required" in out
    # Hex string is formatted as "{ AA BB ... }"
    assert "{" in out and "}" in out


def test_shellcode_yara_skips_low_rarity_nop_sled_preview():
    r = PeAnalysisResult(
        metadata=PeMetadata(sha256=SHA),
        suspected_shellcode=[
            SuspectedShellcodeArtifact(
                source_location=".text",
                offset=0x1000,
                size=256,
                entropy=5.2,
                detection_reason="possible shellcode",
                confidence=0.6,
                preview_hex="90909090909090909090909090909090",
            ),
        ],
    )
    assert "Drake_Candidate_Shellcode_" not in render_pe_yara_candidates(r)


def test_injection_chain_yara_candidate_emitted():
    r = PeAnalysisResult(
        metadata=PeMetadata(sha256=SHA),
        exploit_indicators=[
            ExploitIndicator(
                indicator_type=ExploitIndicatorType.INJECTION_CHAIN,
                title="Injection chain",
                description="d",
                severity="high",
                confidence=0.8,
                evidence_refs=[
                    "VirtualAllocEx", "WriteProcessMemory",
                    "CreateRemoteThread", "GetProcAddress",
                ],
                mitre_attck=["T1055"],
            ),
        ],
    )
    out = render_pe_yara_candidates(r)
    assert "Drake_Candidate_InjectionChain_" in out
    assert "VirtualAllocEx" in out
    assert "3 of ($api_*)" in out


def test_packer_rule_requires_entropy_and_packer_hit():
    # Only high-entropy executable section without packer-name hit → no rule.
    r = PeAnalysisResult(
        metadata=PeMetadata(sha256=SHA),
        sections=[PeSection(name=".x", entropy=7.5, is_executable=True)],
    )
    assert "PackerSection" not in render_pe_yara_candidates(r)

    # Add a packer-name hit → rule emitted.
    r.suspicious_patterns = [{"finding_type": "packer_section_name", "section": ".UPX0"}]
    r.sections = [PeSection(name=".UPX0", entropy=7.8, is_executable=True)]
    out = render_pe_yara_candidates(r)
    assert "Drake_Candidate_PackerSection_" in out
    assert ".UPX0" in out


def test_stix_bundle_empty_when_no_hash():
    r = PeAnalysisResult(metadata=PeMetadata(sha256=""))
    assert render_pe_stix_bundle(r) == ""


def test_stix_bundle_contains_file_and_indicator():
    r = PeAnalysisResult(
        metadata=PeMetadata(sha256=SHA, md5="f" * 32, file_size=1024),
        exploit_indicators=[
            ExploitIndicator(
                indicator_type=ExploitIndicatorType.INJECTION_CHAIN,
                title="Injection chain",
                description="d",
                severity="high",
                confidence=0.75,
                evidence_refs=["VirtualAllocEx"],
                mitre_attck=["T1055"],
            ),
        ],
    )
    out = render_pe_stix_bundle(r)
    bundle = json.loads(out)
    assert bundle["type"] == "bundle"
    types = [o["type"] for o in bundle["objects"]]
    assert "file" in types
    assert "indicator" in types
    assert "relationship" in types
    # Candidate label must be present — doctrine requires it.
    indicators = [o for o in bundle["objects"] if o["type"] == "indicator"]
    assert indicators
    assert "candidate" in indicators[0]["labels"]
    # Drake-X caveat present.
    assert "x_drake_x" in bundle
    assert "analyst review" in bundle["x_drake_x"]["caveat"].lower()


def test_stix_bundle_is_reproducible_for_file_id():
    r = PeAnalysisResult(metadata=PeMetadata(sha256=SHA))
    # Two bundles with no indicators so the only UUIDs are file+bundle id.
    b1 = json.loads(render_pe_stix_bundle(r))
    b2 = json.loads(render_pe_stix_bundle(r))
    file1 = [o for o in b1["objects"] if o["type"] == "file"][0]
    file2 = [o for o in b2["objects"] if o["type"] == "file"][0]
    # File ID is derived from SHA → deterministic.
    assert file1["id"] == file2["id"]
