"""Tests for ATT&CK mapping of exploitation-related findings (v0.9)."""

from __future__ import annotations

from drake_x.models.pe import (
    ExploitIndicator,
    ExploitIndicatorType,
    PeAnalysisResult,
    PeProtectionStatus,
    ProtectionInteractionAssessment,
)
from drake_x.normalize.binary.attack_mapping import map_exploit_indicators_to_attack


def test_injection_chain_maps_to_t1055():
    result = PeAnalysisResult(
        exploit_indicators=[
            ExploitIndicator(
                indicator_type=ExploitIndicatorType.INJECTION_CHAIN,
                title="Suspected process injection chain",
                description="test",
                confidence=0.75,
                evidence_refs=["VirtualAllocEx", "WriteProcessMemory"],
            ),
        ],
    )
    mappings = map_exploit_indicators_to_attack(result)
    t1055 = [m for m in mappings if m.get("technique_id") == "T1055"]
    assert len(t1055) >= 1
    assert "suspected" in str(t1055[0].get("confidence_note", "")).lower()


def test_low_confidence_not_mapped():
    result = PeAnalysisResult(
        exploit_indicators=[
            ExploitIndicator(
                indicator_type=ExploitIndicatorType.FORMAT_STRING,
                title="test",
                description="test",
                confidence=0.3,  # Below threshold
            ),
        ],
    )
    mappings = map_exploit_indicators_to_attack(result)
    assert len(mappings) == 0


def test_protection_interaction_maps_to_attack():
    result = PeAnalysisResult(
        protection_interactions=[
            ProtectionInteractionAssessment(
                protection="DEP",
                protection_enabled=False,
                observed_capability="Shellcode staging indicators",
                interaction_assessment="DEP absent",
                severity="high",
                confidence=0.65,
            ),
        ],
    )
    mappings = map_exploit_indicators_to_attack(result)
    assert len(mappings) >= 1


def test_deduplication():
    result = PeAnalysisResult(
        exploit_indicators=[
            ExploitIndicator(
                indicator_type=ExploitIndicatorType.INJECTION_CHAIN,
                title="test1",
                description="test",
                confidence=0.7,
                mitre_attck=["T1055"],
            ),
            ExploitIndicator(
                indicator_type=ExploitIndicatorType.SHELLCODE_SETUP,
                title="test2",
                description="test",
                confidence=0.6,
                mitre_attck=["T1055"],
            ),
        ],
    )
    mappings = map_exploit_indicators_to_attack(result)
    t1055 = [m for m in mappings if m.get("technique_id") == "T1055"]
    assert len(t1055) == 1  # Deduplicated


def test_mappings_have_caveats():
    result = PeAnalysisResult(
        exploit_indicators=[
            ExploitIndicator(
                indicator_type=ExploitIndicatorType.INJECTION_CHAIN,
                title="test",
                description="test",
                confidence=0.7,
            ),
        ],
    )
    mappings = map_exploit_indicators_to_attack(result)
    for m in mappings:
        caveats = m.get("caveats", [])
        assert len(caveats) > 0
        assert any("requires" in str(c).lower() or "not confirm" in str(c).lower()
                    for c in caveats)
