"""Tests for protection-interaction assessment (v0.9)."""

from __future__ import annotations

from drake_x.models.pe import (
    ExploitIndicator,
    ExploitIndicatorType,
    PeAnalysisResult,
    PeImport,
    PeProtectionStatus,
)
from drake_x.normalize.binary.protection_interaction import assess_protection_interactions


def _make_result(
    imports: list[tuple[str, str]] | None = None,
    protection: PeProtectionStatus | None = None,
    indicators: list[ExploitIndicator] | None = None,
) -> PeAnalysisResult:
    return PeAnalysisResult(
        imports=[PeImport(dll=dll, function=fn) for dll, fn in (imports or [])],
        protection=protection or PeProtectionStatus(),
        exploit_indicators=indicators or [],
    )


def test_dep_absent_with_shellcode_indicators():
    result = _make_result(
        protection=PeProtectionStatus(dep_enabled=False),
        indicators=[
            ExploitIndicator(
                indicator_type=ExploitIndicatorType.SHELLCODE_SETUP,
                title="test",
                description="test",
            ),
        ],
    )
    assessments = assess_protection_interactions(result)
    dep = [a for a in assessments if a.protection == "DEP"]
    assert len(dep) >= 1
    assert dep[0].severity == "high"
    assert not dep[0].protection_enabled


def test_dep_enabled_with_virtualprotect():
    result = _make_result(
        imports=[("kernel32.dll", "VirtualProtect")],
        protection=PeProtectionStatus(dep_enabled=True),
    )
    assessments = assess_protection_interactions(result)
    dep = [a for a in assessments if a.protection == "DEP"]
    assert len(dep) >= 1
    assert dep[0].severity == "medium"
    assert "VirtualProtect" in dep[0].interaction_assessment or "protection" in dep[0].interaction_assessment.lower()


def test_aslr_absent_with_injection():
    result = _make_result(
        protection=PeProtectionStatus(aslr_enabled=False),
        indicators=[
            ExploitIndicator(
                indicator_type=ExploitIndicatorType.INJECTION_CHAIN,
                title="test",
                description="test",
            ),
        ],
    )
    assessments = assess_protection_interactions(result)
    aslr = [a for a in assessments if a.protection == "ASLR"]
    assert len(aslr) >= 1
    assert aslr[0].severity in ("medium", "high")


def test_cfg_absent_with_control_flow():
    result = _make_result(
        protection=PeProtectionStatus(cfg_enabled=False),
        indicators=[
            ExploitIndicator(
                indicator_type=ExploitIndicatorType.CONTROL_FLOW_HIJACK,
                title="test",
                description="test",
            ),
        ],
    )
    assessments = assess_protection_interactions(result)
    cfg = [a for a in assessments if a.protection == "CFG"]
    assert len(cfg) >= 1


def test_all_protections_enabled_minimal_output():
    result = _make_result(
        protection=PeProtectionStatus(
            dep_enabled=True, aslr_enabled=True, cfg_enabled=True, safe_seh=True,
        ),
    )
    assessments = assess_protection_interactions(result)
    # With no indicators and all protections, should have few/no assessments
    high = [a for a in assessments if a.severity == "high"]
    assert len(high) == 0


def test_assessments_never_contain_bypass_guidance():
    result = _make_result(
        imports=[
            ("kernel32.dll", "VirtualProtect"),
            ("kernel32.dll", "VirtualAllocEx"),
            ("kernel32.dll", "WriteProcessMemory"),
            ("kernel32.dll", "CreateRemoteThread"),
        ],
        protection=PeProtectionStatus(
            dep_enabled=False, aslr_enabled=False, cfg_enabled=False, safe_seh=False,
        ),
        indicators=[
            ExploitIndicator(
                indicator_type=ExploitIndicatorType.INJECTION_CHAIN,
                title="test",
                description="test",
            ),
            ExploitIndicator(
                indicator_type=ExploitIndicatorType.SHELLCODE_SETUP,
                title="test",
                description="test",
            ),
            ExploitIndicator(
                indicator_type=ExploitIndicatorType.CONTROL_FLOW_HIJACK,
                title="test",
                description="test",
            ),
        ],
    )
    assessments = assess_protection_interactions(result)
    assert len(assessments) > 0

    forbidden = ["bypass", "exploit this", "weaponize", "step 1", "craft",
                 "use this to", "execute the exploit"]
    for a in assessments:
        text = f"{a.interaction_assessment} {' '.join(a.caveats)}".lower()
        for word in forbidden:
            assert word not in text, (
                f"Bypass guidance '{word}' found in {a.protection} assessment"
            )


def test_assessments_use_analytical_language():
    result = _make_result(
        protection=PeProtectionStatus(dep_enabled=False),
        indicators=[
            ExploitIndicator(
                indicator_type=ExploitIndicatorType.SHELLCODE_SETUP,
                title="test",
                description="test",
            ),
        ],
    )
    assessments = assess_protection_interactions(result)
    for a in assessments:
        caveat_text = " ".join(a.caveats).lower()
        has_analytical = any(
            w in caveat_text for w in ["analytical", "requires", "observation", "positive"]
        )
        assert has_analytical, f"Missing analytical language in {a.protection} caveats"
