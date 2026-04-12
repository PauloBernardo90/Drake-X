"""Protection-interaction assessment for PE/native analysis.

Analytically assesses how observed malware capability interacts with
binary protections (DEP, ASLR, CFG, SafeSEH).

All outputs are **analytic assessments**, not bypass guidance.
Drake-X does NOT provide operational bypass steps.
"""

from __future__ import annotations

from ...models.pe import (
    ExploitIndicator,
    ExploitIndicatorType,
    PeAnalysisResult,
    PeProtectionStatus,
    ProtectionInteractionAssessment,
)


def assess_protection_interactions(
    result: PeAnalysisResult,
) -> list[ProtectionInteractionAssessment]:
    """Produce protection-interaction assessments for observed capability.

    Evaluates how the exploit-related indicators and import patterns
    interact with the binary's protection status. Returns structured
    assessments — never bypass guidance.
    """
    assessments: list[ProtectionInteractionAssessment] = []
    prot = result.protection
    indicators = result.exploit_indicators
    import_funcs = {imp.function.lower() for imp in result.imports}

    assessments.extend(_assess_dep(prot, indicators, import_funcs))
    assessments.extend(_assess_aslr(prot, indicators, import_funcs))
    assessments.extend(_assess_cfg(prot, indicators, import_funcs))
    assessments.extend(_assess_safe_seh(prot, indicators, import_funcs))

    return assessments


def _assess_dep(
    prot: PeProtectionStatus,
    indicators: list[ExploitIndicator],
    import_funcs: set[str],
) -> list[ProtectionInteractionAssessment]:
    """Assess interaction with DEP (Data Execution Prevention)."""

    # Check for shellcode/injection related indicators
    has_shellcode_indicators = any(
        i.indicator_type in (
            ExploitIndicatorType.SHELLCODE_SETUP,
            ExploitIndicatorType.INJECTION_CHAIN,
            ExploitIndicatorType.STACK_CORRUPTION,
        )
        for i in indicators
    )

    has_protect_api = bool(import_funcs & {"virtualprotect", "virtualprotectex",
                                            "ntprotectvirtualmemory"})

    if not prot.dep_enabled:
        if has_shellcode_indicators:
            return [ProtectionInteractionAssessment(
                protection="DEP",
                protection_enabled=False,
                observed_capability=(
                    "Exploit-related indicators suggest potential shellcode staging "
                    "or injection capability"
                ),
                interaction_assessment=(
                    "DEP is not enabled. If the observed capability includes "
                    "shellcode execution, the absence of DEP removes a significant "
                    "barrier to code execution from writable memory regions. "
                    "Pending dynamic validation."
                ),
                severity="high",
                confidence=0.65,
                caveats=[
                    "Analytical assessment — not operational guidance",
                    "Requires dynamic validation to confirm exploitation path",
                ],
            )]
        return [ProtectionInteractionAssessment(
            protection="DEP",
            protection_enabled=False,
            observed_capability="No specific shellcode-related indicators detected",
            interaction_assessment=(
                "DEP is not enabled. While no specific shellcode indicators "
                "were detected, the absence of DEP is a relevant defensive gap."
            ),
            severity="info",
            confidence=0.8,
            caveats=["Analytical observation — DEP status is a static fact"],
        )]

    # DEP enabled
    if has_protect_api:
        return [ProtectionInteractionAssessment(
            protection="DEP",
            protection_enabled=True,
            observed_capability=(
                "Memory protection modification APIs (VirtualProtect or equivalent) "
                "are imported"
            ),
            interaction_assessment=(
                "DEP is enabled, but the sample imports APIs capable of modifying "
                "memory protection attributes. This combination may indicate "
                "an attempt to mark memory as executable at runtime, potentially "
                "circumventing DEP for injected code. Requires dynamic validation."
            ),
            severity="medium",
            confidence=0.55,
            caveats=[
                "Suspected DEP interaction — requires dynamic validation",
                "VirtualProtect has many legitimate uses",
                "Analytical assessment — not operational guidance",
            ],
        )]

    return []


def _assess_aslr(
    prot: PeProtectionStatus,
    indicators: list[ExploitIndicator],
    import_funcs: set[str],
) -> list[ProtectionInteractionAssessment]:
    """Assess interaction with ASLR."""

    has_injection = any(
        i.indicator_type == ExploitIndicatorType.INJECTION_CHAIN
        for i in indicators
    )

    # APIs that may help resolve addresses at runtime
    resolve_apis = {"getprocaddress", "getmodulehandlea", "getmodulehandlew",
                    "loadlibrarya", "loadlibraryw", "loadlibraryexa", "loadlibraryexw"}
    has_resolve = bool(import_funcs & resolve_apis)

    if not prot.aslr_enabled:
        if has_injection:
            return [ProtectionInteractionAssessment(
                protection="ASLR",
                protection_enabled=False,
                observed_capability="Injection chain indicators present",
                interaction_assessment=(
                    "ASLR is not enabled. The binary loads at a predictable "
                    "address, which simplifies potential exploitation if "
                    "injection capability is confirmed. Requires dynamic validation."
                ),
                severity="medium",
                confidence=0.6,
                caveats=[
                    "Analytical assessment — not operational guidance",
                    "ASLR absence alone does not confirm exploitation",
                    "Requires dynamic validation",
                ],
            )]
        return [ProtectionInteractionAssessment(
            protection="ASLR",
            protection_enabled=False,
            observed_capability="No specific address-dependent indicators detected",
            interaction_assessment=(
                "ASLR is not enabled. The binary loads at a fixed base address."
            ),
            severity="info",
            confidence=0.8,
            caveats=["Analytical observation — ASLR status is a static fact"],
        )]

    # ASLR enabled with dynamic resolution
    if has_resolve and has_injection:
        return [ProtectionInteractionAssessment(
            protection="ASLR",
            protection_enabled=True,
            observed_capability=(
                "Runtime address resolution APIs combined with injection indicators"
            ),
            interaction_assessment=(
                "ASLR is enabled, but the sample imports dynamic resolution APIs "
                "(GetProcAddress, LoadLibrary, etc.) alongside injection indicators. "
                "This may indicate runtime address resolution to work around "
                "randomized layouts. Requires dynamic validation."
            ),
            severity="medium",
            confidence=0.5,
            caveats=[
                "Suspected ASLR interaction — requires dynamic validation",
                "Dynamic resolution APIs are extremely common in legitimate software",
                "Analytical assessment — not bypass confirmation",
            ],
        )]

    return []


def _assess_cfg(
    prot: PeProtectionStatus,
    indicators: list[ExploitIndicator],
    import_funcs: set[str],
) -> list[ProtectionInteractionAssessment]:
    """Assess interaction with Control Flow Guard."""

    has_control_flow = any(
        i.indicator_type == ExploitIndicatorType.CONTROL_FLOW_HIJACK
        for i in indicators
    )

    if not prot.cfg_enabled:
        if has_control_flow:
            return [ProtectionInteractionAssessment(
                protection="CFG",
                protection_enabled=False,
                observed_capability="Control-flow manipulation indicators detected",
                interaction_assessment=(
                    "CFG is not enabled. Indirect call targets are not validated, "
                    "which may facilitate control-flow hijacking if exploitation "
                    "capability is confirmed. Requires dynamic validation."
                ),
                severity="medium",
                confidence=0.55,
                caveats=[
                    "Analytical assessment — not operational guidance",
                    "CFG absence is common in many legitimate binaries",
                    "Requires dynamic validation",
                ],
            )]

    elif has_control_flow:
        return [ProtectionInteractionAssessment(
            protection="CFG",
            protection_enabled=True,
            observed_capability="Control-flow manipulation indicators detected",
            interaction_assessment=(
                "CFG is enabled, providing validation of indirect call targets. "
                "This raises the barrier for control-flow hijacking techniques. "
                "However, CFG coverage depends on compilation settings."
            ),
            severity="low",
            confidence=0.6,
            caveats=[
                "CFG presence is a positive defensive indicator",
                "CFG effectiveness depends on compiler and linker settings",
            ],
        )]

    return []


def _assess_safe_seh(
    prot: PeProtectionStatus,
    indicators: list[ExploitIndicator],
    import_funcs: set[str],
) -> list[ProtectionInteractionAssessment]:
    """Assess interaction with SafeSEH."""

    seh_related = {"rtlunwind", "rtladdvectoredexceptionhandler",
                   "addvectoredexceptionhandler", "setunhandledexceptionfilter"}
    has_seh_apis = bool(import_funcs & seh_related)

    has_seh_indicator = any(
        i.indicator_type == ExploitIndicatorType.CONTROL_FLOW_HIJACK
        and "seh" in i.title.lower()
        for i in indicators
    )

    if not prot.safe_seh:
        if has_seh_apis or has_seh_indicator:
            return [ProtectionInteractionAssessment(
                protection="SafeSEH",
                protection_enabled=False,
                observed_capability="Exception handling APIs or SEH indicators detected",
                interaction_assessment=(
                    "SafeSEH is not enabled. Exception handler addresses are not "
                    "validated against a safe table, which may facilitate "
                    "SEH-based exploitation if applicable. Requires dynamic validation."
                ),
                severity="medium",
                confidence=0.5,
                caveats=[
                    "Analytical assessment — not operational guidance",
                    "SafeSEH absence is relevant primarily for x86 binaries",
                    "Requires dynamic validation",
                ],
            )]

    return []
