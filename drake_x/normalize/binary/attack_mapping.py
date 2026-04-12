"""ATT&CK mapping for exploitation-related malware behavior.

Conservative mapping from exploit-aware findings to MITRE ATT&CK
techniques. Only maps when evidence justifies the association.

Drake-X uses ATT&CK for analytical context, not for operational
exploitation guidance.
"""

from __future__ import annotations

from ...models.pe import (
    ExploitIndicator,
    ExploitIndicatorType,
    PeAnalysisResult,
    ProtectionInteractionAssessment,
)


def map_exploit_indicators_to_attack(
    result: PeAnalysisResult,
) -> list[dict[str, str | list[str]]]:
    """Map exploit-aware findings to ATT&CK techniques.

    Returns conservative mappings with evidence citations and caveats.
    Avoids over-mapping from weak evidence.
    """
    mappings: list[dict[str, str | list[str]]] = []

    for indicator in result.exploit_indicators:
        mapping = _map_indicator(indicator)
        if mapping:
            mappings.append(mapping)

    # Aggregate protection-interaction context
    for interaction in result.protection_interactions:
        mapping = _map_protection_interaction(interaction)
        if mapping:
            mappings.append(mapping)

    # Deduplicate by technique ID
    seen_techniques: set[str] = set()
    unique_mappings: list[dict[str, str | list[str]]] = []
    for m in mappings:
        tid = m.get("technique_id", "")
        if isinstance(tid, str) and tid not in seen_techniques:
            seen_techniques.add(tid)
            unique_mappings.append(m)

    return unique_mappings


# ---------------------------------------------------------------------------
# Indicator → ATT&CK mapping
# ---------------------------------------------------------------------------

_INDICATOR_TECHNIQUE_MAP: dict[ExploitIndicatorType, list[dict[str, str]]] = {
    ExploitIndicatorType.INJECTION_CHAIN: [
        {
            "technique_id": "T1055",
            "technique_name": "Process Injection",
            "tactic": "Defense Evasion, Privilege Escalation",
            "confidence_note": "suspected — based on import chain pattern",
        },
    ],
    ExploitIndicatorType.CONTROL_FLOW_HIJACK: [
        {
            "technique_id": "T1203",
            "technique_name": "Exploitation for Client Execution",
            "tactic": "Execution",
            "confidence_note": "potential — control-flow indicators detected",
        },
    ],
    ExploitIndicatorType.STACK_CORRUPTION: [
        {
            "technique_id": "T1203",
            "technique_name": "Exploitation for Client Execution",
            "tactic": "Execution",
            "confidence_note": "potential — stack-related indicators detected",
        },
    ],
    ExploitIndicatorType.SHELLCODE_SETUP: [
        {
            "technique_id": "T1055",
            "technique_name": "Process Injection",
            "tactic": "Defense Evasion",
            "confidence_note": "suspected — shellcode staging indicators",
        },
        {
            "technique_id": "T1059",
            "technique_name": "Command and Scripting Interpreter",
            "tactic": "Execution",
            "confidence_note": "potential — embedded executable content",
        },
    ],
    ExploitIndicatorType.HEAP_MANIPULATION: [
        {
            "technique_id": "T1203",
            "technique_name": "Exploitation for Client Execution",
            "tactic": "Execution",
            "confidence_note": "potential — heap manipulation indicators",
        },
    ],
    ExploitIndicatorType.ROP_INDICATOR: [
        {
            "technique_id": "T1203",
            "technique_name": "Exploitation for Client Execution",
            "tactic": "Execution",
            "confidence_note": "suspected — ROP-like structure indicators",
        },
    ],
}


def _map_indicator(
    indicator: ExploitIndicator,
) -> dict[str, str | list[str]] | None:
    """Map a single exploit indicator to ATT&CK."""
    techniques = _INDICATOR_TECHNIQUE_MAP.get(indicator.indicator_type, [])
    if not techniques:
        return None

    # Use the first (primary) technique
    tech = techniques[0]

    # Only map if confidence is above threshold
    if indicator.confidence < 0.4:
        return None

    return {
        "technique_id": tech["technique_id"],
        "technique_name": tech["technique_name"],
        "tactic": tech["tactic"],
        "source_indicator": indicator.title,
        "evidence": indicator.evidence_refs[:5],
        "confidence": f"{indicator.confidence:.2f}",
        "confidence_note": tech["confidence_note"],
        "caveats": [
            "ATT&CK mapping based on exploit-related indicators — requires validation",
            "Technique association does not confirm exploitation capability",
        ],
    }


def _map_protection_interaction(
    interaction: ProtectionInteractionAssessment,
) -> dict[str, str | list[str]] | None:
    """Map protection-interaction findings to ATT&CK."""
    if interaction.severity not in ("medium", "high"):
        return None

    technique_map = {
        "DEP": ("T1055", "Process Injection", "Defense Evasion"),
        "ASLR": ("T1027", "Obfuscated Files or Information", "Defense Evasion"),
        "CFG": ("T1203", "Exploitation for Client Execution", "Execution"),
        "SafeSEH": ("T1203", "Exploitation for Client Execution", "Execution"),
    }

    mapping = technique_map.get(interaction.protection)
    if not mapping:
        return None

    tid, name, tactic = mapping

    return {
        "technique_id": tid,
        "technique_name": name,
        "tactic": tactic,
        "source_indicator": f"{interaction.protection} interaction: {interaction.observed_capability}",
        "evidence": [interaction.protection, f"enabled={interaction.protection_enabled}"],
        "confidence": f"{interaction.confidence:.2f}",
        "confidence_note": f"protection-interaction assessment for {interaction.protection}",
        "caveats": [
            "ATT&CK mapping from protection-interaction context — analytical only",
            "Requires dynamic validation to confirm technique applicability",
        ],
    }
