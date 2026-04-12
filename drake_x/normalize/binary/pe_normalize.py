"""PE normalization: convert parsed PE data into structured findings.

Produces standard Finding objects from PE analysis results including
import risk, section anomalies, protection status, and suspicious
patterns.
"""

from __future__ import annotations

from ...models.finding import Finding, FindingEvidence, FindingSeverity, FindingSource
from ...models.pe import PeAnalysisResult
from .imports_risk import classify_imports
from .section_anomaly import assess_sections


def pe_result_to_findings(result: PeAnalysisResult) -> list[Finding]:
    """Convert PE analysis into standard Finding objects."""
    findings: list[Finding] = []

    # Import risk findings
    import_risks = classify_imports(result.imports)
    result.import_risk_findings = import_risks

    # Group by category
    categories: dict[str, list[dict]] = {}
    for risk in import_risks:
        cat = risk["category"]
        categories.setdefault(cat, []).append(risk)

    severity_map = {
        "injection": FindingSeverity.HIGH,
        "execution": FindingSeverity.MEDIUM,
        "persistence": FindingSeverity.MEDIUM,
        "evasion": FindingSeverity.MEDIUM,
        "credential_access": FindingSeverity.HIGH,
        "discovery": FindingSeverity.LOW,
        "communication": FindingSeverity.MEDIUM,
    }

    for cat, risks in categories.items():
        high_risk = [r for r in risks if r["risk"] == "high"]
        funcs = ", ".join(r["function"] for r in risks[:5])
        techniques = sorted(set(r["technique_id"] for r in risks))

        findings.append(Finding(
            title=f"PE import risk: {cat}",
            summary=f"{len(risks)} {cat}-related API import(s): {funcs}",
            severity=severity_map.get(cat, FindingSeverity.LOW),
            confidence=0.9 if high_risk else 0.7,
            source=FindingSource.RULE,
            fact_or_inference="fact",
            related_tools=["pefile"],
            evidence=[FindingEvidence(
                artifact_kind=f"pe.import.{cat}",
                tool_name="pefile",
                excerpt=funcs,
                confidence=0.9,
            )],
            mitre_attck=techniques[:3] if techniques else [],
            tags=["pe", "import", cat],
        ))

    # Section anomaly findings
    section_assessments = assess_sections(result.sections)
    result.suspicious_patterns = section_assessments

    packer_sigs = [s for s in section_assessments if s["finding_type"] == "packer_section_name"]
    if packer_sigs:
        names = ", ".join(s["section"] for s in packer_sigs)
        findings.append(Finding(
            title="PE packer detected",
            summary=f"Packer section name(s) found: {names}",
            severity=FindingSeverity.MEDIUM,
            confidence=0.8,
            source=FindingSource.RULE,
            fact_or_inference="fact",
            related_tools=["pefile"],
            evidence=[FindingEvidence(
                artifact_kind="pe.section.packer",
                tool_name="pefile",
                excerpt=names,
            )],
            tags=["pe", "packer", "obfuscation"],
        ))

    packed_signals = [s for s in section_assessments
                      if s["finding_type"] in ("multiple_high_entropy", "high_entropy")]
    if packed_signals:
        findings.append(Finding(
            title="PE likely packed or encrypted",
            summary=f"{len(packed_signals)} high-entropy section signal(s) detected",
            severity=FindingSeverity.MEDIUM,
            confidence=packed_signals[0].get("confidence", 0.7),
            source=FindingSource.RULE,
            fact_or_inference="inference",
            related_tools=["pefile"],
            evidence=[FindingEvidence(
                artifact_kind="pe.section.entropy",
                tool_name="pefile",
                excerpt=packed_signals[0]["description"],
            )],
            caveats=["High entropy may also indicate legitimate compression"],
            tags=["pe", "packing", "entropy"],
        ))

    # Protection findings
    p = result.protection
    if not p.aslr_enabled:
        findings.append(Finding(
            title="PE protection absent: ASLR disabled",
            summary="Binary does not enable ASLR (DYNAMIC_BASE) — loads at fixed address",
            severity=FindingSeverity.INFO,
            confidence=0.95,
            source=FindingSource.RULE,
            fact_or_inference="fact",
            related_tools=["pefile"],
            evidence=[FindingEvidence(
                artifact_kind="pe.protection.aslr",
                tool_name="pefile",
                excerpt="DllCharacteristics does not include DYNAMIC_BASE (0x0040)",
            )],
            tags=["pe", "protection", "aslr"],
        ))

    if not p.dep_enabled:
        findings.append(Finding(
            title="PE protection absent: DEP/NX disabled",
            summary="Binary does not enable DEP (NX_COMPAT) — stack/heap may be executable",
            severity=FindingSeverity.INFO,
            confidence=0.95,
            source=FindingSource.RULE,
            fact_or_inference="fact",
            related_tools=["pefile"],
            evidence=[FindingEvidence(
                artifact_kind="pe.protection.dep",
                tool_name="pefile",
                excerpt="DllCharacteristics does not include NX_COMPAT (0x0100)",
            )],
            tags=["pe", "protection", "dep"],
        ))

    # Anomaly findings (from parser)
    for anomaly in result.anomalies:
        if anomaly.severity in ("medium", "high"):
            findings.append(Finding(
                title=f"PE anomaly: {anomaly.anomaly_type}",
                summary=anomaly.description,
                severity=FindingSeverity.MEDIUM if anomaly.severity == "medium" else FindingSeverity.HIGH,
                confidence=0.75,
                source=FindingSource.RULE,
                fact_or_inference="fact",
                related_tools=["pefile"],
                evidence=[FindingEvidence(
                    artifact_kind=f"pe.anomaly.{anomaly.anomaly_type}",
                    tool_name="pefile",
                    excerpt=anomaly.evidence,
                )],
                tags=["pe", "anomaly", anomaly.anomaly_type],
            ))

    return findings
