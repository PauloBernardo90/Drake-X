"""Cross-domain bridge: APK analysis → standard Finding model.

Converts the APK-specific :class:`ApkAnalysisResult` into a list of
standard :class:`Finding` objects that can be persisted through the
existing :class:`WorkspaceStorage`, displayed by the unified
``drake findings list`` command, and consumed by the general AI tasks.
"""

from __future__ import annotations

from ...models.apk import (
    ApkAnalysisResult,
    CampaignSimilarity,
    ProtectionStatus,
)
from ...models.finding import (
    Finding,
    FindingEvidence,
    FindingSeverity,
    FindingSource,
)


def apk_result_to_findings(result: ApkAnalysisResult) -> list[Finding]:
    """Convert APK analysis indicators into standard Finding rows."""
    findings: list[Finding] = []

    # Suspicious permissions
    suspicious = [p for p in result.permissions if p.is_suspicious]
    if suspicious:
        findings.append(Finding(
            title="Suspicious Android permissions",
            summary=f"{len(suspicious)} permissions flagged: "
                    + ", ".join(p.name.split(".")[-1] for p in suspicious[:5]),
            severity=FindingSeverity.MEDIUM if len(suspicious) >= 3 else FindingSeverity.LOW,
            confidence=0.9,
            source=FindingSource.RULE,
            fact_or_inference="fact",
            related_tools=["aapt"],
            evidence=[FindingEvidence(
                artifact_kind="apk.permissions",
                tool_name="aapt",
                excerpt=", ".join(p.name for p in suspicious[:3]),
                confidence=0.95,
            )],
            tags=["apk", "permissions"],
        ))

    # Behavior indicators (group by category)
    categories = set(b.category for b in result.behavior_indicators)
    severity_map = {
        "dynamic_loading": FindingSeverity.HIGH,
        "dropper": FindingSeverity.HIGH,
        "exfiltration": FindingSeverity.HIGH,
        "persistence": FindingSeverity.MEDIUM,
        "communication": FindingSeverity.LOW,
        "social_engineering": FindingSeverity.MEDIUM,
        "trigger_logic": FindingSeverity.MEDIUM,
    }
    for cat in sorted(categories):
        indicators = [b for b in result.behavior_indicators if b.category == cat]
        sev = severity_map.get(cat, FindingSeverity.LOW)
        patterns = ", ".join(b.pattern for b in indicators[:4])
        findings.append(Finding(
            title=f"APK behavior: {cat}",
            summary=f"{len(indicators)} indicator(s): {patterns}",
            severity=sev,
            confidence=max(b.confidence for b in indicators),
            source=FindingSource.RULE,
            fact_or_inference="fact",
            evidence=[FindingEvidence(
                artifact_kind=f"apk.behavior.{cat}",
                tool_name="static_analysis",
                excerpt=indicators[0].evidence[:120] if indicators else "",
                confidence=indicators[0].confidence if indicators else 0.5,
            )],
            tags=["apk", "behavior", cat],
        ))

    # Protection indicators
    for pi in result.protection_indicators:
        if pi.status == ProtectionStatus.NOT_OBSERVED:
            continue
        findings.append(Finding(
            title=f"APK protection: {pi.protection_type}",
            summary=f"Status: {pi.status.value}. {'; '.join(pi.evidence[:2])}",
            severity=FindingSeverity.INFO,
            confidence=0.8 if pi.status == ProtectionStatus.OBSERVED else 0.5,
            source=FindingSource.RULE,
            fact_or_inference="fact",
            evidence=[FindingEvidence(
                artifact_kind=f"apk.protection.{pi.protection_type}",
                tool_name="static_analysis",
                excerpt=pi.evidence[0][:120] if pi.evidence else "",
            )],
            tags=["apk", "protection", pi.protection_type],
        ))

    # Campaign assessments
    for ca in result.campaign_assessments:
        if ca.similarity == CampaignSimilarity.INSUFFICIENT_EVIDENCE:
            continue
        label = ca.similarity.value.replace("_", " ")
        findings.append(Finding(
            title=f"APK campaign similarity: {ca.category}",
            summary=f"Assessment: {label}. Traits: {', '.join(ca.matching_traits)}",
            severity=FindingSeverity.MEDIUM if ca.confidence > 0.5 else FindingSeverity.LOW,
            confidence=ca.confidence,
            source=FindingSource.RULE,
            fact_or_inference="inference",
            evidence=[FindingEvidence(
                artifact_kind="apk.campaign",
                tool_name="campaign_assessor",
                excerpt=f"{ca.category}: {label}",
            )],
            tags=["apk", "campaign", ca.category],
        ))

    # Native analysis findings (structured Ghidra export)
    findings.extend(_native_findings(result))

    return findings


def _native_findings(result: ApkAnalysisResult) -> list[Finding]:
    """Convert structured native analysis into standard findings."""
    findings: list[Finding] = []
    if not result.native_analysis:
        return findings

    # JNI exports — high interest for malware hiding logic in native code
    all_jni = [
        (na.binary_path, e)
        for na in result.native_analysis
        for e in na.jni_exports
    ]
    if all_jni:
        jni_names = ", ".join(e.name for _, e in all_jni[:5])
        findings.append(Finding(
            title="Native JNI exports detected",
            summary=f"{len(all_jni)} JNI export(s) across native libraries: {jni_names}",
            severity=FindingSeverity.MEDIUM if len(all_jni) >= 3 else FindingSeverity.LOW,
            confidence=0.95,
            source=FindingSource.RULE,
            fact_or_inference="fact",
            related_tools=["ghidra"],
            evidence=[FindingEvidence(
                artifact_kind="apk.native.jni_exports",
                tool_name="ghidra_structured_export",
                excerpt=jni_names,
                confidence=0.95,
            )],
            tags=["apk", "native", "jni"],
        ))

    # Suspicious native functions/strings
    all_suspicious = [
        fn
        for na in result.native_analysis
        for fn in na.suspicious_functions
    ]
    if all_suspicious:
        sample = ", ".join(all_suspicious[:5])
        findings.append(Finding(
            title="Suspicious native symbols",
            summary=f"{len(all_suspicious)} suspicious symbol(s) in native code: {sample}",
            severity=FindingSeverity.MEDIUM,
            confidence=0.7,
            source=FindingSource.RULE,
            fact_or_inference="fact",
            related_tools=["ghidra"],
            evidence=[FindingEvidence(
                artifact_kind="apk.native.suspicious_symbols",
                tool_name="ghidra_structured_export",
                excerpt=sample,
                confidence=0.7,
            )],
            caveats=["Pattern-matched symbol names require analyst verification"],
            tags=["apk", "native", "suspicious"],
        ))

    return findings
