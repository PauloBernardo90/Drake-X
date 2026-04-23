"""Cross-domain bridge: DEX deep analysis → standard Finding model.

Converts :class:`DexAnalysisResult` into standard :class:`Finding` objects
that integrate with the existing workspace storage, unified findings
listing, and AI tasks — exactly like the APK bridge does for
:class:`ApkAnalysisResult`.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from ...models.finding import (
    Finding,
    FindingEvidence,
    FindingSeverity,
    FindingSource,
)

if TYPE_CHECKING:
    from ...models.dex import DexAnalysisResult


# Map DEX severity to Finding severity
_SEV_MAP = {
    "critical": FindingSeverity.CRITICAL,
    "high": FindingSeverity.HIGH,
    "medium": FindingSeverity.MEDIUM,
    "low": FindingSeverity.LOW,
    "info": FindingSeverity.INFO,
}

# Map API categories to Finding severity
_API_SEVERITY: dict[str, FindingSeverity] = {
    "accessibility_service": FindingSeverity.HIGH,
    "package_installer": FindingSeverity.HIGH,
    "sms": FindingSeverity.HIGH,
    "device_admin": FindingSeverity.HIGH,
    "runtime_exec": FindingSeverity.HIGH,
    "dex_loading": FindingSeverity.HIGH,
    "webview": FindingSeverity.MEDIUM,
    "telephony": FindingSeverity.MEDIUM,
    "reflection": FindingSeverity.MEDIUM,
    "clipboard": FindingSeverity.MEDIUM,
    "location": FindingSeverity.MEDIUM,
    "contacts": FindingSeverity.MEDIUM,
    "camera": FindingSeverity.MEDIUM,
    "crypto": FindingSeverity.LOW,
    "file_provider": FindingSeverity.LOW,
    "network": FindingSeverity.INFO,
}


def dex_result_to_findings(result: DexAnalysisResult) -> list[Finding]:
    """Convert DEX deep analysis results into standard Finding rows."""
    findings: list[Finding] = []

    findings.extend(_sensitive_api_findings(result))
    findings.extend(_obfuscation_findings(result))
    findings.extend(_packing_findings(result))
    findings.extend(_string_ioc_findings(result))
    findings.extend(_multidex_summary_finding(result))

    return findings


def _sensitive_api_findings(result: DexAnalysisResult) -> list[Finding]:
    """Group sensitive API hits by category into findings."""
    from collections import defaultdict

    by_cat: dict[str, list] = defaultdict(list)
    for hit in result.sensitive_api_hits:
        by_cat[hit.api_category.value].append(hit)

    findings: list[Finding] = []
    for cat, hits in sorted(by_cat.items()):
        sev = _API_SEVERITY.get(cat, FindingSeverity.MEDIUM)
        api_names = ", ".join(sorted({h.api_name for h in hits}))
        max_conf = max(h.confidence for h in hits)

        # Collect ATT&CK tags
        attck = sorted({t for h in hits for t in h.mitre_attck})

        findings.append(Finding(
            title=f"DEX sensitive API: {cat}",
            summary=f"{len(hits)} hit(s) — {api_names}",
            severity=sev,
            confidence=max_conf,
            source=FindingSource.RULE,
            fact_or_inference="fact",
            related_tools=["dex_deep"],
            evidence=[FindingEvidence(
                artifact_kind=f"dex.api.{cat}",
                tool_name="dex_sensitive_api_detector",
                excerpt=hits[0].raw_match[:120] if hits[0].raw_match else api_names,
                confidence=max_conf,
            )],
            mitre_attck=attck,
            tags=["dex", "sensitive_api", cat],
        ))

    return findings


def _obfuscation_findings(result: DexAnalysisResult) -> list[Finding]:
    """Convert obfuscation indicators into findings."""
    if not result.obfuscation_indicators:
        return []

    findings: list[Finding] = []

    # One summary finding for the obfuscation score
    signals = [ind.signal.value for ind in result.obfuscation_indicators]
    max_conf = max(ind.confidence for ind in result.obfuscation_indicators)

    if result.obfuscation_score >= 0.6:
        sev = FindingSeverity.HIGH
    elif result.obfuscation_score >= 0.3:
        sev = FindingSeverity.MEDIUM
    else:
        sev = FindingSeverity.LOW

    findings.append(Finding(
        title="DEX obfuscation assessment",
        summary=(
            f"Obfuscation score: {result.obfuscation_score:.0%} — "
            f"{len(result.obfuscation_indicators)} signal(s): {', '.join(signals)}"
        ),
        severity=sev,
        confidence=max_conf,
        source=FindingSource.RULE,
        fact_or_inference="fact",
        related_tools=["dex_deep"],
        evidence=[FindingEvidence(
            artifact_kind="dex.obfuscation",
            tool_name="dex_obfuscation_analyzer",
            excerpt=f"Score: {result.obfuscation_score:.2f}, signals: {', '.join(signals)}",
            confidence=max_conf,
        )],
        tags=["dex", "obfuscation"],
    ))

    # Individual high-confidence signals as separate findings
    for ind in result.obfuscation_indicators:
        if ind.confidence >= 0.7:
            findings.append(Finding(
                title=f"DEX obfuscation: {ind.signal.value}",
                summary=ind.description,
                severity=_SEV_MAP.get(ind.severity.value, FindingSeverity.LOW),
                confidence=ind.confidence,
                source=FindingSource.RULE,
                fact_or_inference="fact",
                related_tools=["dex_deep"],
                evidence=[FindingEvidence(
                    artifact_kind=f"dex.obfuscation.{ind.signal.value}",
                    tool_name="dex_obfuscation_analyzer",
                    excerpt="; ".join(ind.evidence[:2]),
                    confidence=ind.confidence,
                )],
                tags=["dex", "obfuscation", ind.signal.value],
            ))

    return findings


def _packing_findings(result: DexAnalysisResult) -> list[Finding]:
    """Convert packing indicators into findings."""
    findings: list[Finding] = []
    for pi in result.packing_indicators:
        findings.append(Finding(
            title=f"DEX packing: {pi.indicator_type}",
            summary=pi.description,
            severity=FindingSeverity.MEDIUM,
            confidence=pi.confidence,
            source=FindingSource.RULE,
            fact_or_inference="fact",
            related_tools=["dex_deep"],
            evidence=[FindingEvidence(
                artifact_kind=f"dex.packing.{pi.indicator_type}",
                tool_name="dex_multidex_analyzer",
                excerpt="; ".join(pi.evidence[:2]),
                confidence=pi.confidence,
            )],
            tags=["dex", "packing", pi.indicator_type],
        ))
    return findings


def _string_ioc_findings(result: DexAnalysisResult) -> list[Finding]:
    """Convert high-confidence IoC strings into findings."""
    iocs = [s for s in result.classified_strings if s.is_potential_ioc and s.confidence >= 0.7]
    if not iocs:
        return []

    # Group by category
    from collections import defaultdict
    by_cat: dict[str, list] = defaultdict(list)
    for s in iocs:
        by_cat[s.category.value].append(s)

    findings: list[Finding] = []
    for cat, strings in sorted(by_cat.items()):
        values = [s.value[:80] for s in strings[:5]]
        findings.append(Finding(
            title=f"DEX string IoC: {cat}",
            summary=f"{len(strings)} {cat} string(s): {', '.join(values)}",
            severity=FindingSeverity.MEDIUM,
            confidence=max(s.confidence for s in strings),
            source=FindingSource.RULE,
            fact_or_inference="fact",
            related_tools=["dex_deep"],
            evidence=[FindingEvidence(
                artifact_kind=f"dex.string.{cat}",
                tool_name="dex_string_classifier",
                excerpt=strings[0].value[:120],
                confidence=strings[0].confidence,
            )],
            tags=["dex", "string", "ioc", cat],
        ))

    return findings


def _multidex_summary_finding(result: DexAnalysisResult) -> list[Finding]:
    """Generate a summary finding for the multi-DEX inventory."""
    if not result.dex_files:
        return []

    dex_names = ", ".join(d.filename for d in result.dex_files)
    return [Finding(
        title="DEX deep analysis summary",
        summary=(
            f"{len(result.dex_files)} DEX file(s) analyzed ({dex_names}): "
            f"{result.total_classes} classes, {result.total_methods} methods, "
            f"{len(result.sensitive_api_hits)} sensitive API hits, "
            f"obfuscation score {result.obfuscation_score:.0%}"
        ),
        severity=FindingSeverity.INFO,
        confidence=1.0,
        source=FindingSource.PARSER,
        fact_or_inference="fact",
        related_tools=["dex_deep"],
        evidence=[FindingEvidence(
            artifact_kind="dex.summary",
            tool_name="dex_pipeline",
            excerpt=f"{len(result.dex_files)} DEX, {result.total_classes} classes",
            confidence=1.0,
        )],
        tags=["dex", "summary"],
    )]
