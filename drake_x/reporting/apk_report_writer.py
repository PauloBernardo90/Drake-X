"""APK static-analysis report writer.

Produces the 11-section Markdown technical report, a JSON findings dump,
and an executive summary — all from a single :class:`ApkAnalysisResult`.

Report structure:
 1. Executive Summary
 2. Methodology
 3. Surface Analysis
 4. Static Analysis
 5. Campaign Objective Assessment
 6. Obfuscation Analysis
 7. Hidden Business Logic
 8. Protection Detection and Dynamic-Analysis Considerations
 9. Indicators and Extracted Artifacts
10. Conclusions
11. Analyst Next Steps

Every major conclusion section includes:
- Observed Evidence
- Analytic Assessment
- Confidence
- Pending Confirmation (where applicable)
"""

from __future__ import annotations

import json
from typing import Any

from ..models.apk import (
    ApkAnalysisResult,
    CampaignSimilarity,
    ProtectionStatus,
)


def render_apk_markdown(result: ApkAnalysisResult) -> str:
    """Render the full technical Markdown report."""
    lines: list[str] = []
    _sec_executive(lines, result)
    _sec_methodology(lines, result)
    _sec_vt_enrichment(lines, result)
    _sec_surface(lines, result)
    _sec_static(lines, result)
    _sec_campaign(lines, result)
    _sec_obfuscation(lines, result)
    _sec_hidden_logic(lines, result)
    _sec_protections(lines, result)
    _sec_ghidra(lines, result)
    _sec_frida_targets(lines, result)
    _sec_indicators(lines, result)
    _sec_conclusions(lines, result)
    _sec_next_steps(lines, result)
    return "\n".join(lines).rstrip() + "\n"


def render_apk_executive(result: ApkAnalysisResult) -> str:
    """Render a short executive summary."""
    lines: list[str] = []
    _sec_executive(lines, result)
    return "\n".join(lines).rstrip() + "\n"


def render_apk_json(result: ApkAnalysisResult) -> str:
    """Render the full analysis result as JSON."""
    return json.dumps(result.model_dump(mode="json"), indent=2, default=str)


# ---------------------------------------------------------------------------
# Section renderers
# ---------------------------------------------------------------------------


def _sec_executive(lines: list[str], r: ApkAnalysisResult) -> None:
    m = r.metadata
    lines.append(f"# APK Static Analysis Report — `{m.package_name or m.sha256[:12]}`")
    lines.append("")
    lines.append("## 1. Executive Summary")
    lines.append("")
    lines.append(f"**Sample:** `{m.file_path}`")
    lines.append(f"**SHA-256:** `{m.sha256}`")
    lines.append(f"**Package:** `{m.package_name}` v{m.version_name} (code {m.version_code})")
    lines.append(f"**Size:** {m.file_size:,} bytes")
    lines.append("")

    susp_perms = [p for p in r.permissions if p.is_suspicious]
    behaviors = len(r.behavior_indicators)
    net_iocs = len(r.network_indicators)
    active_protections = [p for p in r.protection_indicators if p.status != ProtectionStatus.NOT_OBSERVED]
    strong_campaigns = [c for c in r.campaign_assessments if c.similarity in {CampaignSimilarity.CONSISTENT_WITH, CampaignSimilarity.SHARES_TRAITS}]

    lines.append(f"The sample declares **{len(r.permissions)}** permissions "
                 f"(**{len(susp_perms)}** flagged as suspicious), exposes "
                 f"**{len(r.components)}** components, and contains "
                 f"**{len(r.native_libs)}** native libraries. Static analysis "
                 f"identified **{behaviors}** behavior indicators and "
                 f"**{net_iocs}** network indicators.")
    if active_protections:
        lines.append(f"**{len(active_protections)}** anti-analysis protection(s) were detected.")
    if strong_campaigns:
        labels = ", ".join(f"`{c.category}`" for c in strong_campaigns)
        lines.append(f"The sample shares traits with: {labels}.")
    lines.append("")
    lines.append("> All conclusions below separate **observed evidence** from "
                 "**analytic assessment**. Nothing in this report constitutes "
                 "definitive attribution.")
    lines.append("")


def _sec_methodology(lines: list[str], r: ApkAnalysisResult) -> None:
    lines.append("## 2. Methodology")
    lines.append("")
    lines.append("This report was produced by Drake-X APK static analysis using "
                 "the following tools:")
    lines.append("")
    for t in r.tools_ran:
        lines.append(f"- `{t}`")
    if r.tools_skipped:
        lines.append("")
        lines.append("Tools not available on this host (analysis degraded):")
        for t in r.tools_skipped:
            lines.append(f"- `{t}`")
    if r.warnings:
        lines.append("")
        lines.append("**Warnings:**")
        for w in r.warnings:
            lines.append(f"- {w}")
    lines.append("")


def _sec_vt_enrichment(lines: list[str], r: ApkAnalysisResult) -> None:
    vt = r.vt_enrichment
    if not vt.available and not vt.error:
        return  # VT was not requested — omit section entirely
    lines.append("## VirusTotal Enrichment")
    lines.append("")
    lines.append("> **Source classification:** external intel enrichment (not static fact)")
    lines.append("")
    if vt.available and not vt.error:
        lines.append(f"- **Detection ratio:** {vt.detection_ratio}")
        lines.append(f"- **Scan date:** {vt.scan_date}")
        if vt.popular_threat_label:
            lines.append(f"- **Popular threat label:** `{vt.popular_threat_label}`")
        if vt.suggested_threat_label:
            lines.append(f"- **Suggested threat label:** `{vt.suggested_threat_label}`")
        if vt.tags:
            lines.append(f"- **Tags:** {', '.join(vt.tags[:10])}")
        if vt.top_detections:
            lines.append("")
            lines.append("**Top detections:**")
            lines.append("")
            lines.append("| Engine | Result |")
            lines.append("|--------|--------|")
            for d in vt.top_detections:
                lines.append(f"| {d.get('engine', '')} | `{d.get('result', '')}` |")
        lines.append("")
        lines.append("> VT data is external intelligence — treat as supplementary context, "
                     "not as conclusive evidence for attribution or classification.")
    else:
        lines.append(f"_VT enrichment unavailable: {vt.error}_")
    lines.append("")


def _sec_ghidra(lines: list[str], r: ApkAnalysisResult) -> None:
    ga = r.ghidra_analysis
    if not ga.available and not ga.error:
        return  # Ghidra was not requested
    lines.append("## Ghidra Deeper Analysis")
    lines.append("")
    lines.append("> **Source classification:** static fact (deeper binary analysis via Ghidra headless)")
    lines.append("")
    if ga.available:
        lines.append(f"- **Binaries analyzed:** {len(ga.analyzed_binaries)}")
        for b in ga.analyzed_binaries:
            lines.append(f"    - `{b}`")
        if ga.suspicious_symbols:
            lines.append("")
            lines.append("**Suspicious symbols / references:**")
            lines.append("")
            for sym in ga.suspicious_symbols[:20]:
                lines.append(f"- `{sym}`")
        if ga.notes:
            lines.append("")
            lines.append("**Notes:**")
            for n in ga.notes:
                lines.append(f"- {n}")
        lines.append("")
        lines.append("> Ghidra results provide deeper visibility into native code. "
                     "Follow up with manual reverse engineering in the Ghidra GUI "
                     "for functions of interest.")
    else:
        lines.append(f"_Ghidra analysis unavailable: {ga.error}_")
    lines.append("")


def _sec_frida_targets(lines: list[str], r: ApkAnalysisResult) -> None:
    if not r.frida_targets:
        return
    lines.append("## Frida Dynamic Validation Targets")
    lines.append("")
    lines.append("> **Source classification:** analyst-assisted dynamic hypothesis")
    lines.append(">")
    lines.append("> The targets below are candidates for Frida-based validation in a "
                 "controlled environment. They are derived from static evidence and "
                 "represent investigative hypotheses, not confirmed behaviors. Drake-X "
                 "does NOT execute these hooks automatically.")
    lines.append("")

    for i, ft in enumerate(r.frida_targets, 1):
        lines.append(f"### Target {i}: `{ft.target_class}.{ft.target_method}`")
        lines.append("")
        lines.append(f"- **Protection/behavior:** {ft.protection_type}")
        lines.append(f"- **Priority:** {ft.priority}")
        lines.append(f"- **Confidence:** {ft.confidence:.2f}")
        lines.append(f"- **Expected observation:** {ft.expected_observation}")
        lines.append(f"- **Validation objective:** {ft.suggested_validation_objective}")
        if ft.evidence_basis:
            lines.append(f"- **Evidence basis:**")
            for ev in ft.evidence_basis:
                lines.append(f"    - {ev[:120]}")
        lines.append(f"- **Analyst notes:** {ft.analyst_notes}")
        lines.append("")

    lines.append("> These targets are investigative starting points. Actual Frida "
                 "hooking should be performed by a qualified analyst in an authorized "
                 "lab environment.")
    lines.append("")


def _sec_surface(lines: list[str], r: ApkAnalysisResult) -> None:
    m = r.metadata
    lines.append("## 3. Surface Analysis")
    lines.append("")
    lines.append("### Hash Identification")
    lines.append(f"- **MD5:** `{m.md5}`")
    lines.append(f"- **SHA-256:** `{m.sha256}`")
    lines.append(f"- **File type:** {m.file_type}")
    lines.append(f"- **File size:** {m.file_size:,} bytes")
    lines.append("")
    lines.append("### Package Metadata")
    lines.append(f"- **Package:** `{m.package_name}`")
    lines.append(f"- **Version:** {m.version_name} (code {m.version_code})")
    lines.append(f"- **minSdk:** {m.min_sdk}  |  **targetSdk:** {m.target_sdk}")
    lines.append(f"- **Main Activity:** `{m.main_activity}`")
    lines.append("")

    lines.append("### Requested Permissions")
    lines.append("")
    if r.permissions:
        lines.append("| Permission | Dangerous | Suspicious |")
        lines.append("|------------|-----------|------------|")
        for p in r.permissions:
            d = "yes" if p.is_dangerous else ""
            s = "yes" if p.is_suspicious else ""
            lines.append(f"| `{p.name}` | {d} | {s} |")
    else:
        lines.append("_No permissions extracted._")
    lines.append("")

    lines.append("### Declared Components")
    lines.append("")
    if r.components:
        lines.append("| Type | Name | Exported | Intent Filters |")
        lines.append("|------|------|----------|----------------|")
        for c in r.components:
            filters = ", ".join(c.intent_filters[:3]) if c.intent_filters else ""
            lines.append(f"| {c.component_type.value} | `{c.name}` | "
                         f"{'yes' if c.exported else 'no'} | {filters} |")
    else:
        lines.append("_No components extracted._")
    lines.append("")


def _sec_static(lines: list[str], r: ApkAnalysisResult) -> None:
    lines.append("## 4. Static Analysis")
    lines.append("")
    if r.behavior_indicators:
        lines.append("### Behavior Indicators")
        lines.append("")
        lines.append("| Category | Pattern | Confidence | Evidence |")
        lines.append("|----------|---------|------------|----------|")
        for b in r.behavior_indicators:
            ev = b.evidence[:80] + "..." if len(b.evidence) > 80 else b.evidence
            lines.append(f"| {b.category} | {b.pattern} | {b.confidence:.1f} | {ev} |")
        lines.append("")
    else:
        lines.append("_No behavior indicators detected._")
        lines.append("")

    if r.native_libs:
        lines.append("### Native Libraries")
        lines.append("")
        for lib in r.native_libs:
            lines.append(f"- `{lib.path}` ({lib.arch}, {lib.size:,} bytes)")
        lines.append("")

    if r.embedded_files:
        lines.append("### Notable Embedded Files")
        lines.append("")
        for ef in r.embedded_files:
            lines.append(f"- `{ef.path}` ({ef.size:,} bytes)")
        lines.append("")


def _sec_campaign(lines: list[str], r: ApkAnalysisResult) -> None:
    lines.append("## 5. Campaign Objective Assessment")
    lines.append("")
    for ca in r.campaign_assessments:
        if ca.similarity == CampaignSimilarity.INSUFFICIENT_EVIDENCE:
            continue
        label = ca.similarity.value.replace("_", " ")
        lines.append(f"### {ca.category}")
        lines.append(f"- **Assessment:** {label} (confidence {ca.confidence:.1f})")
        lines.append(f"- **Matching traits:** {', '.join(ca.matching_traits)}")
        if ca.notes:
            lines.append(f"- **Notes:** {ca.notes}")
        lines.append("")

    no_match = [c for c in r.campaign_assessments if c.similarity == CampaignSimilarity.INSUFFICIENT_EVIDENCE]
    if len(no_match) == len(r.campaign_assessments):
        lines.append("_Insufficient evidence for campaign similarity assessment._")
        lines.append("")

    lines.append("> **Analytic Assessment:** Campaign similarity is based on "
                 "observed TTP-style traits, not on definitive attribution. "
                 "Pending confirmation through dynamic analysis and threat "
                 "intelligence correlation.")
    lines.append("")


def _sec_obfuscation(lines: list[str], r: ApkAnalysisResult) -> None:
    lines.append("## 6. Obfuscation Analysis")
    lines.append("")
    if r.obfuscation_traits:
        for ot in r.obfuscation_traits:
            lines.append(f"### {ot.trait}")
            lines.append(f"- **Confidence:** {ot.confidence.value}")
            lines.append(f"- **Observed Evidence:** {'; '.join(ot.evidence)}")
            if ot.notes:
                lines.append(f"- **Notes:** {ot.notes}")
            lines.append("")
    else:
        lines.append("_No significant obfuscation traits detected._")
        lines.append("")


def _sec_hidden_logic(lines: list[str], r: ApkAnalysisResult) -> None:
    lines.append("## 7. Hidden Business Logic")
    lines.append("")

    # External communication
    comm = [b for b in r.behavior_indicators if b.category == "communication"]
    lines.append("### External Communication")
    if comm or r.network_indicators:
        for b in comm:
            lines.append(f"- **Observed Evidence:** {b.pattern} — {b.evidence}")
        if r.network_indicators:
            lines.append(f"- **Network IOCs:** {len(r.network_indicators)} URL(s)/IP(s) extracted "
                         "(see Section 9)")
    else:
        lines.append("- No external communication indicators observed.")
    lines.append("")

    # Exfiltration
    exfil = [b for b in r.behavior_indicators if b.category == "exfiltration"]
    lines.append("### Data Exfiltration Indicators")
    if exfil:
        for b in exfil:
            lines.append(f"- **Observed Evidence:** {b.pattern} (confidence {b.confidence:.1f})")
    else:
        lines.append("- No data exfiltration indicators observed.")
    lines.append("")

    # Trigger logic
    triggers = [b for b in r.behavior_indicators if b.category == "trigger_logic"]
    lines.append("### Trigger / Activation Logic")
    if triggers:
        for b in triggers:
            lines.append(f"- **Observed Evidence:** {b.pattern} — {b.evidence}")
    else:
        lines.append("- No hidden trigger logic detected.")
    lines.append("")

    lines.append("> **Pending Confirmation:** Dynamic analysis is required to "
                 "confirm whether communication, exfiltration, or trigger logic "
                 "activates at runtime.")
    lines.append("")


def _sec_protections(lines: list[str], r: ApkAnalysisResult) -> None:
    lines.append("## 8. Protection Detection and Dynamic-Analysis Considerations")
    lines.append("")
    if r.protection_indicators:
        for pi in r.protection_indicators:
            lines.append(f"### {pi.protection_type}")
            lines.append(f"- **Status:** `{pi.status.value}`")
            if pi.evidence:
                lines.append(f"- **Observed Evidence:**")
                for ev in pi.evidence:
                    lines.append(f"    - {ev}")
            lines.append(f"- **Analyst Next Steps:** {pi.analyst_next_steps}")
            lines.append("")
    else:
        lines.append("_No protection indicators assessed._")
        lines.append("")


def _sec_indicators(lines: list[str], r: ApkAnalysisResult) -> None:
    lines.append("## 9. Indicators and Extracted Artifacts")
    lines.append("")

    if r.network_indicators:
        lines.append("### Network Indicators")
        lines.append("")
        lines.append("| Type | Value | Source |")
        lines.append("|------|-------|--------|")
        for ni in r.network_indicators[:50]:
            lines.append(f"| {ni.indicator_type} | `{ni.value}` | {ni.source_file} |")
        if len(r.network_indicators) > 50:
            lines.append(f"| ... | {len(r.network_indicators) - 50} more | |")
        lines.append("")

    if r.extracted_paths:
        lines.append(f"### File Inventory ({len(r.extracted_paths)} entries)")
        lines.append("")
        for p in r.extracted_paths[:30]:
            lines.append(f"- `{p}`")
        if len(r.extracted_paths) > 30:
            lines.append(f"- _...{len(r.extracted_paths) - 30} more files_")
        lines.append("")


def _sec_conclusions(lines: list[str], r: ApkAnalysisResult) -> None:
    lines.append("## 10. Conclusions and Recommendations")
    lines.append("")
    lines.append("### Key findings")
    lines.append("")
    strong = [c for c in r.campaign_assessments
              if c.similarity in {CampaignSimilarity.CONSISTENT_WITH, CampaignSimilarity.SHARES_TRAITS}]
    if strong:
        for c in strong:
            label = c.similarity.value.replace("_", " ")
            lines.append(f"- The sample is **{label}** the `{c.category}` category "
                         f"(confidence {c.confidence:.1f}).")
    else:
        lines.append("- No strong campaign similarity was established.")

    active_prot = [p for p in r.protection_indicators if p.status != ProtectionStatus.NOT_OBSERVED]
    if active_prot:
        lines.append(f"- **{len(active_prot)}** anti-analysis protections were detected, "
                     "which may complicate dynamic analysis.")

    susp = [p for p in r.permissions if p.is_suspicious]
    if susp:
        lines.append(f"- **{len(susp)}** suspicious permissions warrant further investigation.")

    if r.vt_enrichment.available and r.vt_enrichment.detections > 0:
        lines.append(f"- VirusTotal detects this sample at **{r.vt_enrichment.detection_ratio}** "
                     f"(external intel — treat as supplementary).")

    if r.frida_targets:
        lines.append(f"- **{len(r.frida_targets)}** Frida validation targets identified for "
                     "analyst-assisted dynamic analysis.")
    lines.append("")

    lines.append("### Recommendations")
    lines.append("")
    lines.append("- **Containment:** If this sample was found on a managed device, isolate "
                 "the device and revoke any credentials that may have been compromised.")
    lines.append("- **Dynamic validation:** Execute Frida hooks against the identified "
                 "targets in a sandboxed lab environment to confirm static hypotheses.")
    lines.append("- **IOC distribution:** Distribute the extracted hashes and network "
                 "indicators to detection/blocking systems after analyst validation.")
    if r.network_indicators:
        lines.append("- **Network monitoring:** Monitor or block the extracted domains/IPs "
                     "at the perimeter after confirming they are not false positives.")
    if r.obfuscation_traits:
        lines.append("- **Unpacking:** If packing/obfuscation was detected, consider "
                     "dumping the unpacked DEX at runtime for deeper static analysis.")
    lines.append("")
    lines.append("> **Evidence classification in this report:**")
    lines.append("> - Sections 3–4: **static fact** (directly observed from artifacts)")
    lines.append("> - Section 5 (campaign): **analytic assessment** (inference from observed traits)")
    lines.append("> - VT enrichment: **external intel** (third-party, supplementary)")
    lines.append("> - Frida targets: **dynamic hypothesis** (requires analyst validation)")
    lines.append("")


def _sec_next_steps(lines: list[str], r: ApkAnalysisResult) -> None:
    lines.append("## 11. Analyst Next Steps")
    lines.append("")
    lines.append("- Conduct dynamic analysis in a sandboxed environment.")
    lines.append("- Verify network indicators against threat intelligence feeds.")
    lines.append("- If protections were detected, prepare Frida scripts for bypass.")
    lines.append("- Validate obfuscation assessment by manual smali/Java review.")
    lines.append("- Correlate campaign indicators with existing intelligence.")
    if r.tools_skipped:
        lines.append(f"- Install missing tools ({', '.join(r.tools_skipped)}) for deeper coverage.")
    lines.append("")
