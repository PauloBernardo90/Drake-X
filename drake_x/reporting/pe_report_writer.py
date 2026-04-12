"""PE static-analysis report writer.

Produces a multi-section Markdown technical report from a
:class:`PeAnalysisResult`. Follows Drake-X reporting doctrine:
every section labels evidence as observed fact, analytic assessment,
or pending confirmation.
"""

from __future__ import annotations

import json
from typing import Any

from ..models.pe import PeAnalysisResult, PeProtectionStatus


def render_pe_markdown(result: PeAnalysisResult) -> str:
    """Render the full PE technical Markdown report."""
    lines: list[str] = []
    _sec_executive(lines, result)
    _sec_methodology(lines, result)
    _sec_surface(lines, result)
    _sec_pe_metadata(lines, result)
    _sec_sections(lines, result)
    _sec_import_risk(lines, result)
    _sec_protection(lines, result)
    _sec_anomalies(lines, result)
    _sec_behavioral_signals(lines, result)
    _sec_recommendations(lines, result)
    return "\n".join(lines).rstrip() + "\n"


def render_pe_executive(result: PeAnalysisResult) -> str:
    """Render a short executive summary."""
    lines: list[str] = []
    _sec_executive(lines, result)
    return "\n".join(lines).rstrip() + "\n"


def render_pe_json(result: PeAnalysisResult) -> str:
    """Render the full analysis result as JSON."""
    return json.dumps(result.model_dump(mode="json"), indent=2, default=str)


# ---------------------------------------------------------------------------
# Section renderers
# ---------------------------------------------------------------------------


def _sec_executive(lines: list[str], r: PeAnalysisResult) -> None:
    m = r.metadata
    h = r.header
    lines.append(f"# PE Static Analysis Report — `{m.sha256[:16]}...`")
    lines.append("")
    lines.append("## 1. Executive Summary")
    lines.append("")
    lines.append(f"**Sample:** `{m.file_path}`")
    lines.append(f"**SHA-256:** `{m.sha256}`")
    lines.append(f"**Type:** {'DLL' if h.is_dll else 'EXE'} ({h.machine.value})")
    lines.append(f"**Size:** {m.file_size:,} bytes")
    lines.append("")
    lines.append(f"The sample contains **{len(r.sections)}** sections, "
                 f"imports **{len(r.imports)}** functions from "
                 f"**{len(set(i.dll for i in r.imports))}** DLL(s), and "
                 f"exports **{len(r.exports)}** function(s).")

    if r.anomalies:
        lines.append(f"**{len(r.anomalies)}** structural anomaly(ies) were detected.")

    high_risk = [f for f in r.import_risk_findings if f.get("risk") == "high"]
    if high_risk:
        cats = sorted(set(f["category"] for f in high_risk))
        lines.append(f"**{len(high_risk)}** high-risk API import(s) in categories: {', '.join(cats)}.")

    prot = r.protection
    prot_list = []
    if prot.aslr_enabled:
        prot_list.append("ASLR")
    if prot.dep_enabled:
        prot_list.append("DEP")
    if prot.cfg_enabled:
        prot_list.append("CFG")
    if prot.safe_seh:
        prot_list.append("SafeSEH")
    if prot.stack_cookies:
        prot_list.append("GS")
    if prot_list:
        lines.append(f"Binary protections enabled: {', '.join(prot_list)}.")
    else:
        lines.append("No binary protections detected (ASLR, DEP, CFG all absent).")

    lines.append("")
    lines.append("> All conclusions separate **observed evidence** from **analytic "
                 "assessment**. Nothing constitutes definitive attribution.")
    lines.append("")


def _sec_methodology(lines: list[str], r: PeAnalysisResult) -> None:
    lines.append("## 2. Methodology")
    lines.append("")
    lines.append("This report was produced by Drake-X PE static analysis using:")
    lines.append("")
    for t in r.tools_ran:
        lines.append(f"- `{t}`")
    if r.tools_skipped:
        lines.append("")
        lines.append("Tools not available (analysis degraded):")
        for t in r.tools_skipped:
            lines.append(f"- `{t}`")
    if r.warnings:
        lines.append("")
        lines.append("**Warnings:**")
        for w in r.warnings:
            lines.append(f"- {w}")
    lines.append("")


def _sec_surface(lines: list[str], r: PeAnalysisResult) -> None:
    m = r.metadata
    lines.append("## 3. Surface Analysis")
    lines.append("")
    lines.append("### Hash Identification")
    lines.append(f"- **MD5:** `{m.md5}`")
    lines.append(f"- **SHA-256:** `{m.sha256}`")
    lines.append(f"- **File type:** {m.file_type}")
    lines.append(f"- **File size:** {m.file_size:,} bytes")
    lines.append("")


def _sec_pe_metadata(lines: list[str], r: PeAnalysisResult) -> None:
    h = r.header
    lines.append("## 4. PE Metadata")
    lines.append("")
    lines.append(f"- **Machine:** {h.machine.value}")
    lines.append(f"- **Image Base:** `{h.image_base}`")
    lines.append(f"- **Entry Point:** `{h.entry_point}`")
    lines.append(f"- **Subsystem:** {h.subsystem}")
    lines.append(f"- **Timestamp:** {h.timestamp}")
    lines.append(f"- **Linker Version:** {h.linker_version}")
    lines.append(f"- **Sections:** {h.number_of_sections}")
    lines.append(f"- **Type:** {'DLL' if h.is_dll else 'EXE'}")
    if h.dll_characteristics:
        lines.append(f"- **DllCharacteristics:** {', '.join(h.dll_characteristics)}")
    lines.append("")


def _sec_sections(lines: list[str], r: PeAnalysisResult) -> None:
    lines.append("## 5. Section Analysis")
    lines.append("")
    if r.sections:
        lines.append("| Section | Virtual Size | Raw Size | Entropy | Flags |")
        lines.append("|---------|-------------|----------|---------|-------|")
        for s in r.sections:
            flags = " ".join(s.characteristics[:3])
            entropy_mark = " **" if s.entropy > 7.0 else ""
            lines.append(
                f"| `{s.name}` | {s.virtual_size:,} | {s.raw_size:,} | "
                f"{s.entropy:.2f}{entropy_mark} | {flags} |"
            )
        lines.append("")
        lines.append("> Entropy > 7.0 may indicate compression or encryption.")
    else:
        lines.append("_No sections extracted._")
    lines.append("")


def _sec_import_risk(lines: list[str], r: PeAnalysisResult) -> None:
    lines.append("## 6. Import Risk Assessment")
    lines.append("")
    lines.append("> **Source classification:** observed evidence (imports directly "
                 "extracted from PE import table)")
    lines.append("")

    if r.import_risk_findings:
        lines.append("| Function | DLL | Category | Risk | ATT&CK |")
        lines.append("|----------|-----|----------|------|--------|")
        for f in r.import_risk_findings[:30]:
            lines.append(
                f"| `{f['function']}` | {f['dll']} | {f['category']} | "
                f"{f['risk']} | {f.get('technique_id', '')} |"
            )
        if len(r.import_risk_findings) > 30:
            lines.append(f"| ... | {len(r.import_risk_findings) - 30} more | | | |")
        lines.append("")
    else:
        lines.append("_No high-risk API imports detected._")
        lines.append("")

    # Summary by category
    if r.import_risk_findings:
        cats: dict[str, int] = {}
        for f in r.import_risk_findings:
            cats[f["category"]] = cats.get(f["category"], 0) + 1
        lines.append("**Summary by category:**")
        for cat, count in sorted(cats.items()):
            lines.append(f"- {cat}: {count} function(s)")
        lines.append("")


def _sec_protection(lines: list[str], r: PeAnalysisResult) -> None:
    lines.append("## 7. Protection Analysis")
    lines.append("")
    lines.append("> **Source classification:** static fact (parsed from PE headers)")
    lines.append("")

    p = r.protection
    lines.append("| Protection | Status |")
    lines.append("|-----------|--------|")
    lines.append(f"| ASLR (DYNAMIC_BASE) | {'Enabled' if p.aslr_enabled else '**Disabled**'} |")
    lines.append(f"| DEP/NX (NX_COMPAT) | {'Enabled' if p.dep_enabled else '**Disabled**'} |")
    lines.append(f"| CFG (GUARD_CF) | {'Enabled' if p.cfg_enabled else 'Disabled'} |")
    lines.append(f"| SafeSEH | {'Enabled' if p.safe_seh else 'Disabled'} |")
    lines.append(f"| Stack Cookies (GS) | {'Detected' if p.stack_cookies else 'Not detected'} |")
    lines.append(f"| High Entropy VA | {'Enabled' if p.high_entropy_va else 'Disabled'} |")
    lines.append(f"| Force Integrity | {'Enabled' if p.force_integrity else 'Disabled'} |")
    lines.append("")

    if p.notes:
        lines.append("**Protection notes:**")
        for n in p.notes:
            lines.append(f"- {n}")
        lines.append("")


def _sec_anomalies(lines: list[str], r: PeAnalysisResult) -> None:
    if not r.anomalies and not r.suspicious_patterns:
        return

    lines.append("## 8. Structural Anomalies")
    lines.append("")

    if r.anomalies:
        lines.append("| Type | Severity | Description |")
        lines.append("|------|----------|-------------|")
        for a in r.anomalies:
            lines.append(f"| {a.anomaly_type} | {a.severity} | {a.description} |")
        lines.append("")

    if r.suspicious_patterns:
        packer = [s for s in r.suspicious_patterns if s.get("finding_type") == "packer_section_name"]
        if packer:
            names = ", ".join(s["section"] for s in packer)
            lines.append(f"**Packer indicators:** section name(s) `{names}` match known packer signatures.")
            lines.append("")

    lines.append("> **Analytic Assessment:** Structural anomalies are indicators, "
                 "not definitive evidence of malicious intent. Legitimate packers "
                 "and build tools may produce similar signatures.")
    lines.append("")


def _sec_behavioral_signals(lines: list[str], r: PeAnalysisResult) -> None:
    lines.append("## 9. Behavioral Signals")
    lines.append("")

    if not r.import_risk_findings:
        lines.append("_No behavioral signals detected from import analysis._")
        lines.append("")
        return

    # Injection chain detection
    injection_funcs = {f["function"].lower() for f in r.import_risk_findings if f["category"] == "injection"}
    has_alloc = bool(injection_funcs & {"virtualallocex", "virtualalloc", "ntallocatevirtualmemory"})
    has_write = bool(injection_funcs & {"writeprocessmemory", "ntwritevirtualmemory"})
    has_thread = bool(injection_funcs & {"createremotethread", "createremotethreadex", "ntcreatethreadex"})

    if has_alloc and has_write and has_thread:
        lines.append("### Process Injection Chain (Suspected)")
        lines.append("")
        lines.append("**Observed Evidence:** The import table contains the classic "
                     "injection API triad: memory allocation (`VirtualAllocEx`), "
                     "memory write (`WriteProcessMemory`), and remote thread "
                     "creation (`CreateRemoteThread`). This combination is "
                     "characteristic of process injection techniques.")
        lines.append("")
        lines.append("**Analytic Assessment:** The presence of these APIs "
                     "**is consistent with** process injection capability "
                     "(MITRE ATT&CK T1055). **Pending confirmation:** dynamic "
                     "analysis required to verify the injection chain activates.")
        lines.append("")

    # Communication patterns
    comm_funcs = [f for f in r.import_risk_findings if f["category"] == "communication"]
    if comm_funcs:
        func_names = ", ".join(f["function"] for f in comm_funcs[:5])
        lines.append("### Network Communication (Observed)")
        lines.append("")
        lines.append(f"**Observed Evidence:** {len(comm_funcs)} networking API(s) "
                     f"imported: {func_names}")
        lines.append("")

    # Evasion patterns
    evasion_funcs = [f for f in r.import_risk_findings if f["category"] == "evasion"]
    if evasion_funcs:
        func_names = ", ".join(f["function"] for f in evasion_funcs[:5])
        lines.append("### Anti-Analysis (Observed)")
        lines.append("")
        lines.append(f"**Observed Evidence:** {len(evasion_funcs)} anti-analysis "
                     f"API(s) imported: {func_names}")
        lines.append("")


def _sec_recommendations(lines: list[str], r: PeAnalysisResult) -> None:
    lines.append("## 10. Validation Recommendations")
    lines.append("")
    lines.append("### Recommended Next Steps")
    lines.append("")

    if r.import_risk_findings:
        injection = [f for f in r.import_risk_findings if f["category"] == "injection"]
        if injection:
            lines.append("- **Dynamic analysis:** Execute in an instrumented sandbox "
                         "to confirm injection chain activation.")
            lines.append("- **Debugger:** Set breakpoints on VirtualAllocEx, "
                         "WriteProcessMemory, and CreateRemoteThread to observe "
                         "injection targets and payload content.")

    if not r.protection.aslr_enabled or not r.protection.dep_enabled:
        lines.append("- **Protection assessment:** Binary lacks standard protections "
                     "— may indicate intentional evasion or legacy build.")

    if r.anomalies:
        lines.append("- **Unpacking:** If packing is confirmed, dump the unpacked "
                     "binary from memory for deeper static analysis.")

    if r.tools_skipped:
        lines.append(f"- **Install missing tools:** {', '.join(r.tools_skipped)} "
                     "for additional analysis coverage.")

    lines.append("- **VirusTotal:** Submit hash for external intelligence enrichment.")
    lines.append("- **Network analysis:** Monitor traffic during sandbox execution "
                 "to identify C2 endpoints.")
    lines.append("")

    lines.append("> **Evidence classification in this report:**")
    lines.append("> - Sections 3-7: **static fact** (directly parsed from PE structure)")
    lines.append("> - Section 8: **observed anomaly** (structural indicators)")
    lines.append("> - Section 9: **analytic assessment** (behavioral inference from imports)")
    lines.append("> - Section 10: **analyst-assisted recommendations** (validation suggestions)")
    lines.append("")
