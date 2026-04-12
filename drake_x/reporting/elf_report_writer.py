"""ELF static-analysis report writer (v1.0)."""

from __future__ import annotations

import json

from ..models.elf import ElfAnalysisResult


def render_elf_json(result: ElfAnalysisResult) -> str:
    return json.dumps(result.model_dump(mode="json"), indent=2, default=str)


def render_elf_markdown(result: ElfAnalysisResult) -> str:
    m, h, p = result.metadata, result.header, result.protection
    lines = [
        f"# ELF Static Analysis Report — `{m.sha256[:16]}...`",
        "",
        "## 1. Surface",
        "",
        f"- **File:** `{m.file_path}`",
        f"- **SHA-256:** `{m.sha256}`",
        f"- **MD5:** `{m.md5}`",
        f"- **Size:** {m.file_size:,} bytes",
        f"- **Arch:** {h.arch.value} ({h.bits}-bit, "
        f"{'little' if h.little_endian else 'big'}-endian)",
        f"- **Type:** {h.file_type}",
        f"- **Entry:** `{h.entry_point}`",
        "",
        "## 2. Methodology",
        "",
    ]
    for t in result.tools_ran:
        lines.append(f"- `{t}`")
    if result.tools_skipped:
        lines.append("")
        lines.append("Tools not available (analysis degraded):")
        for t in result.tools_skipped:
            lines.append(f"- `{t}`")
    if result.warnings:
        lines.append("")
        lines.append("**Warnings:**")
        for w in result.warnings:
            lines.append(f"- {w}")
    lines.append("")

    lines.append("## 3. Protections")
    lines.append("")
    lines.append("| Protection | Status |")
    lines.append("|------------|--------|")
    lines.append(f"| NX         | {'Enabled' if p.nx_enabled else '**Disabled**'} |")
    lines.append(f"| PIE        | {'Enabled' if p.pie_enabled else 'Disabled'} |")
    lines.append(f"| RELRO      | {p.relro} |")
    lines.append(f"| Stack canary | {'Detected' if p.canary else 'Not detected'} |")
    lines.append(f"| FORTIFY_SOURCE | {'Detected' if p.fortify_source else 'Not detected'} |")
    lines.append("")

    if result.sections:
        lines.append("## 4. Sections")
        lines.append("")
        lines.append("| Name | Size | Flags |")
        lines.append("|------|------|-------|")
        for s in result.sections[:40]:
            lines.append(f"| `{s.name}` | {s.size:,} | {' '.join(s.flags)} |")
        if len(result.sections) > 40:
            lines.append(f"| ... | {len(result.sections) - 40} more | |")
        lines.append("")

    if result.import_risk_findings:
        lines.append("## 5. Import Risk Assessment")
        lines.append("")
        lines.append("| Symbol | Library | Category | ATT&CK |")
        lines.append("|--------|---------|----------|--------|")
        for f in result.import_risk_findings[:40]:
            lines.append(
                f"| `{f['symbol']}` | {f.get('library', '')} | "
                f"{f['category']} | {f.get('technique_id', '')} |"
            )
        lines.append("")
    else:
        lines.append("## 5. Import Risk Assessment")
        lines.append("")
        lines.append("_No high-risk imports detected._")
        lines.append("")

    lines.append("> v1.0 ELF analysis covers surface, imports, and protections. "
                 "Exploit-awareness parity with PE (indicators, shellcode "
                 "carving, protection-interaction) is intentionally deferred.")
    lines.append("")
    return "\n".join(lines)
