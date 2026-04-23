"""DEX analysis report generator — structured evidence output.

Converts :class:`DexAnalysisResult` into structured JSON and Markdown
reports suitable for downstream consumption by the Drake-X reporting
pipeline, correlation engine, and human analysts.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..logging import get_logger
from ..models.dex import (
    DexAnalysisResult,
    DexFinding,
    DexFindingSeverity,
    SensitiveApiHit,
)

log = get_logger("dex.report")


def to_json(result: DexAnalysisResult) -> str:
    """Serialize the full analysis result to JSON."""
    return result.model_dump_json(indent=2)


def to_dict(result: DexAnalysisResult) -> dict[str, Any]:
    """Convert analysis result to a plain dict."""
    return result.model_dump()


def write_json_report(
    result: DexAnalysisResult,
    output_path: Path,
) -> Path:
    """Write the full JSON report to disk."""
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(to_json(result), encoding="utf-8")
    log.info("JSON report written to %s", output_path)
    return output_path


def write_markdown_report(
    result: DexAnalysisResult,
    output_path: Path,
    *,
    apk_name: str = "",
) -> Path:
    """Write a human-readable Markdown summary report."""
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    lines = _build_markdown(result, apk_name=apk_name)
    output_path.write_text("\n".join(lines), encoding="utf-8")
    log.info("Markdown report written to %s", output_path)
    return output_path


def consolidate_findings(result: DexAnalysisResult) -> list[DexFinding]:
    """Generate consolidated findings from all analysis results.

    Transforms sensitive API hits, obfuscation indicators, packing
    indicators, and classified strings into a unified DexFinding list.
    """
    findings: list[DexFinding] = list(result.findings)

    # API hits → findings
    for hit in result.sensitive_api_hits:
        findings.append(DexFinding(
            source_tool="sensitive_api_detector",
            dex_origin=hit.source_dex,
            evidence_type="sensitive_api",
            raw_snippet=hit.raw_match,
            normalized_interpretation=(
                f"{hit.api_category.value}: {hit.api_name} detected"
            ),
            confidence=hit.confidence,
            severity=hit.severity,
            category=hit.api_category.value,
            tags=hit.mitre_attck,
        ))

    # Obfuscation indicators → findings
    for ind in result.obfuscation_indicators:
        findings.append(DexFinding(
            source_tool="obfuscation_analyzer",
            evidence_type="obfuscation",
            raw_snippet="; ".join(ind.evidence[:3]),
            normalized_interpretation=ind.description,
            confidence=ind.confidence,
            severity=ind.severity,
            category=f"obfuscation.{ind.signal.value}",
            tags=["obfuscation"],
        ))

    # Packing indicators → findings
    for pi in result.packing_indicators:
        findings.append(DexFinding(
            source_tool="multidex_analyzer",
            evidence_type="packing",
            raw_snippet="; ".join(pi.evidence[:3]),
            normalized_interpretation=pi.description,
            confidence=pi.confidence,
            severity=DexFindingSeverity.MEDIUM,
            category=f"packing.{pi.indicator_type}",
            tags=["packing", "evasion"],
        ))

    # High-confidence IoC strings → findings
    for cs in result.classified_strings:
        if cs.is_potential_ioc and cs.confidence >= 0.7:
            findings.append(DexFinding(
                source_tool="string_classifier",
                dex_origin=cs.source_dex,
                evidence_type="string_ioc",
                raw_snippet=cs.value[:200],
                normalized_interpretation=(
                    f"{cs.category.value} string: {cs.value[:100]}"
                ),
                confidence=cs.confidence,
                severity=DexFindingSeverity.MEDIUM,
                category=f"string.{cs.category.value}",
                tags=["ioc", cs.category.value],
            ))

    return findings


def _build_markdown(
    result: DexAnalysisResult,
    *,
    apk_name: str = "",
) -> list[str]:
    """Build Markdown lines for the report."""
    lines: list[str] = []
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    lines.append(f"# DEX Deep Analysis Report")
    if apk_name:
        lines.append(f"\n**Sample:** `{apk_name}`")
    lines.append(f"**Generated:** {ts}")
    lines.append(f"**Tools used:** {', '.join(result.tools_used) or 'none'}")
    lines.append("")

    # Multi-DEX summary
    lines.append("## Multi-DEX Inventory")
    lines.append("")
    if result.dex_files:
        lines.append("| DEX File | Size | Classes | Methods | Strings |")
        lines.append("|----------|------|---------|---------|---------|")
        for d in result.dex_files:
            lines.append(
                f"| {d.filename} | {d.size:,} | {d.class_count:,} | "
                f"{d.method_count:,} | {d.string_count:,} |"
            )
        lines.append("")
        lines.append(
            f"**Totals:** {result.total_classes:,} classes, "
            f"{result.total_methods:,} methods, "
            f"{result.total_strings:,} strings"
        )
    else:
        lines.append("*No DEX files analyzed.*")
    lines.append("")

    # Sensitive APIs
    if result.sensitive_api_hits:
        lines.append("## Sensitive API Usage")
        lines.append("")
        by_category: dict[str, list[SensitiveApiHit]] = {}
        for hit in result.sensitive_api_hits:
            by_category.setdefault(hit.api_category.value, []).append(hit)

        for cat, hits in sorted(by_category.items()):
            lines.append(f"### {cat}")
            for h in hits:
                sev = f"[{h.severity.value.upper()}]"
                lines.append(f"- {sev} **{h.api_name}** (conf: {h.confidence:.0%})")
                if h.raw_match:
                    lines.append(f"  > `{h.raw_match[:120]}`")
                if h.notes:
                    lines.append(f"  *{h.notes}*")
            lines.append("")

    # Obfuscation
    if result.obfuscation_indicators:
        lines.append("## Obfuscation Assessment")
        lines.append(f"\n**Overall score:** {result.obfuscation_score:.0%}")
        lines.append("")
        for ind in result.obfuscation_indicators:
            lines.append(f"- **{ind.signal.value}** — {ind.description}")
            for e in ind.evidence[:3]:
                lines.append(f"  - {e}")
        lines.append("")

    # Packing indicators
    if result.packing_indicators:
        lines.append("## Packing / Multi-DEX Indicators")
        lines.append("")
        for pi in result.packing_indicators:
            lines.append(f"- **{pi.indicator_type}**: {pi.description}")
        lines.append("")

    # Classified strings
    ioc_strings = [s for s in result.classified_strings if s.is_potential_ioc]
    if ioc_strings:
        lines.append("## Notable Strings (Potential IoCs)")
        lines.append("")
        for s in ioc_strings[:50]:
            lines.append(f"- [{s.category.value}] `{s.value[:100]}`")
        if len(ioc_strings) > 50:
            lines.append(f"\n*… and {len(ioc_strings) - 50} more*")
        lines.append("")

    # Call graph summary
    if result.call_edges:
        lines.append("## Call Graph Summary")
        lines.append(f"\n**Edges:** {len(result.call_edges):,}")
        lines.append("")

    # Warnings
    if result.warnings:
        lines.append("## Warnings")
        lines.append("")
        for w in result.warnings:
            lines.append(f"- {w}")
        lines.append("")

    # Phases completed
    if result.analysis_phases_completed:
        lines.append("## Analysis Phases")
        lines.append("")
        for phase in result.analysis_phases_completed:
            lines.append(f"- [x] {phase}")
        lines.append("")

    lines.append("---")
    lines.append("*Generated by Drake-X DEX Analysis Pipeline*")

    return lines
