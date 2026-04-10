"""Executive Markdown report writer.

The executive report is short, non-technical, and clearly distinguishes
parser facts from AI inferences. It is designed to be readable by an
engagement stakeholder who is not the analyst.
"""

from __future__ import annotations

from ..constants import AUTHORIZED_USE_NOTICE
from ..models.artifact import Artifact
from ..models.finding import Finding
from ..models.session import Session


def render_executive_report(
    *,
    session: Session,
    artifacts: list[Artifact],
    findings: list[Finding],
) -> str:
    """Render a one-page-ish executive Markdown summary."""
    lines: list[str] = []
    lines.append(f"# Drake-X Executive Summary — `{session.id}`")
    lines.append("")
    lines.append(f"> {AUTHORIZED_USE_NOTICE}")
    lines.append("")

    lines.append("## Engagement context")
    lines.append("")
    lines.append(f"- **Target:** `{session.target.canonical}` ({session.target.target_type})")
    lines.append(f"- **Profile:** `{session.profile}`")
    lines.append(f"- **Status:** `{session.status.value}`")
    if session.duration_seconds is not None:
        lines.append(f"- **Duration:** {session.duration_seconds:.1f}s")
    lines.append("")

    lines.append("## What was assessed")
    lines.append("")
    lines.append(
        f"Drake-X collected {len(artifacts)} normalized observations from "
        f"{len(session.tools_ran)} integrations against the target above. "
        "All observations were produced by automated tooling and require "
        "human validation."
    )
    lines.append("")

    if session.ai_enabled and session.ai_summary:
        lines.append("## AI triage (advisory only)")
        lines.append("")
        if session.ai_model:
            lines.append(f"_Model:_ `{session.ai_model}`")
            lines.append("")
        lines.append(session.ai_summary)
        lines.append("")

    if findings:
        # Show only the top severities for the executive view.
        notable = [
            f
            for f in findings
            if f.severity.value in {"high", "critical", "medium"}
        ]
        if notable:
            lines.append("## Notable findings")
            lines.append("")
            for f in notable:
                lines.append(
                    f"- **[{f.severity.value}] {f.title}** "
                    f"_(confidence {f.confidence:.2f}, source `{f.source.value}`, "
                    f"`{f.fact_or_inference}`)_"
                )
                lines.append(f"    {f.summary}")
            lines.append("")

    if session.warnings:
        lines.append("## Caveats")
        lines.append("")
        for w in session.warnings:
            lines.append(f"- {w}")
        lines.append("")

    lines.append("## Closing reminder")
    lines.append("")
    lines.append(
        "Every observation in this report was produced by automated tooling "
        "or by a local LLM operating under defensive constraints. Drake-X "
        "deliberately stops short of exploitation. Human analyst validation "
        "is required before any of these observations are treated as "
        "authoritative."
    )
    lines.append("")

    return "\n".join(lines).rstrip() + "\n"
