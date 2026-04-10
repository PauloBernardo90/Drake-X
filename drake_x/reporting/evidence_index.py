"""Evidence index builder.

The evidence index is a Markdown table mapping each artifact back to the
tool, command line, and confidence value that produced it. The goal is
auditability — an analyst should be able to scan one page and see what was
collected, by what, and how confident the parser was.
"""

from __future__ import annotations

from ..models.artifact import Artifact


def build_evidence_index(artifacts: list[Artifact]) -> str:
    """Render a Markdown evidence index for one session's artifacts."""
    if not artifacts:
        return "_No artifacts produced for this session._\n"

    lines: list[str] = []
    lines.append("# Evidence index")
    lines.append("")
    lines.append("| Tool | Kind | Confidence | Degraded | Notes |")
    lines.append("|------|------|------------|----------|-------|")
    for art in artifacts:
        notes = "; ".join(art.notes) if art.notes else ""
        lines.append(
            f"| `{art.tool_name}` | `{art.kind}` | {art.confidence:.2f} | "
            f"{'yes' if art.degraded else 'no'} | {notes} |"
        )
    lines.append("")
    return "\n".join(lines)
