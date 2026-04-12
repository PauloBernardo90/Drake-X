"""Render a :class:`ValidationPlan` as analyst-readable Markdown."""

from __future__ import annotations

from ..models.validation_plan import ValidationPlan


def render_validation_plan_markdown(plan: ValidationPlan) -> str:
    lines: list[str] = []
    lines.append(f"# Validation Plan — session `{plan.session_id[:16]}`")
    lines.append("")
    lines.append(f"Total items: **{len(plan.items)}**.")
    lines.append("")

    if not plan.items:
        lines.append("_No validation items were generated for this session._")
        lines.append("")
    else:
        for item in plan.items:
            lines.append(f"## {item.item_id} — {item.hypothesis}")
            lines.append("")
            lines.append(f"- **Domain:** {item.domain}")
            lines.append(f"- **Priority:** {item.priority}")
            lines.append(f"- **Status:** {item.status}")
            lines.append(f"- **Rationale:** {item.rationale}")
            if item.suggested_tool:
                lines.append(f"- **Suggested tool:** {item.suggested_tool}")
            if item.expected_evidence:
                lines.append(f"- **Expected evidence:** {item.expected_evidence}")
            if item.suggested_steps:
                lines.append("- **Suggested steps:**")
                for s in item.suggested_steps:
                    lines.append(f"  - {s}")
            if item.evidence_node_ids:
                lines.append("- **Backing evidence nodes:**")
                for n in item.evidence_node_ids:
                    lines.append(f"  - `{n}`")
            lines.append("")

    for c in plan.caveats:
        lines.append(f"> {c}")
    lines.append("")
    return "\n".join(lines)
