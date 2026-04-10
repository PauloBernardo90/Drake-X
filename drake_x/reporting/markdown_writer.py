"""Technical Markdown report writer (v2).

This is the production report renderer. Compared to the v1 renderer
(still at :mod:`drake_x.reports.markdown` for internal test use), v2
adds:

- **Findings table** with severity sorting and inline CWE / OWASP badges
- **Evidence links** on each finding pointing back to the artifact that
  produced it
- **Remediation column** when present
- **Run timeline** from tool results
- **Fact vs inference labels** on every finding

The output is self-contained Markdown, pasteable into any report tool
that supports CommonMark.
"""

from __future__ import annotations

from typing import Any

from ..constants import AUTHORIZED_USE_NOTICE
from ..models.artifact import Artifact
from ..models.finding import Finding, FindingSeverity
from ..models.session import Session
from ..models.tool_result import ToolResult
from ..utils.timefmt import isoformat_utc

_SEVERITY_ORDER = {
    FindingSeverity.CRITICAL: 0,
    FindingSeverity.HIGH: 1,
    FindingSeverity.MEDIUM: 2,
    FindingSeverity.LOW: 3,
    FindingSeverity.INFO: 4,
}


def render_markdown_report(
    *,
    session: Session,
    tool_results: list[ToolResult],
    artifacts: list[Artifact],
    findings: list[Finding],
) -> str:
    """Render a full technical Markdown report for one session."""
    lines: list[str] = []
    _section_header(lines, session)
    _section_target(lines, session)
    _section_tools(lines, session, tool_results, artifacts)
    _section_timeline(lines, tool_results)
    _section_observations(lines, artifacts)
    _section_findings(lines, findings, session)
    _section_closing(lines)
    return "\n".join(lines).rstrip() + "\n"


# ----- sections ---------------------------------------------------------------


def _section_header(lines: list[str], session: Session) -> None:
    lines.append(f"# Drake-X Technical Report — `{session.id}`")
    lines.append("")
    lines.append(f"> {AUTHORIZED_USE_NOTICE}")
    lines.append("")
    lines.append("## Session metadata")
    lines.append("")
    lines.append(f"- **Session ID:** `{session.id}`")
    lines.append(f"- **Profile:** `{session.profile}`")
    lines.append(f"- **Status:** `{session.status.value}`")
    lines.append(f"- **Started:** {isoformat_utc(session.started_at)}")
    if session.finished_at:
        lines.append(f"- **Finished:** {isoformat_utc(session.finished_at)}")
    if session.duration_seconds is not None:
        lines.append(f"- **Duration:** {session.duration_seconds:.1f}s")
    lines.append("")


def _section_target(lines: list[str], session: Session) -> None:
    t = session.target
    lines.append("## Target")
    lines.append("")
    lines.append(f"- **Raw input:** `{t.raw}`")
    lines.append(f"- **Canonical:** `{t.canonical}`")
    lines.append(f"- **Type:** `{t.target_type}`")
    lines.append(f"- **Host:** `{t.host}`")
    if t.cidr_prefix is not None:
        lines.append(f"- **Prefix length:** /{t.cidr_prefix}")
    if t.url_scheme:
        lines.append(f"- **URL scheme:** `{t.url_scheme}`")
        if t.url_port:
            lines.append(f"- **URL port:** `{t.url_port}`")
        if t.url_path:
            lines.append(f"- **URL path:** `{t.url_path}`")
    lines.append("")


def _section_tools(
    lines: list[str],
    session: Session,
    tool_results: list[ToolResult],
    artifacts: list[Artifact],
) -> None:
    lines.append("## Tools")
    lines.append("")
    lines.append(f"- **Planned:** {_inline(session.tools_planned)}")
    lines.append(f"- **Ran:** {_inline(session.tools_ran)}")
    lines.append(f"- **Skipped / missing:** {_inline(session.tools_skipped)}")
    if session.warnings:
        lines.append("- **Warnings:**")
        for w in session.warnings:
            lines.append(f"    - {w}")
    lines.append("")

    if tool_results:
        lines.append("### Execution summary")
        lines.append("")
        lines.append("| Tool | Status | Exit | Duration | Notes |")
        lines.append("|------|--------|------|----------|-------|")
        for r in tool_results:
            dur = f"{r.duration_seconds:.1f}s" if r.duration_seconds is not None else "—"
            note = (r.error_message or "").splitlines()[0] if r.error_message else ""
            lines.append(
                f"| `{r.tool_name}` | `{r.status.value}` | `{r.exit_code}` | {dur} | {note} |"
            )
        lines.append("")

    degraded = [a for a in artifacts if a.degraded]
    if degraded:
        lines.append(
            "> Some artifacts below were derived from a **degraded** tool "
            "execution. They are flagged inline and their confidence is reduced."
        )
        lines.append("")


def _section_timeline(lines: list[str], tool_results: list[ToolResult]) -> None:
    if not tool_results:
        return
    lines.append("### Timeline")
    lines.append("")
    lines.append("| Tool | Started | Duration |")
    lines.append("|------|---------|----------|")
    for r in sorted(tool_results, key=lambda x: x.started_at):
        started = isoformat_utc(r.started_at) or "?"
        dur = f"{r.duration_seconds:.2f}s" if r.duration_seconds else "—"
        lines.append(f"| `{r.tool_name}` | {started} | {dur} |")
    lines.append("")


def _section_observations(lines: list[str], artifacts: list[Artifact]) -> None:
    if not artifacts:
        return
    lines.append("## Observations")
    lines.append("")
    for art in artifacts:
        _emit_provenance(lines, art)
        lines.append(f"### `{art.kind}` ({art.tool_name})")
        lines.append("")
        _render_payload_summary(lines, art.payload)
        lines.append("")


def _section_findings(lines: list[str], findings: list[Finding], session: Session) -> None:
    if session.ai_enabled and session.ai_summary:
        lines.append("## AI triage (local Ollama)")
        lines.append("")
        if session.ai_model:
            lines.append(f"_Model:_ `{session.ai_model}`")
            lines.append("")
        lines.append("**Executive summary**")
        lines.append("")
        lines.append(session.ai_summary)
        lines.append("")

    if not findings:
        return

    sorted_findings = sorted(
        findings, key=lambda f: _SEVERITY_ORDER.get(f.severity, 99)
    )

    lines.append("## Findings")
    lines.append("")
    lines.append("| Severity | Title | Source | Confidence | CWE | OWASP |")
    lines.append("|----------|-------|--------|------------|-----|-------|")
    for f in sorted_findings:
        cwe = ", ".join(f.cwe) if f.cwe else "—"
        owasp = ", ".join(f.owasp) if f.owasp else "—"
        lines.append(
            f"| `{f.severity.value}` | {f.title} | "
            f"`{f.source.value}` ({f.fact_or_inference}) | "
            f"{f.confidence:.2f} | {cwe} | {owasp} |"
        )
    lines.append("")

    lines.append("### Finding details")
    lines.append("")
    for f in sorted_findings:
        lines.append(f"#### [{f.severity.value}] {f.title}")
        lines.append("")
        lines.append(f"{f.summary}")
        lines.append("")
        lines.append(f"- **Source:** `{f.source.value}` ({f.fact_or_inference})")
        lines.append(f"- **Confidence:** {f.confidence:.2f}")
        if f.cwe:
            lines.append(f"- **CWE:** {', '.join(f.cwe)}")
        if f.owasp:
            lines.append(f"- **OWASP:** {', '.join(f.owasp)}")
        if f.mitre_attck:
            lines.append(f"- **MITRE ATT&CK:** {', '.join(f.mitre_attck)}")
        if f.evidence:
            lines.append("- **Evidence:**")
            for ev in f.evidence:
                excerpt = f" — `{ev.excerpt}`" if ev.excerpt else ""
                lines.append(f"    - `{ev.artifact_kind}` ({ev.tool_name}){excerpt}")
        if f.remediation:
            lines.append(f"- **Remediation:** {f.remediation}")
        if f.recommended_next_steps:
            lines.append("- **Safe next steps:**")
            for step in f.recommended_next_steps:
                lines.append(f"    - {step}")
        if f.caveats:
            lines.append("- **Caveats:**")
            for c in f.caveats:
                lines.append(f"    - {c}")
        if f.tags:
            lines.append(f"- **Tags:** {', '.join(f.tags)}")
        lines.append("")


def _section_closing(lines: list[str]) -> None:
    lines.append("## Analyst guidance")
    lines.append("")
    lines.append(
        "All observations above are produced by automated tooling, parsers, "
        "and (where noted) a local LLM. They MUST be validated by a human "
        "analyst before being treated as authoritative. Drake-X limits "
        "itself to safe reconnaissance and does not perform exploitation."
    )
    lines.append("")


# ----- helpers ---------------------------------------------------------------


def _inline(values: list[str]) -> str:
    if not values:
        return "_none_"
    return ", ".join(f"`{v}`" for v in values)


def _emit_provenance(lines: list[str], artifact: Artifact) -> None:
    if not artifact.degraded:
        return
    exit_str = (
        f", exit_code={artifact.exit_code}" if artifact.exit_code is not None else ""
    )
    lines.append(
        f"_Degraded execution — tool_status=`{artifact.tool_status}`{exit_str}, "
        f"confidence={artifact.confidence:.2f}_"
    )


def _render_payload_summary(lines: list[str], payload: dict[str, Any]) -> None:
    """Render a short summary of an artifact payload.

    For known shapes (records, hosts, hits, endpoints) we render a
    structured excerpt. For everything else we fall back to a key listing.
    """
    for key, val in payload.items():
        if isinstance(val, list) and val:
            lines.append(f"- **{key}:** {len(val)} item(s)")
            for item in val[:5]:
                if isinstance(item, dict):
                    summary = ", ".join(f"{k}={v}" for k, v in list(item.items())[:3])
                    lines.append(f"    - {summary}")
                else:
                    lines.append(f"    - `{item}`")
            if len(val) > 5:
                lines.append(f"    - _…{len(val) - 5} more_")
        elif isinstance(val, dict) and val:
            lines.append(f"- **{key}:** {len(val)} key(s)")
        elif val is not None:
            lines.append(f"- **{key}:** `{val}`")
