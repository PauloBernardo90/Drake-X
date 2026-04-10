"""Presentation layer for the Drake-X CLI.

This module is the single place the CLI looks up visual styling: the theme
(a small set of named Rich styles), the compact brand header, and a handful
of helpers for rendering section titles, status lines, and the post-scan
summary.

Design direction is "cyberpunk-adjacent operator console" with restraint:

- Cyan / bright blue is the primary accent.
- Muted amber/gold is the secondary accent.
- White and gray are the neutral text colors.
- Red is reserved strictly for real errors (never missing tools, warnings,
  or informational state).
- One subtle skull glyph appears once, in the brand header.

The module does not import from the execution layer at runtime; it only
references :class:`drake_x.orchestrator.ScanReport` under ``TYPE_CHECKING``
so it stays cheap to import from test code.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.theme import Theme

if TYPE_CHECKING:  # pragma: no cover - type-check only
    from .orchestrator import ScanReport


# ─────────────────────────────────────────────────────────────────────────────
# THEME
# ─────────────────────────────────────────────────────────────────────────────


#: Named styles used throughout the Drake-X CLI. Keeping all color choices
#: in one place means a single edit here changes the whole tool's look.
THEME = Theme(
    {
        # Brand / primary accent — cyan spectrum.
        "brand": "bold bright_cyan",
        "brand.skull": "bright_cyan",
        "brand.sub": "italic grey62",
        "accent": "bright_cyan",
        "accent.rule": "cyan",
        # Secondary accent — muted amber, used sparingly.
        "accent.secondary": "gold3",
        # Semantic roles. Red is *only* danger.
        "ok": "bold green",
        "warn": "bold yellow",
        "danger": "bold red",
        "info": "bright_blue",
        # Neutrals.
        "label": "bold white",
        "value": "white",
        "muted": "grey58",
        # Notices and meta text.
        "notice": "italic grey62",
        # Section marks.
        "title": "bold bright_cyan",
        "subtitle": "dim bright_cyan",
    }
)


def make_console() -> Console:
    """Return a :class:`Console` preloaded with the Drake-X theme.

    ``highlight=False`` prevents Rich from auto-coloring numbers, paths and
    other literals — we want explicit control over every accent.
    """
    return Console(theme=THEME, highlight=False)


# ─────────────────────────────────────────────────────────────────────────────
# BRAND HEADER
# ─────────────────────────────────────────────────────────────────────────────


def render_header(console: Console, *, version: str | None = None) -> None:
    """Render the compact Drake-X brand header.

    The header is intentionally small: four lines inside a heavy-border
    panel, ~56 columns wide. Uses a single ``☠`` glyph as the only pirate
    motif. Falls back gracefully on terminals without color.
    """
    version_tag = f"  [muted]v{version}[/muted]" if version else ""
    body = (
        f"[brand.skull]☠[/brand.skull]  "
        f"[brand]DRAKE·X[/brand]{version_tag}\n"
        f"[brand.sub]local-first · scope-enforced · evidence-driven[/brand.sub]"
    )
    console.print(
        Panel(
            body,
            box=box.HEAVY,
            border_style="accent.rule",
            padding=(0, 2),
            expand=False,
        )
    )


# ─────────────────────────────────────────────────────────────────────────────
# STATUS LINES
# ─────────────────────────────────────────────────────────────────────────────


def success(console: Console, message: str) -> None:
    """Green ``✓`` prefix. Use for completed operations."""
    console.print(f"[ok]✓[/ok]  {message}")


def info(console: Console, message: str) -> None:
    """Blue ``›`` prefix. Use for neutral progress/state messages."""
    console.print(f"[info]›[/info]  [value]{message}[/value]")


def warn(console: Console, message: str) -> None:
    """Amber ``!`` prefix. Use for recoverable degradations, missing tools,
    non-fatal conditions. *Not* for errors."""
    console.print(f"[warn]![/warn]  [warn]{message}[/warn]")


def error(console: Console, message: str) -> None:
    """Red ``✗`` prefix. Use only for real errors that stop execution."""
    console.print(f"[danger]✗[/danger]  [danger]{message}[/danger]")


# ─────────────────────────────────────────────────────────────────────────────
# SCAN SUMMARY
# ─────────────────────────────────────────────────────────────────────────────


#: Map from :class:`SessionStatus` values to theme styles. Hard-coded as
#: strings so this module does not have to import the model layer.
_STATUS_STYLE: dict[str, str] = {
    "completed": "ok",
    "partial": "warn",
    "failed": "danger",
    "running": "info",
    "pending": "muted",
}


def render_scan_summary(
    console: Console,
    report: ScanReport,
    report_path: Path | None,
    authorized_use_notice: str,
) -> None:
    """Render the interactive post-scan summary.

    The body is a two-column label/value grid inside a bordered panel so
    all the key facts line up vertically and the eye can find them fast.
    Warnings and the AI executive summary, when present, are rendered in
    their own panels so an operator can scan them independently from the
    main status block.
    """
    s = report.session
    status = s.status.value
    status_style = _STATUS_STYLE.get(status, "value")

    grid = Table.grid(padding=(0, 2), expand=False)
    grid.add_column(justify="right", style="label", no_wrap=True)
    grid.add_column(style="value", overflow="fold")

    grid.add_row("Session", f"[accent]{s.id}[/accent]")
    grid.add_row(
        "Target",
        f"{s.target.canonical}  [muted]({s.target.target_type})[/muted]",
    )
    grid.add_row(
        "Profile",
        f"[accent.secondary]{s.profile}[/accent.secondary]",
    )
    grid.add_row(
        "Status",
        f"[{status_style}]{status}[/{status_style}]",
    )
    grid.add_row(
        "Tools ran",
        ", ".join(s.tools_ran) if s.tools_ran else "[muted]—[/muted]",
    )
    if s.tools_skipped:
        grid.add_row(
            "Skipped",
            f"[warn]{', '.join(s.tools_skipped)}[/warn]",
        )
    grid.add_row("Artifacts", f"{len(report.artifacts)}")
    if s.ai_enabled:
        grid.add_row(
            "AI analysis",
            f"[ok]enabled[/ok]  [muted]({s.ai_model})[/muted]",
        )
    else:
        grid.add_row("AI analysis", "[muted]disabled[/muted]")
    if report_path is not None:
        grid.add_row("Report", f"[accent]{report_path}[/accent]")

    console.print()
    console.print(
        Panel(
            grid,
            title="[title]scan summary[/title]",
            title_align="left",
            border_style="accent.rule",
            box=box.HEAVY,
            padding=(1, 2),
            expand=False,
        )
    )

    if s.warnings:
        console.print()
        warnings_body = "\n".join(f"[warn]·[/warn] {w}" for w in s.warnings)
        console.print(
            Panel(
                warnings_body,
                title="[warn]warnings[/warn]",
                title_align="left",
                border_style="warn",
                box=box.HEAVY,
                padding=(0, 2),
                expand=False,
            )
        )

    if s.ai_enabled and s.ai_summary:
        console.print()
        console.print(
            Panel(
                s.ai_summary,
                title=(
                    "[title]AI executive summary[/title]"
                    f"  [muted]{s.ai_model}[/muted]"
                ),
                title_align="left",
                border_style="accent.rule",
                box=box.HEAVY,
                padding=(0, 2),
                expand=False,
            )
        )

    console.print()
    console.print(f"[notice]{authorized_use_notice}[/notice]")


# ─────────────────────────────────────────────────────────────────────────────
# TOOLS LIST
# ─────────────────────────────────────────────────────────────────────────────


def build_tools_table() -> Table:
    """Return an empty, pre-styled Table for ``drake-x tools list``.

    Rows are added by the caller so this helper stays decoupled from the
    registry layer.
    """
    table = Table(
        title="[title]supported tools[/title]",
        title_style="title",
        border_style="accent.rule",
        header_style="label",
        box=box.HEAVY,
        show_lines=False,
        pad_edge=True,
        expand=False,
    )
    table.add_column("Tool", style="brand", no_wrap=True)
    table.add_column("Installed", justify="left", no_wrap=True)
    table.add_column("Profiles", style="muted")
    table.add_column("Targets", style="muted")
    table.add_column("Description", style="value", overflow="fold")
    return table


def format_tool_installed(installed: bool) -> str:
    """Return the styled "Installed" cell for a tool row."""
    return "[ok]✓ yes[/ok]" if installed else "[warn]✗ no[/warn]"


__all__ = [
    "THEME",
    "make_console",
    "render_header",
    "success",
    "info",
    "warn",
    "error",
    "render_scan_summary",
    "build_tools_table",
    "format_tool_installed",
]
