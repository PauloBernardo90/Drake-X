"""``drake correlate`` — cross-sample evidence correlation (v1.0)."""

from __future__ import annotations

import json

import typer

from ..cli_theme import info, make_console, success, warn
from ..correlation import correlate_samples
from . import _shared

app = typer.Typer(
    no_args_is_help=True,
    help="Cross-sample correlation over the workspace evidence graph store.",
)


@app.command("run")
def run(
    workspace: str = typer.Option(..., "--workspace", "-w", help="Workspace name or path."),
    min_shared: int = typer.Option(2, "--min-shared", help="Minimum shared-evidence count."),
    output: str = typer.Option(
        "text", "--format", "-f",
        help="Output format: 'text' or 'json'.",
    ),
) -> None:
    """Compute pairwise evidence-backed correlations across the workspace."""
    console = make_console()
    ws = _shared.resolve_workspace(workspace)
    report = correlate_samples(ws.storage, min_shared=min_shared)

    if output == "json":
        print(report.model_dump_json(indent=2))
        return

    info(console, f"sessions scanned:  [accent]{report.session_count}[/accent]")
    info(console, f"correlations:      [accent]{len(report.correlations)}[/accent]")
    if not report.correlations:
        warn(console, "no correlations surfaced at this min_shared threshold")
        return

    for c in report.correlations:
        success(console, f"{c.source_session[:12]} ↔ {c.target_session[:12]}  "
                f"(score={c.score:.2f}, shared={c.total_shared})")
        for s in c.shared[:5]:
            info(console, f"   · {s.basis}: {s.value}")
        if len(c.shared) > 5:
            info(console, f"   · ... {len(c.shared) - 5} more")
    for caveat in report.caveats:
        info(console, f"[dim]caveat: {caveat}[/dim]")
