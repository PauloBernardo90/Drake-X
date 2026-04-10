"""``drake web`` — focused web inspection commands.

These are convenience wrappers around the engine that pin the module to a
web-oriented one. They keep the CLI verb-friendly without duplicating the
engine logic from :mod:`drake_x.cli.recon_cmd`.
"""

from __future__ import annotations

import typer

from .recon_cmd import run_cmd

app = typer.Typer(no_args_is_help=True, help="Web fingerprinting and inspection.")


@app.command("inspect")
def inspect(
    url: str = typer.Argument(..., help="Target URL or domain."),
    workspace: str = typer.Option(None, "--workspace", "-w", help="Workspace name or path."),
    yes: bool = typer.Option(False, "--yes", "-y", help="Pre-approve confirmation gates."),
    ai: bool = typer.Option(False, "--ai", help="Enable AI triage."),
    dry_run: bool = typer.Option(False, "--dry-run", help="Plan only; do not execute tools."),
) -> None:
    """Run the ``web_inspect`` module against a URL/domain."""
    run_cmd(
        target=url,
        module="web_inspect",
        workspace=workspace,
        dry_run=dry_run,
        yes=yes,
        ai=ai,
        timeout=None,
    )
