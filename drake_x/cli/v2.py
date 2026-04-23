"""Drake-X CLI root.

This module wires the per-command Typer subcommands into the single
``drake`` application. Each subcommand lives in its own module so they
stay small and testable.
"""

from __future__ import annotations

import typer

from .. import __version__
from ..cli_theme import make_console
from ..constants import APP_DISPLAY_NAME, AUTHORIZED_USE_NOTICE
from .banner import render_banner
from . import (
    ai_cmd,
    api_cmd,
    apk_cmd,
    assist_cmd,
    correlate_cmd,
    elf_cmd,
    findings_cmd,
    flow_cmd,
    frida_cmd,
    graph_cmd,
    ingest_cmd,
    init_cmd,
    integrity_cmd,
    ioc_cmd,
    mission_cmd,
    pe_cmd,
    recon_cmd,
    report_cmd,
    sandbox_cmd,
    scope_cmd,
    status_cmd,
    tools_cmd,
    validate_cmd,
    web_cmd,
)

app = typer.Typer(
    name="drake",
    add_completion=False,
    no_args_is_help=True,
    rich_markup_mode="rich",
    help=(
        f"[bold cyan]{APP_DISPLAY_NAME} v{__version__}[/bold cyan] — "
        "AI-assisted evidence-driven malware analysis platform.\n\n"
        f"[bold yellow]{AUTHORIZED_USE_NOTICE}[/bold yellow]\n\n"
        "Drake-X is an operator-driven malware analysis, threat "
        "investigation, and reporting platform. The local LLM assists; "
        "it never replaces a human analyst, and the framework refuses "
        "to perform exploitation."
    ),
)

@app.callback()
def _startup(ctx: typer.Context) -> None:
    """Print the Drake-X banner once before the selected subcommand runs."""
    render_banner(make_console())


# Register subcommand groups.
app.add_typer(mission_cmd.app, name="mission")
app.add_typer(assist_cmd.app, name="assist")
app.add_typer(flow_cmd.app, name="flow")
app.add_typer(status_cmd.app, name="status")
app.add_typer(init_cmd.app, name="init")
app.add_typer(scope_cmd.app, name="scope")
app.add_typer(recon_cmd.app, name="recon")
app.add_typer(web_cmd.app, name="web")
app.add_typer(api_cmd.app, name="api")
app.add_typer(apk_cmd.app, name="apk")
app.add_typer(graph_cmd.app, name="graph")
app.add_typer(ioc_cmd.app, name="ioc")
app.add_typer(pe_cmd.app, name="pe")
app.add_typer(frida_cmd.app, name="frida")
app.add_typer(findings_cmd.app, name="findings")
app.add_typer(ai_cmd.app, name="ai")
app.add_typer(report_cmd.app, name="report")
app.add_typer(tools_cmd.app, name="tools")

# v1.0 platform additions
app.add_typer(correlate_cmd.app, name="correlate")
app.add_typer(ingest_cmd.app, name="ingest")
app.add_typer(validate_cmd.app, name="validate")
app.add_typer(elf_cmd.app, name="elf")
app.add_typer(sandbox_cmd.app, name="sandbox")
app.add_typer(integrity_cmd.app, name="integrity")

# Console is imported lazily to avoid circular import (console_cmd
# imports v2.app for command dispatch).
from . import console_cmd  # noqa: E402
app.add_typer(console_cmd.app, name="console")


__all__ = ["app"]
