"""``drake tools`` — list known integrations and their installation status."""

from __future__ import annotations

import typer

from ..cli_theme import build_tools_table, format_tool_installed, make_console
from ..constants import AUTHORIZED_USE_NOTICE
from ..core.plugin_loader import PluginLoader
from . import _shared

app = typer.Typer(no_args_is_help=False, invoke_without_command=True, help="List supported integrations.")


@app.callback(invoke_without_command=True)
def list_tools(
    workspace: str = typer.Option(None, "--workspace", "-w", help="Workspace name or path (optional)."),
) -> None:
    console = make_console()

    timeout = 180
    try:
        ws = _shared.resolve_workspace(workspace) if workspace else None
        if ws is not None:
            timeout = ws.config.default_timeout
    except SystemExit:
        pass

    loader = PluginLoader(default_timeout=timeout).load()

    table = build_tools_table()
    for entry in loader.all():
        table.add_row(
            entry.name,
            format_tool_installed(entry.installed),
            ", ".join(entry.profiles),
            ", ".join(entry.target_types),
            entry.description,
        )
    console.print()
    console.print(table)
    console.print()
    console.print(f"[notice]{AUTHORIZED_USE_NOTICE}[/notice]")
