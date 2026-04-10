"""``drake init`` — scaffold a new workspace."""

from __future__ import annotations

from pathlib import Path

import typer

from ..cli_theme import info, make_console, success
from ..core.workspace import Workspace, default_workspaces_root
from ..exceptions import WorkspaceError
from . import _shared

app = typer.Typer(
    no_args_is_help=False,
    invoke_without_command=True,
    help="Initialize a new Drake-X workspace.",
)


@app.callback(invoke_without_command=True)
def init(
    name: str = typer.Argument(
        "default",
        help="Workspace name. Used as the directory under ~/.drake-x/workspaces/.",
    ),
    here: bool = typer.Option(
        False,
        "--here",
        help="Create the workspace inside the current directory (./.drake-x/<name>).",
    ),
    operator: str = typer.Option(
        None, "--operator", help="Operator name recorded in workspace.toml."
    ),
    force: bool = typer.Option(
        False,
        "--force",
        help="Reuse a non-empty workspace directory (does not delete files).",
    ),
) -> None:
    console = make_console()

    root: Path | None
    if here:
        root = (Path.cwd() / ".drake-x").resolve()
    else:
        root = default_workspaces_root()

    try:
        ws = Workspace.init(name, root=root, operator=operator, force=force)
    except WorkspaceError as exc:
        _shared.fail(console, f"could not initialize workspace: {exc}", code=2)
        return  # for type-checker

    success(console, f"workspace initialized at [accent]{ws.root}[/accent]")
    info(console, f"scope template: [accent]{ws.scope_path}[/accent]")
    info(console, f"database:       [accent]{ws.db_path}[/accent]")
    info(console, f"runs directory: [accent]{ws.runs_dir}[/accent]")
    info(console, f"audit log:      [accent]{ws.audit_log_path}[/accent]")
    info(
        console,
        "next: edit the scope file, then run `drake scope validate` and "
        "`drake recon run <target> --module recon_passive`",
    )
