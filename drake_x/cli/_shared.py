"""Helpers shared across the v0.2 CLI subcommands.

Centralizes:

- workspace resolution (CLI flag → env → cwd → default)
- console / theme construction
- standard error formatting
- scope-file loading with friendly errors
"""

from __future__ import annotations

import os
from pathlib import Path

import typer

from ..cli_theme import error, make_console
from ..core.workspace import Workspace, default_workspaces_root
from ..exceptions import (
    DrakeXError,
    ScopeFileError,
    WorkspaceError,
)
from ..models.scope import ScopeFile
from ..safety.scope_file import load_scope_file


def get_console():
    return make_console()


def resolve_workspace(workspace_arg: str | None) -> Workspace:
    """Resolve a workspace from a CLI flag or environment.

    Precedence:
    1. ``--workspace`` flag (name or absolute path)
    2. ``DRAKE_X_WORKSPACE`` environment variable
    3. ``./.drake-x/`` (workspace inside the current directory)
    4. ``~/.drake-x/workspaces/default``

    Raises :class:`typer.Exit(2)` with a user-friendly error if no
    workspace can be loaded.
    """
    console = get_console()

    candidates: list[str] = []
    if workspace_arg:
        candidates.append(workspace_arg)
    env = os.environ.get("DRAKE_X_WORKSPACE")
    if env:
        candidates.append(env)

    cwd_local = Path.cwd() / ".drake-x"
    if cwd_local.exists():
        candidates.append(str(cwd_local))

    candidates.append(str(default_workspaces_root() / "default"))

    last_error: Exception | None = None
    for c in candidates:
        try:
            return Workspace.load(c)
        except WorkspaceError as exc:
            last_error = exc
            continue

    error(
        console,
        "no Drake-X workspace found. Run `drake init <name>` to scaffold one. "
        f"Last error: {last_error}",
    )
    raise typer.Exit(code=2)


def load_scope(workspace: Workspace) -> ScopeFile:
    console = get_console()
    try:
        return load_scope_file(workspace.scope_path)
    except ScopeFileError as exc:
        error(console, f"scope file error: {exc}")
        raise typer.Exit(code=2) from exc


def fail(console, message: str, code: int = 1) -> None:
    error(console, message)
    raise typer.Exit(code=code)


def fail_drake(console, exc: DrakeXError, code: int = 1) -> None:
    error(console, f"{type(exc).__name__}: {exc}")
    raise typer.Exit(code=code)
