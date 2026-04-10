"""``drake api`` — API surface mapping commands."""

from __future__ import annotations

from pathlib import Path

import typer

from ..cli_theme import error, info, make_console, success
from ..core.storage import WorkspaceStorage
from ..models.session import Session
from ..normalize.openapi import SpecParseError, parse_openapi_file
from ..scope import parse_target
from . import _shared

app = typer.Typer(no_args_is_help=True, help="API surface mapping and inventory.")


@app.command("ingest")
def ingest(
    spec_file: Path = typer.Argument(..., help="Path to a local OpenAPI/Swagger spec (JSON or YAML)."),
    target: str = typer.Option(
        None,
        "--target",
        "-t",
        help="Associate the spec with a target URL (e.g. https://api.example.com). Defaults to first server in the spec.",
    ),
    workspace: str = typer.Option(None, "--workspace", "-w", help="Workspace name or path."),
) -> None:
    """Parse a local OpenAPI/Swagger spec into an api.inventory artifact."""
    console = make_console()

    ws = _shared.resolve_workspace(workspace)
    scope = _shared.load_scope(ws)

    try:
        artifact = parse_openapi_file(spec_file)
    except SpecParseError as exc:
        _shared.fail(console, str(exc), code=2)
        return

    # Resolve a target to associate the session with.
    target_str = target
    if target_str is None:
        servers = artifact.payload.get("servers") or []
        if servers:
            target_str = servers[0]
    if target_str is None:
        _shared.fail(
            console,
            "could not determine a target URL. Pass --target or add servers to the spec.",
            code=2,
        )
        return

    try:
        parsed_target = parse_target(target_str)
    except Exception as exc:
        _shared.fail(console, f"invalid target: {exc}", code=2)
        return

    # Scope check the target.
    from ..safety.enforcer import ScopeEnforcer
    enforcer = ScopeEnforcer(scope)
    decision = enforcer.check_target(parsed_target)
    if not decision.allowed:
        _shared.fail(console, f"target out of scope: {decision.reason}", code=2)
        return

    storage = WorkspaceStorage(ws.db_path)

    session = Session(
        target=parsed_target,
        profile="api_inventory",
        tools_planned=["openapi_parser"],
        tools_ran=["openapi_parser"],
    )
    session.mark_running()
    storage.legacy.save_session(session)
    storage.legacy.save_artifact(session.id, artifact)
    session.mark_finished(partial=False)
    storage.legacy.save_session(session)

    ep_count = artifact.payload.get("endpoint_count", 0)
    success(
        console,
        f"ingested [accent]{ep_count}[/accent] endpoint(s) from "
        f"[accent]{spec_file}[/accent]",
    )
    info(console, f"session [accent]{session.id}[/accent]")
    info(console, f"spec title: {artifact.payload.get('title')}")
    info(console, f"spec version: {artifact.payload.get('spec_version')}")
    info(console, f"api version: {artifact.payload.get('api_version')}")
    info(
        console,
        f"next: `drake report generate {session.id} -f json -w {ws.name}`",
    )
