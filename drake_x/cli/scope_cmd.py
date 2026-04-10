"""``drake scope`` — inspect and validate the engagement scope file."""

from __future__ import annotations

import json

import typer

from ..cli_theme import error, info, make_console, success
from ..exceptions import InvalidTargetError, ScopeViolationError
from ..safety.enforcer import ScopeEnforcer
from ..scope import parse_target
from . import _shared

app = typer.Typer(no_args_is_help=True, help="Inspect and validate the engagement scope file.")


@app.command("validate")
def validate(
    workspace: str = typer.Option(None, "--workspace", "-w", help="Workspace name or path."),
) -> None:
    """Parse the scope file and report any errors."""
    console = make_console()
    ws = _shared.resolve_workspace(workspace)
    scope = _shared.load_scope(ws)
    success(console, f"scope file at [accent]{ws.scope_path}[/accent] is valid")
    info(console, f"engagement: {scope.engagement}")
    info(console, f"authorization_reference: {scope.authorization_reference}")
    info(console, f"in_scope:    {len(scope.in_scope)} rule(s)")
    info(console, f"out_of_scope: {len(scope.out_of_scope)} rule(s)")
    info(console, f"allow_active: {scope.allow_active}")
    info(console, f"max_concurrency: {scope.max_concurrency}")
    info(console, f"rate_limit_per_host_rps: {scope.rate_limit_per_host_rps}")


@app.command("show")
def show(
    workspace: str = typer.Option(None, "--workspace", "-w", help="Workspace name or path."),
    json_out: bool = typer.Option(False, "--json", help="Print the scope as JSON."),
) -> None:
    """Print the parsed scope file."""
    console = make_console()
    ws = _shared.resolve_workspace(workspace)
    scope = _shared.load_scope(ws)

    if json_out:
        typer.echo(json.dumps(scope.model_dump(mode="json"), indent=2))
        return

    success(console, f"engagement: [accent]{scope.engagement}[/accent]")
    info(console, f"authorization_reference: {scope.authorization_reference}")
    info(console, f"allow_active: {scope.allow_active}")
    info(console, f"in_scope ({len(scope.in_scope)}):")
    for asset in scope.in_scope:
        notes = f"  [muted]({asset.notes})[/muted]" if asset.notes else ""
        console.print(f"  • [accent]{asset.kind}[/accent] = {asset.value}{notes}")
    info(console, f"out_of_scope ({len(scope.out_of_scope)}):")
    for asset in scope.out_of_scope:
        notes = f"  [muted]({asset.notes})[/muted]" if asset.notes else ""
        console.print(f"  • [accent]{asset.kind}[/accent] = {asset.value}{notes}")


@app.command("check")
def check(
    target: str = typer.Argument(..., help="Target IPv4/IPv6/CIDR/domain/URL to check."),
    workspace: str = typer.Option(None, "--workspace", "-w", help="Workspace name or path."),
) -> None:
    """Check whether a target falls within the engagement scope (no scan)."""
    console = make_console()
    ws = _shared.resolve_workspace(workspace)
    scope = _shared.load_scope(ws)

    try:
        parsed = parse_target(target)
    except InvalidTargetError as exc:
        error(console, f"invalid target: {exc}")
        raise typer.Exit(code=2) from exc
    except ScopeViolationError as exc:
        error(console, f"target rejected by safety guard: {exc}")
        raise typer.Exit(code=2) from exc

    enforcer = ScopeEnforcer(scope)
    decision = enforcer.check_target(parsed)

    if decision.allowed:
        success(console, f"[ok]ALLOW[/ok] — {parsed.canonical}")
        info(console, decision.reason)
    else:
        error(console, f"DENY — {parsed.canonical}")
        info(console, decision.reason)
        raise typer.Exit(code=1)
