"""``drake recon`` — plan and run reconnaissance modules."""

from __future__ import annotations

import asyncio

import typer

from ..ai.analyzer import AIAnalyzer
from ..ai.ollama_client import OllamaClient
from ..cli_theme import error, info, make_console, success, warn
from ..core.engine import Engine
from ..core.plugin_loader import PluginLoader
from ..core.storage import WorkspaceStorage
from ..exceptions import (
    ConfirmationDeniedError,
    DrakeXError,
    InvalidTargetError,
    OutOfScopeError,
    ScopeViolationError,
)
from ..modules import ALL_MODULES, get_module
from ..safety.confirm import ConfirmGate, ConfirmMode
from ..scope import parse_target
from . import _shared

app = typer.Typer(no_args_is_help=True, help="Plan and run reconnaissance modules.")


@app.command("list-modules")
def list_modules() -> None:
    """List all known recon modules."""
    console = make_console()
    for cls in ALL_MODULES:
        spec = cls.spec
        kind = "active" if spec.action_policy.value not in {"passive", "light"} else "passive/light"
        notes = f"  [muted]({spec.notes})[/muted]" if spec.notes else ""
        console.print(
            f"[accent]{spec.name}[/accent]  [muted]({kind})[/muted]\n"
            f"  {spec.description}{notes}"
        )


@app.command("plan")
def plan_cmd(
    target: str = typer.Argument(..., help="Target IPv4/IPv6/CIDR/domain/URL."),
    module: str = typer.Option("recon_passive", "--module", "-m", help="Recon module name."),
    workspace: str = typer.Option(None, "--workspace", "-w", help="Workspace name or path."),
) -> None:
    """Build (and print) an execution plan without running anything."""
    console = make_console()
    ws = _shared.resolve_workspace(workspace)
    scope = _shared.load_scope(ws)

    try:
        parsed = parse_target(target)
    except (InvalidTargetError, ScopeViolationError) as exc:
        _shared.fail(console, f"target rejected: {exc}", code=2)
        return

    try:
        mod = get_module(module)
    except KeyError as exc:
        _shared.fail(console, str(exc), code=2)
        return

    if not mod.supports_target_type(parsed.target_type):
        _shared.fail(
            console,
            f"module {module!r} does not support target type {parsed.target_type!r}",
            code=2,
        )

    loader = PluginLoader(default_timeout=ws.config.default_timeout).load()
    storage = WorkspaceStorage(ws.db_path)
    engine = Engine(
        workspace=ws,
        scope=scope,
        loader=loader,
        storage=storage,
        ai=None,
        confirm=ConfirmGate(mode=ConfirmMode.DENY),
    )

    try:
        plan = engine.plan(target=parsed, profile=mod.profile)
    except OutOfScopeError as exc:
        _shared.fail(console, f"out of scope: {exc}", code=2)
        return

    success(console, f"plan for [accent]{parsed.canonical}[/accent] using module [accent]{module}[/accent]")
    info(console, f"profile: {mod.profile}")
    info(console, f"runnable: {', '.join(e.name for e in plan.eligible) or '—'}")
    if plan.requires_confirmation:
        warn(console, f"requires confirmation: {', '.join(e.name for e in plan.requires_confirmation)}")
    if plan.missing:
        warn(console, f"missing tools: {', '.join(e.name for e in plan.missing)}")
    if plan.denied_by_policy:
        warn(
            console,
            f"denied by policy: {', '.join(e.name for e, _ in plan.denied_by_policy)}",
        )


@app.command("run")
def run_cmd(
    target: str = typer.Argument(..., help="Target IPv4/IPv6/CIDR/domain/URL."),
    module: str = typer.Option("recon_passive", "--module", "-m", help="Recon module name."),
    workspace: str = typer.Option(None, "--workspace", "-w", help="Workspace name or path."),
    dry_run: bool = typer.Option(False, "--dry-run", help="Plan only; do not execute tools."),
    yes: bool = typer.Option(False, "--yes", "-y", help="Pre-approve confirmation gates."),
    ai: bool = typer.Option(False, "--ai", help="Enable AI triage if Ollama is reachable."),
    timeout: int = typer.Option(None, "--timeout", "-t", help="Per-tool timeout override."),
) -> None:
    """Run a reconnaissance module against a target."""
    console = make_console()

    ws = _shared.resolve_workspace(workspace)
    scope = _shared.load_scope(ws)

    try:
        parsed = parse_target(target)
    except (InvalidTargetError, ScopeViolationError) as exc:
        _shared.fail(console, f"target rejected: {exc}", code=2)
        return

    try:
        mod = get_module(module)
    except KeyError as exc:
        _shared.fail(console, str(exc), code=2)
        return

    if not mod.supports_target_type(parsed.target_type):
        _shared.fail(
            console,
            f"module {module!r} does not support target type {parsed.target_type!r}",
            code=2,
        )

    info(console, f"workspace: [accent]{ws.name}[/accent] ([muted]{ws.root}[/muted])")
    info(console, f"target:    [accent]{parsed.canonical}[/accent] ({parsed.target_type})")
    info(console, f"module:    [accent]{module}[/accent] (profile {mod.profile})")
    if dry_run:
        warn(console, "dry-run mode — no tools will be executed")

    confirm_mode = ConfirmMode.YES if yes else ConfirmMode.INTERACTIVE
    loader = PluginLoader(default_timeout=ws.config.default_timeout).load()
    storage = WorkspaceStorage(ws.db_path)

    ai_layer = None
    if ai:
        client = OllamaClient(base_url=ws.config.ollama_url, model=ws.config.ollama_model)
        ai_layer = AIAnalyzer(client=client)
        try:
            reachable = asyncio.run(ai_layer.is_available())
        except Exception:  # noqa: BLE001
            reachable = False
        if not reachable:
            warn(console, "Ollama not reachable; continuing without AI triage")
            ai_layer = None

    engine = Engine(
        workspace=ws,
        scope=scope,
        loader=loader,
        storage=storage,
        ai=ai_layer,
        confirm=ConfirmGate(mode=confirm_mode),
    )

    try:
        plan = engine.plan(target=parsed, profile=mod.profile)
        report = asyncio.run(
            engine.run(
                plan,
                dry_run=dry_run,
                ai_enabled=ai_layer is not None,
                tool_timeout=timeout,
            )
        )
    except OutOfScopeError as exc:
        _shared.fail(console, f"out of scope: {exc}", code=2)
        return
    except ConfirmationDeniedError as exc:
        _shared.fail(console, f"confirmation denied: {exc}", code=2)
        return
    except DrakeXError as exc:
        _shared.fail_drake(console, exc)
        return

    success(
        console,
        f"session [accent]{report.session.id}[/accent] finished "
        f"with status [accent]{report.session.status.value}[/accent]",
    )
    if report.session.tools_ran:
        info(console, f"tools ran: {', '.join(report.session.tools_ran)}")
    if report.session.tools_skipped:
        warn(console, f"tools skipped: {', '.join(report.session.tools_skipped)}")
    if report.session.warnings:
        for w in report.session.warnings:
            warn(console, w)
    info(
        console,
        f"next: `drake report generate {report.session.id} --workspace {ws.name}`",
    )
