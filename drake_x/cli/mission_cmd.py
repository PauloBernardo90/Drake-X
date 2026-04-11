"""``drake mission`` — high-level guided workflows.

A mission orchestrates existing Drake-X modules into a multi-step
workflow. It does not reimplement any analysis logic — it calls the
same engine, modules, scope enforcer, and confirmation gate that the
individual commands use.

Supported mission types:

- ``apk``   — primary malware-analysis workflow → report
- ``web``   — supporting passive recon → active recon → web inspect → headers audit → report
- ``recon`` — supporting passive recon → active recon → report
- ``full``  — supporting passive → active → web → headers → content discovery → report
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from pathlib import Path

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
from ..modules import get_module
from ..safety.confirm import ConfirmGate, ConfirmMode
from ..scope import parse_target
from . import _shared

app = typer.Typer(
    no_args_is_help=True,
    help="High-level guided investigation workflows. APK is the primary malware-analysis path; recon/web remain supporting flows.",
)


# ---------------------------------------------------------------------------
# Mission definitions
# ---------------------------------------------------------------------------


@dataclass
class MissionStep:
    """One step in a mission."""

    label: str
    module: str
    skippable: bool = False


_MISSIONS: dict[str, list[MissionStep]] = {
    "recon": [
        MissionStep("Passive Recon", "recon_passive"),
        MissionStep("Active Recon", "recon_active", skippable=True),
    ],
    "web": [
        MissionStep("Passive Recon", "recon_passive"),
        MissionStep("Active Recon", "recon_active", skippable=True),
        MissionStep("Web Inspection", "web_inspect", skippable=True),
        MissionStep("Header Analysis", "headers_audit"),
    ],
    "full": [
        MissionStep("Passive Recon", "recon_passive"),
        MissionStep("Active Recon", "recon_active", skippable=True),
        MissionStep("Web Inspection", "web_inspect", skippable=True),
        MissionStep("Header Analysis", "headers_audit"),
        MissionStep("Content Discovery", "content_discovery", skippable=True),
    ],
}


# ---------------------------------------------------------------------------
# CLI command
# ---------------------------------------------------------------------------


@app.command("run")
def run_mission(
    mission_type: str = typer.Argument(..., help="Mission type: apk, web, recon, full."),
    target: str = typer.Argument(..., help="APK file path or supporting collection target (domain/URL/IP)."),
    workspace: str = typer.Option(None, "--workspace", "-w", help="Workspace name or path."),
    yes: bool = typer.Option(False, "--yes", "-y", help="Pre-approve confirmation gates."),
    dry_run: bool = typer.Option(False, "--dry-run", help="Plan only; do not execute."),
    no_active: bool = typer.Option(False, "--no-active", help="Skip all active/intrusive steps."),
    ai: bool = typer.Option(False, "--ai", help="Enable AI triage."),
    report: bool = typer.Option(True, "--report/--no-report", help="Generate reports."),
    output_dir: Path = typer.Option(None, "--output-dir", "-o", help="Override output directory."),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose output."),
) -> None:
    """Execute a multi-step investigation workflow against a sample or target."""
    console = make_console()

    # --- APK missions delegate directly to the apk analyze command ---
    if mission_type == "apk":
        _run_apk_mission(target, workspace, output_dir, report, console)
        return

    ws = _shared.resolve_workspace(workspace)

    # Check built-in missions first, then workspace templates.
    if mission_type in _MISSIONS:
        steps = _MISSIONS[mission_type]
    else:
        loaded = _load_template(ws, mission_type)
        if loaded is None:
            available = ", ".join(sorted(_MISSIONS)) + " + workspace templates"
            error(console, f"unknown mission: {mission_type!r}. Available: {available}")
            raise typer.Exit(code=2)
        steps = loaded
    scope = _shared.load_scope(ws)

    try:
        parsed = parse_target(target)
    except (InvalidTargetError, ScopeViolationError) as exc:
        _shared.fail(console, f"target rejected: {exc}", code=2)
        return

    console.print()
    console.print(f"[brand]  Drake-X Mission: {mission_type.upper()}[/brand]")
    console.print(f"  Target: [accent]{parsed.canonical}[/accent]")
    console.print(f"  Steps:  {len(steps)}")
    if dry_run:
        console.print(f"  [warn]DRY RUN — no tools will execute[/warn]")
    console.print()

    confirm_mode = ConfirmMode.YES if yes else ConfirmMode.INTERACTIVE
    loader = PluginLoader(default_timeout=ws.config.default_timeout).load()
    storage = WorkspaceStorage(ws.db_path)

    ai_layer = None
    if ai:
        client = OllamaClient(base_url=ws.config.ollama_url, model=ws.config.ollama_model)
        ai_layer = AIAnalyzer(client=client)

    engine = Engine(
        workspace=ws,
        scope=scope,
        loader=loader,
        storage=storage,
        ai=ai_layer,
        confirm=ConfirmGate(mode=confirm_mode),
    )

    session_ids: list[str] = []
    total = len(steps)

    for i, step in enumerate(steps, 1):
        prefix = f"[{i}/{total}]"

        if no_active and step.skippable:
            info(console, f"{prefix} {step.label} — [muted]skipped (--no-active)[/muted]")
            continue

        try:
            mod = get_module(step.module)
        except KeyError:
            warn(console, f"{prefix} {step.label} — module not found, skipping")
            continue

        if not mod.supports_target_type(parsed.target_type):
            info(console, f"{prefix} {step.label} — [muted]skipped (target type not supported)[/muted]")
            continue

        info(console, f"{prefix} {step.label} [muted]({step.module})[/muted]")

        try:
            plan = engine.plan(target=parsed, profile=mod.profile)
            report_obj = asyncio.run(engine.run(
                plan,
                dry_run=dry_run,
                ai_enabled=ai_layer is not None,
            ))
            session_ids.append(report_obj.session.id)
            status = report_obj.session.status.value
            tools = ", ".join(report_obj.session.tools_ran) or "none"
            success(console, f"      {status} — tools: {tools}")
            if report_obj.session.warnings:
                for w in report_obj.session.warnings:
                    warn(console, f"      {w}")

        except OutOfScopeError as exc:
            error(console, f"      out of scope: {exc}")
            break
        except ConfirmationDeniedError:
            info(console, f"      [muted]skipped (confirmation denied)[/muted]")
            continue
        except DrakeXError as exc:
            warn(console, f"      failed: {exc}")
            if not step.skippable:
                break
            continue

    # --- report generation ---
    console.print()
    if report and session_ids and not dry_run:
        from ..reporting import render_markdown_report
        for sid in session_ids:
            session = storage.legacy.load_session(sid)
            if session is None:
                continue
            results = storage.legacy.load_tool_results(sid)
            artifacts = storage.legacy.load_artifacts(sid)
            findings = storage.load_findings(sid)
            md = render_markdown_report(
                session=session, tool_results=results, artifacts=artifacts, findings=findings,
            )
            out_dir = output_dir or ws.session_dir(sid)
            out_dir.mkdir(parents=True, exist_ok=True)
            (out_dir / "report.md").write_text(md, encoding="utf-8")

    success(console, f"Mission complete. {len(session_ids)} session(s) recorded.")
    for sid in session_ids:
        info(console, f"  session: [accent]{sid}[/accent]")
    console.print()


def _run_apk_mission(
    target: str,
    workspace: str | None,
    output_dir: Path | None,
    report: bool,
    console,
) -> None:
    """Delegate APK missions to the existing apk analyze command."""
    from .apk_cmd import analyze

    console.print()
    console.print("[brand]  Drake-X Mission: APK[/brand]")
    console.print(f"  Sample: [accent]{target}[/accent]")
    console.print()

    analyze(
        apk_file=Path(target),
        workspace=workspace,
        output_dir=output_dir,
        report=report,
        deep=False,
        strings=True,
        jadx=True,
        apktool=True,
        radare2=False,
    )


# ---------------------------------------------------------------------------
# Template support
# ---------------------------------------------------------------------------


def _missions_dir(ws) -> Path:
    """Return the workspace missions directory."""
    return ws.root / "missions"


def _load_template(ws, name: str) -> list[MissionStep] | None:
    """Load a mission template from ``<workspace>/missions/<name>.toml``."""
    import tomllib

    missions_dir = _missions_dir(ws)
    path = missions_dir / f"{name}.toml"
    if not path.exists():
        return None
    try:
        with path.open("rb") as fh:
            data = tomllib.load(fh)
    except Exception:
        return None

    raw_steps = data.get("steps") or data.get("step") or []
    if not isinstance(raw_steps, list):
        return None

    steps: list[MissionStep] = []
    for raw in raw_steps:
        if not isinstance(raw, dict):
            continue
        module = raw.get("module", "")
        label = raw.get("label") or raw.get("type", "") + ": " + module
        skippable = bool(raw.get("requires_confirmation") or raw.get("skippable", False))
        if module:
            steps.append(MissionStep(label=label, module=module, skippable=skippable))

    return steps if steps else None


def _list_templates(ws) -> list[tuple[str, Path]]:
    """List all .toml files in the workspace missions directory."""
    missions_dir = _missions_dir(ws)
    if not missions_dir.exists():
        return []
    return sorted(
        (p.stem, p) for p in missions_dir.glob("*.toml") if p.is_file()
    )


# ---------------------------------------------------------------------------
# list / show subcommands
# ---------------------------------------------------------------------------


@app.command("list")
def list_missions(
    workspace: str = typer.Option(None, "--workspace", "-w"),
) -> None:
    """List available missions (built-in + workspace templates)."""
    console = make_console()

    console.print("[title]Built-in missions[/title]")
    for name, steps in sorted(_MISSIONS.items()):
        modules = ", ".join(s.module for s in steps)
        console.print(f"  [accent]{name:15s}[/accent] {len(steps)} steps ({modules})")

    ws = None
    try:
        ws = _shared.resolve_workspace(workspace)
    except SystemExit:
        pass

    if ws:
        templates = _list_templates(ws)
        if templates:
            console.print()
            console.print("[title]Workspace templates[/title]")
            for name, path in templates:
                steps = _load_template(ws, name) or []
                modules = ", ".join(s.module for s in steps)
                console.print(f"  [accent]{name:15s}[/accent] {len(steps)} steps ({modules})")
        else:
            console.print()
            console.print(f"[muted]No workspace templates in {_missions_dir(ws)}[/muted]")
    console.print()


@app.command("show")
def show_mission(
    mission_name: str = typer.Argument(..., help="Mission name (built-in or template)."),
    workspace: str = typer.Option(None, "--workspace", "-w"),
) -> None:
    """Show the steps of a mission."""
    console = make_console()

    steps = None
    if mission_name in _MISSIONS:
        steps = _MISSIONS[mission_name]
    else:
        try:
            ws = _shared.resolve_workspace(workspace)
            steps = _load_template(ws, mission_name)
        except SystemExit:
            pass

    if steps is None:
        error(console, f"mission {mission_name!r} not found.")
        raise typer.Exit(code=1)

    console.print(f"[title]Mission: {mission_name}[/title]")
    console.print()
    for i, step in enumerate(steps, 1):
        skip = " [muted](skippable)[/muted]" if step.skippable else ""
        console.print(f"  {i}. [accent]{step.module}[/accent] — {step.label}{skip}")
    console.print()
