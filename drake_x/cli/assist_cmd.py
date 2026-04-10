"""``drake assist`` — guided AI-assisted operator mode with full audit logging.

Every suggest/confirm/execute/skip step is persisted to the workspace
database so the session is fully reproducible and reviewable.
"""

from __future__ import annotations

import asyncio
import json
import sys

import typer

from ..ai.ollama_client import OllamaClient
from ..ai.tasks.assist_suggest import AssistSuggestTask
from ..ai.tasks.base import TaskContext
from ..cli_theme import error, info, make_console, success, warn
from ..core.engine import Engine
from ..core.plugin_loader import PluginLoader
from ..core.storage import WorkspaceStorage
from ..exceptions import ConfirmationDeniedError, DrakeXError, OutOfScopeError
from ..modules import get_module
from ..safety.confirm import ConfirmGate, ConfirmMode
from ..scope import parse_target
from ..utils.ids import new_session_id
from ..utils.timefmt import isoformat_utc, utcnow
from . import _shared

app = typer.Typer(no_args_is_help=True, help="AI-guided operator assistant with full audit logging.")


@app.command("start")
def start(
    domain: str = typer.Argument(..., help="Domain of work: web, recon, apk."),
    target: str = typer.Argument(..., help="Target domain/URL/IP."),
    workspace: str = typer.Option(None, "--workspace", "-w", help="Workspace name or path."),
    max_steps: int = typer.Option(10, "--max-steps", help="Maximum assist iterations."),
) -> None:
    """Start an AI-guided assist session (fully audit-logged)."""
    console = make_console()

    ws = _shared.resolve_workspace(workspace)
    scope = _shared.load_scope(ws)
    storage = WorkspaceStorage(ws.db_path)

    try:
        parsed = parse_target(target)
    except Exception as exc:
        _shared.fail(console, f"target rejected: {exc}", code=2)
        return

    client = OllamaClient(base_url=ws.config.ollama_url, model=ws.config.ollama_model)
    reachable = asyncio.run(client.is_available())
    if not reachable:
        error(console, f"Ollama not reachable at {ws.config.ollama_url}. Assist Mode requires a local LLM.")
        raise typer.Exit(code=1)

    # Create assist session for audit logging.
    assist_id = f"assist-{new_session_id()}"
    storage.create_assist_session(
        assist_id=assist_id,
        workspace=ws.name,
        domain=domain,
        target=parsed.canonical,
        started_at=isoformat_utc(utcnow()) or "",
    )

    console.print()
    console.print("[brand]  Drake-X Assist Mode[/brand]")
    console.print(f"  Domain:    [accent]{domain}[/accent]")
    console.print(f"  Target:    [accent]{parsed.canonical}[/accent]")
    console.print(f"  Session:   [accent]{assist_id}[/accent]")
    console.print(f"  Type [accent]q[/accent] at any prompt to exit.")
    console.print()

    loader = PluginLoader(default_timeout=ws.config.default_timeout).load()
    engine = Engine(
        workspace=ws, scope=scope, loader=loader, storage=storage,
        confirm=ConfirmGate(mode=ConfirmMode.INTERACTIVE),
    )
    task = AssistSuggestTask()

    for step_num in range(1, max_steps + 1):
        ctx = _build_assist_context(storage, ws, parsed, domain)
        console.print(f"[muted]--- assist step {step_num}/{max_steps} ---[/muted]")
        info(console, "analyzing workspace state...")

        result = asyncio.run(task.run(client=client, context=ctx))
        ts = isoformat_utc(utcnow()) or ""

        if not result.ok or not result.parsed:
            storage.log_assist_event(
                assist_id, ts, step_num,
                json.dumps({"error": result.error}),
                "ai_failed",
            )
            warn(console, f"AI suggestion unavailable: {result.error or 'no response'}")
            break

        suggestion = result.parsed
        action = suggestion.get("suggested_action", "unknown")
        module_name = suggestion.get("module")
        reason = suggestion.get("reason", "")
        evidence_basis = suggestion.get("evidence_basis", [])
        confidence = suggestion.get("confidence", "low")

        console.print()
        console.print(f"[accent]Suggested next step:[/accent]")
        console.print(f"  [brand]{action}[/brand]")
        console.print(f"  [muted]Reason:[/muted] {reason}")
        if evidence_basis:
            console.print(f"  [muted]Based on:[/muted] {', '.join(str(e)[:60] for e in evidence_basis[:3])}")
        console.print(f"  [muted]Confidence:[/muted] {confidence}")
        console.print()

        answer = _prompt_user("Proceed? [y/n/q] > ")

        if answer in {"q", "quit", "exit"}:
            storage.log_assist_event(assist_id, ts, step_num, json.dumps(suggestion), "exit")
            info(console, "exiting assist mode.")
            break

        if answer not in {"y", "yes"}:
            storage.log_assist_event(assist_id, ts, step_num, json.dumps(suggestion), "reject")
            info(console, "skipped.")
            continue

        result_status = "skipped"
        executed_cmd = None
        if module_name and module_name != "null":
            executed_cmd = f"drake recon run {parsed.canonical} -m {module_name}"
            result_status = _execute_module(console, engine, parsed, module_name)
        elif "report" in action.lower():
            info(console, "use `drake report generate <session-id>` to produce reports.")
            executed_cmd = "drake report generate"
            result_status = "manual"
        else:
            info(console, f"action '{action}' requires manual execution.")
            result_status = "manual"

        storage.log_assist_event(
            assist_id, ts, step_num, json.dumps(suggestion), "approve",
            executed_cmd, result_status,
        )
        console.print()

    storage.end_assist_session(assist_id, isoformat_utc(utcnow()) or "")
    console.print()
    success(console, f"Assist session [accent]{assist_id}[/accent] ended.")


@app.command("history")
def history(
    assist_session_id: str = typer.Argument(..., help="Assist session ID."),
    workspace: str = typer.Option(None, "--workspace", "-w"),
) -> None:
    """Show the chronological steps of an assist session."""
    console = make_console()
    ws = _shared.resolve_workspace(workspace)
    storage = WorkspaceStorage(ws.db_path)
    events = storage.load_assist_events(assist_session_id)
    if not events:
        info(console, "no events found for this assist session.")
        return
    for ev in events:
        step = ev.get("step_number", "?")
        action = ev.get("operator_action", "?")
        ts = ev.get("timestamp", "")
        status = ev.get("result_status") or ""
        suggestion = json.loads(ev.get("suggestion_json", "{}"))
        suggested = suggestion.get("suggested_action", suggestion.get("error", ""))
        console.print(
            f"  [accent]step {step}[/accent]  {action:8s}  {suggested:40s}  {status:10s}  [muted]{ts}[/muted]"
        )


@app.command("export")
def export(
    assist_session_id: str = typer.Argument(..., help="Assist session ID."),
    workspace: str = typer.Option(None, "--workspace", "-w"),
) -> None:
    """Export full assist session trace as JSON."""
    ws = _shared.resolve_workspace(workspace)
    storage = WorkspaceStorage(ws.db_path)
    sessions = storage.list_assist_sessions()
    session_data = next((s for s in sessions if s["id"] == assist_session_id), None)
    events = storage.load_assist_events(assist_session_id)
    typer.echo(json.dumps({"assist_session": session_data, "events": events}, indent=2, default=str))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _build_assist_context(storage, ws, target, domain):
    sessions = storage.legacy.list_sessions(limit=5)
    evidence, findings = [], []
    graph_context = None
    for s in sessions:
        for a in storage.legacy.load_artifacts(s.id)[:10]:
            evidence.append(a.model_dump(mode="json"))
        for f in storage.load_findings(s.id)[:10]:
            findings.append(f.model_dump(mode="json"))
        graph = storage.load_evidence_graph(s.id)
        if graph and graph.nodes and graph_context is None:
            from ..graph.context import serialize_graph_context
            graph_context = serialize_graph_context(graph, max_nodes=20, max_chars=3000)
    return TaskContext(
        target_display=target.canonical, profile=domain,
        evidence=evidence, findings=findings, graph_context=graph_context,
    )


def _execute_module(console, engine, target, module_name) -> str:
    try:
        mod = get_module(module_name)
    except KeyError:
        warn(console, f"module {module_name!r} not found.")
        return "failed"
    if not mod.supports_target_type(target.target_type):
        warn(console, f"module {module_name!r} does not support {target.target_type}.")
        return "failed"
    try:
        plan = engine.plan(target=target, profile=mod.profile)
        report = asyncio.run(engine.run(plan))
        success(console, f"completed ({report.session.status.value})")
        return "success"
    except OutOfScopeError as exc:
        error(console, f"out of scope: {exc}")
        return "failed"
    except ConfirmationDeniedError:
        info(console, "confirmation denied.")
        return "skipped"
    except DrakeXError as exc:
        warn(console, f"failed: {exc}")
        return "failed"


def _prompt_user(prompt: str) -> str:
    try:
        sys.stdout.write(prompt)
        sys.stdout.flush()
        return input().strip().lower()
    except (EOFError, KeyboardInterrupt):
        return "q"
