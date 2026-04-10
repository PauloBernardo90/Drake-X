"""``drake ai`` — call individual AI tasks against a stored session."""

from __future__ import annotations

import asyncio
import json

import typer

from ..ai.ollama_client import OllamaClient
from ..ai.tasks import (
    ClassifyTask,
    DedupeTask,
    NextStepsTask,
    ObservationsTask,
    ReportDraftTask,
    SummarizeTask,
    TaskContext,
)
from ..cli_theme import error, info, make_console, success, warn
from ..core.storage import WorkspaceStorage
from . import _shared

app = typer.Typer(no_args_is_help=True, help="Run individual AI tasks against stored sessions.")


def _build_client(ws) -> OllamaClient:
    return OllamaClient(base_url=ws.config.ollama_url, model=ws.config.ollama_model)


def _load_context(storage: WorkspaceStorage, session_id: str) -> TaskContext | None:
    session = storage.legacy.load_session(session_id)
    if session is None:
        return None
    artifacts = storage.legacy.load_artifacts(session_id)
    findings = storage.load_findings(session_id)
    return TaskContext(
        target_display=session.target.canonical,
        profile=session.profile,
        session_id=session_id,
        evidence=[a.model_dump(mode="json") for a in artifacts],
        findings=[f.model_dump(mode="json") for f in findings],
    )


def _print_result(console, label: str, parsed: dict | None, raw: str | None) -> None:
    if parsed is None:
        warn(console, f"{label}: no parseable AI response")
        if raw:
            console.print(raw)
        return
    success(console, f"{label}:")
    console.print(json.dumps(parsed, indent=2))


@app.command("status")
def status(
    workspace: str = typer.Option(None, "--workspace", "-w", help="Workspace name or path."),
) -> None:
    """Check that the configured local Ollama instance is reachable."""
    console = make_console()
    ws = _shared.resolve_workspace(workspace)
    client = _build_client(ws)
    reachable = asyncio.run(client.is_available())
    if reachable:
        success(console, f"Ollama reachable at {ws.config.ollama_url} (model {ws.config.ollama_model})")
    else:
        error(console, f"Ollama NOT reachable at {ws.config.ollama_url}")
        raise typer.Exit(code=1)


def _run_task(task_cls, *, session_id: str, workspace: str | None, label: str) -> None:
    console = make_console()
    ws = _shared.resolve_workspace(workspace)
    storage = WorkspaceStorage(ws.db_path)
    ctx = _load_context(storage, session_id)
    if ctx is None:
        error(console, f"session not found: {session_id}")
        raise typer.Exit(code=1)
    info(console, f"running {label} task on session [accent]{session_id}[/accent]")
    client = _build_client(ws)
    task = task_cls()
    result = asyncio.run(task.run(client=client, context=ctx))
    if not result.ok:
        warn(console, f"{label} task failed: {result.error}")
        raise typer.Exit(code=1)
    _print_result(console, label, result.parsed, result.raw_text)


@app.command("summarize")
def summarize(
    session_id: str = typer.Argument(..., help="Session id."),
    workspace: str = typer.Option(None, "--workspace", "-w", help="Workspace name or path."),
) -> None:
    _run_task(SummarizeTask, session_id=session_id, workspace=workspace, label="summarize")


@app.command("classify")
def classify(
    session_id: str = typer.Argument(..., help="Session id."),
    workspace: str = typer.Option(None, "--workspace", "-w", help="Workspace name or path."),
) -> None:
    _run_task(ClassifyTask, session_id=session_id, workspace=workspace, label="classify")


@app.command("next-steps")
def next_steps(
    session_id: str = typer.Argument(..., help="Session id."),
    workspace: str = typer.Option(None, "--workspace", "-w", help="Workspace name or path."),
) -> None:
    _run_task(NextStepsTask, session_id=session_id, workspace=workspace, label="next_steps")


@app.command("observations")
def observations(
    session_id: str = typer.Argument(..., help="Session id."),
    workspace: str = typer.Option(None, "--workspace", "-w", help="Workspace name or path."),
) -> None:
    _run_task(ObservationsTask, session_id=session_id, workspace=workspace, label="observations")


@app.command("draft-report")
def draft_report(
    session_id: str = typer.Argument(..., help="Session id."),
    workspace: str = typer.Option(None, "--workspace", "-w", help="Workspace name or path."),
) -> None:
    _run_task(ReportDraftTask, session_id=session_id, workspace=workspace, label="report_draft")


@app.command("dedupe")
def dedupe(
    session_id: str = typer.Argument(..., help="Session id."),
    workspace: str = typer.Option(None, "--workspace", "-w", help="Workspace name or path."),
    apply: bool = typer.Option(
        False,
        "--apply",
        help=(
            "Persist 'duplicate-of:<canonical-id>' tags onto the duplicate "
            "findings. Without this flag the command is read-only."
        ),
    ),
) -> None:
    """Ask the local LLM to group duplicate findings in a stored session.

    Without ``--apply`` the command is purely diagnostic — it prints the
    grouping the model produced. With ``--apply`` it walks the groups
    and writes a ``duplicate-of:<canonical-id>`` tag onto each duplicate
    via the v2 storage layer (in place; no v1 row duplication).
    """
    console = make_console()
    ws = _shared.resolve_workspace(workspace)
    storage = WorkspaceStorage(ws.db_path)

    findings = storage.load_findings(session_id)
    if not findings:
        warn(console, "no findings to dedupe in this session")
        raise typer.Exit(code=0)

    session = storage.legacy.load_session(session_id)
    if session is None:
        error(console, f"session not found: {session_id}")
        raise typer.Exit(code=1)

    ctx = TaskContext(
        target_display=session.target.canonical,
        profile=session.profile,
        session_id=session_id,
        evidence=[],
        findings=[f.model_dump(mode="json") for f in findings],
    )

    info(
        console,
        f"running dedupe task on session [accent]{session_id}[/accent] "
        f"({len(findings)} finding(s))",
    )
    client = _build_client(ws)
    task = DedupeTask()
    result = asyncio.run(task.run(client=client, context=ctx))

    if not result.ok:
        warn(console, f"dedupe task failed: {result.error}")
        raise typer.Exit(code=1)

    success(console, "dedupe groups:")
    console.print(json.dumps(result.parsed, indent=2))

    groups = (result.parsed or {}).get("groups") or []
    if not groups:
        info(console, "no duplicate groups proposed")
        return

    if not apply:
        info(
            console,
            "re-run with --apply to persist 'duplicate-of:<canonical>' tags",
        )
        return

    # Apply tags. Walk every duplicate id, append the tag to its v2 row.
    findings_by_id = {f.id: f for f in findings}
    applied = 0
    skipped = 0
    for group in groups:
        canonical = group.get("canonical_id")
        if not canonical:
            continue
        for dup_id in group.get("duplicate_ids") or []:
            if dup_id == canonical:
                continue
            f = findings_by_id.get(dup_id)
            if f is None:
                warn(console, f"finding {dup_id!r} not in this session; skipping")
                skipped += 1
                continue
            tag = f"duplicate-of:{canonical}"
            if tag in f.tags:
                continue
            new_tags = list(f.tags) + [tag]
            try:
                ok = storage.update_finding_tags(dup_id, new_tags)
            except Exception as exc:  # noqa: BLE001
                warn(console, f"could not persist tags for {dup_id}: {exc}")
                skipped += 1
                continue
            if ok:
                applied += 1
                # Keep the in-memory copy consistent in case callers reuse it.
                f.tags.append(tag)
            else:
                warn(console, f"finding {dup_id!r} has no v2 row; skipping")
                skipped += 1

    success(
        console,
        f"applied {applied} duplicate-of tag(s); skipped {skipped}",
    )
