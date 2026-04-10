"""``drake report`` — generate technical, executive, JSON, and manifest reports."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import typer

from ..cli_theme import error, info, make_console, success, warn
from ..core.storage import WorkspaceStorage
from ..reporting import (
    build_evidence_index,
    build_scan_manifest,
    render_executive_report,
    render_json_report,
    render_markdown_report,
)
from ..reporting.manifest import write_manifest_json
from . import _shared

app = typer.Typer(no_args_is_help=True, help="Generate reports for stored sessions.")


_FORMATS = ("md", "executive", "json", "manifest", "evidence")


@app.command("generate")
def generate(
    session_id: str = typer.Argument(..., help="Session id from a prior recon run."),
    workspace: str = typer.Option(None, "--workspace", "-w", help="Workspace name or path."),
    format: str = typer.Option(
        "md",
        "--format",
        "-f",
        help=f"Report format. One of: {', '.join(_FORMATS)}.",
    ),
    output: Path = typer.Option(
        None,
        "--output",
        "-o",
        help="Write to file instead of stdout. Defaults under runs/<sid>/.",
    ),
) -> None:
    """Generate a report for an existing session."""
    console = make_console()
    if format not in _FORMATS:
        _shared.fail(console, f"unknown format {format!r}; choose one of {', '.join(_FORMATS)}", code=2)
        return

    ws = _shared.resolve_workspace(workspace)
    storage = WorkspaceStorage(ws.db_path)

    session = storage.legacy.load_session(session_id)
    if session is None:
        error(console, f"session not found: {session_id}")
        raise typer.Exit(code=1)

    tool_results = storage.legacy.load_tool_results(session_id)
    artifacts = storage.legacy.load_artifacts(session_id)
    findings = storage.load_findings(session_id)
    scope_in, scope_out = storage.load_scope_snapshot(session_id)

    if format == "md":
        body = render_markdown_report(
            session=session,
            tool_results=tool_results,
            artifacts=artifacts,
            findings=findings,
        )
        default_name = "report.md"
    elif format == "executive":
        body = render_executive_report(
            session=session,
            artifacts=artifacts,
            findings=findings,
        )
        default_name = "executive.md"
    elif format == "json":
        body = render_json_report(
            session=session,
            tool_results=tool_results,
            artifacts=artifacts,
            findings=findings,
            scope_in=scope_in,
            scope_out=scope_out,
        )
        default_name = "report.json"
    elif format == "manifest":
        manifest = build_scan_manifest(
            session=session,
            tool_results=tool_results,
            artifacts=artifacts,
            workspace_name=ws.name,
        )
        body = write_manifest_json(manifest)
        default_name = "manifest.json"
    else:  # evidence
        body = build_evidence_index(artifacts)
        default_name = "evidence_index.md"

    if output is None:
        out_dir = ws.session_dir(session.id)
        out_dir.mkdir(parents=True, exist_ok=True)
        target = out_dir / default_name
    else:
        target = output

    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(body, encoding="utf-8")
    success(console, f"{format} report written to [accent]{target}[/accent]")


@app.command("list")
def list_reports(
    workspace: str = typer.Option(None, "--workspace", "-w", help="Workspace name or path."),
    limit: int = typer.Option(20, "--limit", help="Maximum number of sessions to list."),
) -> None:
    """List recent sessions."""
    console = make_console()
    ws = _shared.resolve_workspace(workspace)
    storage = WorkspaceStorage(ws.db_path)
    sessions = storage.legacy.list_sessions(limit=limit)
    if not sessions:
        info(console, "no sessions in this workspace yet")
        return
    for s in sessions:
        console.print(
            f"[accent]{s.id}[/accent]  "
            f"[muted]{s.started_at.isoformat(timespec='seconds')}[/muted]  "
            f"{s.target.canonical}  [muted]({s.profile} / {s.status.value})[/muted]"
        )


@app.command("diff")
def diff(
    session_a: str = typer.Argument(..., help="Baseline session id."),
    session_b: str = typer.Argument(..., help="Comparison session id."),
    workspace: str = typer.Option(None, "--workspace", "-w", help="Workspace name or path."),
    format: str = typer.Option("md", "--format", "-f", help="Output format: md or json."),
    output: Path = typer.Option(None, "--output", "-o", help="Write to file instead of stdout."),
) -> None:
    """Compare artifacts from two sessions to surface attack-surface changes."""
    from ..normalize.diff import diff_sessions

    console = make_console()
    ws = _shared.resolve_workspace(workspace)
    storage = WorkspaceStorage(ws.db_path)

    sa = storage.legacy.load_session(session_a)
    sb = storage.legacy.load_session(session_b)
    if sa is None:
        error(console, f"session A not found: {session_a}")
        raise typer.Exit(code=1)
    if sb is None:
        error(console, f"session B not found: {session_b}")
        raise typer.Exit(code=1)

    arts_a = storage.legacy.load_artifacts(session_a)
    arts_b = storage.legacy.load_artifacts(session_b)

    result = diff_sessions(
        session_a_id=session_a,
        session_b_id=session_b,
        artifacts_a=arts_a,
        artifacts_b=arts_b,
    )

    if format == "json":
        body = json.dumps(result.to_dict(), indent=2, default=str)
    else:
        body = result.to_markdown()

    if output is not None:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(body, encoding="utf-8")
        success(console, f"diff written to [accent]{output}[/accent]")
    else:
        console.print(body)
        info(
            console,
            f"added={len(result.added)} removed={len(result.removed)} changed={len(result.changed)}",
        )
