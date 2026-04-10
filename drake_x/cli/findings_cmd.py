"""``drake findings`` — list, show and tag findings."""

from __future__ import annotations

import typer

from ..cli_theme import error, info, make_console, success
from ..core.storage import WorkspaceStorage
from . import _shared

app = typer.Typer(no_args_is_help=True, help="List and inspect findings.")


@app.command("list")
def list_findings(
    workspace: str = typer.Option(None, "--workspace", "-w", help="Workspace name or path."),
    session_id: str = typer.Option(
        None, "--session", "-s", help="Limit to a specific session id."
    ),
    severity: str = typer.Option(None, "--severity", help="Filter by severity."),
    source: str = typer.Option(None, "--source", help="Filter by source (parser/ai/rule/operator)."),
) -> None:
    """List findings stored in the workspace."""
    console = make_console()
    ws = _shared.resolve_workspace(workspace)
    storage = WorkspaceStorage(ws.db_path)

    sessions = (
        [storage.legacy.load_session(session_id)] if session_id else storage.legacy.list_sessions()
    )
    sessions = [s for s in sessions if s is not None]
    if not sessions:
        info(console, "no sessions found")
        return

    total = 0
    for s in sessions:
        findings = storage.load_findings(s.id)
        if not findings:
            continue
        info(console, f"session [accent]{s.id}[/accent] — {s.target.canonical}")
        for f in findings:
            if severity and f.severity.value != severity.lower():
                continue
            if source and f.source.value != source.lower():
                continue
            total += 1
            console.print(
                f"  • [accent]{f.id}[/accent]  [warn][{f.severity.value}][/warn]  "
                f"{f.title}  [muted](src={f.source.value}, conf={f.confidence:.2f})[/muted]"
            )
    if total == 0:
        info(console, "no findings matched the filters")
    else:
        success(console, f"{total} finding(s) matched")


@app.command("show")
def show_finding(
    finding_id: str = typer.Argument(..., help="Finding id (e.g. f-abc123)."),
    workspace: str = typer.Option(None, "--workspace", "-w", help="Workspace name or path."),
) -> None:
    """Show one finding in detail."""
    console = make_console()
    ws = _shared.resolve_workspace(workspace)
    storage = WorkspaceStorage(ws.db_path)

    for s in storage.legacy.list_sessions(limit=200):
        for f in storage.load_findings(s.id):
            if f.id == finding_id:
                console.print(f"[accent]{f.id}[/accent]  [warn][{f.severity.value}][/warn]  {f.title}")
                console.print(f"  source: {f.source.value} ({f.fact_or_inference})")
                console.print(f"  confidence: {f.confidence:.2f}")
                if f.cwe:
                    console.print(f"  CWE: {', '.join(f.cwe)}")
                if f.owasp:
                    console.print(f"  OWASP: {', '.join(f.owasp)}")
                if f.mitre_attck:
                    console.print(f"  MITRE: {', '.join(f.mitre_attck)}")
                console.print(f"\n  {f.summary}")
                if f.recommended_next_steps:
                    console.print("\n  recommended next steps:")
                    for step in f.recommended_next_steps:
                        console.print(f"    - {step}")
                if f.caveats:
                    console.print("\n  caveats:")
                    for c in f.caveats:
                        console.print(f"    - {c}")
                if f.tags:
                    console.print(f"\n  tags: {', '.join(f.tags)}")
                return
    error(console, f"finding {finding_id} not found")
    raise typer.Exit(code=1)
