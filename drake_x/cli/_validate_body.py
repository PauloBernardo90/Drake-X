"""Body of `drake validate`."""
from __future__ import annotations

from pathlib import Path

import typer

from ..cli_theme import error, info, make_console, success
from . import _shared


def register(app: typer.Typer) -> None:

    @app.command("plan")
    def plan(
        session_id: str = typer.Argument(..., help="Session ID."),
        workspace: str = typer.Option(..., "--workspace", "-w"),
    ) -> None:
        """Generate a structured validation plan for a session (v1.0)."""
        from ..normalize.validation.planner import build_plan_for_session

        console = make_console()
        ws = _shared.resolve_workspace(workspace)
        plan = build_plan_for_session(ws.storage, session_id)
        ws.storage.save_validation_plan(session_id, plan)
        success(console, f"plan: {len(plan.items)} item(s) persisted")

    @app.command("show")
    def show(
        session_id: str = typer.Argument(..., help="Session ID."),
        workspace: str = typer.Option(..., "--workspace", "-w"),
        format: str = typer.Option("text", "--format", "-f", help="text | json"),
    ) -> None:
        """Show a persisted validation plan."""
        console = make_console()
        ws = _shared.resolve_workspace(workspace)
        plan = ws.storage.load_validation_plan(session_id)
        if plan is None:
            error(console, f"no plan persisted for session {session_id}")
            raise typer.Exit(code=1)
        if format == "json":
            print(plan.model_dump_json(indent=2))
            return
        info(console, f"session: {session_id}")
        info(console, f"items:   {len(plan.items)}")
        for i, item in enumerate(plan.items, start=1):
            info(console, f"  [{i:>2}] ({item.priority}) {item.domain}: {item.hypothesis}")
            info(console, f"       status: {item.status}")

    @app.command("export")
    def export(
        session_id: str = typer.Argument(..., help="Session ID."),
        workspace: str = typer.Option(..., "--workspace", "-w"),
        output: Path = typer.Option(..., "--output", "-o", help="Markdown output file."),
    ) -> None:
        """Export a validation plan as Markdown."""
        console = make_console()
        from ..reporting.validation_writer import render_validation_plan_markdown

        ws = _shared.resolve_workspace(workspace)
        plan = ws.storage.load_validation_plan(session_id)
        if plan is None:
            error(console, f"no plan persisted for session {session_id}")
            raise typer.Exit(code=1)
        output.write_text(render_validation_plan_markdown(plan), encoding="utf-8")
        success(console, f"wrote plan to {output}")
