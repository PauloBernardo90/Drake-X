"""Body of `drake ingest` — lives separately so the CLI shell stays tiny."""
from __future__ import annotations

from pathlib import Path

import typer

from ..cli_theme import error, info, make_console, success, warn
from . import _shared


def register(app: typer.Typer) -> None:

    @app.command("evidence")
    def evidence(
        file: Path = typer.Argument(..., help="Path to the external evidence file."),
        workspace: str = typer.Option(..., "--workspace", "-w", help="Workspace."),
        type_: str = typer.Option(
            "json", "--type", "-t",
            help="Adapter name (see `drake ingest list-adapters`).",
        ),
        session_id: str = typer.Option(
            None, "--session",
            help="Attach ingested evidence to an existing session. "
                 "If omitted, a new ingest-only session is created.",
        ),
        merge_into_analysis: bool = typer.Option(
            False, "--merge-into-analysis",
            help="Required with --session when merging external evidence into a non-ingest session.",
        ),
        trust: str = typer.Option(
            "medium", "--trust",
            help="Trust level stamp: low | medium | high.",
        ),
    ) -> None:
        """Ingest an external evidence file into the workspace graph."""
        console = make_console()
        from ..integrations.ingest import adapter_registry, ingest_file

        if not file.exists():
            error(console, f"file not found: {file}")
            raise typer.Exit(code=2)
        if type_ not in adapter_registry():
            error(console, f"unknown adapter '{type_}'. "
                  f"available: {', '.join(sorted(adapter_registry()))}")
            raise typer.Exit(code=2)

        ws = _shared.resolve_workspace(workspace)
        result = ingest_file(
            file=file, adapter_name=type_,
            storage=ws.storage,
            session_id=session_id,
            trust=trust,
            allow_merge_into_analysis=merge_into_analysis,
        )
        success(console, f"ingested {result.node_count} node(s), {result.edge_count} edge(s)")
        info(console, f"session: [accent]{result.session_id}[/accent]")
        if result.warnings:
            for w in result.warnings:
                warn(console, w)

    @app.command("list-adapters")
    def list_adapters() -> None:
        """List available ingestion adapters."""
        from ..integrations.ingest import adapter_registry
        console = make_console()
        for name in sorted(adapter_registry()):
            info(console, f"  · {name}")
