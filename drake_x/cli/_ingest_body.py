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
            help="Required with --session when merging external evidence into a non-ingest session. "
                 "Also requires workspace policy opt-in.",
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

    @app.command("register-producer")
    def register_producer(
        source_tool: str = typer.Argument(..., help="Producer identifier used in provenance.source_tool."),
        workspace: str = typer.Option(..., "--workspace", "-w", help="Workspace."),
        trust: str = typer.Option(
            "medium", "--trust",
            help="Maximum attested trust for this producer: low | medium | high.",
        ),
    ) -> None:
        """Register an external producer and its attested trust level."""
        console = make_console()
        normalized = str(trust).lower()
        if normalized not in {"low", "medium", "high"}:
            error(console, "trust must be one of: low, medium, high")
            raise typer.Exit(code=2)
        ws = _shared.resolve_workspace(workspace)
        ws.register_ingest_producer(source_tool, normalized)
        success(console, f"registered producer [accent]{source_tool}[/accent] at trust={normalized}")

    @app.command("unregister-producer")
    def unregister_producer(
        source_tool: str = typer.Argument(..., help="Producer identifier used in provenance.source_tool."),
        workspace: str = typer.Option(..., "--workspace", "-w", help="Workspace."),
    ) -> None:
        """Remove an attested external producer from the workspace registry."""
        console = make_console()
        ws = _shared.resolve_workspace(workspace)
        if ws.unregister_ingest_producer(source_tool):
            success(console, f"removed producer [accent]{source_tool}[/accent]")
            return
        warn(console, f"producer not registered: {source_tool}")

    @app.command("list-producers")
    def list_producers(
        workspace: str = typer.Option(..., "--workspace", "-w", help="Workspace."),
    ) -> None:
        """List attested external producers for this workspace."""
        console = make_console()
        ws = _shared.resolve_workspace(workspace)
        if not ws.config.ingest_producers:
            warn(console, "no attested external producers registered")
            return
        for source_tool in sorted(ws.config.ingest_producers.keys()):
            info(console, f"  · {source_tool} (trust={ws.config.ingest_producers[source_tool]})")
