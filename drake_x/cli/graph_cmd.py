"""``drake graph`` — inspect the Evidence Graph for a session."""

from __future__ import annotations

import json
from pathlib import Path

import typer

from ..cli_theme import error, info, make_console, success
from ..core.storage import WorkspaceStorage
from ..graph.query import filter_by_edge_type, filter_by_kind, neighborhood
from ..graph.render_ascii import render_ascii
from ..graph.render_summary import render_summary
from ..models.evidence_graph import EdgeType, EvidenceGraph, NodeKind
from . import _shared

app = typer.Typer(no_args_is_help=True, help="Inspect the Evidence Graph for a session.")


@app.command("show")
def show(
    session_id: str = typer.Argument(..., help="Session ID."),
    workspace: str = typer.Option(None, "--workspace", "-w", help="Workspace name or path."),
    format: str = typer.Option("ascii", "--format", "-f", help="Output format: ascii, json, summary."),
    node: str = typer.Option(None, "--node", "-n", help="Focus on a specific node ID (show its neighborhood)."),
    depth: int = typer.Option(2, "--depth", help="BFS depth for neighborhood extraction."),
    max_nodes: int = typer.Option(50, "--max-nodes", help="Maximum nodes to display."),
    kind: str = typer.Option(None, "--kind", "-k", help="Filter by node kind (finding, artifact, indicator, ...)."),
    edge: str = typer.Option(None, "--edge", "-e", help="Filter by edge type (derived_from, supports, ...)."),
    output: Path = typer.Option(None, "--output", "-o", help="Write to file instead of stdout."),
    findings_only: bool = typer.Option(False, "--findings", help="Show only finding nodes."),
    indicators_only: bool = typer.Option(False, "--indicators", help="Show only indicator nodes."),
    artifacts_only: bool = typer.Option(False, "--artifacts", help="Show only artifact nodes."),
) -> None:
    """Display the Evidence Graph for a session.

    Supports ASCII terminal view, JSON export, and statistical summary.
    Use ``--node`` to explore the neighborhood of a specific node.
    """
    console = make_console()
    ws = _shared.resolve_workspace(workspace)
    storage = WorkspaceStorage(ws.db_path)

    graph = storage.load_evidence_graph(session_id)
    if graph is None or not graph.nodes:
        error(console, f"no evidence graph found for session {session_id}")
        raise typer.Exit(code=1)

    # Apply filters.
    if node:
        if graph.get_node(node) is None:
            error(console, f"node {node!r} not found in graph")
            raise typer.Exit(code=1)
        graph = neighborhood(graph, [node], max_depth=depth, max_nodes=max_nodes)

    if findings_only:
        graph = filter_by_kind(graph, {NodeKind.FINDING})
    elif indicators_only:
        graph = filter_by_kind(graph, {NodeKind.INDICATOR})
    elif artifacts_only:
        graph = filter_by_kind(graph, {NodeKind.ARTIFACT})
    elif kind:
        try:
            nk = NodeKind(kind)
        except ValueError:
            error(console, f"invalid node kind: {kind}. Options: {', '.join(k.value for k in NodeKind)}")
            raise typer.Exit(code=2)
        graph = filter_by_kind(graph, {nk})

    if edge:
        try:
            et = EdgeType(edge)
        except ValueError:
            error(console, f"invalid edge type: {edge}. Options: {', '.join(e.value for e in EdgeType)}")
            raise typer.Exit(code=2)
        graph = filter_by_edge_type(graph, {et})

    # Render.
    if format == "json":
        body = json.dumps(graph.to_dict(), indent=2, default=str)
    elif format == "summary":
        body = render_summary(graph)
    else:
        body = render_ascii(graph)

    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(body, encoding="utf-8")
        success(console, f"graph output written to [accent]{output}[/accent]")
    else:
        console.print(body, highlight=False)


@app.command("query")
def query(
    workspace: str = typer.Option(..., "--workspace", "-w", help="Workspace name or path."),
    kind: str = typer.Option(None, "--kind", "-k", help="Filter by node kind."),
    domain: str = typer.Option(None, "--domain", "-d", help="Filter by domain (pe, apk, elf, ...)."),
    label_contains: str = typer.Option(None, "--label", help="Substring match on label."),
    data_contains: str = typer.Option(None, "--data", help="Substring match on serialized node data."),
    min_confidence: float = typer.Option(None, "--min-confidence", help="Minimum node confidence."),
    format: str = typer.Option("text", "--format", "-f", help="Output format: text or json."),
) -> None:
    """Workspace-wide node query across every persisted evidence graph (v1.0)."""
    from ..correlation import query_nodes

    ws = _shared.resolve_workspace(workspace)
    rows = query_nodes(
        ws.storage,
        kind=kind,
        domain=domain,
        label_contains=label_contains,
        data_contains=data_contains,
        min_confidence=min_confidence,
    )
    if format == "json":
        print(json.dumps(rows, indent=2, default=str))
        return
    console = make_console()
    info(console, f"matches: [accent]{len(rows)}[/accent]")
    for row in rows[:50]:
        info(console, f"  {row['session_id'][:12]}  {row['kind']:<12} {row['label']}")
    if len(rows) > 50:
        info(console, f"  ... {len(rows) - 50} more (use --format json)")
