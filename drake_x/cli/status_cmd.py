"""``drake status`` — workspace observability at a glance.

A read-only command that summarizes the current workspace state without
mutating any data. Designed to be fast, graceful on missing data, and
useful as the first thing an operator runs when resuming work.
"""

from __future__ import annotations

import typer

from ..cli_theme import info, make_console, success, warn
from ..core.plugin_loader import PluginLoader
from ..core.storage import WorkspaceStorage
from ..integrations.apk.runner import is_available
from ..models.finding import FindingSeverity
from ..safety.scope_file import load_scope_file
from . import _shared

app = typer.Typer(
    no_args_is_help=False,
    invoke_without_command=True,
    help="Show workspace status and health at a glance.",
)

_KEY_TOOLS = ["nmap", "dig", "whois", "whatweb", "nikto", "curl", "sslscan",
              "httpx", "ffuf", "apktool", "jadx", "yara", "rabin2", "strings", "unzip"]


@app.callback(invoke_without_command=True)
def status(
    workspace: str = typer.Option(None, "--workspace", "-w", help="Workspace name or path."),
) -> None:
    """Display a comprehensive status summary for the workspace."""
    console = make_console()
    ws = _shared.resolve_workspace(workspace)
    storage = WorkspaceStorage(ws.db_path)

    # --- 1. Workspace Info ---
    console.print()
    console.print("[title]Workspace[/title]")
    console.print(f"  name:       [accent]{ws.name}[/accent]")
    console.print(f"  path:       {ws.root}")
    if ws.config.created_at:
        console.print(f"  created:    {ws.config.created_at}")
    if ws.config.operator:
        console.print(f"  operator:   {ws.config.operator}")

    # --- 2. Scope Summary ---
    console.print()
    console.print("[title]Scope[/title]")
    try:
        scope = load_scope_file(ws.scope_path)
        console.print(f"  engagement: {scope.engagement}")
        console.print(f"  in-scope:   {len(scope.in_scope)} rule(s)")
        console.print(f"  out-scope:  {len(scope.out_of_scope)} rule(s)")
        console.print(f"  active:     {'[ok]allowed[/ok]' if scope.allow_active else '[warn]denied[/warn]'}")
        console.print(f"  rate limit: {scope.rate_limit_per_host_rps} rps / {scope.max_concurrency} concurrent")
    except Exception:
        warn(console, "  scope file not loaded (missing or invalid)")

    # --- 3. Sessions ---
    console.print()
    console.print("[title]Sessions[/title]")
    sessions = storage.legacy.list_sessions(limit=100)
    if sessions:
        last = sessions[0]
        console.print(f"  total:      {len(sessions)}")
        console.print(f"  last ID:    [accent]{last.id}[/accent]")
        console.print(f"  last run:   {last.started_at.isoformat(timespec='seconds')}")
        console.print(f"  last status: {last.status.value}")

        profiles = {}
        for s in sessions:
            profiles[s.profile] = profiles.get(s.profile, 0) + 1
        console.print(f"  by profile: {', '.join(f'{p}={c}' for p, c in sorted(profiles.items()))}")
    else:
        console.print("  [muted]no sessions yet[/muted]")

    # --- 4. Findings ---
    console.print()
    console.print("[title]Findings[/title]")
    all_findings = []
    for s in sessions[:50]:
        all_findings.extend(storage.load_findings(s.id))

    if all_findings:
        severity_counts: dict[str, int] = {}
        deduped = 0
        for f in all_findings:
            severity_counts[f.severity.value] = severity_counts.get(f.severity.value, 0) + 1
            if any(t.startswith("duplicate-of:") for t in f.tags):
                deduped += 1

        console.print(f"  total:      {len(all_findings)}")
        for sev in ["critical", "high", "medium", "low", "info"]:
            count = severity_counts.get(sev, 0)
            if count > 0:
                style = {"critical": "danger", "high": "danger", "medium": "warn", "low": "muted", "info": "muted"}.get(sev, "value")
                console.print(f"  [{style}]{sev:10s} {count}[/{style}]")
        if deduped:
            console.print(f"  deduplicated: {deduped}")
    else:
        console.print("  [muted]no findings yet[/muted]")

    # --- 5. Evidence Graph ---
    console.print()
    console.print("[title]Evidence Graph[/title]")
    graph_found = False
    for s in sessions[:10]:
        graph = storage.load_evidence_graph(s.id)
        if graph and graph.nodes:
            from ..graph.query import top_connected
            stats = graph.stats()
            console.print(f"  session:    [accent]{s.id}[/accent]")
            console.print(f"  nodes:      {stats['total_nodes']}")
            console.print(f"  edges:      {stats['total_edges']}")
            top = top_connected(graph, n=3)
            if top:
                console.print(f"  top nodes:")
                for nid, degree in top:
                    node = graph.get_node(nid)
                    label = f" ({node.label})" if node and node.label else ""
                    console.print(f"    {nid}{label} — {degree} edge(s)")
            graph_found = True
            break
    if not graph_found:
        console.print("  [muted]no evidence graph yet[/muted]")

    # --- 6. Tools ---
    console.print()
    console.print("[title]Tools[/title]")
    available = []
    missing = []
    for tool in _KEY_TOOLS:
        if is_available(tool):
            available.append(tool)
        else:
            missing.append(tool)
    console.print(f"  available:  {', '.join(available) if available else 'none'}")
    if missing:
        console.print(f"  [warn]missing:    {', '.join(missing)}[/warn]")

    console.print()
