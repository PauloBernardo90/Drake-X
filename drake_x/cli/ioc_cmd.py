"""``drake ioc`` — IoC enrichment commands."""

from __future__ import annotations

import json
import os

import typer

from ..cli_theme import error, info, make_console, success, warn
from ..core.storage import WorkspaceStorage
from ..integrations.ioc.virustotal import enrich_indicators
from . import _shared

app = typer.Typer(no_args_is_help=True, help="IoC enrichment via external intelligence sources.")


@app.command("lookup")
def lookup(
    session_id: str = typer.Argument(..., help="Session ID to enrich."),
    workspace: str = typer.Option(None, "--workspace", "-w"),
    domains: bool = typer.Option(True, "--domains/--no-domains", help="Look up domains."),
    ips: bool = typer.Option(True, "--ips/--no-ips", help="Look up IPs."),
    max_indicators: int = typer.Option(20, "--max-indicators"),
    json_out: bool = typer.Option(False, "--json", help="Output as JSON."),
) -> None:
    """Enrich extracted IoCs for a session via VirusTotal."""
    console = make_console()
    ws = _shared.resolve_workspace(workspace)
    storage = WorkspaceStorage(ws.db_path)

    api_key = ws.config.vt_api_key or os.environ.get("VT_API_KEY", "")
    if not api_key:
        error(console, "no VT API key. Set [virustotal] api_key in workspace.toml or VT_API_KEY env var.")
        raise typer.Exit(code=2)

    # Gather indicators from findings
    domain_list: list[str] = []
    ip_list: list[str] = []
    for s in storage.legacy.list_sessions(limit=1):
        if s.id == session_id:
            break
    artifacts = storage.legacy.load_artifacts(session_id)
    for art in artifacts:
        payload = art.payload or {}
        for ni in payload.get("network_indicators", []):
            if isinstance(ni, dict):
                if ni.get("indicator_type") == "url":
                    from urllib.parse import urlparse
                    try:
                        host = urlparse(ni["value"]).hostname
                        if host and not host.replace(".", "").isdigit():
                            domain_list.append(host)
                    except Exception:
                        pass
                elif ni.get("indicator_type") == "ip":
                    ip_list.append(ni["value"])

    # Also check network_indicators in APK analysis JSON
    findings = storage.load_findings(session_id)
    for f in findings:
        for tag in f.tags:
            if tag.startswith("domain:"):
                domain_list.append(tag.split(":", 1)[1])

    domain_list = sorted(set(domain_list))[:max_indicators] if domains else []
    ip_list = sorted(set(ip_list))[:max_indicators] if ips else []

    if not domain_list and not ip_list:
        info(console, "no IoCs found in this session to enrich.")
        return

    info(console, f"enriching {len(domain_list)} domain(s) + {len(ip_list)} IP(s)")
    result = enrich_indicators(
        domains=domain_list, ips=ip_list, api_key=api_key, max_indicators=max_indicators,
    )

    if json_out:
        typer.echo(json.dumps(result.model_dump(mode="json"), indent=2, default=str))
        return

    for dr in result.domain_results:
        label = f"[ok]clean[/ok]" if dr.malicious == 0 else f"[danger]{dr.malicious} malicious[/danger]"
        console.print(f"  {dr.indicator:30s}  {label}  [muted]{', '.join(dr.categories[:3])}[/muted]")
    for ir in result.ip_results:
        label = f"[ok]clean[/ok]" if ir.malicious == 0 else f"[danger]{ir.malicious} malicious[/danger]"
        console.print(f"  {ir.indicator:30s}  {label}  [muted]{ir.as_owner}[/muted]")

    success(console, f"enrichment complete: {result.errors} errors, {result.skipped} skipped")
