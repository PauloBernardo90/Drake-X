"""``drake apk`` — APK static analysis commands."""

from __future__ import annotations

import os
from pathlib import Path

import typer

from ..cli_theme import error, info, make_console, success, warn
from ..modules.apk_analyze import run_analysis
from ..normalize.apk.bridge import apk_result_to_findings
from ..normalize.apk.graph_builder import build_apk_evidence_graph
from ..reporting.apk_report_writer import (
    render_apk_executive,
    render_apk_json,
    render_apk_markdown,
)
from . import _shared

app = typer.Typer(no_args_is_help=True, help="APK static analysis for malware research and defensive investigation.")


@app.command("analyze")
def analyze(
    apk_file: Path = typer.Argument(..., help="Path to the .apk file to analyze."),
    workspace: str = typer.Option(None, "--workspace", "-w", help="Workspace name or path."),
    output_dir: Path = typer.Option(None, "--output-dir", "-o", help="Override output directory."),
    report: bool = typer.Option(True, "--report/--no-report", help="Generate the Markdown report."),
    deep: bool = typer.Option(False, "--deep", help="Enable deeper analysis (more time, more coverage)."),
    strings: bool = typer.Option(True, "--strings/--no-strings", help="Run strings extraction."),
    jadx: bool = typer.Option(True, "--jadx/--no-jadx", help="Decompile with jadx."),
    apktool: bool = typer.Option(True, "--apktool/--no-apktool", help="Decompile with apktool."),
    radare2: bool = typer.Option(False, "--radare2", help="Run rabin2 analysis."),
    ghidra: bool = typer.Option(False, "--ghidra", help="Run Ghidra headless deeper analysis on native libraries."),
    vt: bool = typer.Option(False, "--vt", help="Enable VirusTotal hash lookup (requires API key in workspace config)."),
) -> None:
    """Run static analysis on an Android APK file.

    Produces normalized findings, a technical Markdown report, an executive
    summary, an evidence graph, and a JSON evidence dump. When a workspace
    is specified, findings are persisted through the standard storage layer
    for cross-domain correlation and unified reporting.
    """
    console = make_console()

    if not apk_file.exists():
        error(console, f"file not found: {apk_file}")
        raise typer.Exit(code=2)

    if not str(apk_file).lower().endswith(".apk"):
        warn(console, "file does not have .apk extension — proceeding anyway")

    # Resolve workspace and output directory
    ws = None
    storage = None
    if workspace:
        ws = _shared.resolve_workspace(workspace)
        if output_dir:
            work_dir = Path(output_dir)
        else:
            work_dir = ws.runs_dir / f"apk-{apk_file.stem}"
    elif output_dir:
        work_dir = Path(output_dir)
    else:
        work_dir = Path.cwd() / f"drake-apk-{apk_file.stem}"

    work_dir.mkdir(parents=True, exist_ok=True)
    info(console, f"sample:     [accent]{apk_file}[/accent]")
    info(console, f"output dir: [accent]{work_dir}[/accent]")

    # Resolve VT API key
    vt_api_key = ""
    if vt:
        if ws:
            vt_api_key = ws.config.vt_api_key
        if not vt_api_key:
            vt_api_key = os.environ.get("VT_API_KEY", "")
        if not vt_api_key:
            warn(console, "--vt requested but no api_key in workspace [virustotal] config and no VT_API_KEY env var")

    # Run analysis
    try:
        result = run_analysis(
            apk_file,
            work_dir,
            use_jadx=jadx,
            use_apktool=apktool,
            use_strings=strings,
            use_radare2=radare2,
            use_ghidra=ghidra,
            deep=deep,
            vt_api_key=vt_api_key,
        )
    except Exception as exc:
        error(console, f"analysis failed: {exc}")
        raise typer.Exit(code=1) from exc

    # Build evidence graph
    graph = build_apk_evidence_graph(result)
    graph_path = work_dir / "evidence_graph.json"
    graph_path.write_text(graph.to_json(indent=2), encoding="utf-8")

    # Bridge APK findings into standard Finding model
    findings = apk_result_to_findings(result)

    # Persist into workspace if available
    session_id = None
    if ws:
        from ..core.storage import WorkspaceStorage
        from ..models.session import Session
        from ..scope import parse_target

        storage = WorkspaceStorage(ws.db_path)
        # Create a session for this APK analysis
        target_str = result.metadata.package_name or f"file://{apk_file.name}"
        try:
            parsed_target = parse_target(f"https://{result.metadata.package_name or 'apk.local'}")
        except Exception:
            # APK targets don't fit the URL/domain model perfectly — use a
            # minimal target that satisfies the session model.
            from ..models.target import Target
            parsed_target = Target(
                raw=str(apk_file),
                canonical=result.metadata.package_name or str(apk_file),
                target_type="domain",
                host=result.metadata.package_name or "apk.local",
            )

        session = Session(
            target=parsed_target,
            profile="apk_analyze",
            tools_planned=result.tools_ran + result.tools_skipped,
            tools_ran=result.tools_ran,
            tools_skipped=result.tools_skipped,
            warnings=result.warnings,
        )
        session.mark_running()
        storage.legacy.save_session(session)

        for f in findings:
            storage.save_finding(session.id, f)

        storage.save_evidence_graph(session.id, graph)

        session.mark_finished(partial=bool(result.tools_skipped))
        storage.legacy.save_session(session)
        session_id = session.id

    # Print summary
    m = result.metadata
    success(console, f"analysis complete for [accent]{m.package_name or m.sha256[:12]}[/accent]")
    info(console, f"SHA-256:       {m.sha256}")
    info(console, f"permissions:   {len(result.permissions)} ({len([p for p in result.permissions if p.is_suspicious])} suspicious)")
    info(console, f"components:    {len(result.components)}")
    info(console, f"behaviors:     {len(result.behavior_indicators)}")
    info(console, f"network IOCs:  {len(result.network_indicators)}")
    info(console, f"protections:   {len([p for p in result.protection_indicators if p.status.value != 'not_observed'])}")
    info(console, f"frida targets: {len(result.frida_targets)}")
    if result.ghidra_analysis.available:
        structured = len(result.native_analysis)
        total = len(result.ghidra_analysis.analyzed_binaries)
        if structured:
            info(console, f"ghidra:        {total} binary(ies) analyzed ({structured} structured)")
        else:
            info(console, f"ghidra:        {total} binary(ies) analyzed")
    elif ghidra:
        warn(console, f"ghidra:        {result.ghidra_analysis.error or 'unavailable'}")
    if result.vt_enrichment.available:
        info(console, f"VT detection:  {result.vt_enrichment.detection_ratio}")
    elif vt:
        warn(console, f"VT enrichment: {result.vt_enrichment.error or 'unavailable'}")
    info(console, f"findings:      {len(findings)}")
    graph_stats = graph.stats()
    info(console, f"evidence graph: {graph_stats['total_nodes']} nodes, {graph_stats['total_edges']} edges")
    info(console, f"tools ran:     {', '.join(result.tools_ran) or 'none'}")
    if result.tools_skipped:
        warn(console, f"tools skipped: {', '.join(result.tools_skipped)}")
    if session_id:
        info(console, f"session:       [accent]{session_id}[/accent]")

    # Write outputs
    json_path = work_dir / "apk_analysis.json"
    json_path.write_text(render_apk_json(result), encoding="utf-8")
    info(console, f"JSON:          [accent]{json_path}[/accent]")
    info(console, f"graph:         [accent]{graph_path}[/accent]")

    if report:
        md_path = work_dir / "apk_report.md"
        md_path.write_text(render_apk_markdown(result), encoding="utf-8")
        info(console, f"report:        [accent]{md_path}[/accent]")

        exec_path = work_dir / "apk_executive.md"
        exec_path.write_text(render_apk_executive(result), encoding="utf-8")
        info(console, f"executive:     [accent]{exec_path}[/accent]")
