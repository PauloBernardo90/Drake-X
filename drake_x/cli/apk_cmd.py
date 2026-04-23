"""``drake apk`` — APK static analysis commands."""

from __future__ import annotations

import os
from pathlib import Path

import typer

from ..cli_theme import error, info, make_console, success, warn
from ..modules.apk_analyze import run_analysis
from ..normalize.apk.bridge import apk_result_to_findings
from ..normalize.apk.dex_bridge import dex_result_to_findings
from ..normalize.apk.dex_graph import merge_dex_into_evidence_graph
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
    dex_deep: bool = typer.Option(False, "--dex-deep", help="Run DEX deep disassembly and semantic extraction."),
    sandbox: bool = typer.Option(False, "--sandbox", help="Run extraction tools inside sandbox (requires firejail or docker)."),
    sandbox_backend: str = typer.Option("firejail", "--sandbox-backend", help="Sandbox backend: firejail, docker."),
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

    # --- Integrity: compute original hashes and start custody chain ---
    from ..integrity.hashing import compute_file_hashes
    from ..integrity.chain import CustodyChain
    from ..integrity.models import CustodyAction, ExecutionContext
    from ..integrity.versioning import capture_version_info
    from ..integrity.reporting import build_integrity_report, write_integrity_report

    sample_identity = compute_file_hashes(apk_file)
    exec_ctx = ExecutionContext(sample_sha256=sample_identity.sha256, analysis_mode="apk_analyze")
    chain = CustodyChain(run_id=exec_ctx.run_id, sample_sha256=sample_identity.sha256)
    chain.record(CustodyAction.INGEST, actor="apk_cmd", details=f"Ingested {apk_file.name}")
    chain.register_artifact(artifact_type="apk_original", file_path=apk_file, sha256=sample_identity.sha256)

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
            use_dex_deep=dex_deep,
            deep=deep,
            vt_api_key=vt_api_key,
        )
        chain.record(CustodyAction.ANALYZE, actor="apk_analyze", details="Analysis completed")
    except Exception as exc:
        chain.record_failure(actor="apk_analyze", details=str(exc))
        error(console, f"analysis failed: {exc}")
        raise typer.Exit(code=1) from exc

    # Build evidence graph
    graph = build_apk_evidence_graph(result)

    # Bridge APK findings into standard Finding model
    findings = apk_result_to_findings(result)

    # Merge DEX deep analysis into findings and evidence graph
    if result.dex_analysis is not None:
        dex_findings = dex_result_to_findings(result.dex_analysis)
        findings.extend(dex_findings)
        merge_dex_into_evidence_graph(graph, result.dex_analysis, root_sha256=result.metadata.sha256)

        # Write standalone DEX report
        from ..dex.report import write_json_report as write_dex_json, write_markdown_report as write_dex_md
        write_dex_json(result.dex_analysis, work_dir / "dex_analysis.json")
        write_dex_md(
            result.dex_analysis,
            work_dir / "dex_report.md",
            apk_name=result.metadata.package_name or apk_file.name,
        )

        # YARA candidate rules
        from ..reporting.dex_detection_writer import render_dex_yara_candidates, render_dex_stix_bundle, correlate_dex_with_vt
        yara_text = render_dex_yara_candidates(result.dex_analysis, sha256=result.metadata.sha256)
        if yara_text:
            yara_path = work_dir / "dex_candidates.yar"
            yara_path.write_text(yara_text, encoding="utf-8")
            info(console, f"YARA:          [accent]{yara_path}[/accent]")

        # STIX bundle
        stix_text = render_dex_stix_bundle(
            result.dex_analysis,
            sha256=result.metadata.sha256,
            md5=result.metadata.md5,
            file_size=result.metadata.file_size,
        )
        if stix_text:
            stix_path = work_dir / "dex_stix_bundle.json"
            stix_path.write_text(stix_text, encoding="utf-8")
            info(console, f"STIX:          [accent]{stix_path}[/accent]")

        # VT correlation
        if result.vt_enrichment.available:
            vt_data = result.vt_enrichment.model_dump()
            correlations = correlate_dex_with_vt(result.dex_analysis, vt_data)
            if correlations:
                info(console, f"VT×DEX:        {len(correlations)} correlation(s) found")

    graph_path = work_dir / "evidence_graph.json"
    graph_path.write_text(graph.to_json(indent=2), encoding="utf-8")

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
    if result.dex_analysis is not None:
        da = result.dex_analysis
        info(console, f"dex deep:      {len(da.dex_files)} DEX, {len(da.sensitive_api_hits)} API hits, "
             f"obfuscation={da.obfuscation_score:.0%}, {len(da.findings)} findings")
    elif dex_deep:
        warn(console, "dex deep:      analysis failed or unavailable")
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

    # Optional sandboxed extraction
    if sandbox:
        from ..sandbox.base import SandboxConfig as SbxConfig
        from ..sandbox.runner import run_sandboxed as sbx_run
        info(console, f"sandbox:       running strings extraction via {sandbox_backend}")
        sbx_report = sbx_run(
            sample_path=apk_file,
            command=["strings", f"sample/{apk_file.name}"],
            backend_name=sandbox_backend,
            config=SbxConfig(timeout_seconds=120),
            output_dir=work_dir,
        )
        if sbx_report.status == "success":
            info(console, f"sandbox:       completed (run {sbx_report.run_id})")
        else:
            warn(console, f"sandbox:       {sbx_report.status} — {sbx_report.error or 'see report'}")

    # Write outputs
    json_path = work_dir / "apk_analysis.json"
    json_path.write_text(render_apk_json(result), encoding="utf-8")
    info(console, f"JSON:          [accent]{json_path}[/accent]")
    info(console, f"graph:         [accent]{graph_path}[/accent]")

    if report:
        md_path = work_dir / "apk_report.md"
        md_path.write_text(render_apk_markdown(result), encoding="utf-8")
        info(console, f"report:        [accent]{md_path}[/accent]")
        chain.record(CustodyAction.REPORT_GENERATE, actor="report_writer", details="Markdown report")
        chain.register_artifact(artifact_type="report_md", file_path=md_path)

        exec_path = work_dir / "apk_executive.md"
        exec_path.write_text(render_apk_executive(result), encoding="utf-8")
        info(console, f"executive:     [accent]{exec_path}[/accent]")

    # Register JSON output as artifact
    chain.register_artifact(artifact_type="report_json", file_path=json_path)

    # --- Integrity: generate and write integrity report ---
    version_info = capture_version_info(analysis_profile="apk_analyze")
    exec_ctx.version_info = version_info
    integrity_report = build_integrity_report(
        sample_identity=sample_identity,
        chain=chain,
        execution_context=exec_ctx,
        version_info=version_info,
    )
    integrity_path = work_dir / "integrity_report.json"
    write_integrity_report(integrity_report, integrity_path)
    info(console, f"integrity:     [accent]{integrity_path}[/accent] ({'PASS' if integrity_report.verified else 'FAIL'})")
