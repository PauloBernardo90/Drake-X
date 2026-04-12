"""``drake pe`` — Windows PE static analysis commands."""

from __future__ import annotations

import json
import os
from pathlib import Path

import typer

from ..cli_theme import error, info, make_console, success, warn
from ..modules.pe_analyze import (
    attach_graph_snapshot,
    build_graph,
    run_ai_exploit_assessment,
    run_analysis,
)
from ..normalize.binary.pe_normalize import pe_result_to_findings
from ..reporting.pe_report_writer import render_pe_executive, render_pe_json, render_pe_markdown
from . import _shared

app = typer.Typer(no_args_is_help=True, help="Windows PE static analysis for malware research and defensive investigation.")


@app.command("analyze")
def analyze(
    pe_file: Path = typer.Argument(..., help="Path to the .exe or .dll file to analyze."),
    workspace: str = typer.Option(None, "--workspace", "-w", help="Workspace name or path."),
    output_dir: Path = typer.Option(None, "--output-dir", "-o", help="Override output directory."),
    deep: bool = typer.Option(False, "--deep", help="Enable deeper analysis."),
    vt: bool = typer.Option(False, "--vt", help="Enable VirusTotal hash lookup."),
    ai_exploit_assessment: bool = typer.Option(
        False,
        "--ai-exploit-assessment",
        help="Run the AI exploit-awareness assessment task (requires Ollama). "
             "Output is analytical, bounded, and always labeled as requiring validation.",
    ),
    detection_output: bool = typer.Option(
        False,
        "--detection-output",
        help="Emit candidate YARA rules and a STIX IoC bundle alongside the report. "
             "Outputs are labeled as analyst-review-required candidates.",
    ),
    ollama_url: str = typer.Option(
        "http://127.0.0.1:11434",
        "--ollama-url",
        help="Base URL for a local Ollama runtime (AI-assisted features only).",
    ),
    ollama_model: str = typer.Option(
        "llama3.1:8b",
        "--ollama-model",
        help="Ollama model to use for AI-assisted tasks.",
    ),
) -> None:
    """Run static analysis on a Windows PE file (.exe or .dll).

    Produces structured PE metadata, section analysis, import/export
    inventory, anomaly detection, and protection status assessment.
    """
    console = make_console()

    if not pe_file.exists():
        error(console, f"file not found: {pe_file}")
        raise typer.Exit(code=2)

    # Resolve workspace and output directory
    ws = None
    if workspace:
        ws = _shared.resolve_workspace(workspace)
        if output_dir:
            work_dir = Path(output_dir)
        else:
            work_dir = ws.runs_dir / f"pe-{pe_file.stem}"
    elif output_dir:
        work_dir = Path(output_dir)
    else:
        work_dir = Path.cwd() / f"drake-pe-{pe_file.stem}"

    work_dir.mkdir(parents=True, exist_ok=True)
    info(console, f"sample:     [accent]{pe_file}[/accent]")
    info(console, f"output dir: [accent]{work_dir}[/accent]")

    # Resolve VT API key
    vt_api_key = ""
    if vt:
        if ws:
            vt_api_key = ws.config.vt_api_key
        if not vt_api_key:
            vt_api_key = os.environ.get("VT_API_KEY", "")
        if not vt_api_key:
            warn(console, "--vt requested but no API key available")

    # Run analysis
    try:
        result = run_analysis(
            pe_file,
            work_dir,
            deep=deep,
            vt_api_key=vt_api_key,
        )
    except Exception as exc:
        error(console, f"analysis failed: {exc}")
        raise typer.Exit(code=1) from exc

    # Print summary
    m = result.metadata
    h = result.header
    success(console, f"analysis complete for [accent]{pe_file.name}[/accent]")
    info(console, f"SHA-256:       {m.sha256}")
    info(console, f"machine:       {h.machine.value}")
    info(console, f"type:          {'DLL' if h.is_dll else 'EXE'}")
    info(console, f"entry point:   {h.entry_point}")
    info(console, f"sections:      {len(result.sections)}")
    info(console, f"imports:       {len(result.imports)} functions from {len(set(i.dll for i in result.imports))} DLL(s)")
    info(console, f"exports:       {len(result.exports)}")
    info(console, f"resources:     {len(result.resources)}")
    info(console, f"anomalies:     {len(result.anomalies)}")

    # Protection summary
    p = result.protection
    prot_flags = []
    if p.aslr_enabled:
        prot_flags.append("ASLR")
    if p.dep_enabled:
        prot_flags.append("DEP")
    if p.cfg_enabled:
        prot_flags.append("CFG")
    if p.safe_seh:
        prot_flags.append("SafeSEH")
    if p.stack_cookies:
        prot_flags.append("GS")
    info(console, f"protections:   {', '.join(prot_flags) if prot_flags else 'none detected'}")

    # v0.9 exploit-awareness summary
    if result.exploit_indicators:
        high_ei = [ei for ei in result.exploit_indicators if ei.severity == "high"]
        info(console, f"exploit indicators: {len(result.exploit_indicators)} "
             f"({len(high_ei)} high) — all suspected, pending validation")
    if result.suspected_shellcode:
        info(console, f"suspected shellcode: {len(result.suspected_shellcode)} artifact(s)")
    if result.protection_interactions:
        info(console, f"protection interactions: {len(result.protection_interactions)} assessment(s)")

    info(console, f"tools ran:     {', '.join(result.tools_ran) or 'none'}")
    if result.tools_skipped:
        warn(console, f"tools skipped: {', '.join(result.tools_skipped)}")

    # Generate findings
    findings = pe_result_to_findings(result)
    info(console, f"findings:      {len(findings)}")

    # ------------------------------------------------------------------
    # v0.9 — Build the Evidence Graph (canonical integration bus)
    # ------------------------------------------------------------------
    graph = build_graph(result)
    info(console, f"graph:         {len(graph.nodes)} nodes, {len(graph.edges)} edges")

    # ------------------------------------------------------------------
    # v0.9 — Optional AI exploit assessment
    # ------------------------------------------------------------------
    if ai_exploit_assessment:
        audit_dir = work_dir / "ai_audit"
        info(console, f"AI exploit assessment via [accent]{ollama_model}[/accent] ...")
        parsed = run_ai_exploit_assessment(
            result,
            graph,
            ollama_base_url=ollama_url,
            ollama_model=ollama_model,
            audit_dir=audit_dir,
        )
        if parsed is not None:
            success(console, "AI exploit assessment: received parsed response")
        else:
            warn(console, "AI exploit assessment: no parsed response "
                 "(see pe_analysis.json warnings and ai_audit/)")
        info(console, f"audit log:     [accent]{audit_dir}/exploit_assessment.jsonl[/accent]")

    # Attach graph snapshot to the model so the JSON export is self-contained.
    attach_graph_snapshot(result, graph)

    # Write outputs
    json_path = work_dir / "pe_analysis.json"
    json_path.write_text(render_pe_json(result), encoding="utf-8")
    info(console, f"JSON:          [accent]{json_path}[/accent]")

    graph_path = work_dir / "pe_graph.json"
    graph_path.write_text(graph.to_json(indent=2), encoding="utf-8")
    info(console, f"graph:         [accent]{graph_path}[/accent]")

    md_path = work_dir / "pe_report.md"
    md_path.write_text(render_pe_markdown(result), encoding="utf-8")
    info(console, f"report:        [accent]{md_path}[/accent]")

    exec_path = work_dir / "pe_executive.md"
    exec_path.write_text(render_pe_executive(result), encoding="utf-8")
    info(console, f"executive:     [accent]{exec_path}[/accent]")

    # ------------------------------------------------------------------
    # v0.9 — Optional detection artifact emission
    # ------------------------------------------------------------------
    if detection_output:
        from ..reporting.detection_writer import (
            render_pe_yara_candidates,
            render_pe_stix_bundle,
        )
        yara_text = render_pe_yara_candidates(result)
        if yara_text:
            yara_path = work_dir / "pe_candidates.yar"
            yara_path.write_text(yara_text, encoding="utf-8")
            info(console, f"YARA:          [accent]{yara_path}[/accent]  (candidate — analyst review required)")
        else:
            info(console, "YARA:          no candidates generated (insufficient signals)")

        stix_text = render_pe_stix_bundle(result)
        if stix_text:
            stix_path = work_dir / "pe_stix.json"
            stix_path.write_text(stix_text, encoding="utf-8")
            info(console, f"STIX:          [accent]{stix_path}[/accent]  (candidate — analyst review required)")
