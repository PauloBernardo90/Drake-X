"""Body of `drake elf`."""
from __future__ import annotations

from pathlib import Path

import typer

from ..cli_theme import error, info, make_console, success, warn
from . import _shared


def register(app: typer.Typer) -> None:

    @app.command("analyze")
    def analyze(
        elf_file: Path = typer.Argument(..., help="Path to the ELF binary."),
        workspace: str = typer.Option(None, "--workspace", "-w"),
        output_dir: Path = typer.Option(None, "--output-dir", "-o"),
        sandbox: bool = typer.Option(False, "--sandbox", help="Run extraction tools inside sandbox."),
        sandbox_backend: str = typer.Option("firejail", "--sandbox-backend", help="Sandbox backend: firejail, docker."),
        sign_integrity: bool = typer.Option(False, "--sign-integrity", help="GPG-sign integrity report."),
        signing_key: str = typer.Option("", "--signing-key", help="GPG key ID/fingerprint."),
        stix_provenance: bool = typer.Option(False, "--stix-provenance", help="Generate STIX provenance bundle."),
        ledger: bool = typer.Option(False, "--ledger", help="Append to integrity ledger."),
    ) -> None:
        """Run static analysis on an ELF binary (Linux / IoT native)."""
        from ..modules.elf_analyze import run_analysis
        from ..graph.pe_writer import dedupe_graph
        from ..normalize.binary.elf_normalize import build_elf_graph
        from ..reporting.elf_report_writer import render_elf_markdown, render_elf_json

        console = make_console()
        if not elf_file.exists():
            error(console, f"file not found: {elf_file}")
            raise typer.Exit(code=2)

        if workspace:
            ws = _shared.resolve_workspace(workspace)
            work_dir = Path(output_dir) if output_dir else (ws.runs_dir / f"elf-{elf_file.stem}")
        elif output_dir:
            work_dir = Path(output_dir)
        else:
            work_dir = Path.cwd() / f"drake-elf-{elf_file.stem}"

        work_dir.mkdir(parents=True, exist_ok=True)
        info(console, f"sample:     [accent]{elf_file}[/accent]")
        info(console, f"output dir: [accent]{work_dir}[/accent]")

        # --- Integrity: hash sample and start custody chain ---
        from ..integrity.hashing import compute_file_hashes
        from ..integrity.chain import CustodyChain
        from ..integrity.models import CustodyAction, ExecutionContext
        from ..integrity.versioning import capture_version_info
        from ..integrity.reporting import build_integrity_report, finalize_integrity_outputs

        sample_identity = compute_file_hashes(elf_file)
        exec_ctx = ExecutionContext(sample_sha256=sample_identity.sha256, analysis_mode="elf_analyze")
        chain = CustodyChain(run_id=exec_ctx.run_id, sample_sha256=sample_identity.sha256)
        chain.record(CustodyAction.INGEST, actor="elf_cmd", details=f"Ingested {elf_file.name}")
        chain.register_artifact(artifact_type="elf_original", file_path=elf_file, sha256=sample_identity.sha256)

        try:
            result = run_analysis(elf_file, work_dir)
            chain.record(CustodyAction.ANALYZE, actor="elf_analyze", details="Analysis completed")
        except Exception as exc:
            chain.record_failure(actor="elf_analyze", details=str(exc))
            error(console, f"analysis failed: {exc}")
            raise typer.Exit(code=1) from exc

        success(console, f"analysis complete for [accent]{elf_file.name}[/accent]")
        info(console, f"SHA-256:   {result.metadata.sha256}")
        info(console, f"arch:      {result.header.arch}")
        info(console, f"type:      {result.header.file_type}")
        info(console, f"imports:   {len(result.imports)}")
        info(console, f"sections:  {len(result.sections)}")
        info(console, f"tools ran: {', '.join(result.tools_ran) or 'none'}")
        if result.tools_skipped:
            warn(console, f"tools skipped: {', '.join(result.tools_skipped)}")

        # Optional sandboxed extraction
        if sandbox:
            from ..sandbox.base import SandboxConfig as SbxConfig
            from ..sandbox.runner import run_sandboxed as sbx_run
            info(console, f"sandbox:   running strings extraction via {sandbox_backend}")
            sbx_report = sbx_run(
                sample_path=elf_file,
                command=["strings", f"sample/{elf_file.name}"],
                backend_name=sandbox_backend,
                config=SbxConfig(timeout_seconds=120),
                output_dir=work_dir,
            )
            if sbx_report.status == "success":
                info(console, f"sandbox:   completed (run {sbx_report.run_id})")
            else:
                warn(console, f"sandbox:   {sbx_report.status} — {sbx_report.error or 'see report'}")

        graph = dedupe_graph(build_elf_graph(result))
        (work_dir / "elf_analysis.json").write_text(render_elf_json(result), encoding="utf-8")
        (work_dir / "elf_report.md").write_text(render_elf_markdown(result), encoding="utf-8")
        (work_dir / "elf_graph.json").write_text(graph.to_json(indent=2), encoding="utf-8")
        info(console, f"wrote: {work_dir/'elf_analysis.json'}")
        info(console, f"wrote: {work_dir/'elf_report.md'}")
        info(console, f"wrote: {work_dir/'elf_graph.json'}")

        # Register reports as artifacts
        chain.record(CustodyAction.REPORT_GENERATE, actor="report_writer", details="ELF reports")
        chain.register_artifact(artifact_type="report_json", file_path=work_dir / "elf_analysis.json")
        chain.register_artifact(artifact_type="report_md", file_path=work_dir / "elf_report.md")

        # --- Integrity: generate integrity report ---
        version_info = capture_version_info(analysis_profile="elf_analyze")
        exec_ctx.version_info = version_info
        integrity_report = build_integrity_report(
            sample_identity=sample_identity,
            chain=chain,
            execution_context=exec_ctx,
            version_info=version_info,
        )
        if ledger:
            ledger_path = ws.db_path if workspace else (work_dir.parent / "integrity_ledger.db")
        else:
            ledger_path = None
        outputs = finalize_integrity_outputs(
            integrity_report,
            work_dir,
            sign=sign_integrity,
            signing_key=signing_key,
            write_stix=stix_provenance,
            ledger_path=ledger_path,
        )
        info(console, f"integrity: [accent]{outputs.get('integrity_report')}[/accent] "
             f"({'PASS' if integrity_report.verified else 'FAIL'})")
        if outputs.get("signature"):
            info(console, f"signature: [accent]{outputs['signature']}[/accent]")
        elif sign_integrity:
            warn(console, f"signature: {outputs.get('signature_error', 'signing failed')}")
        if outputs.get("stix_provenance"):
            info(console, f"STIX:      [accent]{outputs['stix_provenance']}[/accent]")
        if outputs.get("ledger"):
            info(console, f"ledger:    [accent]{outputs['ledger']}[/accent]")

        if workspace:
            from ..models.session import Session
            from ..models.target import Target

            assert ws is not None
            target = Target(
                raw=str(elf_file),
                canonical=str(elf_file.resolve()),
                target_type="domain",
                host=elf_file.name,
            )
            session = Session(
                target=target,
                profile="elf_analyze",
                tools_planned=result.tools_ran + result.tools_skipped,
                tools_ran=result.tools_ran,
                tools_skipped=result.tools_skipped,
                warnings=result.warnings,
            )
            session.mark_running()
            ws.storage.legacy.save_session(session)
            ws.storage.save_evidence_graph(session.id, graph)
            session.mark_finished(partial=bool(result.tools_skipped))
            ws.storage.legacy.save_session(session)
            info(console, f"session:   [accent]{session.id}[/accent]")
