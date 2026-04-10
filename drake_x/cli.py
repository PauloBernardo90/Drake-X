"""Drake-X command-line interface (Typer).

All visual styling (colors, panels, the brand header) lives in
:mod:`drake_x.cli_theme`. This module wires Typer commands to the
orchestrator and delegates presentation.
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

import typer

from . import __version__
from .ai.analyzer import AIAnalyzer
from .ai.ollama_client import OllamaClient
from .cli_theme import (
    build_tools_table,
    error,
    format_tool_installed,
    info,
    make_console,
    render_header,
    render_scan_summary,
    success,
    warn,
)
from .config import DrakeXConfig, load_config
from .constants import (
    ALL_PROFILES,
    APP_DISPLAY_NAME,
    AUTHORIZED_USE_NOTICE,
)
from .exceptions import (
    ConfigurationError,
    DrakeXError,
    InvalidTargetError,
    ScopeViolationError,
    StorageError,
)
from .logging import configure_logging, get_logger
from .orchestrator import Orchestrator, ScanReport
from .registry import ToolRegistry
from .reports.markdown import render_markdown_report
from .scope import parse_target
from .session_store import SessionStore

# Typer renders its own help text via an internal Console that does not see
# our theme, so the ``help`` string below uses plain Rich style names rather
# than theme style names. Everything we print ourselves goes through
# ``console`` below, which *is* theme-aware.
app = typer.Typer(
    name="drake-x",
    add_completion=False,
    no_args_is_help=True,
    rich_markup_mode="rich",
    help=(
        f"[bold cyan]{APP_DISPLAY_NAME}[/bold cyan] — "
        "local CLI reconnaissance assistant.\n\n"
        f"[bold yellow]{AUTHORIZED_USE_NOTICE}[/bold yellow]\n\n"
        "Drake-X orchestrates locally installed Kali tools and (optionally) "
        "asks a local Ollama model for triage. It does not perform exploitation."
    ),
)

console = make_console()
log = get_logger("cli")


# ----- shared option helpers -------------------------------------------------


def _build_config(
    *,
    db_path: Path | None,
    output_dir: Path | None,
    ollama_url: str | None,
    model: str | None,
    timeout: int | None,
    profile: str | None,
    no_ai: bool,
    verbose: bool,
) -> DrakeXConfig:
    try:
        cfg = load_config()
    except ConfigurationError as exc:
        error(console, f"Configuration error: {exc}")
        raise typer.Exit(code=2) from exc

    cfg = cfg.with_overrides(
        db_path=db_path,
        output_dir=output_dir,
        ollama_url=ollama_url,
        ollama_model=model,
        default_timeout=timeout,
        default_profile=profile,
        verbose=verbose,
    )
    if no_ai:
        cfg = cfg.with_overrides(disable_ai=True)
    cfg.ensure_directories()
    return cfg


def _build_components(cfg: DrakeXConfig) -> tuple[ToolRegistry, SessionStore, Orchestrator]:
    registry = ToolRegistry(default_timeout=cfg.default_timeout)
    try:
        store = SessionStore(cfg.db_path)
    except StorageError as exc:
        error(console, f"Storage error: {exc}")
        raise typer.Exit(code=2) from exc

    ai = None
    if not cfg.disable_ai:
        client = OllamaClient(base_url=cfg.ollama_url, model=cfg.ollama_model)
        ai = AIAnalyzer(client=client)

    orchestrator = Orchestrator(config=cfg, registry=registry, store=store, ai=ai)
    return registry, store, orchestrator


# ----- scan ------------------------------------------------------------------


@app.command("scan", help="Run a recon session against a single target. Authorized use only.")
def scan(
    target: str = typer.Argument(..., help="Target IPv4/IPv6/CIDR/domain/URL."),
    profile: str = typer.Option(
        None,
        "--profile",
        "-p",
        help=f"Recon profile. One of: {', '.join(ALL_PROFILES)}.",
    ),
    timeout: int = typer.Option(None, "--timeout", "-t", help="Per-tool timeout in seconds."),
    output_dir: Path = typer.Option(None, "--output-dir", help="Where to write reports and raw artifacts."),
    db_path: Path = typer.Option(None, "--db-path", help="SQLite database path."),
    ollama_url: str = typer.Option(None, "--ollama-url", help="Local Ollama base URL."),
    model: str = typer.Option(None, "--model", help="Ollama model name (e.g. llama3.2:3b)."),
    no_ai: bool = typer.Option(False, "--no-ai", help="Skip AI analysis even if Ollama is reachable."),
    json_out: bool = typer.Option(False, "--json", help="Print a machine-readable JSON summary instead of pretty text."),
    write_report: bool = typer.Option(True, "--write-report/--no-write-report", help="Generate a Markdown report file."),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable debug logging."),
) -> None:
    configure_logging(verbose=verbose)

    cfg = _build_config(
        db_path=db_path,
        output_dir=output_dir,
        ollama_url=ollama_url,
        model=model,
        timeout=timeout,
        profile=profile,
        no_ai=no_ai,
        verbose=verbose,
    )

    if cfg.default_profile not in ALL_PROFILES:
        error(console, f"Invalid profile: {cfg.default_profile}")
        raise typer.Exit(code=2)

    try:
        parsed_target = parse_target(target)
    except InvalidTargetError as exc:
        error(console, f"Invalid target: {exc}")
        raise typer.Exit(code=2) from exc
    except ScopeViolationError as exc:
        error(console, f"Refused to scan: {exc}")
        raise typer.Exit(code=2) from exc

    # Brand header shown only in interactive (non-JSON) mode so JSON output
    # stays machine-parseable on stdout.
    if not json_out:
        render_header(console, version=__version__)
        info(
            console,
            f"target [accent]{parsed_target.canonical}[/accent] "
            f"[muted]({parsed_target.target_type})[/muted]  ·  "
            f"profile [accent.secondary]{cfg.default_profile}[/accent.secondary]",
        )

    registry, store, orchestrator = _build_components(cfg)

    ai_enabled_request = not cfg.disable_ai
    if ai_enabled_request and orchestrator.ai is not None:
        try:
            ai_reachable = asyncio.run(orchestrator.ai.is_available())
        except Exception:  # noqa: BLE001
            ai_reachable = False
        if not ai_reachable:
            if not json_out:
                warn(
                    console,
                    f"Ollama not reachable at {cfg.ollama_url}; continuing without AI",
                )
            ai_enabled_request = False

    try:
        report = asyncio.run(
            orchestrator.run_scan(
                parsed_target,
                profile=cfg.default_profile,
                tool_timeout=cfg.default_timeout,
                ai_enabled=ai_enabled_request,
            )
        )
    except DrakeXError as exc:
        error(console, f"Scan failed: {exc}")
        raise typer.Exit(code=1) from exc

    report_path: Path | None = None
    if write_report:
        report_path = _write_markdown(cfg, report)
        report.session.report_path = str(report_path)
        store.save_session(report.session)

    if json_out:
        _print_json_summary(report, report_path)
    else:
        render_scan_summary(console, report, report_path, AUTHORIZED_USE_NOTICE)


# ----- tools list ------------------------------------------------------------


tools_app = typer.Typer(no_args_is_help=True, help="Inspect tool support.")
app.add_typer(tools_app, name="tools")


@tools_app.command("list", help="List supported tools and which ones are installed locally.")
def tools_list(
    db_path: Path = typer.Option(None, "--db-path", help="SQLite database path (unused but kept consistent)."),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
) -> None:
    configure_logging(verbose=verbose)
    cfg = _build_config(
        db_path=db_path,
        output_dir=None,
        ollama_url=None,
        model=None,
        timeout=None,
        profile=None,
        no_ai=True,
        verbose=verbose,
    )
    registry = ToolRegistry(default_timeout=cfg.default_timeout)

    table = build_tools_table()
    for entry in registry.all_entries():
        table.add_row(
            entry.name,
            format_tool_installed(entry.installed),
            ", ".join(entry.profiles),
            ", ".join(entry.target_types),
            entry.description,
        )

    render_header(console, version=__version__)
    console.print()
    console.print(table)
    console.print()
    console.print(f"[notice]{AUTHORIZED_USE_NOTICE}[/notice]")


# ----- report ----------------------------------------------------------------


@app.command("report", help="Generate a Markdown report for a previously stored session.")
def report(
    session_id: str = typer.Argument(..., help="Session ID returned by `drake-x scan`."),
    output: Path = typer.Option(None, "--output", "-o", help="Write to file instead of stdout."),
    db_path: Path = typer.Option(None, "--db-path", help="SQLite database path."),
    output_dir: Path = typer.Option(None, "--output-dir", help="Override default output directory."),
    verbose: bool = typer.Option(False, "--verbose", "-v"),
) -> None:
    configure_logging(verbose=verbose)
    cfg = _build_config(
        db_path=db_path,
        output_dir=output_dir,
        ollama_url=None,
        model=None,
        timeout=None,
        profile=None,
        no_ai=True,
        verbose=verbose,
    )

    try:
        store = SessionStore(cfg.db_path)
    except StorageError as exc:
        error(console, f"Storage error: {exc}")
        raise typer.Exit(code=2) from exc

    session = store.load_session(session_id)
    if session is None:
        error(console, f"Session not found: {session_id}")
        raise typer.Exit(code=1)

    tool_results = store.load_tool_results(session_id)
    artifacts = store.load_artifacts(session_id)
    findings = store.load_findings(session_id)

    md = render_markdown_report(
        session=session,
        tool_results=tool_results,
        artifacts=artifacts,
        findings=findings,
    )

    # When writing to stdout we want the Markdown to be the *only* output so
    # the command is safe to pipe. File output can show a short confirmation.
    if output is None:
        sys.stdout.write(md)
    else:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(md, encoding="utf-8")
        success(console, f"Report written to [accent]{output}[/accent]")


# ----- helpers ---------------------------------------------------------------


def _write_markdown(cfg: DrakeXConfig, report: ScanReport) -> Path:
    out_dir = cfg.output_dir / report.session.id
    out_dir.mkdir(parents=True, exist_ok=True)
    md_path = out_dir / "report.md"
    md = render_markdown_report(
        session=report.session,
        tool_results=report.tool_results,
        artifacts=report.artifacts,
        findings=report.findings,
    )
    md_path.write_text(md, encoding="utf-8")

    # Also dump raw artifacts for auditability.
    (out_dir / "artifacts.json").write_text(
        json.dumps([a.model_dump() for a in report.artifacts], indent=2, default=str),
        encoding="utf-8",
    )
    return md_path


def _print_json_summary(report: ScanReport, report_path: Path | None) -> None:
    payload = {
        "session_id": report.session.id,
        "target": report.session.target.model_dump(),
        "profile": report.session.profile,
        "status": report.session.status.value,
        "tools_ran": report.session.tools_ran,
        "tools_skipped": report.session.tools_skipped,
        "warnings": report.session.warnings,
        "artifact_count": len(report.artifacts),
        "ai_enabled": report.session.ai_enabled,
        "ai_model": report.session.ai_model,
        "ai_summary": report.session.ai_summary,
        "report_path": str(report_path) if report_path else None,
    }
    sys.stdout.write(json.dumps(payload, indent=2, default=str) + "\n")


if __name__ == "__main__":  # pragma: no cover
    app()
