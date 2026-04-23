"""``drake integrity`` — integrity ledger, verification, and provenance utilities.

Subcommands:
- ``verify-ledger`` — validate the linked-hash chain of an integrity ledger
- ``verify-report`` — re-verify an integrity_report.json off-line
- ``export-bundle`` — generate a STIX 2.1 provenance bundle from a
  past report (either a JSON file or a run recorded in the ledger)
- ``list-runs`` — list all runs recorded in a ledger
- ``show-run`` — show the custody chain summary for a specific run
"""

from __future__ import annotations

import json
from pathlib import Path

import typer

from ..cli_theme import error, info, make_console, success, warn
from ..integrity.exceptions import IntegrityVerificationError
from ..integrity.ledger import IntegrityLedger
from ..integrity.models import IntegrityReport
from ..integrity.stix_bundle import render_provenance_stix
from ..integrity.verifier import IntegrityVerifier
from . import _shared

app = typer.Typer(
    no_args_is_help=True,
    help="Integrity ledger, verification, and provenance bundle utilities.",
)


# ---------------------------------------------------------------------------
# Path resolution helpers
# ---------------------------------------------------------------------------


def _resolve_ledger(ledger_arg: Path | None, workspace_arg: str | None) -> Path:
    """Resolve which ledger DB to use.

    Precedence:
    1. --ledger <path> (explicit file)
    2. --workspace <name> → <workspace>/drake.db (shared ledger)
    3. ./integrity_ledger.db
    """
    if ledger_arg:
        path = Path(ledger_arg)
        if not path.is_file():
            raise FileNotFoundError(f"Ledger not found: {path}")
        return path

    if workspace_arg:
        ws = _shared.resolve_workspace(workspace_arg)
        if not ws.db_path.is_file():
            raise FileNotFoundError(f"Workspace DB not found: {ws.db_path}")
        return ws.db_path

    local = Path.cwd() / "integrity_ledger.db"
    if local.is_file():
        return local

    raise FileNotFoundError(
        "No ledger path resolved. Use --ledger <path> or --workspace <name>."
    )


# ---------------------------------------------------------------------------
# verify-ledger
# ---------------------------------------------------------------------------


@app.command("verify-ledger")
def verify_ledger(
    ledger: Path = typer.Option(None, "--ledger", "-l", help="Path to integrity_ledger.db."),
    workspace: str = typer.Option(None, "--workspace", "-w", help="Workspace name (uses shared drake.db)."),
    run_id: str = typer.Option(None, "--run-id", help="Verify only one run_id (default: full chain)."),
) -> None:
    """Verify the linked-hash chain of an integrity ledger.

    Checks that every entry's payload SHA-256 and link_hash are consistent
    with the chain. Fails explicitly if tampering is detected.
    """
    console = make_console()

    try:
        ledger_path = _resolve_ledger(ledger, workspace)
    except FileNotFoundError as exc:
        error(console, str(exc))
        raise typer.Exit(code=2)

    info(console, f"ledger: [accent]{ledger_path}[/accent]")

    ledger_db = IntegrityLedger(ledger_path)
    total = ledger_db.count_entries()
    info(console, f"entries: {total}")

    violations = ledger_db.verify_chain(run_id=run_id)

    if violations:
        error(console, f"LEDGER VERIFICATION FAILED ({len(violations)} violation(s))")
        for v in violations[:10]:
            error(console, f"  - {v}")
        if len(violations) > 10:
            error(console, f"  … and {len(violations) - 10} more")
        raise typer.Exit(code=1)

    if run_id:
        success(console, f"ledger chain for run '{run_id}' VERIFIED")
    else:
        success(console, f"ledger chain VERIFIED ({total} entries)")


# ---------------------------------------------------------------------------
# verify-report
# ---------------------------------------------------------------------------


@app.command("verify-report")
def verify_report(
    report_path: Path = typer.Argument(..., help="Path to integrity_report.json."),
) -> None:
    """Re-verify an integrity_report.json file off-line.

    Loads the report, runs full integrity verification, and displays
    violations if any. Exits with code 1 on verification failure.
    """
    console = make_console()

    if not report_path.is_file():
        error(console, f"Report not found: {report_path}")
        raise typer.Exit(code=2)

    try:
        data = json.loads(report_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        error(console, f"Cannot parse report: {exc}")
        raise typer.Exit(code=2)

    try:
        report = IntegrityReport(**data)
    except Exception as exc:
        error(console, f"Report schema invalid: {exc}")
        raise typer.Exit(code=2)

    info(console, f"run_id:        [accent]{report.run_id}[/accent]")
    info(console, f"sample SHA256: {report.sample_sha256}")
    info(console, f"artifacts:     {len(report.artifacts)}")
    info(console, f"custody:       {len(report.custody_events)} event(s)")

    verifier = IntegrityVerifier()
    try:
        verifier.verify(report)
    except IntegrityVerificationError as exc:
        error(console, f"VERIFICATION FAILED ({len(exc.violations)} violation(s))")
        for v in exc.violations[:10]:
            error(console, f"  - {v}")
        if len(exc.violations) > 10:
            error(console, f"  … and {len(exc.violations) - 10} more")
        raise typer.Exit(code=1)

    success(console, "integrity report VERIFIED")


# ---------------------------------------------------------------------------
# export-bundle
# ---------------------------------------------------------------------------


@app.command("export-bundle")
def export_bundle(
    source: Path = typer.Argument(
        None,
        help="Path to integrity_report.json (omit if using --run-id with --ledger).",
    ),
    run_id: str = typer.Option(None, "--run-id", help="Run ID to look up in the ledger."),
    ledger: Path = typer.Option(None, "--ledger", "-l", help="Path to integrity_ledger.db."),
    workspace: str = typer.Option(None, "--workspace", "-w", help="Workspace name."),
    output: Path = typer.Option(None, "--output", "-o", help="Output STIX bundle path."),
) -> None:
    """Generate a STIX 2.1 provenance bundle from an integrity report.

    Two input modes:
    1. File mode: ``drake integrity export-bundle ./integrity_report.json``
    2. Ledger mode: ``drake integrity export-bundle --run-id RUN --ledger DB``
       (or --workspace NAME)
    """
    console = make_console()

    report: IntegrityReport | None = None

    if source and source.is_file():
        try:
            data = json.loads(source.read_text(encoding="utf-8"))
            report = IntegrityReport(**data)
        except Exception as exc:
            error(console, f"Cannot load report from {source}: {exc}")
            raise typer.Exit(code=2)
    elif run_id:
        try:
            ledger_path = _resolve_ledger(ledger, workspace)
        except FileNotFoundError as exc:
            error(console, str(exc))
            raise typer.Exit(code=2)
        ledger_db = IntegrityLedger(ledger_path)
        report = ledger_db.get_integrity_report(run_id)
        if report is None:
            error(console, f"No integrity report found for run_id '{run_id}' in {ledger_path}")
            raise typer.Exit(code=1)
    else:
        error(console, "Provide either a report path or --run-id [--ledger | --workspace]")
        raise typer.Exit(code=2)

    bundle_text = render_provenance_stix(report)
    if not bundle_text:
        error(console, "Cannot generate STIX bundle (missing sample SHA-256 in report)")
        raise typer.Exit(code=1)

    if output is None:
        output = Path.cwd() / f"integrity_provenance_{report.run_id}.stix.json"

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(bundle_text, encoding="utf-8")

    success(console, f"STIX bundle exported: [accent]{output}[/accent]")
    info(console, f"run_id:        {report.run_id}")
    info(console, f"sample SHA256: {report.sample_sha256}")
    info(console, f"events:        {len(report.custody_events)}")
    info(console, f"artifacts:     {len(report.artifacts)}")


# ---------------------------------------------------------------------------
# list-runs
# ---------------------------------------------------------------------------


@app.command("list-runs")
def list_runs(
    ledger: Path = typer.Option(None, "--ledger", "-l", help="Path to integrity_ledger.db."),
    workspace: str = typer.Option(None, "--workspace", "-w", help="Workspace name."),
) -> None:
    """List all run_ids recorded in the ledger."""
    console = make_console()

    try:
        ledger_path = _resolve_ledger(ledger, workspace)
    except FileNotFoundError as exc:
        error(console, str(exc))
        raise typer.Exit(code=2)

    ledger_db = IntegrityLedger(ledger_path)
    runs = ledger_db.list_runs()

    if not runs:
        info(console, "No runs found in ledger.")
        return

    info(console, f"ledger: [accent]{ledger_path}[/accent]")
    info(console, f"runs:   [accent]{len(runs)}[/accent]")
    console.print()
    for run in runs:
        summary = ledger_db.run_summary(run)
        verified = summary.get("verified")
        status = "PASS" if verified else ("FAIL" if verified is False else "?")
        console.print(
            f"  {run}  entries={summary['entry_count']}  "
            f"types={summary['entry_types']}  verified={status}"
        )


# ---------------------------------------------------------------------------
# show-run
# ---------------------------------------------------------------------------


@app.command("show-run")
def show_run(
    run_id: str = typer.Argument(..., help="The run_id to display."),
    ledger: Path = typer.Option(None, "--ledger", "-l", help="Path to integrity_ledger.db."),
    workspace: str = typer.Option(None, "--workspace", "-w", help="Workspace name."),
    detailed: bool = typer.Option(False, "--detailed", help="Show full payload of each entry."),
) -> None:
    """Show the custody chain for a specific run."""
    console = make_console()

    try:
        ledger_path = _resolve_ledger(ledger, workspace)
    except FileNotFoundError as exc:
        error(console, str(exc))
        raise typer.Exit(code=2)

    ledger_db = IntegrityLedger(ledger_path)
    entries = ledger_db.read_run(run_id)

    if not entries:
        error(console, f"No entries found for run_id '{run_id}'")
        raise typer.Exit(code=1)

    info(console, f"run_id:  [accent]{run_id}[/accent]")
    info(console, f"ledger:  [accent]{ledger_path}[/accent]")
    info(console, f"entries: [accent]{len(entries)}[/accent]")
    console.print()

    for e in entries:
        header = (
            f"seq={e.seq}  type={e.entry_type}  ts={e.timestamp}  "
            f"payload_sha256={e.payload_sha256[:16]}…"
        )
        console.print(header)
        if detailed:
            console.print(json.dumps(e.payload, indent=2, default=str)[:2000])
            console.print()
