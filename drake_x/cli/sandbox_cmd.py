"""``drake sandbox`` — local-first sandboxed execution commands."""

from __future__ import annotations

from pathlib import Path

import typer

from ..cli_theme import error, info, make_console, success, warn
from ..sandbox.base import NetworkPolicy, SandboxConfig, SandboxStatus
from ..sandbox.runner import run_sandboxed

app = typer.Typer(
    no_args_is_help=True,
    help="Local-first sandbox for controlled sample execution (defensive research only).",
)


@app.command("run")
def run(
    sample: Path = typer.Argument(..., help="Path to the sample file (APK, DEX, binary, etc.)."),
    command: list[str] = typer.Argument(..., help="Command to execute inside the sandbox."),
    timeout: int = typer.Option(120, "--timeout", "-t", help="Execution timeout in seconds."),
    network: bool = typer.Option(False, "--network/--no-network", help="Enable network access (lab mode only)."),
    output_dir: Path = typer.Option(None, "--output-dir", "-o", help="Directory to write the execution report."),
) -> None:
    """Execute a command in a sandboxed environment.

    The sample is copied into an ephemeral workspace, executed inside
    a Firejail sandbox with restricted permissions, and the workspace
    is destroyed after execution.

    By default, network access is DENIED. Use ``--network`` only in
    controlled lab environments with proper network isolation.

    Examples::

        drake sandbox run malware.apk -- file sample/malware.apk
        drake sandbox run sample.dex -- ls -la sample/
        drake sandbox run payload.apk --timeout 60 -- strings sample/payload.apk
    """
    console = make_console()

    if not sample.exists():
        error(console, f"Sample not found: {sample}")
        raise typer.Exit(code=2)

    net_policy = NetworkPolicy.LAB if network else NetworkPolicy.DENY
    config = SandboxConfig(
        timeout_seconds=timeout,
        network=net_policy,
    )

    if network:
        warn(console, "Network access ENABLED — lab mode. Ensure proper network isolation.")
    else:
        info(console, "Network access: [accent]DENIED[/accent] (default safe mode)")

    info(console, f"Sample:  [accent]{sample}[/accent]")
    info(console, f"Command: [accent]{' '.join(command)}[/accent]")
    info(console, f"Timeout: {timeout}s")

    report = run_sandboxed(
        sample_path=sample,
        command=command,
        config=config,
        output_dir=output_dir,
    )

    # Display results
    if report.status == SandboxStatus.SUCCESS.value:
        success(console, f"Sandbox execution completed (exit {report.exit_code})")
    elif report.status == SandboxStatus.TIMEOUT.value:
        warn(console, f"Sandbox execution TIMED OUT after {timeout}s")
    elif report.status == SandboxStatus.BACKEND_UNAVAILABLE.value:
        error(console, "Firejail not installed — cannot execute without sandbox (fail-closed)")
        error(console, "Install with: sudo apt install firejail")
        raise typer.Exit(code=1)
    elif report.status == SandboxStatus.ISOLATION_FAILURE.value:
        error(console, f"Isolation verification failed: {report.error}")
        error(console, "Execution refused — fail-closed design")
        raise typer.Exit(code=1)
    else:
        error(console, f"Sandbox error: {report.error}")
        raise typer.Exit(code=1)

    info(console, f"Run ID:    [accent]{report.run_id}[/accent]")
    info(console, f"SHA-256:   {report.sample_sha256}")
    info(console, f"Duration:  {report.duration_seconds:.1f}s")
    info(console, f"Isolation: {'verified' if report.isolation_verified else 'NOT verified'}")

    if report.stdout.strip():
        info(console, "--- stdout ---")
        console.print(report.stdout[:2000])

    if report.stderr.strip():
        warn(console, "--- stderr ---")
        console.print(report.stderr[:2000])

    if output_dir:
        info(console, f"Report:    [accent]{output_dir / f'{report.run_id}.json'}[/accent]")


@app.command("check")
def check() -> None:
    """Check if the sandbox backend is available and functional."""
    console = make_console()

    from ..sandbox.firejail_runner import FirejailBackend
    backend = FirejailBackend()

    if not backend.is_available():
        error(console, "Firejail is NOT installed")
        error(console, "Install with: sudo apt install firejail")
        raise typer.Exit(code=1)

    try:
        backend.verify_isolation(SandboxConfig())
        success(console, "Firejail is installed and functional")
        info(console, "Sandbox backend: [accent]firejail[/accent]")
        info(console, "Default network: [accent]DENIED[/accent]")
        info(console, "Fail-closed:     [accent]yes[/accent]")
    except Exception as exc:
        error(console, f"Firejail verification failed: {exc}")
        raise typer.Exit(code=1)
