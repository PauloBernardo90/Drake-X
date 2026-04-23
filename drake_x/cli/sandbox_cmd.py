"""``drake sandbox`` — local-first sandboxed execution commands."""

from __future__ import annotations

from pathlib import Path

import typer

from ..cli_theme import error, info, make_console, success, warn
from ..sandbox.base import NetworkPolicy, SandboxConfig, SandboxStatus
from ..sandbox.runner import resolve_backend, run_sandboxed

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
    backend: str = typer.Option("firejail", "--backend", "-b", help="Backend: firejail, docker, emulator."),
    output_dir: Path = typer.Option(None, "--output-dir", "-o", help="Directory to write report and artifacts."),
) -> None:
    """Execute a command in a sandboxed environment.

    The sample is copied into an ephemeral workspace, executed inside
    the selected sandbox backend, and the workspace is destroyed after
    execution. Output artifacts are collected and optionally persisted.

    Backends: firejail (default), docker (stronger), emulator (Android AVD).
    Network access is DENIED by default.

    Examples::

        drake sandbox run malware.apk -- file sample/malware.apk
        drake sandbox run sample.apk --backend docker -- strings sample/sample.apk
        drake sandbox run sample.apk --backend emulator -- sample.apk --launch
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

    info(console, f"Backend: [accent]{backend}[/accent]")
    info(console, f"Sample:  [accent]{sample}[/accent]")
    info(console, f"Command: [accent]{' '.join(command)}[/accent]")
    info(console, f"Timeout: {timeout}s")

    report = run_sandboxed(
        sample_path=sample,
        command=command,
        config=config,
        backend_name=backend,
        output_dir=output_dir,
    )

    _display_report(console, report, timeout, output_dir)


@app.command("check")
def check(
    backend: str = typer.Option("firejail", "--backend", "-b", help="Backend to check."),
) -> None:
    """Check if a sandbox backend is available and functional."""
    console = make_console()

    try:
        be = resolve_backend(backend)
    except Exception as exc:
        error(console, f"Cannot resolve backend '{backend}': {exc}")
        raise typer.Exit(code=1)

    if not be.is_available():
        error(console, f"{backend} is NOT available")
        if backend == "firejail":
            error(console, "Install with: sudo apt install firejail")
        elif backend == "docker":
            error(console, "Install Docker and ensure the daemon is running")
        elif backend == "emulator":
            error(console, "Set ANDROID_HOME and install emulator + platform-tools")
        raise typer.Exit(code=1)

    try:
        be.verify_isolation(SandboxConfig())
        success(console, f"{backend} is installed and functional")
        info(console, f"Sandbox backend: [accent]{backend}[/accent]")
        info(console, f"Default network: [accent]DENIED[/accent]")
        info(console, f"Fail-closed:     [accent]yes[/accent]")
    except Exception as exc:
        error(console, f"{backend} verification failed: {exc}")
        raise typer.Exit(code=1)


def _display_report(console, report, timeout, output_dir) -> None:
    """Display sandbox execution results."""
    if report.status == SandboxStatus.SUCCESS.value:
        success(console, f"Sandbox execution completed (exit {report.exit_code})")
    elif report.status == SandboxStatus.TIMEOUT.value:
        warn(console, f"Sandbox execution TIMED OUT after {timeout}s")
    elif report.status == SandboxStatus.BACKEND_UNAVAILABLE.value:
        error(console, f"Backend '{report.backend}' not available (fail-closed)")
        raise typer.Exit(code=1)
    elif report.status == SandboxStatus.ISOLATION_FAILURE.value:
        error(console, f"Isolation verification failed: {report.error}")
        raise typer.Exit(code=1)
    else:
        error(console, f"Sandbox error: {report.error}")
        raise typer.Exit(code=1)

    info(console, f"Run ID:    [accent]{report.run_id}[/accent]")
    info(console, f"SHA-256:   {report.sample_sha256}")
    info(console, f"Duration:  {report.duration_seconds:.1f}s")
    info(console, f"Backend:   {report.backend}")
    info(console, f"Isolation: {'verified' if report.isolation_verified else 'NOT verified'}")

    if report.stdout.strip():
        info(console, "--- stdout ---")
        console.print(report.stdout[:2000])

    if report.stderr.strip():
        warn(console, "--- stderr ---")
        console.print(report.stderr[:2000])

    if output_dir:
        info(console, f"Report:    [accent]{output_dir / f'{report.run_id}.json'}[/accent]")
