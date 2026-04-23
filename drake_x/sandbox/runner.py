"""Sandbox runner — orchestrates isolated command execution.

This is the main entry point for sandboxed execution. It:

1. Validates the sample and configuration
2. Creates an ephemeral workspace
3. Verifies sandbox isolation (fail-closed)
4. Executes the command
5. Generates the audit report
6. Destroys the workspace

Usage::

    from drake_x.sandbox import run_sandboxed
    from drake_x.sandbox.base import SandboxConfig

    report = run_sandboxed(
        sample_path=Path("malware.apk"),
        command=["file", "sample/malware.apk"],
        config=SandboxConfig(timeout_seconds=60),
    )
    print(report.status)        # "success" | "timeout" | "error" | ...
    print(report.exit_code)     # 0
    print(report.stdout)        # file type output
"""

from __future__ import annotations

import time
from pathlib import Path

from ..logging import get_logger
from .base import SandboxConfig, SandboxStatus
from .exceptions import (
    IsolationError,
    SandboxError,
    SandboxUnavailableError,
)
from .firejail_runner import FirejailBackend
from .network_guard import validate_network_policy
from .report import SandboxReport, now_utc_iso
from .workspace import EphemeralWorkspace

log = get_logger("sandbox.runner")


def run_sandboxed(
    sample_path: Path,
    command: list[str],
    *,
    config: SandboxConfig | None = None,
    output_dir: Path | None = None,
) -> SandboxReport:
    """Execute a command in a sandboxed environment.

    Parameters
    ----------
    sample_path:
        Path to the sample file (APK, DEX, binary, etc.).
    command:
        Command to execute inside the sandbox. Paths should be relative
        to the workspace root.
    config:
        Sandbox configuration. Uses safe defaults if not provided.
    output_dir:
        Optional directory to write the execution report to.

    Returns
    -------
    SandboxReport with full execution details and audit metadata.

    Raises
    ------
    SandboxUnavailableError:
        If the sandbox backend is not installed.
    IsolationError:
        If isolation cannot be guaranteed (fail-closed).
    """
    if config is None:
        config = SandboxConfig()

    report = SandboxReport(
        sample_path=str(sample_path),
        backend="firejail",
        network_policy=config.network.value,
        timeout_seconds=config.timeout_seconds,
    )

    # Phase 1: Validate network policy
    try:
        validate_network_policy(config)
    except SandboxError as exc:
        report.status = SandboxStatus.ERROR.value
        report.error = str(exc)
        report.audit_observations.append(f"Network policy validation failed: {exc}")
        return report

    # Phase 2: Verify backend availability and isolation (fail-closed)
    backend = FirejailBackend()

    if not backend.is_available():
        report.status = SandboxStatus.BACKEND_UNAVAILABLE.value
        report.error = "Firejail is not installed"
        report.audit_observations.append(
            "FAIL-CLOSED: Sandbox backend unavailable — execution refused"
        )
        log.error("Firejail not available — refusing to execute without sandbox")
        return report

    try:
        backend.verify_isolation(config)
        report.isolation_verified = True
        report.isolation_notes.append("Firejail isolation verified")
    except (IsolationError, SandboxUnavailableError) as exc:
        report.status = SandboxStatus.ISOLATION_FAILURE.value
        report.error = str(exc)
        report.isolation_notes.append(f"Isolation check failed: {exc}")
        report.audit_observations.append(
            f"FAIL-CLOSED: Isolation verification failed — {exc}"
        )
        log.error("Isolation verification failed — refusing to execute: %s", exc)
        return report

    # Phase 3: Create ephemeral workspace and execute
    report.started_at = now_utc_iso()
    start_time = time.monotonic()

    try:
        with EphemeralWorkspace(sample_path) as ws:
            report.workspace_path = str(ws.root)
            report.sample_sha256 = ws.sample_sha256

            try:
                report.sample_size = ws.sample.stat().st_size
            except OSError:
                pass

            report.command = list(command)
            report.audit_observations.append(
                f"Workspace created: {ws.root}"
            )

            # Phase 4: Execute inside sandbox
            result = backend.execute(command, ws.root, config)

            # Populate report from result
            report.exit_code = result.exit_code
            report.timed_out = result.timed_out
            report.status = result.status.value
            report.stdout = result.stdout
            report.stderr = result.stderr
            report.error = result.error

            if result.timed_out:
                report.audit_observations.append(
                    f"Execution timed out after {config.timeout_seconds}s"
                )

            report.audit_observations.append("Workspace cleanup: pending")

        # Workspace destroyed by context manager
        report.audit_observations.append("Workspace cleanup: completed")

    except SandboxError as exc:
        report.status = SandboxStatus.ERROR.value
        report.error = str(exc)
        report.audit_observations.append(f"Sandbox error: {exc}")
        log.error("Sandbox execution failed: %s", exc)

    except Exception as exc:  # noqa: BLE001
        report.status = SandboxStatus.ERROR.value
        report.error = f"Unexpected error: {type(exc).__name__}: {exc}"
        report.audit_observations.append(f"Unexpected error: {exc}")
        log.error("Unexpected error in sandbox: %s", exc)

    # Phase 5: Finalize report
    elapsed = time.monotonic() - start_time
    report.finished_at = now_utc_iso()
    report.duration_seconds = round(elapsed, 3)

    # Write report if output_dir specified
    if output_dir:
        report_path = Path(output_dir) / f"{report.run_id}.json"
        try:
            report.write_json(report_path)
            report.audit_observations.append(f"Report written: {report_path}")
        except OSError as exc:
            log.warning("Failed to write report: %s", exc)

    log.info(
        "Sandbox run %s: status=%s, exit=%s, duration=%.1fs",
        report.run_id, report.status, report.exit_code, report.duration_seconds,
    )

    return report
