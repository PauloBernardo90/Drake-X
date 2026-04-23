"""Firejail sandbox backend — primary execution engine.

Executes commands inside a Firejail sandbox with:
- Restrictive security profile (auto-generated)
- Deny-all network by default
- Private filesystem namespace
- Seccomp syscall filtering
- No new privileges
- Timeout enforcement
- Output capture with size limits

Fail-closed design: if Firejail is not available or isolation cannot be
verified, execution is refused with a clear error.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

from ..logging import get_logger
from .base import (
    NetworkPolicy,
    SandboxBackend,
    SandboxConfig,
    SandboxResult,
    SandboxStatus,
)
from .exceptions import IsolationError, SandboxTimeoutError, SandboxUnavailableError
from .profile_builder import write_profile

log = get_logger("sandbox.firejail")

FIREJAIL_BINARY = "firejail"


class FirejailBackend(SandboxBackend):
    """Firejail-based sandbox backend for Linux systems."""

    @property
    def name(self) -> str:
        return "firejail"

    def is_available(self) -> bool:
        """Check if Firejail is installed and executable."""
        return shutil.which(FIREJAIL_BINARY) is not None

    def verify_isolation(self, config: SandboxConfig) -> bool:
        """Verify that Firejail can enforce the required isolation.

        Checks:
        1. Firejail binary exists and is executable
        2. Firejail can start (basic sanity test)

        Raises :class:`IsolationError` on failure.
        """
        if not self.is_available():
            raise SandboxUnavailableError(
                f"{FIREJAIL_BINARY} is not installed. "
                "Install with: sudo apt install firejail"
            )

        # Verify Firejail works by running --version
        try:
            proc = subprocess.run(
                [FIREJAIL_BINARY, "--version"],
                capture_output=True,
                timeout=10,
            )
            if proc.returncode != 0:
                raise IsolationError(
                    f"Firejail sanity check failed (exit {proc.returncode}): "
                    f"{proc.stderr.decode('utf-8', errors='replace')[:200]}"
                )
        except subprocess.TimeoutExpired:
            raise IsolationError("Firejail --version timed out")
        except FileNotFoundError:
            raise SandboxUnavailableError(f"{FIREJAIL_BINARY} not found at exec time")
        except OSError as exc:
            raise IsolationError(f"Cannot execute Firejail: {exc}")

        log.info("Firejail isolation verified")
        return True

    def execute(
        self,
        command: list[str],
        workspace: Path,
        config: SandboxConfig,
    ) -> SandboxResult:
        """Execute a command inside the Firejail sandbox.

        Parameters
        ----------
        command:
            The command to run (e.g., ``["file", "sample.apk"]``).
        workspace:
            The ephemeral workspace root directory.
        config:
            Sandbox configuration (timeout, network, etc.).
        """
        # Write the Firejail profile
        profile_path = write_profile(workspace, config)

        # Build the full Firejail command
        # IMPORTANT: Use list form to prevent shell injection
        fj_cmd = [
            FIREJAIL_BINARY,
            f"--profile={profile_path}",
            f"--private={workspace}",
            "--quiet",
        ]

        # Network policy enforcement via command-line flag
        # (belt-and-suspenders with the profile's net none)
        if config.network == NetworkPolicy.DENY:
            fj_cmd.append("--net=none")

        # Additional user-provided args (validated)
        for arg in config.extra_args:
            if not isinstance(arg, str):
                continue
            # Prevent injection of --profile or --private overrides
            lower = arg.lower()
            if lower.startswith("--profile") or lower.startswith("--private"):
                log.warning("Blocked attempt to override profile/private: %s", arg)
                continue
            fj_cmd.append(arg)

        # Append the actual command
        fj_cmd.extend(command)

        log.info(
            "Executing in Firejail: %s (timeout=%ds, net=%s)",
            " ".join(command),
            config.timeout_seconds,
            config.network.value,
        )

        # Execute with timeout
        try:
            proc = subprocess.run(
                fj_cmd,
                capture_output=True,
                timeout=config.timeout_seconds,
                cwd=str(workspace),
                env=_build_env(config),
            )
        except subprocess.TimeoutExpired:
            log.warning("Sandbox execution timed out after %ds", config.timeout_seconds)
            return SandboxResult(
                status=SandboxStatus.TIMEOUT,
                timed_out=True,
                error=f"Timed out after {config.timeout_seconds}s",
                backend=self.name,
                command=fj_cmd,
                isolation_verified=True,
            )
        except FileNotFoundError:
            return SandboxResult(
                status=SandboxStatus.BACKEND_UNAVAILABLE,
                error=f"{FIREJAIL_BINARY} not found at exec time",
                backend=self.name,
                command=fj_cmd,
            )
        except OSError as exc:
            return SandboxResult(
                status=SandboxStatus.ERROR,
                error=f"OS error: {exc}",
                backend=self.name,
                command=fj_cmd,
            )

        stdout = _truncate(proc.stdout, config.max_output_bytes)
        stderr = _truncate(proc.stderr, config.max_output_bytes)

        status = SandboxStatus.SUCCESS if proc.returncode == 0 else SandboxStatus.ERROR

        return SandboxResult(
            status=status,
            exit_code=proc.returncode,
            stdout=stdout,
            stderr=stderr,
            timed_out=False,
            backend=self.name,
            command=fj_cmd,
            isolation_verified=True,
        )


def _build_env(config: SandboxConfig) -> dict[str, str]:
    """Build a minimal environment for the sandboxed process."""
    env: dict[str, str] = {
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
        "HOME": "/tmp",
        "LANG": "C.UTF-8",
    }
    # Add user-provided vars (no overriding PATH)
    for k, v in config.env_vars.items():
        if k.upper() != "PATH":
            env[k] = v
    return env


def _truncate(data: bytes, max_bytes: int) -> str:
    """Decode and truncate output bytes."""
    text = data.decode("utf-8", errors="replace")
    if len(text) > max_bytes:
        return text[:max_bytes] + "\n...[truncated]"
    return text
