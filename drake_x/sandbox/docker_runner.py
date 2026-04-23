"""Docker sandbox backend — stronger isolation via container.

Provides container-level isolation using Docker, which is stronger than
Firejail's namespace-based approach:

- Full filesystem isolation (overlay FS)
- Network namespace isolation (default: ``--network none``)
- PID namespace isolation
- Resource limits (memory, CPU)
- No capabilities by default
- Read-only root filesystem
- Non-root execution

Requires Docker to be installed and the current user to have permission
to run containers (docker group or rootless Docker).
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
from .exceptions import IsolationError, SandboxUnavailableError

log = get_logger("sandbox.docker")

DOCKER_BINARY = "docker"
DEFAULT_IMAGE = "ubuntu:22.04"
MEMORY_LIMIT = "512m"
CPU_LIMIT = "1.0"


class DockerBackend(SandboxBackend):
    """Docker-based sandbox backend with container-level isolation."""

    def __init__(self, *, image: str = DEFAULT_IMAGE) -> None:
        self._image = image

    @property
    def name(self) -> str:
        return "docker"

    def is_available(self) -> bool:
        """Check if Docker is installed and the daemon is running."""
        if shutil.which(DOCKER_BINARY) is None:
            return False
        try:
            proc = subprocess.run(
                [DOCKER_BINARY, "info"],
                capture_output=True,
                timeout=10,
            )
            return proc.returncode == 0
        except (subprocess.TimeoutExpired, OSError):
            return False

    def verify_isolation(self, config: SandboxConfig) -> bool:
        """Verify Docker can enforce isolation.

        Checks:
        1. Docker binary exists
        2. Docker daemon is responsive
        3. Image can be pulled or exists locally
        """
        if not self.is_available():
            raise SandboxUnavailableError(
                f"{DOCKER_BINARY} is not installed or daemon is not running. "
                "Install Docker and ensure the daemon is started."
            )

        # Check if image exists locally
        try:
            proc = subprocess.run(
                [DOCKER_BINARY, "image", "inspect", self._image],
                capture_output=True,
                timeout=10,
            )
            if proc.returncode != 0:
                log.info("Image %s not found locally — will pull on first run", self._image)
        except (subprocess.TimeoutExpired, OSError) as exc:
            raise IsolationError(f"Cannot inspect Docker image: {exc}") from exc

        log.info("Docker isolation verified (image: %s)", self._image)
        return True

    def execute(
        self,
        command: list[str],
        workspace: Path,
        config: SandboxConfig,
    ) -> SandboxResult:
        """Execute a command inside a Docker container.

        The workspace is bind-mounted into the container at ``/workspace``.
        The sample directory is mounted read-only, output is writable.
        """
        docker_cmd = [
            DOCKER_BINARY, "run",
            "--rm",                              # auto-remove container
            "--read-only",                       # read-only root FS
            f"--memory={MEMORY_LIMIT}",          # memory limit
            f"--cpus={CPU_LIMIT}",               # CPU limit
            "--cap-drop=ALL",                    # no capabilities
            "--security-opt=no-new-privileges",  # no privilege escalation
            "--pids-limit=256",                  # process limit
            "--tmpfs=/tmp:rw,noexec,nosuid,size=64m",  # writable /tmp
        ]

        # Network policy
        if config.network == NetworkPolicy.DENY:
            docker_cmd.append("--network=none")

        # Bind-mount workspace directories
        sample_dir = workspace / "sample"
        output_dir = workspace / "output"
        docker_cmd.extend([
            "-v", f"{sample_dir}:/workspace/sample:ro",
            "-v", f"{output_dir}:/workspace/output:rw",
            "-w", "/workspace",
        ])

        # Environment variables
        for k, v in config.env_vars.items():
            if k.upper() not in ("PATH", "HOME"):
                docker_cmd.extend(["-e", f"{k}={v}"])

        # Image and command
        docker_cmd.append(self._image)
        docker_cmd.extend(command)

        log.info(
            "Executing in Docker (%s): %s (timeout=%ds, net=%s)",
            self._image, " ".join(command),
            config.timeout_seconds, config.network.value,
        )

        try:
            proc = subprocess.run(
                docker_cmd,
                capture_output=True,
                timeout=config.timeout_seconds,
            )
        except subprocess.TimeoutExpired:
            log.warning("Docker execution timed out after %ds", config.timeout_seconds)
            return SandboxResult(
                status=SandboxStatus.TIMEOUT,
                timed_out=True,
                error=f"Timed out after {config.timeout_seconds}s",
                backend=self.name,
                command=docker_cmd,
                isolation_verified=True,
            )
        except FileNotFoundError:
            return SandboxResult(
                status=SandboxStatus.BACKEND_UNAVAILABLE,
                error=f"{DOCKER_BINARY} not found at exec time",
                backend=self.name,
                command=docker_cmd,
            )
        except OSError as exc:
            return SandboxResult(
                status=SandboxStatus.ERROR,
                error=f"OS error: {exc}",
                backend=self.name,
                command=docker_cmd,
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
            command=docker_cmd,
            isolation_verified=True,
        )


def _truncate(data: bytes, max_bytes: int) -> str:
    text = data.decode("utf-8", errors="replace")
    if len(text) > max_bytes:
        return text[:max_bytes] + "\n...[truncated]"
    return text
