"""Base abstraction for sandbox backends.

Defines the interface that all sandbox backends must implement, plus
shared data structures for sandbox configuration and results.
"""

from __future__ import annotations

import abc
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any


class NetworkPolicy(StrEnum):
    """Network access policy for sandboxed execution."""
    DENY = "deny"       # No network access (default, safe)
    LAB = "lab"         # Lab-mode: network allowed (explicit opt-in)


class SandboxStatus(StrEnum):
    """Outcome status of a sandboxed execution."""
    SUCCESS = "success"
    TIMEOUT = "timeout"
    ERROR = "error"
    ISOLATION_FAILURE = "isolation_failure"
    BACKEND_UNAVAILABLE = "backend_unavailable"


@dataclass(frozen=True)
class SandboxConfig:
    """Immutable configuration for one sandbox run.

    Defaults are chosen for maximum safety:
    - No network access
    - 120-second timeout
    - Read-only bind of sample
    """
    timeout_seconds: int = 120
    network: NetworkPolicy = NetworkPolicy.DENY
    read_only_sample: bool = True
    max_output_bytes: int = 512 * 1024  # 512 KiB per stream
    env_vars: dict[str, str] = field(default_factory=dict)
    extra_args: list[str] = field(default_factory=list)


@dataclass
class SandboxResult:
    """Structured outcome of one sandboxed execution.

    This is the sandbox-internal result that gets transformed into
    a :class:`SandboxReport` with full audit metadata.
    """
    status: SandboxStatus
    exit_code: int | None = None
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False
    error: str | None = None
    backend: str = ""
    command: list[str] = field(default_factory=list)
    isolation_verified: bool = False


class SandboxBackend(abc.ABC):
    """Abstract base class for sandbox backends.

    A backend knows how to:
    1. Check if it is available on the current system
    2. Validate that isolation can be guaranteed
    3. Execute a command within the sandbox
    """

    @property
    @abc.abstractmethod
    def name(self) -> str:
        """Human-readable backend name (e.g. 'firejail')."""

    @abc.abstractmethod
    def is_available(self) -> bool:
        """Return True if the backend is installed and usable."""

    @abc.abstractmethod
    def verify_isolation(self, config: SandboxConfig) -> bool:
        """Verify that the backend can enforce the required isolation level.

        Raises :class:`IsolationError` if isolation cannot be guaranteed.
        Returns True on success.
        """

    @abc.abstractmethod
    def execute(
        self,
        command: list[str],
        workspace: Path,
        config: SandboxConfig,
    ) -> SandboxResult:
        """Execute *command* within the sandbox.

        The command runs inside *workspace*, which is the ephemeral
        directory containing the sample and any required support files.
        """
