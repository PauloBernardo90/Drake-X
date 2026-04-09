"""Base classes for Drake-X tool adapters.

Adapters expose a tiny, predictable interface:

- a class-level :class:`ToolMeta` describing the tool
- :meth:`is_available` (uses :func:`shutil.which`)
- :meth:`build_command` returns a safe argv list for a given target
- :meth:`run` executes the command asynchronously and returns a ToolResult

The base class handles subprocess execution, timeouts, and consistent error
mapping so individual adapters stay tiny.
"""

from __future__ import annotations

import asyncio
import shutil
from dataclasses import dataclass
from datetime import UTC, datetime

from ..exceptions import ToolExecutionError
from ..logging import get_logger
from ..models.target import Target
from ..models.tool_result import ToolResult, ToolResultStatus

log = get_logger("tools")

# How much stdout/stderr we keep on a single tool run. Truncating prevents a
# misbehaving tool from blowing up the database or the LLM context.
_MAX_OUTPUT_BYTES = 256 * 1024


@dataclass(frozen=True)
class ToolMeta:
    """Static metadata about a tool adapter."""

    name: str                            # canonical short name (e.g. "nmap")
    binary: str                          # binary to look up via shutil.which
    description: str                     # one-line description for `tools list`
    profiles: tuple[str, ...]            # profiles this tool participates in
    target_types: tuple[str, ...]        # which target types it handles
    required: bool = False               # if True, missing => session warning
    parallel_safe: bool = True           # may run concurrently with peers


class BaseTool:
    """Abstract base class. Subclasses MUST set ``meta`` and override ``build_command``."""

    meta: ToolMeta

    def __init__(self, *, default_timeout: int) -> None:
        self.default_timeout = default_timeout

    # ----- discovery ---------------------------------------------------

    @classmethod
    def is_available(cls) -> bool:
        return shutil.which(cls.meta.binary) is not None

    @classmethod
    def matches_target(cls, target: Target) -> bool:
        return target.target_type in cls.meta.target_types

    @classmethod
    def participates_in(cls, profile: str) -> bool:
        return profile in cls.meta.profiles

    # ----- execution ---------------------------------------------------

    def build_command(self, target: Target) -> list[str]:  # pragma: no cover - abstract
        raise NotImplementedError

    async def run(self, target: Target, *, timeout: int | None = None) -> ToolResult:
        """Execute the tool against ``target`` and return a structured result.

        This never raises for routine subprocess failures — those become
        non-OK :class:`ToolResult` statuses. It only raises
        :class:`ToolExecutionError` for genuinely unexpected internal problems.
        """

        if not self.is_available():
            return ToolResult(
                tool_name=self.meta.name,
                command=[self.meta.binary],
                status=ToolResultStatus.NOT_INSTALLED,
                error_message=f"{self.meta.binary} is not installed",
                finished_at=datetime.now(UTC),
                duration_seconds=0.0,
            )

        cmd = self.build_command(target)
        if not cmd or not isinstance(cmd, list) or not all(isinstance(p, str) for p in cmd):
            raise ToolExecutionError(
                f"{self.meta.name}: build_command must return a list[str], got {cmd!r}"
            )

        wait_for = timeout if timeout is not None else self.default_timeout
        started = datetime.now(UTC)
        log.debug("running %s: %s", self.meta.name, " ".join(cmd))

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except FileNotFoundError:
            # Binary disappeared between the which() check and exec.
            return ToolResult(
                tool_name=self.meta.name,
                command=cmd,
                status=ToolResultStatus.NOT_INSTALLED,
                error_message=f"{self.meta.binary} not found at exec time",
                started_at=started,
                finished_at=datetime.now(UTC),
                duration_seconds=0.0,
            )
        except OSError as exc:
            raise ToolExecutionError(
                f"{self.meta.name}: failed to spawn process: {exc}"
            ) from exc

        try:
            stdout_b, stderr_b = await asyncio.wait_for(proc.communicate(), timeout=wait_for)
        except TimeoutError:
            with _suppress():
                proc.kill()
            with _suppress():
                await proc.wait()
            finished = datetime.now(UTC)
            return ToolResult(
                tool_name=self.meta.name,
                command=cmd,
                status=ToolResultStatus.TIMEOUT,
                error_message=f"timed out after {wait_for}s",
                started_at=started,
                finished_at=finished,
                duration_seconds=(finished - started).total_seconds(),
            )

        finished = datetime.now(UTC)
        stdout = _truncate(stdout_b.decode("utf-8", errors="replace"))
        stderr = _truncate(stderr_b.decode("utf-8", errors="replace"))
        exit_code = proc.returncode if proc.returncode is not None else -1

        status = ToolResultStatus.OK if exit_code == 0 else ToolResultStatus.NONZERO

        return ToolResult(
            tool_name=self.meta.name,
            command=cmd,
            started_at=started,
            finished_at=finished,
            duration_seconds=(finished - started).total_seconds(),
            exit_code=exit_code,
            stdout=stdout,
            stderr=stderr,
            status=status,
            error_message=None if status == ToolResultStatus.OK else stderr.strip()[:500] or None,
        )


def _truncate(text: str) -> str:
    encoded = text.encode("utf-8", errors="replace")
    if len(encoded) <= _MAX_OUTPUT_BYTES:
        return text
    return encoded[:_MAX_OUTPUT_BYTES].decode("utf-8", errors="replace") + "\n…[truncated]"


class _suppress:
    """Tiny inline context manager that swallows everything. Used for cleanup."""

    def __enter__(self) -> _suppress:
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:  # noqa: D401
        return True
