"""Shared subprocess runner for file-based APK tools.

Unlike :mod:`drake_x.tools.base` (which targets network hosts), APK tools
operate on local files and do not need async execution, rate-limiting, or
scope enforcement. This module provides a synchronous ``run_tool`` helper
that handles:

- binary availability checks
- subprocess execution with timeout
- stdout / stderr capture and truncation
- structured result objects
"""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

_MAX_OUTPUT = 512 * 1024  # 512 KiB per stream


@dataclass
class ToolOutput:
    """Result of invoking one APK tool."""

    tool_name: str
    command: list[str]
    exit_code: int | None = None
    stdout: str = ""
    stderr: str = ""
    ok: bool = False
    error: str | None = None
    available: bool = True


def is_available(binary: str) -> bool:
    return shutil.which(binary) is not None


def run_tool(
    name: str,
    cmd: list[str],
    *,
    timeout: int = 300,
    cwd: str | Path | None = None,
) -> ToolOutput:
    """Run ``cmd`` synchronously and return a :class:`ToolOutput`.

    Never raises for routine failures — those are captured in the result.
    Only truly unexpected OS-level errors propagate.
    """
    binary = cmd[0] if cmd else name
    if not is_available(binary):
        return ToolOutput(
            tool_name=name,
            command=cmd,
            available=False,
            error=f"{binary} is not installed",
        )

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            timeout=timeout,
            cwd=cwd,
        )
    except subprocess.TimeoutExpired:
        return ToolOutput(
            tool_name=name,
            command=cmd,
            error=f"timed out after {timeout}s",
        )
    except FileNotFoundError:
        return ToolOutput(
            tool_name=name,
            command=cmd,
            available=False,
            error=f"{binary} not found at exec time",
        )
    except OSError as exc:
        return ToolOutput(
            tool_name=name,
            command=cmd,
            error=f"OS error: {exc}",
        )

    stdout = _trunc(proc.stdout)
    stderr = _trunc(proc.stderr)
    return ToolOutput(
        tool_name=name,
        command=cmd,
        exit_code=proc.returncode,
        stdout=stdout,
        stderr=stderr,
        ok=proc.returncode == 0,
    )


def _trunc(data: bytes) -> str:
    text = data.decode("utf-8", errors="replace")
    if len(text) > _MAX_OUTPUT:
        return text[:_MAX_OUTPUT] + "\n...[truncated]"
    return text
