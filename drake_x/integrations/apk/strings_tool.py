"""strings(1) wrapper for extracting printable strings from binaries."""

from __future__ import annotations

from pathlib import Path

from .runner import ToolOutput, run_tool


def extract_strings(path: Path, *, min_length: int = 6) -> ToolOutput:
    """Run ``strings -n <min_length>`` on *path*."""
    return run_tool(
        "strings",
        ["strings", "-n", str(min_length), str(path)],
    )
