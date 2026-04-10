"""radare2 / rabin2 wrappers for binary-level analysis."""

from __future__ import annotations

from pathlib import Path

from .runner import ToolOutput, run_tool


def rabin2_info(path: Path) -> ToolOutput:
    """Run ``rabin2 -I`` for basic binary info."""
    return run_tool("rabin2", ["rabin2", "-I", str(path)])


def rabin2_strings(path: Path) -> ToolOutput:
    """Run ``rabin2 -zz`` for strings across all sections."""
    return run_tool("rabin2", ["rabin2", "-zz", str(path)])


def rabin2_libs(path: Path) -> ToolOutput:
    """Run ``rabin2 -l`` to list linked libraries."""
    return run_tool("rabin2", ["rabin2", "-l", str(path)])


def rabin2_imports(path: Path) -> ToolOutput:
    """Run ``rabin2 -i`` to list imports."""
    return run_tool("rabin2", ["rabin2", "-i", str(path)])
