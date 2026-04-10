"""unzip wrapper for extracting raw APK contents."""

from __future__ import annotations

from pathlib import Path

from .runner import ToolOutput, run_tool


def extract(apk: Path, output_dir: Path) -> ToolOutput:
    """Run ``unzip -o`` to extract the APK contents."""
    output_dir.mkdir(parents=True, exist_ok=True)
    return run_tool(
        "unzip",
        ["unzip", "-o", "-q", str(apk), "-d", str(output_dir)],
    )


def list_contents(apk: Path) -> ToolOutput:
    """Run ``unzip -l`` to list APK archive entries."""
    return run_tool("unzip", ["unzip", "-l", str(apk)])
