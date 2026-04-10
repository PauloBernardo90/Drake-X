"""apktool wrapper for APK decompilation to smali + resources."""

from __future__ import annotations

from pathlib import Path

from .runner import ToolOutput, run_tool


def decompile(apk: Path, output_dir: Path, *, timeout: int = 600) -> ToolOutput:
    """Run ``apktool d`` to decompile the APK into *output_dir*."""
    output_dir.mkdir(parents=True, exist_ok=True)
    return run_tool(
        "apktool",
        ["apktool", "d", "-f", "-o", str(output_dir), str(apk)],
        timeout=timeout,
    )
