"""jadx wrapper for APK-to-Java decompilation."""

from __future__ import annotations

from pathlib import Path

from .runner import ToolOutput, run_tool


def decompile(apk: Path, output_dir: Path, *, timeout: int = 900) -> ToolOutput:
    """Run ``jadx`` to decompile the APK into Java sources."""
    output_dir.mkdir(parents=True, exist_ok=True)
    return run_tool(
        "jadx",
        [
            "jadx",
            "--no-res",           # skip resource decoding (apktool handles that)
            "--no-debug-info",
            "--deobf",            # attempt deobfuscation of short names
            "-d", str(output_dir),
            str(apk),
        ],
        timeout=timeout,
    )
