"""yara wrapper for rule-based pattern matching against the APK."""

from __future__ import annotations

from pathlib import Path

from .runner import ToolOutput, run_tool


def scan(apk: Path, rules_path: Path, *, timeout: int = 120) -> ToolOutput:
    """Run ``yara -s <rules> <apk>``."""
    if not rules_path.exists():
        return ToolOutput(
            tool_name="yara",
            command=["yara", str(rules_path), str(apk)],
            error=f"rules file not found: {rules_path}",
            available=True,
        )
    return run_tool(
        "yara",
        ["yara", "-s", str(rules_path), str(apk)],
        timeout=timeout,
    )
