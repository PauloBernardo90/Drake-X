"""aapt / aapt2 wrapper for APK manifest and badging extraction."""

from __future__ import annotations

from pathlib import Path

from .runner import ToolOutput, is_available, run_tool


def dump_badging(apk: Path) -> ToolOutput:
    """Run ``aapt dump badging`` to extract package metadata."""
    binary = "aapt2" if is_available("aapt2") else "aapt"
    return run_tool("aapt", [binary, "dump", "badging", str(apk)])


def dump_permissions(apk: Path) -> ToolOutput:
    """Run ``aapt dump permissions``."""
    binary = "aapt2" if is_available("aapt2") else "aapt"
    return run_tool("aapt", [binary, "dump", "permissions", str(apk)])


def dump_xmltree(apk: Path, asset: str = "AndroidManifest.xml") -> ToolOutput:
    """Run ``aapt dump xmltree`` for the manifest."""
    binary = "aapt2" if is_available("aapt2") else "aapt"
    return run_tool("aapt", [binary, "dump", "xmltree", str(apk), "--file", asset])
