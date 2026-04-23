"""Pipeline and tool versioning — capture analysis environment snapshot.

Records the version of Drake-X, Python, and external tools (apktool,
jadx, androguard, etc.) at analysis time. If a tool is unavailable,
this is recorded explicitly rather than silently omitted.
"""

from __future__ import annotations

import shutil
import subprocess
import sys

from ..logging import get_logger
from .models import AnalysisVersionInfo, ToolAvailability, ToolVersionInfo

log = get_logger("integrity.versioning")

# Tools to check and their version commands
_TOOL_VERSION_COMMANDS: dict[str, list[str]] = {
    "apktool": ["apktool", "--version"],
    "jadx": ["jadx", "--version"],
    "firejail": ["firejail", "--version"],
    "docker": ["docker", "--version"],
    "adb": ["adb", "version"],
    "strings": ["strings", "--version"],
    "file": ["file", "--version"],
}


def capture_version_info(
    *,
    analysis_profile: str = "",
    pipeline_version: str = "",
    extra_tools: list[str] | None = None,
) -> AnalysisVersionInfo:
    """Capture a complete version snapshot of the analysis environment.

    Parameters
    ----------
    analysis_profile:
        Name of the analysis profile (e.g., "apk_analyze", "pe_analyze").
    pipeline_version:
        Pipeline version string (defaults to Drake-X version).
    extra_tools:
        Additional tool names to check beyond the defaults.
    """
    from .. import __version__ as drake_version

    if not pipeline_version:
        pipeline_version = drake_version

    tools: list[ToolVersionInfo] = []

    # Check all configured tools
    tool_names = list(_TOOL_VERSION_COMMANDS.keys())
    if extra_tools:
        tool_names.extend(extra_tools)

    for name in tool_names:
        tools.append(_check_tool(name))

    # Check androguard (Python library, not CLI)
    tools.append(_check_python_lib("androguard"))

    info = AnalysisVersionInfo(
        drake_x_version=drake_version,
        pipeline_version=pipeline_version,
        analysis_profile=analysis_profile,
        tools=tools,
        python_version=sys.version.split()[0],
    )

    log.info(
        "Version snapshot: Drake-X %s, Python %s, %d tools checked",
        info.drake_x_version, info.python_version, len(tools),
    )
    return info


def _check_tool(name: str) -> ToolVersionInfo:
    """Check availability and version of an external tool."""
    binary = name
    if shutil.which(binary) is None:
        return ToolVersionInfo(
            tool_name=name,
            availability=ToolAvailability.UNAVAILABLE,
            notes=f"{name} not found in PATH",
        )

    cmd = _TOOL_VERSION_COMMANDS.get(name, [name, "--version"])
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            timeout=10,
        )
        version_text = proc.stdout.decode("utf-8", errors="replace").strip()
        if not version_text:
            version_text = proc.stderr.decode("utf-8", errors="replace").strip()
        # Take first line, cap at 100 chars
        version = version_text.splitlines()[0][:100] if version_text else "unknown"

        return ToolVersionInfo(
            tool_name=name,
            version=version,
            availability=ToolAvailability.AVAILABLE,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
        return ToolVersionInfo(
            tool_name=name,
            availability=ToolAvailability.UNAVAILABLE,
            notes=str(exc)[:100],
        )


def _check_python_lib(name: str) -> ToolVersionInfo:
    """Check if a Python library is importable and get its version."""
    try:
        mod = __import__(name)
        version = getattr(mod, "__version__", getattr(mod, "VERSION", "unknown"))
        return ToolVersionInfo(
            tool_name=name,
            version=str(version),
            availability=ToolAvailability.AVAILABLE,
        )
    except ImportError:
        return ToolVersionInfo(
            tool_name=name,
            availability=ToolAvailability.UNAVAILABLE,
            notes=f"Python library '{name}' not installed",
        )
