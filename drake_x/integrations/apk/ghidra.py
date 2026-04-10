"""Ghidra headless analyzer integration for deeper static analysis.

Ghidra's ``analyzeHeadless`` mode allows batch analysis of binaries
without the GUI. Drake-X uses it to:

- Analyze native ``.so`` libraries from the APK
- Analyze embedded DEX/JAR payloads that jadx could not decompile
- Extract function names, strings, imports, and cross-references
- Feed results into the obfuscation assessor and Frida target generator

Design:

- **Optional.** The APK pipeline runs fully without Ghidra. This is a
  deeper-analysis enrichment layer, activated via ``--ghidra``.
- **Headless.** Uses ``analyzeHeadless`` — no GUI interaction.
- **Local-only.** All analysis happens on the operator's host.
- **Degradation-safe.** If Ghidra is not installed or the analysis
  fails, the pipeline continues with a warning.
- **Evidence-labeled.** Results are tagged as ``ghidra_headless`` source
  so the report clearly attributes them.

Ghidra is detected via:
1. ``GHIDRA_INSTALL_DIR`` environment variable
2. ``analyzeHeadless`` on ``PATH``
3. Common Kali paths (``/opt/ghidra``, ``/usr/share/ghidra``)
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path

from ...logging import get_logger
from .runner import ToolOutput, run_tool

log = get_logger("ghidra")

_COMMON_GHIDRA_PATHS = [
    "/opt/ghidra",
    "/usr/share/ghidra",
    "/usr/local/ghidra",
]


def find_ghidra_home() -> Path | None:
    """Locate the Ghidra installation directory."""
    env = os.environ.get("GHIDRA_INSTALL_DIR")
    if env:
        p = Path(env)
        if p.exists():
            return p

    # Check if analyzeHeadless is on PATH
    ah = shutil.which("analyzeHeadless")
    if ah:
        # analyzeHeadless lives in <ghidra>/support/
        return Path(ah).resolve().parent.parent

    for base in _COMMON_GHIDRA_PATHS:
        p = Path(base)
        if p.exists() and (p / "support" / "analyzeHeadless").exists():
            return p

    return None


def find_analyze_headless() -> str | None:
    """Return the path to ``analyzeHeadless`` or None."""
    ah = shutil.which("analyzeHeadless")
    if ah:
        return ah

    home = find_ghidra_home()
    if home:
        candidate = home / "support" / "analyzeHeadless"
        if candidate.exists():
            return str(candidate)

    return None


def is_available() -> bool:
    """Check if Ghidra headless is available."""
    return find_analyze_headless() is not None


def analyze_binary(
    binary_path: Path,
    project_dir: Path,
    *,
    project_name: str = "drake_ghidra",
    timeout: int = 600,
    script: str | None = None,
) -> ToolOutput:
    """Run ``analyzeHeadless`` on a single binary.

    Creates a temporary Ghidra project in *project_dir*, imports
    *binary_path*, and runs the default analysis (or a custom script
    if provided).

    Returns a :class:`ToolOutput` with stdout/stderr from the headless
    process.
    """
    ah = find_analyze_headless()
    if ah is None:
        return ToolOutput(
            tool_name="ghidra",
            command=["analyzeHeadless"],
            available=False,
            error="Ghidra headless not found. Set GHIDRA_INSTALL_DIR or install Ghidra.",
        )

    project_dir.mkdir(parents=True, exist_ok=True)
    cmd = [
        ah,
        str(project_dir),
        project_name,
        "-import", str(binary_path),
        "-overwrite",
        "-analysisTimeoutPerFile", str(timeout),
    ]

    if script:
        cmd.extend(["-postScript", script])

    return run_tool("ghidra", cmd, timeout=timeout + 60)


def extract_function_list(
    binary_path: Path,
    project_dir: Path,
    *,
    timeout: int = 300,
) -> list[str]:
    """Run Ghidra headless and extract function names via stdout parsing.

    This uses the default analysis and parses Ghidra's import summary
    output for function names. For deeper extraction, a custom Ghidra
    script would be needed (future enhancement).
    """
    result = analyze_binary(binary_path, project_dir, timeout=timeout)
    if not result.ok:
        log.warning("Ghidra analysis failed for %s: %s", binary_path.name, result.error)
        return []

    # Parse function names from Ghidra's analysis output.
    # Ghidra logs function discoveries to stdout during analysis.
    functions: list[str] = []
    for line in result.stdout.splitlines():
        line = line.strip()
        # Ghidra logs "INFO  ANALYZING..." and function names in various formats.
        # We extract lines that look like function/symbol references.
        if "Function:" in line or "Symbol:" in line:
            parts = line.split(":", 1)
            if len(parts) == 2:
                functions.append(parts[1].strip())

    return functions


def analyze_native_libs(
    raw_dir: Path,
    ghidra_dir: Path,
    *,
    timeout: int = 600,
) -> dict[str, ToolOutput]:
    """Analyze all .so files in the APK's lib/ directory.

    Returns a dict mapping relative lib path → ToolOutput.
    """
    lib_dir = raw_dir / "lib"
    results: dict[str, ToolOutput] = {}

    if not lib_dir.exists():
        return results

    for so_file in sorted(lib_dir.glob("**/*.so")):
        rel_path = str(so_file.relative_to(raw_dir))
        log.info("Ghidra analyzing: %s", rel_path)
        project_sub = ghidra_dir / so_file.stem
        result = analyze_binary(so_file, project_sub, timeout=timeout)
        results[rel_path] = result

    return results
