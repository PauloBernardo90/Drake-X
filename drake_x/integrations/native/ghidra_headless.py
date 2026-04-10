"""Structured Ghidra headless wrapper using the Drake-X export script.

Instead of parsing stdout, this wrapper invokes Ghidra with a custom
Java script (``DrakeXExportNativeJson.java``) that emits a clean JSON
file. The JSON is then parsed by
:mod:`drake_x.normalize.native.ghidra_json`.

Falls back to the v0.6 stdout-based wrapper if the script is not found.
"""

from __future__ import annotations

from pathlib import Path

from ...integrations.apk.ghidra import find_analyze_headless, is_available
from ...integrations.apk.runner import ToolOutput, run_tool
from ...logging import get_logger

log = get_logger("ghidra_headless")

# The Java script lives at the repo root under ghidra_scripts/.
_SCRIPT_PATH = Path(__file__).resolve().parents[3] / "ghidra_scripts" / "DrakeXExportNativeJson.java"


def analyze_with_structured_export(
    binary_path: Path,
    project_dir: Path,
    output_json: Path,
    *,
    timeout: int = 600,
) -> ToolOutput:
    """Run Ghidra headless with the Drake-X structured export script.

    Produces a JSON file at *output_json* with functions, strings,
    imports, exports, and metadata.
    """
    ah = find_analyze_headless()
    if ah is None:
        return ToolOutput(
            tool_name="ghidra",
            command=["analyzeHeadless"],
            available=False,
            error="Ghidra headless not found",
        )

    script_path = _SCRIPT_PATH
    if not script_path.exists():
        return ToolOutput(
            tool_name="ghidra",
            command=["analyzeHeadless"],
            available=True,
            error=f"Drake-X Ghidra script not found at {script_path}",
        )

    project_dir.mkdir(parents=True, exist_ok=True)
    cmd = [
        ah,
        str(project_dir),
        "drake_native",
        "-import", str(binary_path),
        "-overwrite",
        "-analysisTimeoutPerFile", str(timeout),
        "-postScript", str(script_path), str(output_json),
    ]

    return run_tool("ghidra", cmd, timeout=timeout + 120)


def analyze_native_libs_structured(
    raw_dir: Path,
    ghidra_dir: Path,
    *,
    timeout: int = 600,
) -> dict[str, Path]:
    """Analyze all .so files and return paths to their JSON exports.

    Returns a dict mapping relative lib path → JSON output path.
    Missing/failed analyses are logged but don't halt the pipeline.
    """
    lib_dir = raw_dir / "lib"
    results: dict[str, Path] = {}

    if not lib_dir.exists():
        return results

    for so_file in sorted(lib_dir.glob("**/*.so")):
        rel_path = str(so_file.relative_to(raw_dir))
        json_out = ghidra_dir / f"{so_file.stem}.json"
        log.info("Ghidra structured export: %s", rel_path)

        result = analyze_with_structured_export(
            so_file, ghidra_dir / so_file.stem, json_out, timeout=timeout,
        )
        if result.ok and json_out.exists():
            results[rel_path] = json_out
        else:
            log.warning("Ghidra export failed for %s: %s", rel_path, result.error)

    return results
