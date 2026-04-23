"""JADX bridge — decompile APK to Java source and extract text corpus.

Wraps the existing ``drake_x.integrations.apk.jadx`` runner and adds
DEX-specific post-processing: walking the decompiled output tree to
collect Java source text for downstream analyzers.
"""

from __future__ import annotations

from pathlib import Path

from ..integrations.apk.jadx import decompile as _jadx_decompile
from ..integrations.apk.runner import ToolOutput, is_available
from ..logging import get_logger

log = get_logger("dex.jadx_bridge")

TOOL_NAME = "jadx"


def is_jadx_available() -> bool:
    """Check if jadx is installed and accessible."""
    return is_available("jadx")


def decompile_apk(
    apk_path: Path,
    output_dir: Path,
    *,
    timeout: int = 900,
) -> ToolOutput:
    """Decompile an APK to Java sources using jadx.

    Returns the raw :class:`ToolOutput` from the subprocess runner.
    """
    log.info("Decompiling %s with jadx → %s", apk_path, output_dir)
    return _jadx_decompile(apk_path, output_dir, timeout=timeout)


def collect_java_sources(jadx_output_dir: Path) -> dict[str, str]:
    """Walk jadx output and collect Java source files.

    Returns a mapping of relative path → source text.
    """
    jadx_dir = Path(jadx_output_dir)
    sources_dir = jadx_dir / "sources"
    if not sources_dir.is_dir():
        # jadx sometimes puts sources directly in output dir
        sources_dir = jadx_dir

    result: dict[str, str] = {}
    for java_file in sources_dir.rglob("*.java"):
        try:
            text = java_file.read_text(encoding="utf-8", errors="replace")
            rel = str(java_file.relative_to(jadx_dir))
            result[rel] = text
        except OSError:
            continue

    log.info("Collected %d Java source file(s) from jadx output", len(result))
    return result


def collect_java_corpus(jadx_output_dir: Path, *, max_size: int = 10_000_000) -> str:
    """Concatenate all Java sources into a single text corpus.

    Caps at *max_size* bytes to avoid memory issues with very large APKs.
    """
    sources = collect_java_sources(jadx_output_dir)
    parts: list[str] = []
    total = 0

    for path, text in sorted(sources.items()):
        if total + len(text) > max_size:
            log.warning("Java corpus capped at %d bytes", max_size)
            break
        parts.append(f"// --- {path} ---\n{text}\n")
        total += len(text)

    return "\n".join(parts)
