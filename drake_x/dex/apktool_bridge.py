"""Apktool bridge — decompile APK to smali and extract resources.

Wraps ``drake_x.integrations.apk.apktool`` and adds DEX-specific
post-processing for multi-DEX smali directories.
"""

from __future__ import annotations

from pathlib import Path

from ..integrations.apk.apktool import decompile as _apktool_decompile
from ..integrations.apk.runner import ToolOutput, is_available
from ..logging import get_logger

log = get_logger("dex.apktool_bridge")

TOOL_NAME = "apktool"


def is_apktool_available() -> bool:
    """Check if apktool is installed and accessible."""
    return is_available("apktool")


def decompile_apk(
    apk_path: Path,
    output_dir: Path,
    *,
    timeout: int = 600,
) -> ToolOutput:
    """Decompile APK using apktool.

    Returns the raw :class:`ToolOutput` from the subprocess runner.
    """
    log.info("Decompiling %s with apktool → %s", apk_path, output_dir)
    return _apktool_decompile(apk_path, output_dir, timeout=timeout)


def collect_smali_corpus(
    apktool_dir: Path,
    *,
    max_size: int = 10_000_000,
) -> str:
    """Concatenate all smali files into a single text corpus.

    Walks all ``smali*/`` directories in the apktool output.
    Caps at *max_size* bytes.
    """
    apktool_dir = Path(apktool_dir)
    parts: list[str] = []
    total = 0

    for smali_dir in _find_smali_dirs(apktool_dir):
        for smali_file in sorted(smali_dir.rglob("*.smali")):
            try:
                text = smali_file.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if total + len(text) > max_size:
                log.warning("Smali corpus capped at %d bytes", max_size)
                return "\n".join(parts)
            parts.append(text)
            total += len(text)

    return "\n".join(parts)


def extract_manifest_xml(apktool_dir: Path) -> str | None:
    """Read the decoded AndroidManifest.xml from apktool output."""
    manifest = Path(apktool_dir) / "AndroidManifest.xml"
    if not manifest.is_file():
        return None
    try:
        return manifest.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def list_assets(apktool_dir: Path) -> list[str]:
    """List files in the assets/ directory of apktool output."""
    assets = Path(apktool_dir) / "assets"
    if not assets.is_dir():
        return []
    return [
        str(f.relative_to(assets))
        for f in assets.rglob("*")
        if f.is_file()
    ]


def _find_smali_dirs(apktool_dir: Path) -> list[Path]:
    """Find all smali directories in apktool output."""
    dirs: list[Path] = []
    for d in sorted(apktool_dir.iterdir()):
        if d.is_dir() and d.name.startswith("smali"):
            dirs.append(d)
    return dirs
