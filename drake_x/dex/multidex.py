"""Multi-DEX enumerator and cross-DEX correlator.

Handles APKs containing multiple DEX files (classes.dex, classes2.dex, …,
classesN.dex) by:

1. Enumerating all DEX files from an unpacked APK directory.
2. Parsing each DEX individually.
3. Consolidating a unified view of all classes and methods.
4. Detecting packing indicators (unusual DEX distribution patterns).
"""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from pathlib import Path

from ..logging import get_logger
from ..models.dex import (
    DexClassInfo,
    DexFileInfo,
    DexMethodInfo,
    PackingIndicator,
)
from .parser import is_dex_file, parse_dex_header

log = get_logger("dex.multidex")

_DEX_NAME_RE = re.compile(r"^classes\d*\.dex$", re.I)


def enumerate_dex_files(apk_dir: Path) -> list[Path]:
    """Find all DEX files in an unpacked APK directory.

    Looks for ``classes.dex``, ``classes2.dex``, …, ``classesN.dex``
    at the root of the unpacked directory, plus any additional ``.dex``
    files in subdirectories (possible hidden/packed DEX).
    """
    apk_dir = Path(apk_dir)
    found: list[Path] = []

    if not apk_dir.is_dir():
        log.warning("APK directory does not exist: %s", apk_dir)
        return found

    # Standard DEX files at root
    for f in sorted(apk_dir.iterdir()):
        if f.is_file() and _DEX_NAME_RE.match(f.name):
            found.append(f)

    # Deep scan for hidden/packed DEX files
    for f in apk_dir.rglob("*.dex"):
        if f not in found and is_dex_file(f):
            found.append(f)

    log.info("Enumerated %d DEX file(s) in %s", len(found), apk_dir)
    return found


def parse_all_dex(dex_paths: list[Path]) -> list[DexFileInfo]:
    """Parse headers of all provided DEX files."""
    results: list[DexFileInfo] = []
    for path in dex_paths:
        info = parse_dex_header(path)
        if info is not None:
            results.append(info)
        else:
            log.warning("Skipping unparseable DEX: %s", path)
    return results


def build_class_inventory(
    dex_infos: list[DexFileInfo],
    class_lists: dict[str, list[str]],
) -> list[DexClassInfo]:
    """Build a consolidated class inventory across all DEX files.

    Parameters
    ----------
    dex_infos:
        Parsed DEX file metadata.
    class_lists:
        Mapping of DEX filename → list of fully-qualified class names.
        Typically extracted via androguard or smali parsing.
    """
    classes: list[DexClassInfo] = []
    for dex_info in dex_infos:
        class_names = class_lists.get(dex_info.filename, [])
        for name in class_names:
            package = _extract_package(name)
            classes.append(DexClassInfo(
                class_name=name,
                source_dex=dex_info.filename,
                package=package,
            ))
    return classes


def detect_packing_indicators(
    dex_infos: list[DexFileInfo],
    class_lists: dict[str, list[str]] | None = None,
) -> list[PackingIndicator]:
    """Detect packing and payload distribution indicators.

    Heuristics:
    - Abnormal number of DEX files (>3 is unusual for legitimate apps)
    - Highly unequal class distribution across DEX files
    - DEX files in non-standard locations (subdirectories)
    - Very small primary DEX with large secondary DEX (dropper pattern)
    - DEX files without standard naming
    """
    indicators: list[PackingIndicator] = []

    if not dex_infos:
        return indicators

    # 1. High DEX count
    if len(dex_infos) > 3:
        indicators.append(PackingIndicator(
            indicator_type="high_dex_count",
            description=f"APK contains {len(dex_infos)} DEX files — above typical threshold",
            evidence=[f"{d.filename}: {d.class_count} classes" for d in dex_infos],
            confidence=0.6,
            affected_files=[d.filename for d in dex_infos],
        ))

    # 2. Non-standard DEX location
    for dex in dex_infos:
        parts = Path(dex.path).parts
        # If DEX is nested in assets/ or other subdirectory
        if any(p in ("assets", "res", "lib") for p in parts):
            indicators.append(PackingIndicator(
                indicator_type="hidden_dex",
                description=f"DEX file found in non-standard location: {dex.path}",
                evidence=[f"Path: {dex.path}"],
                confidence=0.8,
                affected_files=[dex.filename],
            ))

    # 3. Non-standard naming
    for dex in dex_infos:
        if not _DEX_NAME_RE.match(dex.filename):
            indicators.append(PackingIndicator(
                indicator_type="non_standard_dex_name",
                description=f"DEX with non-standard name: {dex.filename}",
                evidence=[f"Filename: {dex.filename}"],
                confidence=0.7,
                affected_files=[dex.filename],
            ))

    # 4. Dropper pattern: small primary, large secondary
    if len(dex_infos) >= 2:
        primary = dex_infos[0]
        secondary_total = sum(d.class_count for d in dex_infos[1:])
        if primary.class_count > 0 and secondary_total > primary.class_count * 5:
            indicators.append(PackingIndicator(
                indicator_type="dropper_pattern",
                description=(
                    f"Primary DEX has {primary.class_count} classes vs "
                    f"{secondary_total} in secondary DEX files — "
                    "consistent with stub/dropper pattern"
                ),
                evidence=[
                    f"{d.filename}: {d.class_count} classes" for d in dex_infos
                ],
                confidence=0.75,
                affected_files=[d.filename for d in dex_infos],
            ))

    # 5. Unequal class distribution
    if class_lists and len(dex_infos) >= 2:
        counts = [len(class_lists.get(d.filename, [])) for d in dex_infos]
        if counts and max(counts) > 0:
            ratio = min(counts) / max(counts)
            if ratio < 0.05:
                indicators.append(PackingIndicator(
                    indicator_type="unequal_class_distribution",
                    description="Highly unequal class distribution across DEX files",
                    evidence=[
                        f"{d.filename}: {c} classes"
                        for d, c in zip(dex_infos, counts)
                    ],
                    confidence=0.6,
                    affected_files=[d.filename for d in dex_infos],
                ))

    return indicators


def cross_reference_classes(
    class_lists: dict[str, list[str]],
) -> dict[str, list[str]]:
    """Build a map of package → DEX files containing classes from that package.

    Useful for detecting package fragmentation across DEX files.
    """
    pkg_to_dex: dict[str, set[str]] = defaultdict(set)
    for dex_name, classes in class_lists.items():
        for cls in classes:
            pkg = _extract_package(cls)
            if pkg:
                pkg_to_dex[pkg].add(dex_name)

    return {pkg: sorted(dexes) for pkg, dexes in pkg_to_dex.items()}


def _extract_package(class_name: str) -> str:
    """Extract package from a fully-qualified class name."""
    # Handle both dot and slash notation
    normalized = class_name.replace("/", ".").lstrip("L").rstrip(";")
    parts = normalized.rsplit(".", 1)
    return parts[0] if len(parts) > 1 else ""
