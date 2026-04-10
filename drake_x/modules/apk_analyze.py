"""APK static-analysis engine — 8-phase orchestrator.

Phase 1: File intake and inventory
Phase 2: Manifest and surface analysis
Phase 3: Code and asset extraction
Phase 4: Static behavior analysis
Phase 5: Obfuscation and packing assessment
Phase 6: Protection detection
Phase 7: Campaign similarity assessment
Phase 8: (handled by the report writer — not in this module)

The engine runs synchronously (APK tools are I/O-bound, not network-bound)
and produces an :class:`ApkAnalysisResult` that the report writer consumes.
"""

from __future__ import annotations

import os
from pathlib import Path

from ..integrations.apk import runner
from ..integrations.apk.aapt import dump_badging
from ..integrations.apk.apktool import decompile as apktool_decompile
from ..integrations.apk.file_tool import compute_hashes, identify_file
from ..integrations.apk.jadx import decompile as jadx_decompile
from ..integrations.apk.radare2 import rabin2_info, rabin2_strings
from ..integrations.apk.strings_tool import extract_strings
from ..integrations.apk.unzip_tool import extract as unzip_extract, list_contents
from ..logging import get_logger
from ..models.apk import (
    ApkAnalysisResult,
    ApkEmbeddedFile,
    ApkMetadata,
    ApkNativeLib,
)
from ..normalize.apk.behavior import analyze_behavior
from ..normalize.apk.campaign import assess_campaigns
from ..normalize.apk.components import parse_components, parse_manifest_xml
from ..normalize.apk.manifest import parse_badging
from ..normalize.apk.network import extract_network_indicators
from ..normalize.apk.obfuscation import assess_obfuscation
from ..normalize.apk.permissions import parse_permissions
from ..normalize.apk.protections import detect_protections

log = get_logger("apk_analyze")


def run_analysis(
    apk_path: Path,
    work_dir: Path,
    *,
    use_jadx: bool = True,
    use_apktool: bool = True,
    use_strings: bool = True,
    use_radare2: bool = False,
    deep: bool = False,
) -> ApkAnalysisResult:
    """Run the full 8-phase APK analysis and return a structured result."""

    result = ApkAnalysisResult()
    apk = Path(apk_path).resolve()
    work = Path(work_dir)
    work.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # Phase 1 — File intake and inventory
    # ------------------------------------------------------------------
    log.info("Phase 1: file intake — %s", apk)
    hashes = compute_hashes(apk)
    file_out = identify_file(apk)
    file_type = file_out.stdout.strip() if file_out.ok else "unknown"

    result.metadata = ApkMetadata(
        file_path=str(apk),
        file_size=apk.stat().st_size,
        md5=hashes["md5"],
        sha256=hashes["sha256"],
        file_type=file_type,
    )

    # ------------------------------------------------------------------
    # Phase 2 — Manifest and surface analysis
    # ------------------------------------------------------------------
    log.info("Phase 2: manifest analysis")
    badging = dump_badging(apk)
    if badging.ok:
        result.tools_ran.append("aapt")
        meta = parse_badging(badging.stdout)
        # Merge aapt metadata into the top-level metadata
        result.metadata.package_name = meta.package_name
        result.metadata.version_name = meta.version_name
        result.metadata.version_code = meta.version_code
        result.metadata.min_sdk = meta.min_sdk
        result.metadata.target_sdk = meta.target_sdk
        result.metadata.main_activity = meta.main_activity

        result.permissions = parse_permissions(badging.stdout)
        result.components = parse_components(badging.stdout)
    elif not badging.available:
        result.tools_skipped.append("aapt")
        result.warnings.append("aapt not installed — manifest analysis limited")
    else:
        result.tools_ran.append("aapt")
        result.warnings.append(f"aapt failed: {badging.error or badging.stderr[:200]}")

    # ------------------------------------------------------------------
    # Phase 3 — Code and asset extraction
    # ------------------------------------------------------------------
    log.info("Phase 3: extraction")

    raw_dir = work / "raw"
    apktool_dir = work / "apktool"
    jadx_dir = work / "jadx"

    # unzip for raw contents
    unzip_out = unzip_extract(apk, raw_dir)
    if unzip_out.ok:
        result.tools_ran.append("unzip")
    elif not unzip_out.available:
        result.tools_skipped.append("unzip")
    else:
        result.warnings.append(f"unzip failed: {unzip_out.error}")

    # List contents for file inventory
    listing_out = list_contents(apk)
    file_listing: list[str] = []
    if listing_out.ok:
        file_listing = [
            line.strip().split()[-1]
            for line in listing_out.stdout.splitlines()
            if line.strip() and not line.strip().startswith("Archive")
            and not line.strip().startswith("Length")
            and not line.strip().startswith("---")
        ]
        result.extracted_paths = file_listing

    # Native libraries
    result.native_libs = _inventory_native_libs(raw_dir)

    # Embedded suspicious files
    result.embedded_files = _inventory_embedded_files(file_listing, raw_dir)

    # apktool decompile
    manifest_xml = ""
    smali_text = ""
    if use_apktool:
        atk = apktool_decompile(apk, apktool_dir)
        if atk.ok:
            result.tools_ran.append("apktool")
            manifest_path = apktool_dir / "AndroidManifest.xml"
            if manifest_path.exists():
                manifest_xml = manifest_path.read_text(encoding="utf-8", errors="replace")
                xml_components = parse_manifest_xml(manifest_xml)
                if xml_components:
                    result.components = xml_components
            smali_text = _collect_text(apktool_dir, "*.smali", limit_mb=10)
        elif not atk.available:
            result.tools_skipped.append("apktool")
        else:
            result.warnings.append(f"apktool failed: {atk.error or atk.stderr[:200]}")

    # jadx decompile
    java_text = ""
    if use_jadx:
        jdx = jadx_decompile(apk, jadx_dir)
        if jdx.ok:
            result.tools_ran.append("jadx")
            java_text = _collect_text(jadx_dir, "*.java", limit_mb=10)
        elif not jdx.available:
            result.tools_skipped.append("jadx")
        else:
            result.warnings.append(f"jadx failed: {jdx.error or jdx.stderr[:200]}")

    # strings
    strings_text = ""
    if use_strings:
        for target in [apk] + list((raw_dir / "lib").glob("**/*.so")) if (raw_dir / "lib").exists() else [apk]:
            sout = extract_strings(target)
            if sout.ok:
                strings_text += sout.stdout + "\n"
                if "strings" not in result.tools_ran:
                    result.tools_ran.append("strings")

    # radare2
    if use_radare2:
        r2 = rabin2_info(apk)
        if r2.ok:
            result.tools_ran.append("rabin2")
            strings_text += r2.stdout + "\n"
        elif not r2.available:
            result.tools_skipped.append("rabin2")

    # Build a combined text corpus for analysis
    corpus = "\n".join([smali_text, java_text, strings_text, manifest_xml])

    # ------------------------------------------------------------------
    # Phase 4 — Static behavior analysis
    # ------------------------------------------------------------------
    log.info("Phase 4: behavior analysis")
    result.behavior_indicators = analyze_behavior(corpus, source_label="combined_corpus")
    result.network_indicators = extract_network_indicators(
        corpus, source_label="combined_corpus"
    )

    # ------------------------------------------------------------------
    # Phase 5 — Obfuscation and packing assessment
    # ------------------------------------------------------------------
    log.info("Phase 5: obfuscation assessment")
    result.obfuscation_traits = assess_obfuscation(
        file_listing=file_listing,
        smali_text=smali_text,
        strings_text=strings_text,
        asset_names=[f for f in file_listing if f.startswith("assets/")],
        native_lib_names=[lib.path for lib in result.native_libs],
    )

    # ------------------------------------------------------------------
    # Phase 6 — Protection detection
    # ------------------------------------------------------------------
    log.info("Phase 6: protection detection")
    result.protection_indicators = detect_protections(
        smali_text=smali_text,
        strings_text=strings_text,
        java_text=java_text,
        manifest_text=manifest_xml,
        native_lib_names=[lib.path for lib in result.native_libs],
    )

    # ------------------------------------------------------------------
    # Phase 7 — Campaign similarity assessment
    # ------------------------------------------------------------------
    log.info("Phase 7: campaign similarity")
    result.campaign_assessments = assess_campaigns(result)

    log.info("Analysis complete: %d findings, %d network IOCs, %d protections",
             len(result.behavior_indicators),
             len(result.network_indicators),
             len(result.protection_indicators))
    return result


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _inventory_native_libs(raw_dir: Path) -> list[ApkNativeLib]:
    libs: list[ApkNativeLib] = []
    lib_dir = raw_dir / "lib"
    if not lib_dir.exists():
        return libs
    for so in lib_dir.glob("**/*.so"):
        arch = so.parent.name  # e.g. armeabi-v7a, arm64-v8a
        libs.append(ApkNativeLib(
            path=str(so.relative_to(raw_dir)),
            arch=arch,
            size=so.stat().st_size,
        ))
    return libs


def _inventory_embedded_files(file_listing: list[str], raw_dir: Path) -> list[ApkEmbeddedFile]:
    embedded: list[ApkEmbeddedFile] = []
    import re
    suspicious_re = re.compile(
        r'\.(dex|jar|zip|apk|bin|dat|enc|so|elf)$|classes\d+\.dex', re.I
    )
    for name in file_listing:
        if suspicious_re.search(name):
            full = raw_dir / name
            size = full.stat().st_size if full.exists() else 0
            embedded.append(ApkEmbeddedFile(
                path=name,
                size=size,
            ))
    return embedded


def _collect_text(root: Path, glob_pattern: str, *, limit_mb: int = 10) -> str:
    """Collect text from all files matching *glob_pattern* under *root*."""
    limit_bytes = limit_mb * 1024 * 1024
    collected = 0
    parts: list[str] = []
    for path in sorted(root.rglob(glob_pattern)):
        if collected >= limit_bytes:
            break
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
            parts.append(text)
            collected += len(text)
        except OSError:
            continue
    return "\n".join(parts)
