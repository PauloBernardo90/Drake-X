"""DEX analysis pipeline — main entry point for deep APK/DEX analysis.

Orchestrates the full multi-DEX analysis workflow:

1. Unpack APK (enumerate DEX files)
2. Decompile with jadx and/or apktool
3. Parse DEX headers and smali bytecode
4. Detect sensitive APIs
5. Classify strings
6. Analyze obfuscation
7. Build call graph
8. Generate structured findings
9. Export report

This module is designed to be called either standalone or as an
additional phase in the existing APK analysis pipeline.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ..integrations.apk.runner import ToolOutput
from ..integrations.apk.unzip_tool import extract as unzip_extract
from ..logging import get_logger
from ..models.dex import (
    DexAnalysisResult,
    DexFinding,
    DexFindingSeverity,
)
from . import androguard_bridge
from . import apktool_bridge
from . import jadx_bridge
from .callgraph import DexCallGraph
from .multidex import (
    detect_packing_indicators,
    enumerate_dex_files,
    parse_all_dex,
)
from .obfuscation import analyze_obfuscation
from .parser import extract_dex_strings
from .report import consolidate_findings
from .sensitive_apis import detect_sensitive_apis
from .smali_analyzer import collect_smali_directories, parse_smali_directory
from .strings import classify_strings

log = get_logger("dex.pipeline")


def run_dex_analysis(
    apk_path: Path,
    work_dir: Path,
    *,
    use_jadx: bool = True,
    use_apktool: bool = True,
    use_androguard: bool = True,
    jadx_timeout: int = 900,
    apktool_timeout: int = 600,
) -> DexAnalysisResult:
    """Run the full DEX deep analysis pipeline on an APK.

    Parameters
    ----------
    apk_path:
        Path to the APK file.
    work_dir:
        Working directory for intermediate outputs.
    use_jadx:
        Enable jadx decompilation (Java source).
    use_apktool:
        Enable apktool decompilation (smali + resources).
    use_androguard:
        Enable androguard analysis (if installed).
    jadx_timeout:
        Timeout for jadx in seconds.
    apktool_timeout:
        Timeout for apktool in seconds.
    """
    result = DexAnalysisResult()
    apk = Path(apk_path).resolve()
    work = Path(work_dir)
    work.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # Phase 1 — Unpack APK and enumerate DEX files
    # ------------------------------------------------------------------
    log.info("Phase 1: Unpack APK and enumerate DEX files")
    unpack_dir = work / "unpack"

    unzip_out = unzip_extract(apk, unpack_dir)
    if not unzip_out.ok:
        result.warnings.append(f"APK unpack failed: {unzip_out.error}")
        log.warning("APK unpack failed: %s", unzip_out.error)
        # Try to continue if directory exists from previous run
        if not unpack_dir.is_dir():
            return result

    dex_paths = enumerate_dex_files(unpack_dir)
    dex_infos = parse_all_dex(dex_paths)
    result.dex_files = dex_infos
    result.total_classes = sum(d.class_count for d in dex_infos)
    result.total_methods = sum(d.method_count for d in dex_infos)
    result.total_strings = sum(d.string_count for d in dex_infos)
    result.analysis_phases_completed.append("dex_enumeration")

    log.info(
        "Found %d DEX file(s): %d classes, %d methods, %d strings",
        len(dex_infos), result.total_classes,
        result.total_methods, result.total_strings,
    )

    # ------------------------------------------------------------------
    # Phase 2 — Decompile with jadx
    # ------------------------------------------------------------------
    java_corpus = ""
    jadx_dir = work / "jadx"

    if use_jadx:
        if jadx_bridge.is_jadx_available():
            log.info("Phase 2: jadx decompilation")
            jadx_out = jadx_bridge.decompile_apk(apk, jadx_dir, timeout=jadx_timeout)
            if jadx_out.ok:
                java_corpus = jadx_bridge.collect_java_corpus(jadx_dir)
                result.tools_used.append("jadx")
                result.analysis_phases_completed.append("jadx_decompilation")
            else:
                result.warnings.append(f"jadx failed: {jadx_out.error or jadx_out.stderr[:200]}")
                result.tools_skipped.append("jadx")
        else:
            result.tools_skipped.append("jadx")
            result.warnings.append("jadx not installed — skipping Java decompilation")

    # ------------------------------------------------------------------
    # Phase 3 — Decompile with apktool (smali)
    # ------------------------------------------------------------------
    smali_corpus = ""
    apktool_dir = work / "apktool"
    all_classes = []
    all_methods = []
    all_call_edges = []

    if use_apktool:
        if apktool_bridge.is_apktool_available():
            log.info("Phase 3: apktool decompilation")
            apktool_out = apktool_bridge.decompile_apk(
                apk, apktool_dir, timeout=apktool_timeout
            )
            if apktool_out.ok:
                result.tools_used.append("apktool")
                result.analysis_phases_completed.append("apktool_decompilation")

                # Parse smali directories
                smali_dirs = collect_smali_directories(apktool_dir)
                for sdir, dex_name in smali_dirs:
                    classes, methods, edges = parse_smali_directory(
                        sdir, source_dex=dex_name
                    )
                    all_classes.extend(classes)
                    all_methods.extend(methods)
                    all_call_edges.extend(edges)

                result.classes = all_classes
                result.methods = all_methods
                result.analysis_phases_completed.append("smali_parsing")

                smali_corpus = apktool_bridge.collect_smali_corpus(apktool_dir)

                # Extract Android components from manifest
                manifest_xml = apktool_bridge.extract_manifest_xml(apktool_dir)
                if manifest_xml:
                    result.android_components = _extract_components_from_manifest(
                        manifest_xml
                    )
            else:
                result.warnings.append(
                    f"apktool failed: {apktool_out.error or apktool_out.stderr[:200]}"
                )
                result.tools_skipped.append("apktool")
        else:
            result.tools_skipped.append("apktool")
            result.warnings.append("apktool not installed — skipping smali decompilation")

    # ------------------------------------------------------------------
    # Phase 4 — Androguard analysis (optional)
    # ------------------------------------------------------------------
    class_lists: dict[str, list[str]] = {}

    if use_androguard and androguard_bridge.is_androguard_available():
        log.info("Phase 4: androguard analysis")
        class_lists = androguard_bridge.extract_classes_per_dex(apk)
        if class_lists:
            result.tools_used.append("androguard")
            result.analysis_phases_completed.append("androguard_analysis")

            # Supplement call edges
            ag_edges = androguard_bridge.extract_call_edges(apk)
            all_call_edges.extend(ag_edges)

            # Get components if not from manifest
            if not result.android_components:
                result.android_components = (
                    androguard_bridge.extract_android_components(apk)
                )
    else:
        if use_androguard:
            result.tools_skipped.append("androguard")

    # ------------------------------------------------------------------
    # Phase 5 — String extraction and classification
    # ------------------------------------------------------------------
    log.info("Phase 5: String extraction and classification")
    all_raw_strings: list[str] = []

    # From DEX binary parsing
    for dex_path in dex_paths:
        dex_strings = extract_dex_strings(dex_path)
        all_raw_strings.extend(dex_strings)

    # Classify strings
    analysis_text = java_corpus + "\n" + smali_corpus
    classified = classify_strings(all_raw_strings, source_dex="all")
    result.classified_strings = classified
    result.analysis_phases_completed.append("string_classification")

    # ------------------------------------------------------------------
    # Phase 6 — Sensitive API detection
    # ------------------------------------------------------------------
    log.info("Phase 6: Sensitive API detection")
    api_hits = detect_sensitive_apis(
        analysis_text,
        source_dex="all",
        source_label="combined_corpus",
    )
    result.sensitive_api_hits = api_hits
    result.analysis_phases_completed.append("sensitive_api_detection")

    # ------------------------------------------------------------------
    # Phase 7 — Obfuscation analysis
    # ------------------------------------------------------------------
    log.info("Phase 7: Obfuscation analysis")
    obf_indicators, obf_score = analyze_obfuscation(
        classes=all_classes or None,
        methods=all_methods or None,
        dex_infos=dex_infos or None,
        raw_strings=all_raw_strings or None,
        smali_text=smali_corpus,
        java_text=java_corpus,
    )
    result.obfuscation_indicators = obf_indicators
    result.obfuscation_score = obf_score
    result.analysis_phases_completed.append("obfuscation_analysis")

    # ------------------------------------------------------------------
    # Phase 8 — Multi-DEX packing indicators
    # ------------------------------------------------------------------
    log.info("Phase 8: Packing indicator detection")
    packing = detect_packing_indicators(dex_infos, class_lists or None)
    result.packing_indicators = packing
    result.analysis_phases_completed.append("packing_detection")

    # ------------------------------------------------------------------
    # Phase 9 — Call graph construction
    # ------------------------------------------------------------------
    log.info("Phase 9: Call graph construction")
    graph = DexCallGraph()
    graph.add_edges(all_call_edges)
    if all_classes:
        graph.add_class_references(all_classes)

    result.call_edges = graph.edges
    result.analysis_phases_completed.append("callgraph_construction")

    # ------------------------------------------------------------------
    # Phase 10 — Consolidate findings
    # ------------------------------------------------------------------
    log.info("Phase 10: Consolidating findings")
    result.findings = consolidate_findings(result)
    result.analysis_phases_completed.append("finding_consolidation")

    log.info(
        "DEX analysis complete: %d findings, %d API hits, "
        "%d obfuscation indicators, %d call edges",
        len(result.findings), len(result.sensitive_api_hits),
        len(result.obfuscation_indicators), len(result.call_edges),
    )

    return result


def _extract_components_from_manifest(xml: str) -> dict[str, list[str]]:
    """Extract Android components from decoded AndroidManifest.xml."""
    import re

    components: dict[str, list[str]] = {
        "activities": [],
        "services": [],
        "receivers": [],
        "providers": [],
    }

    tag_map = {
        "activity": "activities",
        "service": "services",
        "receiver": "receivers",
        "provider": "providers",
    }

    for tag, key in tag_map.items():
        pattern = rf'<{tag}\s[^>]*android:name="([^"]+)"'
        components[key] = re.findall(pattern, xml)

    return components
