"""PE static-analysis engine — multi-phase orchestrator.

Phase 1: File intake and identification
Phase 2: PE parsing (headers, sections, imports, exports, resources)
Phase 3: Anomaly and protection analysis
Phase 4: (v0.8 Phase 2) Normalization, import risk, bounded disassembly
Phase 5: (v0.8 Phase 3) Reporting

The engine runs synchronously and produces a :class:`PeAnalysisResult`.
"""

from __future__ import annotations

from pathlib import Path

from ..integrations.apk.file_tool import compute_hashes, identify_file
from ..integrations.binary.format_detect import BinaryFormat, detect_format
from ..integrations.binary.pe_parser import is_available as pefile_available, parse_pe
from ..logging import get_logger
from ..models.pe import PeAnalysisResult, PeMetadata

log = get_logger("pe_analyze")


def run_analysis(
    pe_path: Path,
    work_dir: Path,
    *,
    deep: bool = False,
    vt_api_key: str = "",
) -> PeAnalysisResult:
    """Run PE static analysis and return a structured result."""

    result = PeAnalysisResult()
    sample = Path(pe_path).resolve()
    work = Path(work_dir)
    work.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # Phase 1 — File intake and identification
    # ------------------------------------------------------------------
    log.info("Phase 1: file intake — %s", sample)
    hashes = compute_hashes(sample)
    file_out = identify_file(sample)
    file_type = file_out.stdout.strip() if file_out.ok else "unknown"

    result.metadata = PeMetadata(
        file_path=str(sample),
        file_size=sample.stat().st_size,
        md5=hashes["md5"],
        sha256=hashes["sha256"],
        file_type=file_type,
    )

    # Format verification
    detected = detect_format(sample)
    if detected != BinaryFormat.PE:
        result.warnings.append(
            f"Format detection returned {detected.value} instead of PE — proceeding anyway"
        )

    # VT enrichment (opt-in)
    if vt_api_key:
        log.info("VT enrichment: querying VirusTotal for %s", hashes["sha256"][:12])
        try:
            from ..integrations.apk.virustotal import lookup_sha256
            vt = lookup_sha256(hashes["sha256"], api_key=vt_api_key)
            if vt.available and not vt.error:
                result.tools_ran.append("virustotal")
            elif vt.error:
                result.warnings.append(f"VT enrichment degraded: {vt.error}")
        except Exception as exc:  # noqa: BLE001
            log.warning("VT enrichment failed: %s", exc)
            result.warnings.append(f"VT enrichment failed: {exc}")

    # ------------------------------------------------------------------
    # Phase 2 — PE parsing
    # ------------------------------------------------------------------
    log.info("Phase 2: PE parsing")
    if pefile_available():
        parsed = parse_pe(sample)
        result.header = parsed["header"]
        result.sections = parsed["sections"]
        result.imports = parsed["imports"]
        result.exports = parsed["exports"]
        result.resources = parsed["resources"]
        result.anomalies = parsed["anomalies"]
        result.protection = parsed["protection"]
        result.tools_ran.append("pefile")
        for w in parsed["warnings"]:
            result.warnings.append(w)
    else:
        result.tools_skipped.append("pefile")
        result.warnings.append(
            "pefile library not installed — PE parsing unavailable. "
            "Install with: pip install pefile"
        )

    # ------------------------------------------------------------------
    # Phase 3 — Normalization and risk assessment
    # ------------------------------------------------------------------
    log.info("Phase 3: normalization and risk assessment")
    from ..normalize.binary.imports_risk import classify_imports
    from ..normalize.binary.section_anomaly import assess_sections

    result.import_risk_findings = classify_imports(result.imports)
    result.suspicious_patterns = assess_sections(result.sections)

    # ------------------------------------------------------------------
    # Phase 4 — Bounded disassembly (entry point region)
    # ------------------------------------------------------------------
    log.info("Phase 4: bounded disassembly")
    from ..integrations.disasm.capstone_engine import is_available as capstone_available, disassemble_pe_entry

    disasm_artifact: dict = {}
    if capstone_available():
        disasm_artifact = disassemble_pe_entry(str(sample), max_instructions=200)
        result.tools_ran.append("capstone")
        for w in disasm_artifact.get("warnings", []):
            result.warnings.append(w)
    else:
        result.tools_skipped.append("capstone")
        result.warnings.append(
            "Capstone not installed — bounded disassembly unavailable. "
            "Install with: pip install capstone"
        )

    # Save disassembly artifact (off-graph, as structured JSON attachment)
    if disasm_artifact.get("instructions"):
        import json
        disasm_path = work / "entry_disasm.json"
        disasm_path.write_text(
            json.dumps(disasm_artifact, indent=2),
            encoding="utf-8",
        )

    # ------------------------------------------------------------------
    # Phase 5 — Summary
    # ------------------------------------------------------------------
    log.info(
        "Analysis complete: %d sections, %d imports, %d exports, %d anomalies, "
        "%d import risks, %d section signals",
        len(result.sections),
        len(result.imports),
        len(result.exports),
        len(result.anomalies),
        len(result.import_risk_findings),
        len(result.suspicious_patterns),
    )
    return result
