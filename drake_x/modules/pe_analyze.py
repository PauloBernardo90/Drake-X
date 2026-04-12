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
from ..models.evidence_graph import EvidenceGraph
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
    # Phase 3b — Exploit-indicator heuristics (v0.9)
    # ------------------------------------------------------------------
    log.info("Phase 3b: exploit-indicator heuristics (v0.9)")
    from ..normalize.binary.exploit_indicators import detect_exploit_indicators

    result.exploit_indicators = detect_exploit_indicators(result)

    # ------------------------------------------------------------------
    # Phase 3c — Shellcode carving (v0.9)
    # ------------------------------------------------------------------
    log.info("Phase 3c: suspected shellcode carving (v0.9)")
    from ..integrations.exploit.shellcode_carver import carve_suspected_shellcode

    pe_data: bytes | None = None
    try:
        pe_data = sample.read_bytes()
    except Exception as exc:  # noqa: BLE001
        log.warning("Could not read PE data for shellcode scan: %s", exc)

    result.suspected_shellcode = carve_suspected_shellcode(result, pe_data=pe_data)

    # Bounded decoding for suspected shellcode artifacts
    if result.suspected_shellcode and pe_data is not None:
        log.info("Phase 3c: bounded decoding for triage")
        from ..integrations.exploit.shellcode_decode import bounded_decode

        for artifact in result.suspected_shellcode:
            if artifact.preview_hex:
                try:
                    blob = bytes.fromhex(artifact.preview_hex)
                    decodings = bounded_decode(
                        blob,
                        source_ref=f"{artifact.source_location}@{artifact.offset}",
                    )
                    result.bounded_decodings.extend(decodings)
                except Exception as exc:  # noqa: BLE001
                    log.debug("Bounded decode failed for %s: %s", artifact.source_location, exc)

    # ------------------------------------------------------------------
    # Phase 3d — Protection-interaction assessment (v0.9)
    # ------------------------------------------------------------------
    log.info("Phase 3d: protection-interaction assessment (v0.9)")
    from ..normalize.binary.protection_interaction import assess_protection_interactions

    result.protection_interactions = assess_protection_interactions(result)

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
        "%d import risks, %d section signals, %d exploit indicators, "
        "%d suspected shellcode, %d protection interactions",
        len(result.sections),
        len(result.imports),
        len(result.exports),
        len(result.anomalies),
        len(result.import_risk_findings),
        len(result.suspicious_patterns),
        len(result.exploit_indicators),
        len(result.suspected_shellcode),
        len(result.protection_interactions),
    )
    return result


# ---------------------------------------------------------------------------
# v0.9 — Graph-first helpers and AI exploit-assessment wiring
# ---------------------------------------------------------------------------


def build_graph(result: PeAnalysisResult) -> EvidenceGraph:
    """Build the Evidence Graph for a completed PE analysis.

    Separated from :func:`run_analysis` so the graph can be consumed
    without forcing AI invocation, and so tests can exercise graph
    construction deterministically.
    """
    from ..graph.pe_writer import build_pe_graph, dedupe_graph

    graph = build_pe_graph(result)
    return dedupe_graph(graph)


def attach_graph_snapshot(result: PeAnalysisResult, graph: EvidenceGraph) -> None:
    """Attach a JSON-serializable snapshot of *graph* to *result*."""
    result.graph_snapshot = graph.to_dict()


def run_ai_exploit_assessment(
    result: PeAnalysisResult,
    graph: EvidenceGraph,
    *,
    ollama_base_url: str,
    ollama_model: str,
    audit_dir: Path | None = None,
    session_id: str | None = None,
) -> dict | None:
    """Run the AI exploit-assessment task against an already-built graph.

    Returns the parsed AI response (also stored on
    ``result.ai_exploit_assessment``) or ``None`` if the runtime was
    unreachable / the response was not valid JSON. Failures never raise;
    a warning is appended to ``result.warnings``.

    An audit record is always written when ``audit_dir`` is provided,
    regardless of success or failure — auditability must not depend on
    the model answering correctly.
    """
    from ..ai.audited_run import run_audited
    from ..ai.context_builder import build_pe_exploit_context
    from ..ai.ollama_client import OllamaClient
    from ..ai.tasks.exploit_assessment import ExploitAssessmentTask

    built = build_pe_exploit_context(
        graph=graph,
        pe_result=result,
        target_display=result.metadata.sha256[:16] or "pe-sample",
        session_id=session_id,
    )

    task = ExploitAssessmentTask()
    client = OllamaClient(base_url=ollama_base_url, model=ollama_model)

    log.info("AI exploit assessment: %d context nodes",
             len(built.context_node_ids))

    task_result = run_audited(
        task=task,
        context=built.task_context,
        client=client,
        audit_dir=audit_dir,
        context_node_ids=built.context_node_ids,
        truncation_notes=built.truncation_notes,
    )
    parsed = task_result.parsed
    if not task_result.ok and task_result.error:
        result.warnings.append(f"AI exploit assessment degraded: {task_result.error}")

    if parsed is not None:
        # Store on the result and mirror into the graph as a finding node
        # so downstream consumers can reference it by ID.
        result.ai_exploit_assessment = parsed
        from ..graph.pe_writer import ai_assessment_id
        from ..models.evidence_graph import EdgeType, EvidenceEdge, EvidenceNode, NodeKind
        from ..graph.pe_writer import artifact_id as _art

        sha = result.metadata.sha256 or "unknown"
        ai_nid = ai_assessment_id(sha)
        graph.add_node(EvidenceNode(
            node_id=ai_nid,
            kind=NodeKind.FINDING,
            domain="pe",
            label="AI exploit assessment",
            data={
                "overall_confidence": parsed.get("overall_confidence"),
                "summary": parsed.get("exploit_capability_summary"),
                "context_node_ids": built.context_node_ids,
                "model": ollama_model,
            },
        ))
        graph.add_edge(EvidenceEdge(
            source_id=ai_nid,
            target_id=_art(sha),
            edge_type=EdgeType.DERIVED_FROM,
            notes="AI-assisted assessment derived from PE analysis subgraph",
        ))

    return parsed
