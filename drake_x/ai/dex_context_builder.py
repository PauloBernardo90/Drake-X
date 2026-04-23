"""Build AI task context from DEX deep analysis results.

Converts :class:`DexAnalysisResult` into the :class:`TaskContext` format
that AI tasks consume. Applies budgets to keep evidence within the LLM
context window, prioritizing high-severity and high-confidence findings.
"""

from __future__ import annotations

from typing import Any, TYPE_CHECKING

from ..logging import get_logger
from .tasks.base import TaskContext

if TYPE_CHECKING:
    from ..models.dex import DexAnalysisResult

log = get_logger("ai.dex_context")

DEFAULT_MAX_EVIDENCE = 30
DEFAULT_MAX_FINDINGS = 20
DEFAULT_MAX_STRINGS = 15


def build_dex_task_context(
    result: DexAnalysisResult,
    *,
    target_display: str = "",
    session_id: str | None = None,
    max_evidence: int = DEFAULT_MAX_EVIDENCE,
    max_findings: int = DEFAULT_MAX_FINDINGS,
    max_strings: int = DEFAULT_MAX_STRINGS,
) -> TaskContext:
    """Build a TaskContext from a DexAnalysisResult.

    Evidence is assembled in priority order:
    1. Multi-DEX inventory summary
    2. High-severity sensitive API hits
    3. Obfuscation indicators + score
    4. Packing indicators
    5. Classified string IoCs
    6. Call graph summary
    """
    evidence: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []

    # 1. Multi-DEX inventory
    evidence.append({
        "type": "dex_inventory",
        "dex_count": len(result.dex_files),
        "total_classes": result.total_classes,
        "total_methods": result.total_methods,
        "total_strings": result.total_strings,
        "dex_files": [
            {
                "filename": d.filename,
                "class_count": d.class_count,
                "method_count": d.method_count,
            }
            for d in result.dex_files
        ],
    })

    # 2. Sensitive API hits (sorted by severity, then confidence)
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    sorted_apis = sorted(
        result.sensitive_api_hits,
        key=lambda h: (severity_order.get(h.severity.value, 5), -h.confidence),
    )
    for hit in sorted_apis[:max_evidence]:
        evidence.append({
            "type": "sensitive_api",
            "category": hit.api_category.value,
            "api_name": hit.api_name,
            "severity": hit.severity.value,
            "confidence": hit.confidence,
            "mitre_attck": hit.mitre_attck,
            "source_dex": hit.source_dex,
            "raw_match": hit.raw_match[:150],
        })

    # 3. Obfuscation
    if result.obfuscation_indicators:
        evidence.append({
            "type": "obfuscation_summary",
            "score": result.obfuscation_score,
            "indicator_count": len(result.obfuscation_indicators),
            "signals": [
                {
                    "signal": ind.signal.value,
                    "description": ind.description,
                    "confidence": ind.confidence,
                }
                for ind in result.obfuscation_indicators
            ],
        })

    # 4. Packing indicators
    for pi in result.packing_indicators:
        evidence.append({
            "type": "packing_indicator",
            "indicator_type": pi.indicator_type,
            "description": pi.description,
            "confidence": pi.confidence,
        })

    # 5. String IoCs (high-confidence first)
    iocs = sorted(
        [s for s in result.classified_strings if s.is_potential_ioc],
        key=lambda s: -s.confidence,
    )
    for s in iocs[:max_strings]:
        evidence.append({
            "type": "string_ioc",
            "category": s.category.value,
            "value": s.value[:100],
            "confidence": s.confidence,
            "source_dex": s.source_dex,
        })

    # 6. Call graph summary
    if result.call_edges:
        evidence.append({
            "type": "callgraph_summary",
            "edge_count": len(result.call_edges),
        })

    # Build findings from consolidated DEX findings
    for f in result.findings[:max_findings]:
        findings.append({
            "finding_id": f.finding_id,
            "category": f.category,
            "severity": f.severity.value,
            "confidence": f.confidence,
            "interpretation": f.normalized_interpretation,
            "evidence_type": f.evidence_type,
            "source_tool": f.source_tool,
        })

    # Build extra context
    extra: dict[str, Any] = {
        "tools_used": result.tools_used,
        "tools_skipped": result.tools_skipped,
        "phases_completed": result.analysis_phases_completed,
    }

    return TaskContext(
        target_display=target_display,
        profile="dex_deep",
        session_id=session_id,
        evidence=evidence,
        findings=findings,
        extra=extra,
    )
