"""Tests for the graph-aware AI context builder (v0.9)."""

from __future__ import annotations

from drake_x.ai.context_builder import build_pe_exploit_context
from drake_x.graph.pe_writer import build_pe_graph
from drake_x.models.pe import (
    ExploitIndicator,
    ExploitIndicatorType,
    PeAnalysisResult,
    PeImport,
    PeMetadata,
)

SHA = "c" * 64


def _result() -> PeAnalysisResult:
    r = PeAnalysisResult(
        metadata=PeMetadata(sha256=SHA),
        imports=[
            PeImport(dll="kernel32.dll", function="VirtualAllocEx"),
            PeImport(dll="kernel32.dll", function="WriteProcessMemory"),
            PeImport(dll="kernel32.dll", function="CreateRemoteThread"),
        ],
        exploit_indicators=[
            ExploitIndicator(
                indicator_type=ExploitIndicatorType.INJECTION_CHAIN,
                title="Classic injection chain",
                description="d",
                severity="high",
                confidence=0.8,
                evidence_refs=["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"],
                mitre_attck=["T1055"],
            ),
        ],
    )
    r.import_risk_findings = [
        {"dll": "kernel32.dll", "function": "VirtualAllocEx",
         "risk": "high", "category": "injection"},
    ]
    return r


def test_context_contains_root_and_indicator():
    pe = _result()
    g = build_pe_graph(pe)
    built = build_pe_exploit_context(graph=g, pe_result=pe, target_display="sample")
    # The root artifact must always be in the seed set.
    assert any("artifact" in nid for nid in built.context_node_ids)
    # The indicator must be included because it's high-priority.
    assert any("indicator:injection_chain" in nid for nid in built.context_node_ids)


def test_task_context_carries_graph_and_evidence():
    pe = _result()
    g = build_pe_graph(pe)
    built = build_pe_exploit_context(graph=g, pe_result=pe, target_display="sample")
    ctx = built.task_context
    assert ctx.graph_context is not None
    assert len(ctx.graph_context["nodes"]) >= 1
    assert any(item["kind"] == "exploit_indicator" for item in ctx.evidence)


def test_truncation_notes_surface_when_capped():
    pe = _result()
    g = build_pe_graph(pe)
    # max_nodes=1 forces the graph to drop seeds → truncation note expected.
    built = build_pe_exploit_context(
        graph=g, pe_result=pe, target_display="s", max_nodes=1, max_edges=1,
    )
    assert any("graph truncated" in n for n in built.truncation_notes)


def test_determinism():
    pe = _result()
    g = build_pe_graph(pe)
    a = build_pe_exploit_context(graph=g, pe_result=pe, target_display="s")
    b = build_pe_exploit_context(graph=g, pe_result=pe, target_display="s")
    assert a.context_node_ids == b.context_node_ids


def test_empty_analysis_is_safe():
    pe = PeAnalysisResult(metadata=PeMetadata(sha256="d" * 64))
    g = build_pe_graph(pe)
    built = build_pe_exploit_context(graph=g, pe_result=pe, target_display="s")
    # Root is always present; nothing else required.
    assert built.task_context.graph_context is not None
