"""Tests for the PE pipeline ↔ AI exploit-assessment wiring (v0.9).

We do not stand up a real Ollama in CI. Instead, we patch
:class:`OllamaClient.generate` and verify that:

- the graph is built and attached
- the audit log is written whether or not the model responds
- a successful response is stored on ``result.ai_exploit_assessment``
  and mirrored onto the graph as a ``finding`` node
- truncation notes propagate into the audit record
"""

from __future__ import annotations

import json

from drake_x.ai.audit import read_records
from drake_x.graph.pe_writer import ai_assessment_id, build_pe_graph
from drake_x.models.evidence_graph import NodeKind
from drake_x.models.pe import (
    ExploitIndicator,
    ExploitIndicatorType,
    PeAnalysisResult,
    PeImport,
    PeMetadata,
)
from drake_x.modules.pe_analyze import run_ai_exploit_assessment

SHA = "1" * 64


def _pe() -> PeAnalysisResult:
    r = PeAnalysisResult(
        metadata=PeMetadata(sha256=SHA),
        imports=[PeImport(dll="kernel32.dll", function="VirtualAllocEx")],
        exploit_indicators=[
            ExploitIndicator(
                indicator_type=ExploitIndicatorType.INJECTION_CHAIN,
                title="inj", description="d",
                severity="high", confidence=0.7,
                evidence_refs=["VirtualAllocEx"],
            ),
        ],
    )
    r.import_risk_findings = [
        {"dll": "kernel32.dll", "function": "VirtualAllocEx",
         "risk": "high", "category": "injection"},
    ]
    return r


def test_successful_assessment_attaches_to_result_and_graph(monkeypatch, tmp_path):
    fake_response = json.dumps({
        "exploit_capability_summary": "suspected injection capability",
        "observed_indicators": [],
        "protection_interaction": [],
        "attck_techniques": [],
        "overall_confidence": "medium",
        "dynamic_validation_needed": ["execute in sandbox"],
        "caveats": ["requires validation"],
    })

    async def fake_generate(self, prompt, system=None):  # noqa: ARG001
        return fake_response

    monkeypatch.setattr(
        "drake_x.ai.ollama_client.OllamaClient.generate",
        fake_generate,
    )

    pe = _pe()
    graph = build_pe_graph(pe)
    parsed = run_ai_exploit_assessment(
        pe, graph,
        ollama_base_url="http://127.0.0.1:11434",
        ollama_model="test-model",
        audit_dir=tmp_path / "ai_audit",
    )
    assert parsed is not None
    assert pe.ai_exploit_assessment is not None
    assert pe.ai_exploit_assessment["overall_confidence"] == "medium"

    # Mirror onto the graph as a FINDING node
    node = graph.get_node(ai_assessment_id(SHA))
    assert node is not None
    assert node.kind == NodeKind.FINDING

    # Audit record written
    recs = read_records(tmp_path / "ai_audit", "exploit_assessment")
    assert len(recs) == 1
    assert recs[0].ok is True
    assert recs[0].parsed is not None
    # Context IDs are deterministic and include the root artifact.
    assert any("artifact" in nid for nid in recs[0].context_node_ids)


def test_unreachable_ollama_still_audits(monkeypatch, tmp_path):
    async def explode(self, prompt, system=None):  # noqa: ARG001
        from drake_x.exceptions import AIUnavailableError
        raise AIUnavailableError("connection refused")

    monkeypatch.setattr(
        "drake_x.ai.ollama_client.OllamaClient.generate",
        explode,
    )

    pe = _pe()
    graph = build_pe_graph(pe)
    out = run_ai_exploit_assessment(
        pe, graph,
        ollama_base_url="http://127.0.0.1:1",
        ollama_model="nope",
        audit_dir=tmp_path / "ai_audit",
    )
    assert out is None
    assert pe.ai_exploit_assessment is None
    # Warning surfaces graceful degradation.
    assert any("AI exploit assessment" in w for w in pe.warnings)
    # Audit record still written with ok=False.
    recs = read_records(tmp_path / "ai_audit", "exploit_assessment")
    assert len(recs) == 1
    assert recs[0].ok is False


def test_non_json_response_recorded_but_not_attached(monkeypatch, tmp_path):
    async def fake_generate(self, prompt, system=None):  # noqa: ARG001
        return "sorry I cannot answer"

    monkeypatch.setattr(
        "drake_x.ai.ollama_client.OllamaClient.generate",
        fake_generate,
    )

    pe = _pe()
    graph = build_pe_graph(pe)
    out = run_ai_exploit_assessment(
        pe, graph,
        ollama_base_url="http://x",
        ollama_model="m",
        audit_dir=tmp_path / "ai_audit",
    )
    assert out is None
    assert pe.ai_exploit_assessment is None
    recs = read_records(tmp_path / "ai_audit", "exploit_assessment")
    assert len(recs) == 1
    assert recs[0].ok is False
    assert recs[0].raw_response == "sorry I cannot answer"
