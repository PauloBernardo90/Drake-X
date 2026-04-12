"""Regression tests for the v0.9.1 release-gate blockers.

Findings covered:

- CRITICAL: ordinal-only imports collapsed onto a single graph node
- CRITICAL: YARA ``generated_at`` was the current UTC date, making
  output non-reproducible across day boundaries
- MEDIUM: AI truncation notes blamed ``max_nodes`` even when
  ``max_chars`` was the actual limiter
- LOW:    PE CLI ``--ollama-model`` default disagreed with the
  project-wide default in ``drake_x.constants``
"""

from __future__ import annotations

import json

from drake_x.ai.context_builder import build_pe_exploit_context
from drake_x.constants import DEFAULT_OLLAMA_MODEL
from drake_x.graph.context import serialize_graph_context
from drake_x.graph.pe_writer import build_pe_graph, import_id
from drake_x.models.evidence_graph import EvidenceGraph, EvidenceNode, NodeKind
from drake_x.models.pe import (
    ExploitIndicator,
    ExploitIndicatorType,
    PeAnalysisResult,
    PeImport,
    PeMetadata,
    SuspectedShellcodeArtifact,
)
from drake_x.reporting.detection_writer import render_pe_yara_candidates

SHA = "3" * 64


# ---------------------------------------------------------------------------
# CRITICAL — ordinal-only imports must not collapse
# ---------------------------------------------------------------------------


def test_two_ordinal_only_imports_from_same_dll_become_two_nodes():
    r = PeAnalysisResult(
        metadata=PeMetadata(sha256=SHA),
        imports=[
            PeImport(dll="ws2_32.dll", function="", ordinal=1),
            PeImport(dll="ws2_32.dll", function="", ordinal=7),
        ],
    )
    g = build_pe_graph(r)
    n1 = g.get_node(import_id(SHA, "ws2_32.dll", "", ordinal=1))
    n7 = g.get_node(import_id(SHA, "ws2_32.dll", "", ordinal=7))
    assert n1 is not None
    assert n7 is not None
    assert n1.node_id != n7.node_id
    # Both survive with their correct ordinal evidence.
    assert n1.data["ordinal"] == 1
    assert n7.data["ordinal"] == 7


def test_named_imports_unchanged_by_ordinal_fix():
    r = PeAnalysisResult(
        metadata=PeMetadata(sha256=SHA),
        imports=[
            PeImport(dll="kernel32.dll", function="VirtualAllocEx"),
        ],
    )
    g = build_pe_graph(r)
    # Legacy signature (no ordinal) must resolve for named imports.
    assert g.get_node(import_id(SHA, "kernel32.dll", "VirtualAllocEx")) is not None


def test_mixed_named_and_ordinal_imports_all_survive():
    r = PeAnalysisResult(
        metadata=PeMetadata(sha256=SHA),
        imports=[
            PeImport(dll="ws2_32.dll", function="", ordinal=1),
            PeImport(dll="ws2_32.dll", function="", ordinal=2),
            PeImport(dll="ws2_32.dll", function="WSAStartup"),
        ],
    )
    g = build_pe_graph(r)
    # Three distinct import nodes expected.
    import_nodes = [
        n for n in g.nodes
        if n.kind == NodeKind.EVIDENCE and str(n.node_id).startswith(
            f"pe:{SHA[:16]}:import:ws2_32.dll:"
        )
    ]
    assert len(import_nodes) == 3


# ---------------------------------------------------------------------------
# CRITICAL — YARA output must be reproducible across time
# ---------------------------------------------------------------------------


def _yara_fixture() -> PeAnalysisResult:
    return PeAnalysisResult(
        metadata=PeMetadata(sha256=SHA),
        exploit_indicators=[
            ExploitIndicator(
                indicator_type=ExploitIndicatorType.INJECTION_CHAIN,
                title="Injection chain", description="d",
                severity="high", confidence=0.8,
                evidence_refs=[
                    "VirtualAllocEx", "WriteProcessMemory",
                    "CreateRemoteThread", "GetProcAddress",
                ],
                mitre_attck=["T1055"],
            ),
        ],
        suspected_shellcode=[
            SuspectedShellcodeArtifact(
                source_location=".text", offset=0x1000, size=128, entropy=7.6,
                detection_reason="x86 prologue", confidence=0.6,
                preview_hex="909090909090eb10",
            ),
        ],
    )


def test_yara_output_uses_frozen_sentinel_timestamp():
    out = render_pe_yara_candidates(_yara_fixture())
    # Frozen sentinel appears in meta.generated_at; a real UTC date
    # would be "2024-…" / "2025-…" / "2026-…" etc.
    assert 'generated_at = "1970-01-01"' in out
    # Make sure no wall-clock-looking date leaked through.
    import re
    real_dates = re.findall(r'generated_at = "(20[0-9]{2}-\d{2}-\d{2})"', out)
    assert real_dates == [], f"wall-clock dates leaked: {real_dates}"


def test_yara_output_is_byte_reproducible():
    a = render_pe_yara_candidates(_yara_fixture())
    b = render_pe_yara_candidates(_yara_fixture())
    assert a == b


def test_yara_reproducibility_under_patched_clock(monkeypatch):
    """Even if the system clock advances, YARA output must not change."""
    import datetime as _dt

    class _FrozenDT(_dt.datetime):
        @classmethod
        def now(cls, tz=None):  # noqa: ARG003 — sig-compatible
            return cls(2099, 12, 31, tzinfo=_dt.timezone.utc)

    # Patch BEFORE running to simulate an alternate clock.
    monkeypatch.setattr("drake_x.reporting.detection_writer._dt.datetime", _FrozenDT)
    a = render_pe_yara_candidates(_yara_fixture())
    # Unpatch and rerun — output must match.
    monkeypatch.undo()
    b = render_pe_yara_candidates(_yara_fixture())
    assert a == b


# ---------------------------------------------------------------------------
# MEDIUM — truncation note attribution is correct for max_chars
# ---------------------------------------------------------------------------


def _context_fixture() -> PeAnalysisResult:
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
                title="inj", description="d",
                severity="high", confidence=0.8,
                evidence_refs=["VirtualAllocEx"],
                mitre_attck=["T1055"],
            ),
        ],
    )
    r.import_risk_findings = [
        {"dll": "kernel32.dll", "function": "VirtualAllocEx",
         "risk": "high", "category": "injection"},
    ]
    return r


def test_truncation_note_attributes_max_chars_correctly():
    pe = _context_fixture()
    g = build_pe_graph(pe)
    built = build_pe_exploit_context(
        graph=g, pe_result=pe, target_display="s",
        max_nodes=100, max_edges=200,
        max_chars=40,  # tiny char budget → will collapse to minimal dict
    )
    # The note must mention max_chars, not max_nodes.
    notes = " ".join(built.truncation_notes)
    assert "max_chars=40" in notes
    assert "char budget" in notes
    # And we should NOT be attributing it to max_nodes=100.
    assert "max_nodes=100" not in notes


def test_truncation_note_attributes_max_nodes_when_that_is_limiter():
    pe = _context_fixture()
    g = build_pe_graph(pe)
    built = build_pe_exploit_context(
        graph=g, pe_result=pe, target_display="s",
        max_nodes=1, max_edges=1,     # node budget is the real limiter
        max_chars=100000,
    )
    # The note should attribute to max_nodes, not max_chars.
    notes = " ".join(built.truncation_notes)
    assert "max_nodes=1" in notes
    assert "char budget" not in notes


# ---------------------------------------------------------------------------
# LOW — CLI model default matches constants
# ---------------------------------------------------------------------------


def test_pe_cli_default_model_matches_constants():
    from drake_x.cli import app
    from typer.testing import CliRunner

    r = CliRunner().invoke(app, ["pe", "analyze", "--help"])
    assert r.exit_code == 0
    # The printed default for --ollama-model must be DEFAULT_OLLAMA_MODEL.
    assert DEFAULT_OLLAMA_MODEL in r.output


def test_pe_cli_v09_flags_registered():
    from drake_x.cli import app
    from typer.testing import CliRunner

    r = CliRunner().invoke(app, ["pe", "analyze", "--help"])
    assert r.exit_code == 0
    for flag in (
        "--ai-exploit-assessment",
        "--detection-output",
        "--ollama-url",
        "--ollama-model",
    ):
        assert flag in r.output, f"{flag} missing from pe analyze --help"
