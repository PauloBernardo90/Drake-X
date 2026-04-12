"""Regression tests for the four v0.9 validated findings.

Each test is labelled with its finding ID so a future reader can trace
the behaviour back to the specific bug the test was written to prevent.
"""

from __future__ import annotations

import json

from drake_x.graph.context import serialize_graph_context
from drake_x.graph.pe_writer import (
    build_pe_graph,
    section_id,
    shellcode_id,
)
from drake_x.models.evidence_graph import EdgeType, EvidenceGraph, EvidenceNode, NodeKind
from drake_x.models.pe import (
    PeAnalysisResult,
    PeMetadata,
    PeSection,
    SuspectedShellcodeArtifact,
    ExploitIndicator,
    ExploitIndicatorType,
)
from drake_x.reporting.detection_writer import (
    render_pe_stix_bundle,
    render_pe_yara_candidates,
)

SHA = "9" * 64


# ---------------------------------------------------------------------------
# Finding 1 — duplicate section names must not collapse
# ---------------------------------------------------------------------------


def test_finding1_duplicate_section_names_survive_as_distinct_nodes():
    r = PeAnalysisResult(
        metadata=PeMetadata(sha256=SHA),
        sections=[
            PeSection(name=".text", entropy=6.0, raw_size=100, is_executable=True),
            PeSection(name=".text", entropy=7.8, raw_size=200, is_executable=True),
        ],
    )
    g = build_pe_graph(r)
    n0 = g.get_node(section_id(SHA, ".text", ordinal=0))
    n1 = g.get_node(section_id(SHA, ".text", ordinal=1))
    assert n0 is not None
    assert n1 is not None
    assert n0.node_id != n1.node_id
    # Evidence preserved on both nodes (distinct raw sizes and entropies).
    assert n0.data["raw_size"] == 100
    assert n1.data["raw_size"] == 200
    assert n0.data["entropy"] == 6.0
    assert n1.data["entropy"] == 7.8
    # Both sections link back to the artifact root.
    pe_section_nodes = [
        n for n in g.nodes
        if n.kind == NodeKind.EVIDENCE and n.data.get("name") == ".text"
    ]
    assert len(pe_section_nodes) == 2


def test_finding1_shellcode_links_to_all_matching_sections():
    r = PeAnalysisResult(
        metadata=PeMetadata(sha256=SHA),
        sections=[
            PeSection(name=".text", entropy=6.0, is_executable=True),
            PeSection(name=".text", entropy=7.8, is_executable=True),
        ],
        suspected_shellcode=[
            SuspectedShellcodeArtifact(
                source_location=".text",
                offset=0x1000, size=64, entropy=7.5,
                detection_reason="x86 prologue", confidence=0.5,
                preview_hex="909090",
            ),
        ],
    )
    g = build_pe_graph(r)
    # Shellcode node gets SUPPORTS edges from BOTH sections named ".text".
    sc_nid = shellcode_id(SHA, 0x1000, 0)
    supporting = [e for e in g.edges_to(sc_nid) if e.edge_type == EdgeType.SUPPORTS]
    sources = {e.source_id for e in supporting}
    assert section_id(SHA, ".text", ordinal=0) in sources
    assert section_id(SHA, ".text", ordinal=1) in sources


def test_finding1_determinism_same_analysis_same_ids():
    def make() -> PeAnalysisResult:
        return PeAnalysisResult(
            metadata=PeMetadata(sha256=SHA),
            sections=[
                PeSection(name=".text", entropy=6.0, is_executable=True),
                PeSection(name=".text", entropy=7.8, is_executable=True),
            ],
        )

    g1 = build_pe_graph(make())
    g2 = build_pe_graph(make())
    assert sorted(n.node_id for n in g1.nodes) == sorted(n.node_id for n in g2.nodes)


# ---------------------------------------------------------------------------
# Finding 2 — packer YARA must intersect evidence, not union it
# ---------------------------------------------------------------------------


def test_finding2_packer_rule_not_emitted_from_unrelated_sections():
    """Packer hit on .UPX0 + high-entropy on .text must NOT emit a rule
    citing .text. The original bug emitted the union of suspicious
    sections; the fix requires the same section to carry both signals.
    """
    r = PeAnalysisResult(
        metadata=PeMetadata(sha256=SHA),
        sections=[
            PeSection(name=".text", entropy=7.6, is_executable=True),  # high-entropy but no packer hit
            PeSection(name=".UPX0", entropy=5.0, is_executable=True),  # packer hit but low entropy
        ],
        suspicious_patterns=[
            {"finding_type": "packer_section_name", "section": ".UPX0"},
        ],
    )
    out = render_pe_yara_candidates(r)
    assert "PackerSection" not in out, \
        "Packer rule must not cite unrelated .text when .UPX0 lacks entropy"


def test_finding2_packer_rule_emitted_only_on_true_intersection():
    """A section that carries BOTH high entropy + executable AND a
    packer-name hit is a valid evidence join → rule emitted, citing
    only that section.
    """
    r = PeAnalysisResult(
        metadata=PeMetadata(sha256=SHA),
        sections=[
            PeSection(name=".text", entropy=7.6, is_executable=True),  # distractor
            PeSection(name=".UPX0", entropy=7.8, is_executable=True),  # real evidence
        ],
        suspicious_patterns=[
            {"finding_type": "packer_section_name", "section": ".UPX0"},
        ],
    )
    out = render_pe_yara_candidates(r)
    assert "Drake_Candidate_PackerSection_" in out
    assert ".UPX0" in out
    # .text must NOT appear as a YARA string in this rule.
    assert '$sec_0 = ".text"' not in out
    assert '$sec_1 = ".text"' not in out


def test_finding2_no_packer_rule_when_packer_hit_but_no_entropy():
    r = PeAnalysisResult(
        metadata=PeMetadata(sha256=SHA),
        sections=[
            PeSection(name=".UPX0", entropy=3.0, is_executable=True),
        ],
        suspicious_patterns=[
            {"finding_type": "packer_section_name", "section": ".UPX0"},
        ],
    )
    assert "PackerSection" not in render_pe_yara_candidates(r)


# ---------------------------------------------------------------------------
# Finding 3 — serialize_graph_context must honour max_chars
# ---------------------------------------------------------------------------


def _populate_graph(n_nodes: int = 8) -> EvidenceGraph:
    g = EvidenceGraph()
    for i in range(n_nodes):
        g.add_node(EvidenceNode(
            node_id=f"pe:ff:section:long_section_name_{i}:{i}",
            kind=NodeKind.EVIDENCE,
            domain="pe",
            label=f"section long_section_name_{i}",
            data={
                "name": f"long_section_name_{i}",
                "virtual_size": 0x1000 * i,
                "raw_size": 0x800 * i,
                "entropy": 5.5 + i * 0.1,
            },
        ))
    return g


def test_finding3_tiny_budget_is_honoured():
    g = _populate_graph(8)
    ctx = serialize_graph_context(g, max_nodes=20, max_edges=40, max_chars=80)
    assert len(json.dumps(ctx, default=str)) <= 80


def test_finding3_medium_budget_is_honoured():
    g = _populate_graph(30)
    ctx = serialize_graph_context(g, max_nodes=50, max_edges=100, max_chars=500)
    assert len(json.dumps(ctx, default=str)) <= 500


def test_finding3_empty_graph_serializes_normally():
    g = EvidenceGraph()
    ctx = serialize_graph_context(g, max_chars=4000)
    assert ctx == {"nodes": [], "edges": [], "stats": {"total_nodes": 0, "total_edges": 0}}


def test_finding3_deterministic_across_calls():
    g = _populate_graph(12)
    a = serialize_graph_context(g, max_nodes=20, max_edges=40, max_chars=120)
    b = serialize_graph_context(g, max_nodes=20, max_edges=40, max_chars=120)
    assert json.dumps(a, default=str) == json.dumps(b, default=str)


def test_finding3_truncation_result_is_valid_json_dict():
    g = _populate_graph(20)
    ctx = serialize_graph_context(g, max_nodes=20, max_edges=40, max_chars=40)
    # Must be a dict, must serialize within budget, must parse back.
    text = json.dumps(ctx, default=str)
    assert len(text) <= 40
    parsed = json.loads(text)
    assert isinstance(parsed, dict)


# ---------------------------------------------------------------------------
# Finding 4 — STIX reproducibility
# ---------------------------------------------------------------------------


def _stix_fixture() -> PeAnalysisResult:
    return PeAnalysisResult(
        metadata=PeMetadata(sha256=SHA, md5="a" * 32, file_size=1024),
        exploit_indicators=[
            ExploitIndicator(
                indicator_type=ExploitIndicatorType.INJECTION_CHAIN,
                title="Injection chain", description="d",
                severity="high", confidence=0.75,
                evidence_refs=["VirtualAllocEx"], mitre_attck=["T1055"],
            ),
            ExploitIndicator(
                indicator_type=ExploitIndicatorType.SHELLCODE_SETUP,
                title="Shellcode setup", description="d",
                severity="medium", confidence=0.6,
                evidence_refs=["VirtualAlloc"], mitre_attck=["T1059"],
            ),
        ],
    )


def test_finding4_identical_input_produces_identical_stix_bytes():
    a = render_pe_stix_bundle(_stix_fixture())
    b = render_pe_stix_bundle(_stix_fixture())
    assert a == b


def test_finding4_different_sample_produces_different_bundle_id():
    r1 = _stix_fixture()
    r2 = _stix_fixture()
    r2.metadata = PeMetadata(sha256="7" * 64, md5="b" * 32, file_size=2048)
    b1 = json.loads(render_pe_stix_bundle(r1))
    b2 = json.loads(render_pe_stix_bundle(r2))
    assert b1["id"] != b2["id"]
    file_ids_1 = [o["id"] for o in b1["objects"] if o["type"] == "file"]
    file_ids_2 = [o["id"] for o in b2["objects"] if o["type"] == "file"]
    assert file_ids_1 != file_ids_2


def test_finding4_relationship_ids_are_stable():
    b1 = json.loads(render_pe_stix_bundle(_stix_fixture()))
    b2 = json.loads(render_pe_stix_bundle(_stix_fixture()))
    rel1 = sorted(o["id"] for o in b1["objects"] if o["type"] == "relationship")
    rel2 = sorted(o["id"] for o in b2["objects"] if o["type"] == "relationship")
    assert rel1 == rel2
    assert len(rel1) >= 1  # fixture has high-confidence indicators


def test_finding4_indicator_ids_differ_per_indicator_within_one_bundle():
    b = json.loads(render_pe_stix_bundle(_stix_fixture()))
    ind_ids = [o["id"] for o in b["objects"] if o["type"] == "indicator"]
    assert len(ind_ids) == len(set(ind_ids))  # unique within the bundle
