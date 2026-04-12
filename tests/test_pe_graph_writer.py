"""Tests for the PE graph writer (v0.9).

Verifies:

- root artifact node is present and carries the sample hash
- sections, imports, protections, indicators are ingested
- indicator nodes link ``supports`` edges back to matching import nodes
- node IDs are deterministic (same result → same IDs)
- merge + dedupe passes are idempotent
"""

from __future__ import annotations

from drake_x.graph.pe_writer import (
    artifact_id,
    build_pe_graph,
    dedupe_graph,
    import_id,
    indicator_id,
    merge_graphs,
    protection_id,
    section_id,
)
from drake_x.models.evidence_graph import EdgeType, NodeKind
from drake_x.models.pe import (
    ExploitIndicator,
    ExploitIndicatorType,
    PeAnalysisResult,
    PeImport,
    PeMetadata,
    PeProtectionStatus,
    PeSection,
    ProtectionInteractionAssessment,
    SuspectedShellcodeArtifact,
)

SHA = "a" * 64


def _fixture() -> PeAnalysisResult:
    r = PeAnalysisResult(
        metadata=PeMetadata(sha256=SHA, md5="b" * 32, file_size=12345, file_type="PE32"),
        sections=[
            PeSection(name=".text", entropy=6.5, is_executable=True),
            PeSection(name=".UPX0", entropy=7.8, is_executable=True),
        ],
        imports=[
            PeImport(dll="kernel32.dll", function="VirtualAllocEx"),
            PeImport(dll="kernel32.dll", function="WriteProcessMemory"),
            PeImport(dll="kernel32.dll", function="CreateRemoteThread"),
        ],
        protection=PeProtectionStatus(dep_enabled=False, aslr_enabled=True),
        exploit_indicators=[
            ExploitIndicator(
                indicator_type=ExploitIndicatorType.INJECTION_CHAIN,
                title="Classic injection chain",
                description="alloc+write+execute",
                severity="high",
                confidence=0.75,
                evidence_refs=["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"],
                mitre_attck=["T1055"],
            ),
        ],
        suspected_shellcode=[
            SuspectedShellcodeArtifact(
                source_location=".UPX0",
                offset=0x1000,
                size=256,
                entropy=7.9,
                detection_reason="x86 prologue",
                confidence=0.5,
                preview_hex="909090909090",
            ),
        ],
        protection_interactions=[
            ProtectionInteractionAssessment(
                protection="DEP",
                protection_enabled=False,
                observed_capability="shellcode setup",
                interaction_assessment="capability plausible without DEP",
                severity="high",
                confidence=0.7,
            ),
        ],
    )
    r.import_risk_findings = [
        {"dll": "kernel32.dll", "function": "VirtualAllocEx",
         "risk": "high", "category": "injection", "technique_id": "T1055"},
        {"dll": "kernel32.dll", "function": "WriteProcessMemory",
         "risk": "high", "category": "injection"},
        {"dll": "kernel32.dll", "function": "CreateRemoteThread",
         "risk": "high", "category": "injection"},
    ]
    return r


def test_root_artifact_present():
    g = build_pe_graph(_fixture())
    root = g.get_node(artifact_id(SHA))
    assert root is not None
    assert root.kind == NodeKind.ARTIFACT
    assert root.data["sha256"] == SHA


def test_sections_and_imports_ingested():
    g = build_pe_graph(_fixture())
    assert g.get_node(section_id(SHA, ".text")) is not None
    assert g.get_node(section_id(SHA, ".UPX0")) is not None
    assert g.get_node(import_id(SHA, "kernel32.dll", "VirtualAllocEx")) is not None
    # all imports should link back to the root artifact via derived_from
    imp = import_id(SHA, "kernel32.dll", "VirtualAllocEx")
    root = artifact_id(SHA)
    edges = [e for e in g.edges_from(imp) if e.target_id == root]
    assert any(e.edge_type == EdgeType.DERIVED_FROM for e in edges)


def test_protection_nodes_present():
    g = build_pe_graph(_fixture())
    dep = g.get_node(protection_id(SHA, "DEP"))
    aslr = g.get_node(protection_id(SHA, "ASLR"))
    assert dep is not None and dep.data["enabled"] is False
    assert aslr is not None and aslr.data["enabled"] is True


def test_indicator_links_supports_to_import():
    g = build_pe_graph(_fixture())
    ind_nid = indicator_id(SHA, "injection_chain", 0)
    # There should be SUPPORTS edges from each matching import → indicator.
    supports = [e for e in g.edges_to(ind_nid) if e.edge_type == EdgeType.SUPPORTS]
    # All three APIs match, so we expect three supporting edges.
    assert len(supports) == 3
    src_ids = {e.source_id for e in supports}
    assert import_id(SHA, "kernel32.dll", "VirtualAllocEx") in src_ids


def test_shellcode_links_to_its_section():
    g = build_pe_graph(_fixture())
    sec = section_id(SHA, ".UPX0")
    # any shellcode node should have an edge from the section (SUPPORTS).
    supp = [e for e in g.edges_from(sec) if e.edge_type == EdgeType.SUPPORTS]
    assert len(supp) >= 1


def test_ids_are_deterministic():
    g1 = build_pe_graph(_fixture())
    g2 = build_pe_graph(_fixture())
    ids1 = sorted(n.node_id for n in g1.nodes)
    ids2 = sorted(n.node_id for n in g2.nodes)
    assert ids1 == ids2


def test_dedupe_removes_duplicate_edges():
    g = build_pe_graph(_fixture())
    # Insert a duplicate edge with lower confidence; dedupe should keep
    # the higher-confidence one.
    from drake_x.models.evidence_graph import EvidenceEdge

    dup_src = import_id(SHA, "kernel32.dll", "VirtualAllocEx")
    dup_tgt = indicator_id(SHA, "injection_chain", 0)
    g.add_edge(EvidenceEdge(
        source_id=dup_src, target_id=dup_tgt,
        edge_type=EdgeType.SUPPORTS, confidence=0.1,
    ))
    deduped = dedupe_graph(g)
    kept = [e for e in deduped.edges
            if e.source_id == dup_src and e.target_id == dup_tgt
            and e.edge_type == EdgeType.SUPPORTS]
    assert len(kept) == 1
    assert kept[0].confidence >= 0.5  # higher-confidence original won


def test_merge_graphs_idempotent():
    g1 = build_pe_graph(_fixture())
    g2 = build_pe_graph(_fixture())
    merged = merge_graphs(g1, g2)
    # After merge+dedupe, node count equals single graph's count.
    deduped = dedupe_graph(merged)
    assert len({n.node_id for n in deduped.nodes}) == len({n.node_id for n in g1.nodes})
