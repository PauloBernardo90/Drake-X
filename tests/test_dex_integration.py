"""Integration tests for DEX deep analysis wiring into APK pipeline.

Tests the bridge (DexAnalysisResult → Finding), evidence graph merge,
report writer DEX section, and CLI flag propagation.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from drake_x.models.apk import ApkAnalysisResult, ApkMetadata
from drake_x.models.dex import (
    ClassifiedString,
    DexAnalysisResult,
    DexFileInfo,
    DexFinding,
    DexFindingSeverity,
    ObfuscationIndicator,
    ObfuscationSignal,
    PackingIndicator,
    SensitiveApiCategory,
    SensitiveApiHit,
    StringCategory,
)
from drake_x.models.evidence_graph import EvidenceGraph, EvidenceNode, NodeKind
from drake_x.models.finding import Finding, FindingSeverity
from drake_x.normalize.apk.dex_bridge import dex_result_to_findings
from drake_x.normalize.apk.dex_graph import merge_dex_into_evidence_graph
from drake_x.normalize.apk.graph_builder import build_apk_evidence_graph
from drake_x.reporting.apk_report_writer import render_apk_markdown, render_apk_executive


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def dex_result() -> DexAnalysisResult:
    """A populated DexAnalysisResult for integration testing."""
    return DexAnalysisResult(
        dex_files=[
            DexFileInfo(
                filename="classes.dex", path="/x/classes.dex",
                size=80000, sha256="aabb" * 16,
                class_count=120, method_count=600, string_count=2000,
            ),
            DexFileInfo(
                filename="classes2.dex", path="/x/classes2.dex",
                size=40000, sha256="ccdd" * 16,
                class_count=50, method_count=200, string_count=800,
            ),
        ],
        total_classes=170,
        total_methods=800,
        total_strings=2800,
        sensitive_api_hits=[
            SensitiveApiHit(
                api_category=SensitiveApiCategory.SMS,
                api_name="SmsManager",
                raw_match="SmsManager.getDefault().sendTextMessage",
                confidence=0.85,
                severity=DexFindingSeverity.HIGH,
                mitre_attck=["T1582.001"],
                source_dex="classes.dex",
            ),
            SensitiveApiHit(
                api_category=SensitiveApiCategory.ACCESSIBILITY,
                api_name="AccessibilityService",
                raw_match="extends AccessibilityService",
                confidence=0.9,
                severity=DexFindingSeverity.HIGH,
                mitre_attck=["T1517"],
                source_dex="classes2.dex",
            ),
            SensitiveApiHit(
                api_category=SensitiveApiCategory.DEX_LOADING,
                api_name="DexClassLoader",
                raw_match="new DexClassLoader(path, dir, null, parent)",
                confidence=0.9,
                severity=DexFindingSeverity.HIGH,
                mitre_attck=["T1407"],
                source_dex="classes.dex",
            ),
        ],
        obfuscation_indicators=[
            ObfuscationIndicator(
                signal=ObfuscationSignal.SHORT_IDENTIFIERS,
                description="25 short class names",
                evidence=["Short class count: 25", "Ratio: 15%"],
                confidence=0.75,
                severity=DexFindingSeverity.MEDIUM,
            ),
            ObfuscationIndicator(
                signal=ObfuscationSignal.DYNAMIC_LOADING,
                description="3 DexClassLoader patterns",
                evidence=["DexClassLoader: 2", "InMemoryDexClassLoader: 1"],
                confidence=0.85,
                severity=DexFindingSeverity.HIGH,
            ),
        ],
        obfuscation_score=0.55,
        packing_indicators=[
            PackingIndicator(
                indicator_type="dropper_pattern",
                description="Small primary, large secondary",
                evidence=["classes.dex: 5, classes2.dex: 150"],
                confidence=0.75,
                affected_files=["classes.dex", "classes2.dex"],
            ),
        ],
        classified_strings=[
            ClassifiedString(
                value="https://evil.example.com/gate.php",
                category=StringCategory.URL,
                confidence=0.8,
                is_potential_ioc=True,
                source_dex="classes.dex",
            ),
            ClassifiedString(
                value="com.targetbank.app",
                category=StringCategory.PACKAGE_TARGET,
                confidence=0.7,
                is_potential_ioc=True,
                source_dex="classes2.dex",
            ),
        ],
        tools_used=["jadx", "apktool"],
        analysis_phases_completed=["dex_enumeration", "jadx_decompilation"],
    )


@pytest.fixture
def apk_result(dex_result: DexAnalysisResult) -> ApkAnalysisResult:
    """An ApkAnalysisResult with DEX deep analysis attached."""
    return ApkAnalysisResult(
        metadata=ApkMetadata(
            file_path="/samples/test.apk",
            sha256="deadbeef" * 8,
            package_name="com.test.malware",
            file_size=500000,
        ),
        dex_analysis=dex_result,
        tools_ran=["aapt", "jadx", "apktool", "dex_deep"],
    )


# ---------------------------------------------------------------------------
# DEX → Finding bridge tests
# ---------------------------------------------------------------------------


class TestDexBridge:
    def test_generates_findings(self, dex_result: DexAnalysisResult) -> None:
        findings = dex_result_to_findings(dex_result)
        assert len(findings) > 0
        assert all(isinstance(f, Finding) for f in findings)

    def test_sensitive_api_findings(self, dex_result: DexAnalysisResult) -> None:
        findings = dex_result_to_findings(dex_result)
        api_findings = [f for f in findings if "sensitive_api" in f.tags]
        assert len(api_findings) == 3  # sms, accessibility, dex_loading
        # All should be HIGH severity
        for f in api_findings:
            assert f.severity == FindingSeverity.HIGH

    def test_api_findings_have_attck(self, dex_result: DexAnalysisResult) -> None:
        findings = dex_result_to_findings(dex_result)
        api_findings = [f for f in findings if "sensitive_api" in f.tags]
        for f in api_findings:
            assert len(f.mitre_attck) > 0

    def test_obfuscation_findings(self, dex_result: DexAnalysisResult) -> None:
        findings = dex_result_to_findings(dex_result)
        obf_findings = [f for f in findings if "obfuscation" in f.tags]
        assert len(obf_findings) >= 1  # at least summary
        summary = [f for f in obf_findings if f.title == "DEX obfuscation assessment"]
        assert len(summary) == 1
        assert "55%" in summary[0].summary

    def test_packing_findings(self, dex_result: DexAnalysisResult) -> None:
        findings = dex_result_to_findings(dex_result)
        pack_findings = [f for f in findings if "packing" in f.tags]
        assert len(pack_findings) == 1
        assert "dropper" in pack_findings[0].title

    def test_string_ioc_findings(self, dex_result: DexAnalysisResult) -> None:
        findings = dex_result_to_findings(dex_result)
        ioc_findings = [f for f in findings if "ioc" in f.tags]
        assert len(ioc_findings) >= 1

    def test_summary_finding(self, dex_result: DexAnalysisResult) -> None:
        findings = dex_result_to_findings(dex_result)
        summary = [f for f in findings if "summary" in f.tags]
        assert len(summary) == 1
        assert "170 classes" in summary[0].summary

    def test_all_findings_have_evidence(self, dex_result: DexAnalysisResult) -> None:
        findings = dex_result_to_findings(dex_result)
        for f in findings:
            assert len(f.evidence) > 0
            assert f.evidence[0].tool_name

    def test_all_findings_tagged_dex(self, dex_result: DexAnalysisResult) -> None:
        findings = dex_result_to_findings(dex_result)
        for f in findings:
            assert "dex" in f.tags

    def test_empty_result(self) -> None:
        findings = dex_result_to_findings(DexAnalysisResult())
        assert findings == []


# ---------------------------------------------------------------------------
# DEX → EvidenceGraph merge tests
# ---------------------------------------------------------------------------


class TestDexGraphMerge:
    def test_adds_dex_nodes(self, dex_result: DexAnalysisResult) -> None:
        graph = EvidenceGraph()
        # Add a root APK node
        root_sha = "deadbeef" * 8
        graph.add_node(EvidenceNode(
            node_id=f"apk:sample:{root_sha[:12]}",
            kind=NodeKind.ARTIFACT,
            domain="apk",
            label="test",
        ))
        merge_dex_into_evidence_graph(graph, dex_result, root_sha256=root_sha)

        dex_nodes = [n for n in graph.nodes if n.domain == "dex"]
        assert len(dex_nodes) > 0

    def test_dex_file_nodes(self, dex_result: DexAnalysisResult) -> None:
        graph = EvidenceGraph()
        merge_dex_into_evidence_graph(graph, dex_result)

        file_nodes = [n for n in graph.nodes if n.node_id.startswith("dex:file:")]
        assert len(file_nodes) == 2
        names = {n.label for n in file_nodes}
        assert "classes.dex" in names
        assert "classes2.dex" in names

    def test_api_finding_nodes(self, dex_result: DexAnalysisResult) -> None:
        graph = EvidenceGraph()
        merge_dex_into_evidence_graph(graph, dex_result)

        api_nodes = [n for n in graph.nodes if n.node_id.startswith("dex:api:")]
        assert len(api_nodes) == 3

    def test_obfuscation_nodes(self, dex_result: DexAnalysisResult) -> None:
        graph = EvidenceGraph()
        merge_dex_into_evidence_graph(graph, dex_result)

        obf_nodes = [n for n in graph.nodes if n.node_id.startswith("dex:obfuscation:")]
        # 2 indicators + 1 score node
        assert len(obf_nodes) >= 2

    def test_packing_nodes(self, dex_result: DexAnalysisResult) -> None:
        graph = EvidenceGraph()
        merge_dex_into_evidence_graph(graph, dex_result)

        pack_nodes = [n for n in graph.nodes if n.node_id.startswith("dex:packing:")]
        assert len(pack_nodes) == 1

    def test_string_ioc_nodes(self, dex_result: DexAnalysisResult) -> None:
        graph = EvidenceGraph()
        merge_dex_into_evidence_graph(graph, dex_result)

        str_nodes = [n for n in graph.nodes if n.node_id.startswith("dex:string:")]
        assert len(str_nodes) == 2

    def test_linked_to_root(self, dex_result: DexAnalysisResult) -> None:
        graph = EvidenceGraph()
        root_sha = "deadbeef" * 8
        graph.add_node(EvidenceNode(
            node_id=f"apk:sample:{root_sha[:12]}",
            kind=NodeKind.ARTIFACT,
            domain="apk",
            label="test",
        ))
        merge_dex_into_evidence_graph(graph, dex_result, root_sha256=root_sha)

        root_id = f"apk:sample:{root_sha[:12]}"
        edges_to_root = graph.edges_to(root_id)
        assert len(edges_to_root) > 0

    def test_serializable(self, dex_result: DexAnalysisResult) -> None:
        graph = EvidenceGraph()
        merge_dex_into_evidence_graph(graph, dex_result)

        # Should serialize to JSON without error
        j = graph.to_json(indent=2)
        data = json.loads(j)
        assert data["node_count"] > 0
        assert data["edge_count"] >= 0

    def test_merges_with_apk_graph(
        self, apk_result: ApkAnalysisResult, dex_result: DexAnalysisResult
    ) -> None:
        """Test that DEX graph merges cleanly into an APK evidence graph."""
        graph = build_apk_evidence_graph(apk_result)
        initial_nodes = len(graph.nodes)

        merge_dex_into_evidence_graph(
            graph, dex_result, root_sha256=apk_result.metadata.sha256
        )

        assert len(graph.nodes) > initial_nodes
        dex_nodes = [n for n in graph.nodes if n.domain == "dex"]
        assert len(dex_nodes) > 0

    def test_empty_result(self) -> None:
        graph = EvidenceGraph()
        merge_dex_into_evidence_graph(graph, DexAnalysisResult())
        assert len(graph.nodes) == 0


# ---------------------------------------------------------------------------
# Report writer DEX section tests
# ---------------------------------------------------------------------------


class TestReportWriterDexSection:
    def test_markdown_includes_dex_section(self, apk_result: ApkAnalysisResult) -> None:
        md = render_apk_markdown(apk_result)
        assert "## DEX Deep Analysis" in md
        assert "classes.dex" in md
        assert "classes2.dex" in md

    def test_markdown_includes_api_table(self, apk_result: ApkAnalysisResult) -> None:
        md = render_apk_markdown(apk_result)
        assert "SmsManager" in md
        assert "AccessibilityService" in md
        assert "T1582.001" in md

    def test_markdown_includes_obfuscation(self, apk_result: ApkAnalysisResult) -> None:
        md = render_apk_markdown(apk_result)
        assert "Obfuscation score" in md
        assert "55%" in md

    def test_markdown_includes_packing(self, apk_result: ApkAnalysisResult) -> None:
        md = render_apk_markdown(apk_result)
        assert "dropper_pattern" in md

    def test_markdown_includes_string_iocs(self, apk_result: ApkAnalysisResult) -> None:
        md = render_apk_markdown(apk_result)
        assert "evil.example.com" in md

    def test_executive_includes_dex_summary(self, apk_result: ApkAnalysisResult) -> None:
        exec_md = render_apk_executive(apk_result)
        assert "DEX deep analysis" in exec_md
        assert "sensitive API" in exec_md

    def test_no_dex_section_without_analysis(self) -> None:
        result = ApkAnalysisResult(
            metadata=ApkMetadata(sha256="abcd" * 16, package_name="com.test"),
        )
        md = render_apk_markdown(result)
        assert "## DEX Deep Analysis" not in md

    def test_markdown_json_serializable(self, apk_result: ApkAnalysisResult) -> None:
        """Ensure the full result with dex_analysis serializes to JSON."""
        from drake_x.reporting.apk_report_writer import render_apk_json
        j = render_apk_json(apk_result)
        data = json.loads(j)
        assert "dex_analysis" in data
        assert data["dex_analysis"] is not None


# ---------------------------------------------------------------------------
# CLI flag propagation test
# ---------------------------------------------------------------------------


class TestCliWiring:
    def test_run_analysis_accepts_dex_deep_flag(self) -> None:
        """Verify run_analysis accepts the use_dex_deep parameter."""
        import inspect
        from drake_x.modules.apk_analyze import run_analysis
        sig = inspect.signature(run_analysis)
        assert "use_dex_deep" in sig.parameters

    def test_apk_result_has_dex_analysis_field(self) -> None:
        """Verify ApkAnalysisResult has the dex_analysis field."""
        r = ApkAnalysisResult()
        assert hasattr(r, "dex_analysis")
        assert r.dex_analysis is None
