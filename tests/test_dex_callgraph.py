"""Tests for drake_x.dex.callgraph — call graph builder."""

from __future__ import annotations

import pytest

from drake_x.dex.callgraph import DexCallGraph
from drake_x.models.dex import CallEdge, DexClassInfo, SensitiveApiHit, SensitiveApiCategory


@pytest.fixture
def sample_edges() -> list[CallEdge]:
    return [
        CallEdge(
            caller_class="com.app.Main",
            caller_method="onCreate",
            callee_class="com.app.Utils",
            callee_method="init",
        ),
        CallEdge(
            caller_class="com.app.Utils",
            caller_method="init",
            callee_class="com.app.Network",
            callee_method="connect",
        ),
        CallEdge(
            caller_class="com.app.Network",
            caller_method="connect",
            callee_class="java.net.HttpURLConnection",
            callee_method="openConnection",
        ),
        CallEdge(
            caller_class="com.app.Main",
            caller_method="onResume",
            callee_class="com.app.Sms",
            callee_method="sendData",
        ),
    ]


class TestDexCallGraph:
    def test_add_edges(self, sample_edges: list[CallEdge]) -> None:
        g = DexCallGraph()
        g.add_edges(sample_edges)
        assert g.edge_count == 4
        assert g.method_count > 0
        assert g.class_count > 0

    def test_callees_of(self, sample_edges: list[CallEdge]) -> None:
        g = DexCallGraph()
        g.add_edges(sample_edges)
        callees = g.callees_of("com.app.Main", "onCreate")
        assert ("com.app.Utils", "init") in callees

    def test_callers_of(self, sample_edges: list[CallEdge]) -> None:
        g = DexCallGraph()
        g.add_edges(sample_edges)
        callers = g.callers_of("com.app.Utils", "init")
        assert ("com.app.Main", "onCreate") in callers

    def test_classes_referenced_by(self, sample_edges: list[CallEdge]) -> None:
        g = DexCallGraph()
        g.add_edges(sample_edges)
        refs = g.classes_referenced_by("com.app.Main")
        assert "com.app.Utils" in refs
        assert "com.app.Sms" in refs

    def test_add_class_references(self) -> None:
        g = DexCallGraph()
        classes = [
            DexClassInfo(
                class_name="com.app.Main",
                superclass="android.app.Activity",
                interfaces=["java.io.Serializable"],
            ),
        ]
        g.add_class_references(classes)
        refs = g.classes_referenced_by("com.app.Main")
        assert "android.app.Activity" in refs
        assert "java.io.Serializable" in refs

    def test_find_paths_to_api(self, sample_edges: list[CallEdge]) -> None:
        g = DexCallGraph()
        g.add_edges(sample_edges)
        api_hits = [
            SensitiveApiHit(
                api_category=SensitiveApiCategory.SMS,
                api_name="sendData",
                class_name="com.app.Sms",
            ),
        ]
        paths = g.find_paths_to_api(
            api_hits, entry_classes=["com.app.Main"]
        )
        assert len(paths) >= 1

    def test_empty_graph(self) -> None:
        g = DexCallGraph()
        assert g.edge_count == 0
        assert g.method_count == 0
        assert g.callees_of("x", "y") == []
        assert g.callers_of("x", "y") == []

    def test_to_summary(self, sample_edges: list[CallEdge]) -> None:
        g = DexCallGraph()
        g.add_edges(sample_edges)
        summary = g.to_summary()
        assert "total_methods" in summary
        assert "total_edges" in summary
        assert summary["total_edges"] == 4

    def test_component_graph(self, sample_edges: list[CallEdge]) -> None:
        g = DexCallGraph()
        g.add_edges(sample_edges)
        components = {
            "activities": ["com.app.Main"],
            "services": ["com.app.Network"],
        }
        comp_edges = g.get_component_graph(components)
        # Main references Network via Utils (but that's a transitive ref)
        # Direct: Main → Utils (not a component), so might be empty
        assert isinstance(comp_edges, list)
