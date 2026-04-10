"""Tests for v0.4 APK additions: evidence graph builder, cross-domain bridge, AI task registration."""

from __future__ import annotations

import json

import pytest

from drake_x.ai.tasks import (
    ALL_TASKS,
    ApkAssessmentTask,
    ApkCampaignTask,
    ApkObfuscationTask,
)
from drake_x.models.apk import (
    ApkAnalysisResult,
    ApkComponent,
    ApkMetadata,
    ApkPermission,
    BehaviorIndicator,
    CampaignAssessment,
    CampaignSimilarity,
    ComponentType,
    NetworkIndicator,
    ObfuscationConfidence,
    ObfuscationTrait,
    ProtectionIndicator,
    ProtectionStatus,
)
from drake_x.models.evidence_graph import EdgeType, NodeKind
from drake_x.normalize.apk.bridge import apk_result_to_findings
from drake_x.normalize.apk.graph_builder import build_apk_evidence_graph


def _sample_result() -> ApkAnalysisResult:
    return ApkAnalysisResult(
        metadata=ApkMetadata(
            sha256="abcd1234" * 8,
            package_name="com.evil.dropper",
            file_size=2_000_000,
        ),
        permissions=[
            ApkPermission(name="android.permission.READ_SMS", is_dangerous=True, is_suspicious=True),
            ApkPermission(name="android.permission.REQUEST_INSTALL_PACKAGES", is_suspicious=True),
            ApkPermission(name="android.permission.INTERNET"),
        ],
        behavior_indicators=[
            BehaviorIndicator(category="dropper", pattern="PackageInstaller", evidence="PI found", confidence=0.9),
            BehaviorIndicator(category="dynamic_loading", pattern="DexClassLoader", evidence="DCL found", confidence=0.9),
            BehaviorIndicator(category="exfiltration", pattern="SMS read/send", evidence="SmsManager found", confidence=0.85),
            BehaviorIndicator(category="communication", pattern="Firebase / FCM", evidence="FCM topic subscribe", confidence=0.7),
        ],
        network_indicators=[
            NetworkIndicator(value="https://evil.example.com/drop", indicator_type="url"),
        ],
        obfuscation_traits=[
            ObfuscationTrait(trait="identifier_renaming", confidence=ObfuscationConfidence.HIGH, evidence=["25 short names"]),
        ],
        protection_indicators=[
            ProtectionIndicator(protection_type="root_detection", status=ProtectionStatus.OBSERVED, evidence=["su check"]),
            ProtectionIndicator(protection_type="emulator_detection", status=ProtectionStatus.NOT_OBSERVED),
        ],
        campaign_assessments=[
            CampaignAssessment(
                category="dropper",
                similarity=CampaignSimilarity.CONSISTENT_WITH,
                matching_traits=["PackageInstaller", "dynamic loading", "REQUEST_INSTALL_PACKAGES"],
                confidence=0.8,
            ),
            CampaignAssessment(category="banker-like", similarity=CampaignSimilarity.INSUFFICIENT_EVIDENCE),
        ],
        tools_ran=["aapt", "apktool", "strings"],
    )


# ---- evidence graph builder ----


def test_graph_has_root_node() -> None:
    g = build_apk_evidence_graph(_sample_result())
    roots = [n for n in g.nodes if n.kind == NodeKind.ARTIFACT and n.domain == "apk"]
    assert len(roots) == 1
    assert "com.evil.dropper" in roots[0].label


def test_graph_has_permission_nodes() -> None:
    g = build_apk_evidence_graph(_sample_result())
    perms = [n for n in g.nodes if n.kind == NodeKind.EVIDENCE and "perm:" in n.node_id]
    assert len(perms) == 3


def test_graph_has_behavior_nodes() -> None:
    g = build_apk_evidence_graph(_sample_result())
    behaviors = [n for n in g.nodes if n.kind == NodeKind.FINDING and "behavior:" in n.node_id]
    assert len(behaviors) == 4


def test_graph_has_network_indicator() -> None:
    g = build_apk_evidence_graph(_sample_result())
    nets = [n for n in g.nodes if n.kind == NodeKind.INDICATOR]
    assert len(nets) >= 1
    assert any("evil.example.com" in n.label for n in nets)


def test_graph_has_protection_node_only_for_observed() -> None:
    g = build_apk_evidence_graph(_sample_result())
    prots = g.nodes_by_kind(NodeKind.PROTECTION)
    assert len(prots) == 1  # root_detection observed; emulator not observed
    assert prots[0].label == "root_detection"


def test_graph_has_campaign_node_only_for_matching() -> None:
    g = build_apk_evidence_graph(_sample_result())
    campaigns = g.nodes_by_kind(NodeKind.CAMPAIGN)
    assert len(campaigns) == 1
    assert campaigns[0].label == "dropper"


def test_graph_edges_link_to_root() -> None:
    g = build_apk_evidence_graph(_sample_result())
    root = [n for n in g.nodes if n.kind == NodeKind.ARTIFACT][0]
    incoming = g.edges_to(root.node_id)
    assert len(incoming) > 0
    assert all(e.edge_type in {EdgeType.DERIVED_FROM, EdgeType.RELATED_TO} for e in incoming)


def test_graph_supports_edges_exist() -> None:
    g = build_apk_evidence_graph(_sample_result())
    supports = [e for e in g.edges if e.edge_type == EdgeType.SUPPORTS]
    assert len(supports) > 0


# ---- cross-domain bridge ----


def test_bridge_produces_standard_findings() -> None:
    findings = apk_result_to_findings(_sample_result())
    assert len(findings) > 0
    # Every finding must have the correct source and tags
    for f in findings:
        assert f.source.value in {"rule"}
        assert "apk" in f.tags


def test_bridge_suspicious_permissions_finding() -> None:
    findings = apk_result_to_findings(_sample_result())
    perm_findings = [f for f in findings if "permission" in f.title.lower()]
    assert len(perm_findings) == 1
    assert perm_findings[0].fact_or_inference == "fact"


def test_bridge_behavior_findings_per_category() -> None:
    findings = apk_result_to_findings(_sample_result())
    behavior_findings = [f for f in findings if "behavior" in f.title.lower()]
    categories = {f.title.split(": ")[-1] for f in behavior_findings}
    assert "dropper" in categories
    assert "dynamic_loading" in categories
    assert "exfiltration" in categories


def test_bridge_campaign_findings_are_inference() -> None:
    findings = apk_result_to_findings(_sample_result())
    campaign_findings = [f for f in findings if "campaign" in f.title.lower()]
    assert len(campaign_findings) == 1
    assert campaign_findings[0].fact_or_inference == "inference"


def test_bridge_protection_findings() -> None:
    findings = apk_result_to_findings(_sample_result())
    prot_findings = [f for f in findings if "protection" in f.title.lower()]
    assert len(prot_findings) == 1  # only root_detection (observed)


# ---- AI task registration ----


def test_apk_ai_tasks_registered() -> None:
    assert ApkAssessmentTask in ALL_TASKS
    assert ApkObfuscationTask in ALL_TASKS
    assert ApkCampaignTask in ALL_TASKS


def test_apk_ai_tasks_have_prompt_files() -> None:
    for cls in [ApkAssessmentTask, ApkObfuscationTask, ApkCampaignTask]:
        task = cls()
        path = task.prompts_dir / task.prompt_file
        assert path.exists(), f"missing prompt: {path}"


def test_apk_ai_tasks_have_schemas() -> None:
    for cls in [ApkAssessmentTask, ApkObfuscationTask, ApkCampaignTask]:
        assert cls.schema, f"{cls.name} has empty schema"
