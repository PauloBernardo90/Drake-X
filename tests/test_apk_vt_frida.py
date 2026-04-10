"""Tests for VT enrichment, Frida targets, and enhanced APK reporting."""

from __future__ import annotations

import json

import pytest

from drake_x.integrations.apk.virustotal import lookup_sha256
from drake_x.models.apk import (
    ApkAnalysisResult,
    ApkMetadata,
    ApkPermission,
    BehaviorIndicator,
    CampaignAssessment,
    CampaignSimilarity,
    FridaHookTarget,
    ProtectionIndicator,
    ProtectionStatus,
    VtEnrichment,
)
from drake_x.normalize.apk.frida_targets import generate_frida_targets
from drake_x.reporting.apk_report_writer import render_apk_json, render_apk_markdown


# ======================================================================
# VT enrichment — disabled / degraded
# ======================================================================


def test_vt_no_api_key() -> None:
    result = lookup_sha256("a" * 64, api_key="")
    assert result.available is False
    assert "no API key" in result.error


def test_vt_invalid_hash() -> None:
    result = lookup_sha256("tooshort", api_key="fake-key")
    assert result.available is False
    assert "invalid SHA-256" in result.error


def test_vt_enrichment_model_defaults() -> None:
    vt = VtEnrichment()
    assert vt.available is False
    assert vt.sha256 == ""
    assert vt.source_label == "virustotal_v3_api"


def test_vt_enrichment_serializes_to_json() -> None:
    vt = VtEnrichment(
        available=True, sha256="a" * 64, detection_ratio="42/72",
        detections=42, total_engines=72,
        top_detections=[{"engine": "TestAV", "result": "Trojan.Android.Test"}],
    )
    data = vt.model_dump(mode="json")
    assert data["detection_ratio"] == "42/72"
    assert len(data["top_detections"]) == 1


# ======================================================================
# Frida targets — generation
# ======================================================================


def _result_with_protections() -> ApkAnalysisResult:
    return ApkAnalysisResult(
        protection_indicators=[
            ProtectionIndicator(
                protection_type="root_detection",
                status=ProtectionStatus.OBSERVED,
                evidence=["su binary check at /system/xbin/su"],
            ),
            ProtectionIndicator(
                protection_type="certificate_pinning",
                status=ProtectionStatus.OBSERVED,
                evidence=["CertificatePinner.check() in OkHttp"],
            ),
            ProtectionIndicator(
                protection_type="emulator_detection",
                status=ProtectionStatus.NOT_OBSERVED,
            ),
        ],
        behavior_indicators=[
            BehaviorIndicator(category="dynamic_loading", pattern="DexClassLoader", evidence="DCL found", confidence=0.9),
            BehaviorIndicator(category="dropper", pattern="PackageInstaller", evidence="PI found", confidence=0.85),
            BehaviorIndicator(category="communication", pattern="Firebase / FCM", evidence="FCM topic", confidence=0.7),
        ],
    )


def test_frida_targets_from_protections() -> None:
    targets = generate_frida_targets(_result_with_protections())
    assert len(targets) > 0
    types = {t.protection_type for t in targets}
    assert "root_detection" in types
    assert "certificate_pinning" in types
    # emulator_detection was NOT_OBSERVED → no target
    assert "emulator_detection" not in types


def test_frida_targets_from_behaviors() -> None:
    targets = generate_frida_targets(_result_with_protections())
    types = {t.protection_type for t in targets}
    assert "dynamic_loading" in types
    assert "dropper_behavior" in types
    assert "c2_communication" in types


def test_frida_target_has_evidence() -> None:
    targets = generate_frida_targets(_result_with_protections())
    for t in targets:
        assert t.evidence_basis, f"target {t.target_class}.{t.target_method} has no evidence"
        assert t.expected_observation
        assert t.suggested_validation_objective
        assert t.analyst_notes


def test_frida_target_model_fields() -> None:
    ft = FridaHookTarget(
        target_class="java.io.File",
        target_method="exists",
        protection_type="root_detection",
        evidence_basis=["su binary check"],
        expected_observation="Returns true for su paths",
        priority="high",
        confidence=0.9,
    )
    assert ft.priority == "high"
    data = ft.model_dump(mode="json")
    assert data["confidence"] == 0.9


def test_empty_result_produces_no_targets() -> None:
    targets = generate_frida_targets(ApkAnalysisResult())
    assert targets == []


# ======================================================================
# Report rendering — VT + Frida sections
# ======================================================================


def _full_result() -> ApkAnalysisResult:
    return ApkAnalysisResult(
        metadata=ApkMetadata(
            file_path="/tmp/sample.apk", file_size=4_000_000,
            md5="d41d8cd98f00b204e9800998ecf8427e",
            sha256="e3b0c44298fc1c149afbf4c8996fb924" * 2,
            package_name="com.evil.dropper", version_name="1.0",
            version_code="1", min_sdk="21", target_sdk="33",
        ),
        permissions=[
            ApkPermission(name="android.permission.READ_SMS", is_dangerous=True, is_suspicious=True),
        ],
        protection_indicators=[
            ProtectionIndicator(protection_type="root_detection", status=ProtectionStatus.OBSERVED,
                                evidence=["su check"]),
        ],
        behavior_indicators=[
            BehaviorIndicator(category="dynamic_loading", pattern="DexClassLoader",
                              evidence="DCL found", confidence=0.9),
        ],
        vt_enrichment=VtEnrichment(
            available=True, sha256="e3b0" * 16, detection_ratio="42/72",
            detections=42, total_engines=72, scan_date="2026-04-01",
            popular_threat_label="Trojan.Android.Dropper",
            top_detections=[{"engine": "TestAV", "result": "Trojan.Android.Test"}],
        ),
        frida_targets=[
            FridaHookTarget(
                target_class="java.io.File", target_method="exists",
                protection_type="root_detection", evidence_basis=["su check"],
                expected_observation="Returns true for su paths",
                suggested_validation_objective="Confirm root check",
                analyst_notes="Hook and monitor",
                priority="high", confidence=0.8,
            ),
        ],
        campaign_assessments=[
            CampaignAssessment(category="dropper", similarity=CampaignSimilarity.CONSISTENT_WITH,
                               matching_traits=["DexClassLoader"], confidence=0.7),
        ],
        tools_ran=["aapt", "apktool", "virustotal"],
    )


def test_report_contains_vt_section() -> None:
    md = render_apk_markdown(_full_result())
    assert "## VirusTotal Enrichment" in md
    assert "42/72" in md
    assert "external intel enrichment" in md
    assert "Trojan.Android.Dropper" in md


def test_report_contains_frida_section() -> None:
    md = render_apk_markdown(_full_result())
    assert "## Frida Dynamic Validation Targets" in md
    assert "analyst-assisted dynamic hypothesis" in md
    assert "java.io.File" in md
    assert "root_detection" in md
    assert "does NOT execute" in md


def test_report_vt_omitted_when_not_requested() -> None:
    result = ApkAnalysisResult(metadata=ApkMetadata(package_name="clean"))
    md = render_apk_markdown(result)
    assert "VirusTotal" not in md


def test_report_frida_omitted_when_no_targets() -> None:
    result = ApkAnalysisResult(metadata=ApkMetadata(package_name="clean"))
    md = render_apk_markdown(result)
    assert "Frida Dynamic Validation" not in md


def test_report_conclusions_has_recommendations() -> None:
    md = render_apk_markdown(_full_result())
    assert "Recommendations" in md
    assert "Containment" in md
    assert "Dynamic validation" in md


def test_report_evidence_classification_labels() -> None:
    md = render_apk_markdown(_full_result())
    assert "static fact" in md
    assert "analytic assessment" in md
    assert "external intel" in md
    assert "dynamic hypothesis" in md


def test_json_includes_vt_and_frida() -> None:
    body = render_apk_json(_full_result())
    data = json.loads(body)
    assert data["vt_enrichment"]["detection_ratio"] == "42/72"
    assert len(data["frida_targets"]) == 1
    assert data["frida_targets"][0]["protection_type"] == "root_detection"


# ======================================================================
# Fact vs inference vs dynamic hypothesis separation
# ======================================================================


def test_fact_inference_hypothesis_distinct_in_report() -> None:
    """The report must clearly label each evidence category."""
    md = render_apk_markdown(_full_result())
    # Static facts are in surface/static sections
    assert "Surface Analysis" in md
    # Campaign assessment is inference
    assert "Campaign Objective Assessment" in md
    # VT is external intel
    assert "external intel enrichment" in md
    # Frida is dynamic hypothesis
    assert "analyst-assisted dynamic hypothesis" in md
    # Conclusions clarify all four
    assert "static fact" in md
    assert "external intel" in md
    assert "dynamic hypothesis" in md
